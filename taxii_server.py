# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

import base64
import contextlib
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
import fcntl
from flask import request, abort
from functools import wraps
from models import ApiKey, RequestLog, ServerStats, CustomBundle, db
from stix_generator import STIXGenerator
from version import __version__

class TAXIIServer:
    """TAXII 2.x server implementation"""
    
    API_ROOT = "api"
    COLLECTION_ID = "threat-intel-demo"
    COLLECTION_TITLE = "Demo Threat Intelligence Collection"
    COLLECTION_DESCRIPTION = "Mock STIX threat intelligence indicators for demonstration purposes by GoCortex.io"
    MAX_OBJECTS_LIMIT = 100
    # The generated feed is synthetic rather than a durable repository.  Keep
    # one bounded snapshot long enough for a client to walk it with `next`
    # and for the manifest to describe those exact objects.  A later poll
    # receives a fresh snapshot after expiry.
    SYNTHETIC_SNAPSHOT_OBJECTS = 50
    SYNTHETIC_SNAPSHOT_TTL = timedelta(minutes=5)
    _snapshot = None
    _snapshot_lock = threading.Lock()
    _object_date_added = {}
    SNAPSHOT_STATE_VERSION = 1

    @staticmethod
    def collection_descriptor():
        """Single source of truth for the TAXII Collection resource.

        Returned by both /collections/ and /collections/{id}/ so the two can never drift.
        """
        return {
            "id": TAXIIServer.COLLECTION_ID,
            "title": TAXIIServer.COLLECTION_TITLE,
            "description": TAXIIServer.COLLECTION_DESCRIPTION,
            "can_read": True,
            "can_write": False,
            "media_types": [
                "application/stix+json;version=2.1"
            ]
        }

    @staticmethod
    def _format_timestamp(value):
        """Return an RFC3339 timestamp with millisecond precision."""
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
            return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return value

    @classmethod
    def _new_synthetic_snapshot(cls):
        """Build the bounded in-memory snapshot used by the demo feed.

        The object generator intentionally remains database-backed and
        realistic.  Snapshotting its result is the small piece of repository
        behaviour needed by TAXII: object IDs in a manifest must be the same
        IDs a client can retrieve on the following objects request.
        """
        created_at = datetime.now(timezone.utc)
        objects = STIXGenerator.generate_related_indicators_bundle(
            cls.SYNTHETIC_SNAPSHOT_OBJECTS
        )
        snapshot = {
            "id": str(uuid.uuid4()),
            "objects": objects,
            # For a synthetic feed, this is the time the snapshot entered the
            # ephemeral repository, not each object's STIX `created` time.
            "date_added": created_at,
            "expires_at": created_at + cls.SYNTHETIC_SNAPSHOT_TTL,
        }
        for obj in objects:
            if obj.get("id"):
                cls._object_date_added[obj["id"]] = created_at
        return snapshot

    @classmethod
    def _index_snapshot(cls, snapshot):
        """Populate local date metadata from a shared snapshot."""
        for obj in snapshot.get("objects", []):
            if obj.get("id"):
                cls._object_date_added[obj["id"]] = snapshot["date_added"]

    @classmethod
    def _state_directory(cls):
        """Return secured, database-scoped shared TAXII state storage."""
        parent = os.environ.get("MOCKTAXII_STATE_DIR", "/tmp")
        directory = os.path.join(parent, "mocktaxii-taxii")
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            os.chmod(directory, 0o700)
            details = os.stat(directory)
        except OSError as exc:
            raise RuntimeError(
                f"Unable to prepare secured TAXII state directory: {exc}"
            ) from exc
        if hasattr(os, "getuid") and details.st_uid != os.getuid():
            raise RuntimeError("TAXII state directory is not owned by this worker")
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise RuntimeError("TAXII state directory must not be group/world accessible")
        database_identity = os.environ.get("DATABASE_URL", "default")
        identity = hashlib.sha256(database_identity.encode("utf-8")).hexdigest()[:16]
        return directory, identity

    @classmethod
    @contextlib.contextmanager
    def _state_lock(cls, name):
        """Lock a shared state file for an atomic read-modify-write."""
        directory, identity = cls._state_directory()
        path = os.path.join(directory, f"{name}-{identity}.json")
        lock_path = f"{path}.lock"
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "a+") as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                yield path
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise RuntimeError(f"Unable to lock shared TAXII state: {exc}") from exc

    @staticmethod
    def _read_state(path):
        try:
            with open(path, encoding="utf-8") as state_file:
                value = json.load(state_file)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Unable to read shared TAXII state: {exc}") from exc
        if not isinstance(value, dict) or value.get("version") != TAXIIServer.SNAPSHOT_STATE_VERSION:
            raise RuntimeError("Shared TAXII state has an unsupported format")
        return value

    @staticmethod
    def _write_state(path, value):
        directory = os.path.dirname(path)
        fd, temporary = tempfile.mkstemp(
            prefix=".taxii-state-", suffix=".tmp", dir=directory
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as state_file:
                json.dump(value, state_file, separators=(",", ":"))
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
        except (OSError, TypeError, ValueError) as exc:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise RuntimeError(f"Unable to write shared TAXII state: {exc}") from exc

    @classmethod
    def _serialise_snapshot(cls, snapshot):
        return {
            "version": cls.SNAPSHOT_STATE_VERSION,
            "id": snapshot["id"],
            "objects": snapshot["objects"],
            "date_added": cls._format_timestamp(snapshot["date_added"]),
            "expires_at": cls._format_timestamp(snapshot["expires_at"]),
        }

    @staticmethod
    def _parse_state_timestamp(value):
        if not isinstance(value, str):
            raise RuntimeError("Shared TAXII state contains an invalid timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeError("Shared TAXII state contains an invalid timestamp") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _deserialise_snapshot(cls, value):
        if not isinstance(value.get("id"), str) or not isinstance(value.get("objects"), list):
            raise RuntimeError("Shared TAXII state contains an invalid snapshot")
        return {
            "id": value["id"],
            "objects": value["objects"],
            "date_added": cls._parse_state_timestamp(value.get("date_added")),
            "expires_at": cls._parse_state_timestamp(value.get("expires_at")),
        }

    @classmethod
    def _get_synthetic_snapshot(cls, snapshot_id=None):
        """Get a current snapshot or reject an expired pagination cursor."""
        now = datetime.now(timezone.utc)
        with cls._snapshot_lock:
            with cls._state_lock("synthetic-snapshot") as path:
                stored = cls._read_state(path)
                snapshot = (
                    cls._deserialise_snapshot(stored)
                    if stored is not None else None
                )
                cls._snapshot = snapshot
                if snapshot is not None:
                    cls._index_snapshot(snapshot)

                if snapshot_id is not None:
                    if not snapshot or snapshot["id"] != snapshot_id:
                        abort(400, description="The TAXII pagination cursor is unknown or expired")
                    if snapshot["expires_at"] <= now:
                        cls._snapshot = None
                        abort(400, description="The TAXII pagination cursor is expired")
                    return snapshot

                if snapshot and snapshot["expires_at"] > now:
                    return snapshot

                cls._snapshot = cls._new_synthetic_snapshot()
                cls._write_state(path, cls._serialise_snapshot(cls._snapshot))
                return cls._snapshot

    @staticmethod
    def _custom_state_name(api_key_id):
        """One state file per API key.

        A single shared file accumulated every key's bundle forever and was
        parsed in full on every manifest request, so one key's poll paid for
        every other key's bundle.
        """
        return f"custom-snapshot-{int(api_key_id)}"

    @staticmethod
    def _serialise_custom_snapshot(snapshot):
        # Only the reference is persisted.  CustomBundle.stix_payload is the
        # durable copy and is never rewritten after upload, so storing the
        # objects again bought nothing and made the file unbounded.
        return {
            "version": TAXIIServer.SNAPSHOT_STATE_VERSION,
            "id": snapshot["id"],
            "bundle": snapshot["bundle"],
            "date_added": TAXIIServer._format_timestamp(snapshot["date_added"]),
            "expires_at": TAXIIServer._format_timestamp(snapshot["expires_at"]),
        }

    @classmethod
    def _get_custom_snapshot(cls, api_key_id):
        """Return the live custom snapshot for one API key, if it still is.

        Custom snapshots lapse on the same TTL as the synthetic one.  Without
        that, one served bundle pinned the key's manifest to it permanently
        while the objects endpoint had long since rotated back to synthetic
        data, so the two endpoints described different collections.
        """
        if api_key_id is None:
            return None
        with cls._state_lock(cls._custom_state_name(api_key_id)) as path:
            value = cls._read_state(path)
        if not value:
            return None
        snapshot_id = value.get("id")
        bundle_id = value.get("bundle")
        if (
            not isinstance(snapshot_id, str)
            or not snapshot_id
            or not isinstance(bundle_id, int)
        ):
            raise RuntimeError("Shared TAXII state contains an invalid custom snapshot")
        expires_at = cls._parse_state_timestamp(value.get("expires_at"))
        if expires_at <= datetime.now(timezone.utc):
            return None
        bundle = db.session.get(CustomBundle, bundle_id)
        stix_data = bundle.get_stix_bundle() if bundle else None
        if not stix_data:
            return None
        snapshot = {
            "id": snapshot_id,
            "bundle": bundle_id,
            "objects": stix_data.get("objects", []),
            "date_added": cls._parse_state_timestamp(value.get("date_added")),
            "expires_at": expires_at,
        }
        return snapshot

    @classmethod
    def _record_custom_snapshot(cls, api_key_id, snapshot):
        """Persist a custom snapshot for workers and worker replacements."""
        if api_key_id is None:
            raise RuntimeError("A custom snapshot requires an API key")
        with cls._state_lock(cls._custom_state_name(api_key_id)) as path:
            cls._write_state(path, cls._serialise_custom_snapshot(snapshot))

    @staticmethod
    def _cursor_secret():
        try:
            from flask import current_app
            secret = current_app.secret_key
        except RuntimeError:
            from app import app
            secret = app.secret_key
        if not secret:
            raise RuntimeError("TAXII cursor signing requires the application secret")
        return secret.encode("utf-8") if isinstance(secret, str) else secret

    @classmethod
    def _sign_cursor_payload(cls, payload):
        canonical = json.dumps(
            payload, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return hmac.new(cls._cursor_secret(), canonical, hashlib.sha256).hexdigest()

    @classmethod
    def _encode_cursor(
        cls, kind, snapshot_id=None, offset=0, bundle_id=None, api_key_id=None
    ):
        payload = {
            "kind": kind,
            "offset": offset,
            # The numeric database ID is not secret; binding it prevents a
            # signed cursor obtained by one API key being replayed by another.
            "key": "" if api_key_id is None else str(api_key_id),
        }
        if snapshot_id:
            payload["snapshot"] = snapshot_id
        if bundle_id is not None:
            payload["bundle"] = bundle_id
        payload["sig"] = cls._sign_cursor_payload(payload)
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return encoded

    @classmethod
    def _decode_cursor(cls, value, api_key_id=None):
        if not value:
            return None
        try:
            padded = value + "=" * (-len(value) % 4)
            payload = json.loads(
                base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            )
            signature = payload.pop("sig")
            key = payload["key"]
            if (
                not isinstance(signature, str)
                or not isinstance(key, str)
                or not hmac.compare_digest(
                signature, cls._sign_cursor_payload(payload)
                )
            ):
                raise ValueError
            expected_key = "" if api_key_id is None else str(api_key_id)
            if key != expected_key:
                raise ValueError
            if payload.get("kind") not in {"synthetic", "custom", "custom_manifest"}:
                raise ValueError
            offset = payload["offset"]
            if not isinstance(offset, int) or offset < 0:
                raise ValueError
            if not payload.get("snapshot"):
                raise ValueError
            if payload["kind"] in {"custom", "custom_manifest"} and not payload.get("bundle"):
                raise ValueError
            return payload
        except (AttributeError, ValueError, TypeError, KeyError, json.JSONDecodeError,
                UnicodeDecodeError):
            abort(400, description="The TAXII pagination cursor is invalid")

    @classmethod
    def _normalise_limit(cls, limit, default=50):
        try:
            value = int(limit)
        except (ValueError, TypeError):
            return default
        if value < 1:
            return default
        return min(value, cls.MAX_OBJECTS_LIMIT)

    @staticmethod
    def _as_utc(value):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _repository_timestamp(value):
        """Normalise a stored ingestion time to the wire precision."""
        value = TAXIIServer._as_utc(value)
        return value.replace(microsecond=(value.microsecond // 1000) * 1000)

    @classmethod
    def date_added_range(cls, objects):
        """Return repository ingestion timestamps for a response page."""
        values = [
            cls._object_date_added[obj["id"]]
            for obj in objects
            if obj.get("id") in cls._object_date_added
        ]
        if not values:
            return None
        return (
            cls._format_timestamp(min(values)),
            cls._format_timestamp(max(values)),
        )

    @staticmethod
    def parse_added_after(added_after):
        """Parse TAXII's RFC3339 ``added_after`` filter."""
        if not added_after:
            return None
        value = added_after.strip()
        if value.endswith('Z'):
            value = value[:-1] + '+00:00'
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            abort(400, description=(
                f"added_after must be an RFC3339 timestamp, got '{added_after}'"
            ))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def added_after_excludes_everything(added_after):
        """Interpret the TAXII `added_after` filter for a generating server.

        This server synthesises objects at request time, so everything it
        returns was added just now. That makes the filter meaningful in exactly
        one direction: a timestamp in the future excludes everything, anything
        else excludes nothing.

        The parameter was previously accepted and dropped on the floor without
        even being validated. Malformed values now get a TAXII error rather than
        being silently ignored.
        """
        parsed = TAXIIServer.parse_added_after(added_after)
        return bool(parsed and parsed > datetime.now(timezone.utc))

    @staticmethod
    def credential_from_authorization(auth_header):
        """Extract the presented credential from an Authorization header.

        Exactly one `Bearer ` prefix is removed.  This is the single source of
        truth for both authentication and the per-API-key rate-limit bucket:
        while authentication stripped *every* occurrence and the limiter key
        stripped one, `Bearer Bearer <key>` authenticated as the key but was
        counted under its own bucket, so one key could be replayed under
        unlimited independent rate limits.
        """
        auth_header = (auth_header or '').strip()
        if auth_header.startswith('Bearer '):
            return auth_header[len('Bearer '):].strip()
        # Direct API key format (Cortex XSIAM with _header:Authorization)
        return auth_header

    @staticmethod
    def validate_api_key(f):
        """Decorator to validate API key for TAXII endpoints"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for API key in headers
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                abort(401, description="Missing Authorization header")

            api_key_value = TAXIIServer.credential_from_authorization(auth_header)
            api_key = ApiKey.query.filter_by(key=api_key_value, is_active=True).first()
            
            if not api_key:
                abort(401, description="Invalid API key")
            
            # Get real client IP considering proxy headers
            from app import get_real_ip

            # Log the request
            log_entry = RequestLog()
            log_entry.api_key_id = api_key.id
            log_entry.endpoint = request.endpoint
            log_entry.method = request.method
            log_entry.ip_address = request.remote_addr
            log_entry.user_agent = request.headers.get('User-Agent')
            db.session.add(log_entry)

            # Counters are bumped SQL-side so concurrent workers cannot lose
            # increments to a read-modify-write race.
            #
            # requests_since_bundle only advances on the objects endpoint. It
            # used to advance on all five, while only get_collection_objects
            # could consume it - so a standard TIM poll (api-root -> collections
            # -> collection-info -> objects) advanced it by 4 per poll and a
            # frequency=10 bundle actually arrived about every 3rd poll.
            updates = {ApiKey.request_count: ApiKey.request_count + 1}
            if request.endpoint == 'taxii_collection_objects':
                updates[ApiKey.requests_since_bundle] = ApiKey.requests_since_bundle + 1
            ApiKey.query.filter_by(id=api_key.id).update(updates, synchronize_session=False)
            db.session.commit()
            db.session.refresh(api_key)

            # Add api_key to kwargs for use in the endpoint
            kwargs['api_key'] = api_key
            kwargs['log_entry'] = log_entry

            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def get_discovery_response():
        """TAXII Discovery endpoint response"""
        return {
            "title": f"MockTAXII v{__version__}",
            "description": "A lightweight TAXII 2.x server providing synthetic threat intelligence for demonstration and testing",
            "contact": "demo@mocktaxii.local",
            "default": f"/taxii2/{TAXIIServer.API_ROOT}/",
            "api_roots": [
                f"/taxii2/{TAXIIServer.API_ROOT}/"
            ]
        }
    
    @staticmethod
    def get_api_root_response():
        """TAXII API Root endpoint response"""
        return {
            "title": f"MockTAXII v{__version__} API Root",
            "description": "Synthetic threat intelligence data for TAXII client testing",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760  # 10MB
        }
    
    @staticmethod
    def get_collections_response():
        """TAXII Collections endpoint response"""
        return {
            "collections": [
                TAXIIServer.collection_descriptor()
            ]
        }
    
    @staticmethod
    def get_collection_objects(
        collection_id, limit=50, added_after=None, api_key=None, log_entry=None,
        next_token=None
    ):
        """Get a stable, bounded page of objects from a collection.

        Generated objects are captured once per short-lived snapshot.  Custom
        bundles use the same cursor scheme, with the bundle ID bound into the
        cursor so a later page cannot accidentally switch to another bundle
        (or another API key's bundle).
        """
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")

        limit = TAXIIServer._normalise_limit(limit)
        added_after_value = TAXIIServer.parse_added_after(added_after)
        if TAXIIServer.added_after_excludes_everything(added_after):
            return {"more": False, "objects": []}

        api_key_id = getattr(api_key, "id", None)
        cursor = TAXIIServer._decode_cursor(next_token, api_key_id)
        source_kind = "synthetic"
        source_id = None
        source_snapshot_id = None
        source_objects = None
        source_date_added = None

        if cursor:
            source_kind = cursor["kind"]
            if source_kind == "synthetic":
                snapshot = TAXIIServer._get_synthetic_snapshot(cursor["snapshot"])
                source_id = snapshot["id"]
                source_snapshot_id = snapshot["id"]
                source_objects = snapshot["objects"]
                source_date_added = snapshot["date_added"]
            elif source_kind == "custom":
                # A custom cursor is only valid for the API key that owns the
                # request.  Global bundles are valid for any authenticated key
                # but are still checked for active status.
                if not api_key:
                    abort(401, description="A TAXII API key is required for pagination")
                custom_bundle = db.session.get(CustomBundle, cursor["bundle"])
                if (
                    not custom_bundle
                    or not custom_bundle.is_active
                    or (
                        custom_bundle.api_key_id is not None
                        and custom_bundle.api_key_id != api_key.id
                    )
                ):
                    abort(400, description="The custom bundle pagination cursor is no longer available")
                custom_snapshot = TAXIIServer._get_custom_snapshot(api_key.id)
                if (
                    not custom_snapshot
                    or custom_snapshot["bundle"] != custom_bundle.id
                    or custom_snapshot["id"] != cursor["snapshot"]
                ):
                    abort(400, description="The custom bundle pagination cursor is no longer available")
                source_objects = custom_snapshot["objects"]
                source_id = custom_bundle.id
                source_snapshot_id = custom_snapshot["id"]
                source_date_added = custom_snapshot["date_added"]
                for obj in source_objects:
                    if obj.get("id"):
                        TAXIIServer._object_date_added[obj["id"]] = source_date_added
            else:
                abort(400, description="The TAXII objects cursor is invalid")
        else:
            # A custom bundle is offered only when its normal rotation slot is
            # claimed.  Once offered, every page follows its cursor and is not
            # affected by subsequent rotation counter changes.
            custom_bundle = None
            if api_key:
                custom_bundle = CustomBundle.get_bundle_for_api_key(api_key.id)
                if custom_bundle:
                    claimed = db.session.query(ApiKey).filter(
                        ApiKey.id == api_key.id,
                        ApiKey.requests_since_bundle >= custom_bundle.frequency
                    ).update(
                        {ApiKey.requests_since_bundle: 0},
                        synchronize_session=False
                    )
                    if claimed:
                        stix_data = custom_bundle.get_stix_bundle()
                        if not stix_data:
                            db.session.rollback()
                            abort(500, description="The stored custom STIX bundle is unreadable")
                        source_kind = "custom"
                        source_id = custom_bundle.id
                        # Repository ingestion time is when this page set
                        # entered the served collection, not when an operator
                        # uploaded it.  Using created_at meant every
                        # incremental `added_after` poll filtered the bundle
                        # out *after* its rotation slot had been spent, so the
                        # bundle was recorded as served and never delivered.
                        served_at = datetime.now(timezone.utc)
                        custom_snapshot = {
                            "id": str(uuid.uuid4()),
                            "bundle": custom_bundle.id,
                            "objects": stix_data.get("objects", []),
                            "date_added": served_at,
                            "expires_at": served_at + TAXIIServer.SYNTHETIC_SNAPSHOT_TTL,
                        }
                        source_snapshot_id = custom_snapshot["id"]
                        source_objects = custom_snapshot["objects"]
                        source_date_added = served_at
                        for obj in source_objects:
                            if obj.get("id"):
                                TAXIIServer._object_date_added[obj["id"]] = source_date_added
                        # Retain the last served custom page set so the
                        # key-scoped manifest can describe objects that are
                        # actually available through this collection.
                        TAXIIServer._record_custom_snapshot(
                            api_key.id, custom_snapshot
                        )
                        custom_bundle.mark_served()
                        if log_entry:
                            log_entry.custom_bundle_served = True
                            log_entry.custom_bundle_id = custom_bundle.id
                        db.session.commit()
                if not custom_bundle:
                    # No bundle applies (deleted, deactivated, or never
                    # assigned).  Clamp the counter so a newly uploaded bundle
                    # starts its configured cadence at zero.
                    db.session.query(ApiKey).filter(
                        ApiKey.id == api_key.id,
                        ApiKey.requests_since_bundle > 0
                    ).update(
                        {ApiKey.requests_since_bundle: 0},
                        synchronize_session=False
                    )
                    db.session.commit()

            if source_objects is None:
                snapshot = TAXIIServer._get_synthetic_snapshot()
                source_id = snapshot["id"]
                source_snapshot_id = snapshot["id"]
                source_objects = snapshot["objects"]
                source_date_added = snapshot["date_added"]

        if (
            added_after_value
            and source_date_added
            and TAXIIServer._repository_timestamp(source_date_added) <= added_after_value
        ):
            # Nothing in this snapshot entered the collection after the
            # client's watermark.  End the page set rather than emptying the
            # source and then rejecting a cursor that is still valid.
            return {"more": False, "objects": []}

        offset = cursor["offset"] if cursor else 0
        if offset > len(source_objects):
            abort(400, description="The TAXII pagination cursor is past the end of the collection")
        page = source_objects[offset:offset + limit]
        next_offset = offset + len(page)
        more = next_offset < len(source_objects)

        response = {
            "more": more,
            "objects": page
        }
        if more:
            response["next"] = TAXIIServer._encode_cursor(
                source_kind,
                snapshot_id=source_snapshot_id,
                bundle_id=source_id if source_kind == "custom" else None,
                offset=next_offset,
                api_key_id=api_key_id,
            )

        # Update server stats. Only indicator objects count - relationships and
        # narrative SDOs were previously counted too, inflating the figure ~4x.
        indicator_count = sum(1 for obj in page if obj.get('type') == 'indicator')
        ServerStats.increment_indicators(indicator_count)

        # Keep this mapping populated for route-level TAXII date headers.  It
        # deliberately records repository ingestion time, never STIX `created`.
        for obj in page:
            if obj.get("id"):
                TAXIIServer._object_date_added[obj["id"]] = source_date_added
        return response

    @classmethod
    def get_collection_manifest(
        cls, collection_id, limit=50, added_after=None, api_key=None,
        next_token=None
    ):
        """Return a manifest for IDs that the synthetic collection serves."""
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")

        limit = cls._normalise_limit(limit)
        added_after_value = cls.parse_added_after(added_after)
        if TAXIIServer.added_after_excludes_everything(added_after):
            return {"more": False, "objects": []}

        api_key_id = getattr(api_key, "id", None)
        cursor = cls._decode_cursor(next_token, api_key_id)
        if cursor and cursor["kind"] not in {"synthetic", "custom_manifest"}:
            abort(400, description="The TAXII manifest cursor is invalid")
        source_date_added = None

        if cursor and cursor["kind"] == "custom_manifest":
            if not api_key:
                abort(401, description="A TAXII API key is required for pagination")
            custom_snapshot = cls._get_custom_snapshot(api_key.id)
            if (
                not custom_snapshot
                or custom_snapshot["bundle"] != cursor["bundle"]
                or custom_snapshot["id"] != cursor["snapshot"]
            ):
                abort(400, description="The custom manifest cursor is no longer available")
            custom_bundle = db.session.get(CustomBundle, cursor["bundle"])
            if (
                not custom_bundle
                or not custom_bundle.is_active
                or (
                    custom_bundle.api_key_id is not None
                    and custom_bundle.api_key_id != api_key.id
                )
            ):
                abort(400, description="The custom manifest cursor is no longer available")
            source_kind = "custom_manifest"
            source_snapshot_id = custom_snapshot["id"]
            source_objects = custom_snapshot["objects"]
            source_date_added = custom_snapshot["date_added"]
        elif cursor:
            snapshot = cls._get_synthetic_snapshot(cursor["snapshot"])
            source_kind = "synthetic"
            source_snapshot_id = snapshot["id"]
            source_objects = snapshot["objects"]
            source_date_added = snapshot["date_added"]
        else:
            custom_snapshot = (
                cls._get_custom_snapshot(api_key.id) if api_key else None
            )
            custom_bundle = (
                db.session.get(CustomBundle, custom_snapshot["bundle"])
                if custom_snapshot else None
            )
            if (
                custom_snapshot
                and custom_bundle
                and custom_bundle.is_active
                and (
                    custom_bundle.api_key_id is None
                    or custom_bundle.api_key_id == api_key.id
                )
            ):
                source_objects = custom_snapshot["objects"]
                source_date_added = custom_snapshot["date_added"]
                source_kind = "custom_manifest"
                source_snapshot_id = custom_snapshot["id"]
            else:
                snapshot = cls._get_synthetic_snapshot()
                source_objects = snapshot["objects"]
                source_date_added = snapshot["date_added"]
                source_kind = "synthetic"
                source_snapshot_id = snapshot["id"]

        if (
            added_after_value
            and cls._repository_timestamp(source_date_added) <= added_after_value
        ):
            # As in get_collection_objects: end the page set rather than
            # invalidating a live cursor.
            return {"more": False, "objects": []}
        offset = cursor["offset"] if cursor else 0
        if offset > len(source_objects):
            abort(400, description="The TAXII manifest cursor is past the end of the collection")

        page = source_objects[offset:offset + limit]
        next_offset = offset + len(page)
        # `version` is omitted when absent rather than emitted as null. STIX
        # Cyber Observables carry neither `modified` nor `created`, so a custom
        # bundle of raw IOCs produced "version": null - which is not a valid
        # TAXII versioning value and which strict clients reject.
        response_objects = []
        for obj in page:
            record = {
                "id": obj["id"],
                "date_added": cls._format_timestamp(source_date_added),
                "media_type": "application/stix+json;version=2.1",
            }
            version = obj.get("modified") or obj.get("created")
            if version:
                record["version"] = version
            response_objects.append(record)
        response = {
            "more": next_offset < len(source_objects),
            "objects": response_objects,
        }
        if response["more"]:
            if source_kind == "custom_manifest":
                response["next"] = cls._encode_cursor(
                    "custom_manifest",
                    snapshot_id=source_snapshot_id,
                    bundle_id=custom_snapshot["bundle"],
                    offset=next_offset,
                    api_key_id=api_key_id,
                )
            else:
                response["next"] = cls._encode_cursor(
                    "synthetic",
                    snapshot_id=source_snapshot_id,
                    offset=next_offset,
                    api_key_id=api_key_id,
                )
        return response
    
    @staticmethod
    def get_collection_info(collection_id):
        """Get information about a specific collection"""
        if collection_id != TAXIIServer.COLLECTION_ID:
            abort(404, description="Collection not found")
        
        return TAXIIServer.collection_descriptor()
