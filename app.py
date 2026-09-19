# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

import ipaddress
import logging
import os
import secrets
import stat
from flask import Blueprint, Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Placeholder values that must never be used as a real signing key. A signing
# key published in the repository lets anyone forge an authenticated session.
PLACEHOLDER_SECRETS = {
    "your-secret-key-here-change-in-production",
    "your-secret-key",
    "your-unique-session-secret-key-here-64-characters-minimum",
    "your-session-secret-here",
    "change-me",
    "changeme",
    "change-this-secret",
    "replace-with-a-random-secret",
    "replace-me",
    "default-secret",
    "development-secret",
    "secret",
}

# Shared state that must be identical across gunicorn workers. Held on a
# filesystem path rather than in process memory, because a per-process value
# makes worker A reject a session cookie that worker B signed.
RUNTIME_STATE_DIR = os.environ.get("MOCKTAXII_STATE_DIR", "/tmp")


def read_or_create_shared_secret(filename, nbytes=32):
    """Return a secret shared by every worker, creating it once if absent.

    Uses O_CREAT|O_EXCL so that concurrent workers racing at startup cannot
    clobber each other: the loser of the race falls through to the read.
    Mode 0600 - the previous implementation left the admin password
    world-readable at 0644.
    """
    path = os.path.join(RUNTIME_STATE_DIR, filename)
    value = secrets.token_hex(nbytes)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    except OSError:
        # Unwritable state dir: fall back to a process-local value. Sessions
        # will not survive a restart, and multi-worker logins will be flaky.
        return value, False
    else:
        with os.fdopen(fd, "w") as fh:
            fh.write(value)
        return value, True

    # An existing file is only trusted if this process could have written it.
    # Without these checks a local user could pre-create
    # /tmp/mocktaxii_admin_password (or the session secret) on a shared host
    # and have it adopted verbatim - choosing the admin password, or the key
    # that signs sessions and TAXII cursors. O_NOFOLLOW additionally refuses a
    # symlink pointing somewhere else entirely.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return value, False

    try:
        info = os.fstat(fd)
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            print(f"[MockTAXII] WARNING: {path} is not owned by this process; "
                  "ignoring it and using a process-local value instead.", flush=True)
            return value, False
        if stat.S_ISREG(info.st_mode) is False or stat.S_IMODE(info.st_mode) & 0o077:
            print(f"[MockTAXII] WARNING: {path} is group- or world-accessible; "
                  "ignoring it and using a process-local value instead.", flush=True)
            return value, False
        with os.fdopen(fd, "r") as fh:
            fd = None
            existing = fh.read().strip()
        if existing:
            return existing, True
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    return value, False


def resolve_session_secret(is_production):
    """Resolve the Flask signing key, refusing known-bad values in production."""
    configured = os.environ.get("SESSION_SECRET", "").strip()

    if configured and configured.lower() not in PLACEHOLDER_SECRETS:
        return configured

    if is_production:
        raise RuntimeError(
            "SESSION_SECRET is unset or set to a known placeholder. Refusing to "
            "start in production: a predictable signing key lets anyone forge an "
            "authenticated admin session. Generate one with "
            "`openssl rand -base64 32` and set SESSION_SECRET."
        )

    secret, shared = read_or_create_shared_secret("mocktaxii_session_secret")
    if not shared:
        print(
            "[MockTAXII] WARNING: SESSION_SECRET is unset and the runtime state "
            "directory is not writable. Each worker has generated its own signing "
            "key, so logins will fail intermittently. Set SESSION_SECRET."
        )
    else:
        print(
            "[MockTAXII] WARNING: SESSION_SECRET is unset; using a generated "
            "development key. Set SESSION_SECRET for any non-local deployment."
        )
    return secret


def get_real_ip():
    """Client IP for logging.

    Reads only remote_addr. When TRUST_PROXY is enabled, ProxyFix has already
    resolved X-Forwarded-For into remote_addr by taking the rightmost entry -
    the one the trusted proxy appended. Reading the header directly here (as
    this function previously did, taking the leftmost entry) would hand the
    value straight to the client, letting anyone forge it.
    """
    ip = request.remote_addr or "127.0.0.1"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    # request_log.ip_address is VARCHAR(45); an over-long value would abort the
    # transaction on PostgreSQL rather than merely logging badly.
    return ip[:45]


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()
# Keyed on the real peer address, never on a client-supplied header.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)

# Create the app.
#
# Static files live in assets/ and are served from /assets. The Flask endpoint
# is still called "static", so every url_for('static', filename=...) in the
# templates keeps working unchanged.
app = Flask(__name__, static_folder='assets', static_url_path='/assets')

# Third-party libraries are served from /vendor, out of a directory of their
# own at the repository root, so assets/ holds only first-party files. Flask
# supports exactly one static_folder per application, so the second tree needs
# a blueprint; static_folder is relative to this module, which puts it at
# ./vendor in a checkout and /app/vendor in the image.
#
# The endpoint is "vendor.static", so templates reference these with
# url_for('vendor.static', filename=...) rather than url_for('static', ...).
# Both are same-origin, so the Content-Security-Policy is unaffected.
app.register_blueprint(Blueprint(
    'vendor', __name__, static_folder='vendor', static_url_path='/vendor'))

is_production = os.environ.get('FLASK_ENV') == 'production'
app.secret_key = resolve_session_secret(is_production)

# Only honour X-Forwarded-* when explicitly told there is a trusted proxy in
# front. Applied unconditionally, it makes remote_addr forgeable by any direct
# client - which is exactly the deployment docker-compose.yml describes.
trust_proxy = os.environ.get('TRUST_PROXY', 'false').lower() in ('1', 'true', 'yes')
if trust_proxy:
    # x_host and x_prefix are deliberately 0. Neither shipped proxy sets or
    # strips X-Forwarded-Host or X-Forwarded-Prefix, so trusting them let a
    # client supply its own: X-Forwarded-Prefix became SCRIPT_NAME, and every
    # url_for() redirect - /logout among them - then pointed wherever the
    # client asked. Nothing in the shipped topology serves the app under a
    # rewritten host or a path prefix; if that changes, have the proxy set
    # them explicitly and turn these back on together.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_prefix=0)

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("DATABASE_URL environment variable is not set")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# Connection pool. These were documented in production.env.template but read by
# nothing, and the defaults matter now: with gthread (2 workers x 4 threads)
# there are 8 concurrent requests against SQLAlchemy's default pool_size of 5,
# so the pool would be the bottleneck rather than the database.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": _int_env("DB_POOL_SIZE", 10),
    "max_overflow": _int_env("DB_MAX_OVERFLOW", 20),
    "pool_timeout": _int_env("DB_POOL_TIMEOUT", 30),
    "pool_recycle": _int_env("DB_POOL_RECYCLE", 300),
    "pool_pre_ping": True,
}

# LOG_LEVEL was likewise documented and unread; nothing configured logging at all.
logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
app.logger.setLevel(
    getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
)

# Reject oversized uploads before the body is buffered into memory. Matches
# both CustomBundle.validate_stix_payload and nginx's client_max_body_size.
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

# CSRF Protection - disable for local development if needed
csrf_enabled = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'
app.config['WTF_CSRF_ENABLED'] = csrf_enabled
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = is_production  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cross-domain for local deployments
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# CSRF configuration for local deployments
app.config['WTF_CSRF_SSL_STRICT'] = is_production  # Only require SSL in production
app.config['WTF_CSRF_CHECK_DEFAULT'] = True

# Initialise extensions
db.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

def check_schema_drift():
    """Compare the live schema against the models and report what is missing.

    db.create_all() only ever CREATEs - it will not add a column to a table
    that already exists. The only migration mechanism is the hand-written ALTER
    block in docker-entrypoint.sh, so a column added to models.py without a
    matching entry there works on a fresh volume and is silently absent on every
    upgraded deployment, surfacing later as an UndefinedColumn error mid-request.

    Alembic would be the general answer; for a schema this size a startup check
    that names the drift is proportionate.
    """
    from sqlalchemy import inspect

    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    drift = []

    for table_name, table in db.metadata.tables.items():
        if table_name not in existing_tables:
            continue  # create_all handles wholly new tables
        actual = {col["name"] for col in inspector.get_columns(table_name)}
        missing = {col.name for col in table.columns} - actual
        for column in sorted(missing):
            drift.append(f"{table_name}.{column}")

    return drift


with app.app_context():
    import models  # noqa: F401
    # NB: this creates missing tables only. Any column added or changed on an
    # existing table must ALSO be added to the migration block in
    # docker-entrypoint.sh, or it will exist only on fresh deployments.
    db.create_all()

    schema_drift = check_schema_drift()
    if schema_drift:
        message = (
            "Schema drift detected. These columns exist in the models but not in "
            f"the database: {', '.join(schema_drift)}. db.create_all() cannot add "
            "columns to an existing table - add matching ALTER TABLE statements to "
            "the migration block in docker-entrypoint.sh."
        )
        if is_production:
            raise RuntimeError(message)
        app.logger.error(message)

    import routes  # noqa: F401
