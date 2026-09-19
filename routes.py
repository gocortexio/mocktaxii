# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

from flask import render_template, request, redirect, url_for, flash, jsonify, session, make_response
from flask_wtf.csrf import CSRFError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import defer
from app import app, db, limiter, get_real_ip, read_or_create_shared_secret, RUNTIME_STATE_DIR
from models import ApiKey, ServerStats, RequestLog
from taxii_server import TAXIIServer
from version import __version__
from functools import wraps

import hmac
import json
import os
import time


def _api_key_identity():
    """Rate-limit key function that identifies by API key value, falling back to IP.

    Shares TAXIIServer.credential_from_authorization with authentication, so a
    header that authenticates as a given key can only ever land in that key's
    bucket.
    """
    auth = request.headers.get('Authorization', '')
    if auth:
        return TAXIIServer.credential_from_authorization(auth)
    return request.remote_addr

def get_or_create_admin_password():
    """Resolve the admin password, shared across gunicorn workers.

    Order of precedence:
      1. ADMIN_PASSWORD environment variable (operator-supplied secret).
      2. An existing password file in the runtime state directory.
      3. A freshly generated password, persisted at mode 0600.

    The password is NEVER printed. Operators read it from the file inside the
    container or supply ADMIN_PASSWORD; putting the secret in container logs
    would turn read-only log access into full administrative control of the
    TAXII API keys.

    read_or_create_shared_secret uses O_CREAT|O_EXCL, so two workers racing at
    startup cannot each write a different password and then disagree about
    which one is valid - the loser of the race reads the winner's value.
    """
    env_password = os.environ.get('ADMIN_PASSWORD', '').strip()
    if env_password:
        return env_password

    password, shared = read_or_create_shared_secret('mocktaxii_admin_password', nbytes=12)
    if shared:
        print(
            "[MockTAXII] Admin password generated. Set ADMIN_PASSWORD to override, "
            f"or read it from {os.path.join(RUNTIME_STATE_DIR, 'mocktaxii_admin_password')} "
            "inside the container."
        )
    else:
        print(
            "[MockTAXII] WARNING: the admin password could not be persisted, so each "
            "worker has generated its own and login will be unreliable. "
            "Set ADMIN_PASSWORD to a fixed value."
        )
    return password


API_KEY_PASSWORD = get_or_create_admin_password()

@app.context_processor
def inject_version():
    """Make version available to all templates"""
    return dict(version=f"v{__version__}")

def taxii_response(data, status=200, headers=None):
    """Create a proper TAXII 2.1 JSON response with correct content-type"""
    response = make_response(json.dumps(data), status)
    response.headers['Content-Type'] = 'application/taxii+json;version=2.1'
    for key, value in (headers or {}).items():
        response.headers[key] = value
    return response


def _is_taxii_request():
    return request.path.startswith('/taxii2/')


def taxii_error(error, status=None, error_id=None):
    """Render one consistent TAXII 2.1 error envelope.

    Flask's ``jsonify`` defaults to ``application/json``.  That is correct for
    the browser-facing JSON endpoints but not for TAXII errors, where clients
    negotiate and parse ``application/taxii+json;version=2.1`` just like a
    successful response.
    """
    status = status or getattr(error, 'code', None) or 500
    code = str(status)
    return taxii_response({
        "title": getattr(error, 'name', None) or "TAXII Error",
        "description": str(getattr(error, 'description', None) or "Request failed"),
        "error_id": error_id or f"taxii_error_{code}",
        "error_code": code,
    }, status=status)


def _wants_json():
    """True when the caller is an API client rather than the admin browser UI.

    The error handlers previously returned JSON unconditionally, so a failed
    admin action rendered a raw JSON body into the operator's browser.
    """
    if request.path.startswith('/taxii2/') or request.path.startswith('/api/'):
        return True
    return request.accept_mimetypes.best_match(['application/json', 'text/html']) == 'application/json'


def require_auth(f):
    """Decorator to require authentication for API key management"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    # Everything the pages load is served from this origin: Bootstrap, the
    # webfonts and the icon sprite are all served from this origin. The policy
    # therefore names no external host at all - a tampered CDN has nothing to
    # tamper with here, and the UI works on a host with no internet access.
    #
    # 'unsafe-inline' remains for styles and scripts: the templates carry
    # inline <style> and small inline handlers. Removing it needs nonces or
    # hashes on each, which is a separate change.
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # Enhanced security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Only add HSTS for secure connections
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    
    # Cache control for sensitive pages
    if request.endpoint in ['api_keys', 'login']:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# Reject oversized uploads (Flask raises 413 when MAX_CONTENT_LENGTH is exceeded)
@app.errorhandler(413)
def request_too_large(e):
    """Handle requests whose body exceeds MAX_CONTENT_LENGTH (10MB)."""
    if _is_taxii_request():
        return taxii_error(e, 413, 'payload_too_large')
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Payload too large',
            'message': 'Request body exceeds the 10MB maximum.',
        }), 413
    flash('Upload too large. Bundles must be 10MB or smaller.', 'error')
    return redirect(url_for('custom_bundles'))

# Error handlers for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    if _is_taxii_request():
        return taxii_error(e, 429, 'rate_limit_exceeded')
    if request.path.startswith('/api/'):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please slow down.',
            'retry_after': getattr(e, 'retry_after', None) or 60
        }), 429
    
    flash('Too many requests. Please slow down and try again.', 'warning')
    return redirect(url_for('index'))

# Web interface routes
@app.route('/')
@limiter.limit("30 per minute")
def index():
    """Home page with indicator counter"""
    stats = ServerStats.get_stats()
    recent_requests = RequestLog.query.order_by(RequestLog.id.desc()).limit(10).all()
    return render_template('index.html', stats=stats, recent_requests=recent_requests)

@app.route('/login')
@limiter.limit("10 per minute")
def login():
    """Login page for API key management"""
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_post():
    """Handle login form submission.

    CSRF failures raise before this view runs (Flask-WTF validates in a
    before_request hook) and are handled by the CSRFError handler below, so
    there is nothing here for a try/except to catch.
    """
    password = request.form.get('password') or ''
    # Compare encoded bytes, not str. hmac.compare_digest raises TypeError on a
    # str containing any non-ASCII character, so an accented admin password -
    # which production.env.template invites the operator to choose - turned
    # every login attempt, including the correct one, into a 500 and locked the
    # admin UI out permanently. Encoding both sides is total for any str and
    # keeps the comparison constant-time.
    if hmac.compare_digest(password.encode('utf-8'), API_KEY_PASSWORD.encode('utf-8')):
        session['authenticated'] = True
        session.permanent = True
        flash('Successfully logged in', 'success')
        return redirect(url_for('api_keys'))

    flash('Invalid password', 'error')
    return redirect(url_for('login'))

@app.route('/logout')
@limiter.limit("30 per minute")
def logout():
    """Logout and clear session"""
    session.pop('authenticated', None)
    flash('Successfully logged out', 'info')
    return redirect(url_for('index'))

@app.route('/api-keys')
@require_auth
@limiter.limit("20 per minute")
def api_keys():
    """API key management page"""
    keys = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.created_at.desc()).all()
    client_ip = request.remote_addr
    return render_template('api_keys.html', api_keys=keys, client_ip=client_ip)

@app.route('/api-keys/create', methods=['POST'])
@require_auth
@limiter.limit("10 per minute") 
def create_api_key():
    """Create a new API key"""
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    if not name or len(name) > 100:
        flash('API key name is required and must be under 100 characters', 'error')
        return redirect(url_for('api_keys'))
    
    if description and len(description) > 500:
        flash('Description must be under 500 characters', 'error')
        return redirect(url_for('api_keys'))
    
    # Generate new API key
    api_key = ApiKey()
    api_key.name = name
    api_key.description = description
    
    db.session.add(api_key)
    db.session.commit()
    
    flash(f'API key created successfully: {api_key.key}', 'success')
    return redirect(url_for('api_keys'))

@app.route('/api-keys/<int:key_id>/deactivate', methods=['POST'])
@require_auth
@limiter.limit("15 per minute")
def deactivate_api_key(key_id):
    """Deactivate an API key"""
    api_key = db.get_or_404(ApiKey, key_id)
    api_key.is_active = False
    db.session.commit()
    
    flash(f'API key "{api_key.name}" has been deactivated', 'info')
    return redirect(url_for('api_keys'))


# Custom Bundles Management
@app.route('/admin/bundles')
@require_auth
@limiter.limit("20 per minute")
def custom_bundles():
    """Custom STIX bundles management page"""
    from models import CustomBundle
    # Defer the payload: this page shows metadata only, but loading the entity
    # pulled every bundle's full Text column (10MB cap each) into the worker.
    bundles = CustomBundle.query.options(
        defer(CustomBundle.stix_payload)
    ).order_by(CustomBundle.created_at.desc()).all()
    api_keys_list = ApiKey.query.filter_by(is_active=True).order_by(ApiKey.name).all()
    return render_template('bundles.html', bundles=bundles, api_keys=api_keys_list)


@app.route('/admin/bundles/upload', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def upload_bundle():
    """Upload a new custom STIX bundle"""
    from models import CustomBundle
    
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    api_key_id = request.form.get('api_key_id', '').strip()
    frequency = request.form.get('frequency', '10').strip()
    
    if not name or len(name) > 100:
        flash('Bundle name is required and must be under 100 characters', 'error')
        return redirect(url_for('custom_bundles'))
    
    try:
        frequency = int(frequency)
        if frequency < 1 or frequency > 1000:
            raise ValueError("Frequency out of range")
    except ValueError:
        flash('Frequency must be a number between 1 and 1000', 'error')
        return redirect(url_for('custom_bundles'))
    
    if 'bundle_file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('custom_bundles'))
    
    file = request.files['bundle_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('custom_bundles'))
    
    if not file.filename.endswith('.json'):
        flash('File must be a JSON file', 'error')
        return redirect(url_for('custom_bundles'))

    max_bytes = 10 * 1024 * 1024  # 10 MB
    content_length = request.content_length
    if content_length is not None and content_length > max_bytes:
        flash('File exceeds the 10MB maximum allowed size', 'error')
        return redirect(url_for('custom_bundles'))

    try:
        payload_str = file.read().decode('utf-8')
    except UnicodeDecodeError:
        flash('File must be valid UTF-8 text', 'error')
        return redirect(url_for('custom_bundles'))
    
    result, error = CustomBundle.validate_stix_payload(payload_str)
    if error:
        flash(f'Invalid STIX bundle: {error}', 'error')
        return redirect(url_for('custom_bundles'))
    
    bundle = CustomBundle()
    bundle.name = name
    bundle.description = description
    bundle.api_key_id = int(api_key_id) if api_key_id else None
    bundle.frequency = frequency
    bundle.stix_payload = payload_str
    bundle.object_count = result['object_count']
    bundle.bundle_size_bytes = result['size_bytes']
    
    db.session.add(bundle)
    db.session.commit()
    
    flash(f'Bundle "{name}" uploaded successfully with {result["object_count"]} objects', 'success')
    return redirect(url_for('custom_bundles'))


@app.route('/admin/bundles/<int:bundle_id>/view')
@require_auth
@limiter.limit("30 per minute")
def view_bundle(bundle_id):
    """View bundle content as JSON"""
    from models import CustomBundle
    
    bundle = db.get_or_404(CustomBundle, bundle_id)
    
    try:
        data = json.loads(bundle.stix_payload)
        formatted_json = json.dumps(data, indent=2)
    except:
        formatted_json = bundle.stix_payload
    
    return render_template('bundle_view.html', bundle=bundle, json_content=formatted_json)


@app.route('/admin/bundles/<int:bundle_id>/download')
@require_auth
@limiter.limit("20 per minute")
def download_bundle(bundle_id):
    """Download bundle as JSON file"""
    from models import CustomBundle
    from flask import Response
    
    bundle = db.get_or_404(CustomBundle, bundle_id)
    
    filename = f"{bundle.name.replace(' ', '_').lower()}_bundle.json"
    
    return Response(
        bundle.stix_payload,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/admin/bundles/<int:bundle_id>/toggle', methods=['POST'])
@require_auth
@limiter.limit("20 per minute")
def toggle_bundle(bundle_id):
    """Toggle bundle active status"""
    from models import CustomBundle
    
    bundle = db.get_or_404(CustomBundle, bundle_id)
    bundle.is_active = not bundle.is_active
    db.session.commit()
    
    status = "activated" if bundle.is_active else "deactivated"
    flash(f'Bundle "{bundle.name}" has been {status}', 'info')
    return redirect(url_for('custom_bundles'))


@app.route('/admin/bundles/<int:bundle_id>/delete', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def delete_bundle(bundle_id):
    """Delete a custom bundle.

    RequestLog.custom_bundle_id is a ForeignKey with no ondelete rule, so once
    a bundle has been served, deleting it raised an unhandled IntegrityError
    and the bundle became permanently undeletable through the UI. Detaching the
    log rows first works without altering live schema (db.create_all() will not
    modify an existing constraint). Nothing reads custom_bundle_id, so nulling
    it loses no information that is used anywhere.
    """
    from models import CustomBundle

    bundle = db.get_or_404(CustomBundle, bundle_id)
    bundle_name = bundle.name

    try:
        RequestLog.query.filter_by(custom_bundle_id=bundle.id).update(
            {'custom_bundle_id': None, 'custom_bundle_served': False},
            synchronize_session=False
        )
        db.session.delete(bundle)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Failed to delete bundle %s", bundle_id)
        flash(f'Could not delete bundle "{bundle_name}". Please try again.', 'error')
        return redirect(url_for('custom_bundles'))

    flash(f'Bundle "{bundle_name}" has been deleted', 'info')
    return redirect(url_for('custom_bundles'))


# TAXII 2.x endpoints
@app.route('/taxii2/')
@limiter.limit("300 per minute")
def taxii_discovery():
    """TAXII Discovery endpoint"""
    try:
        response_data = TAXIIServer.get_discovery_response()
        return taxii_response(response_data)
    except Exception as e:
        app.logger.error(f"TAXII Discovery error: {str(e)}")
        return taxii_response({
            "title": "MockTAXII Server Error",
            "description": "Service temporarily unavailable",
            "error": str(e)
        }), 503

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/')
@TAXIIServer.validate_api_key
@limiter.limit("300 per minute")
def taxii_api_root(api_key=None, log_entry=None):
    """TAXII API Root endpoint"""
    return taxii_response(TAXIIServer.get_api_root_response())

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/collections/')
@TAXIIServer.validate_api_key
@limiter.limit("300 per minute")
def taxii_collections(api_key=None, log_entry=None):
    """TAXII Collections endpoint"""
    return taxii_response(TAXIIServer.get_collections_response())

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/collections/<collection_id>/')
@TAXIIServer.validate_api_key
@limiter.limit("300 per minute")
def taxii_collection_info(collection_id, api_key=None, log_entry=None):
    """TAXII Collection information endpoint"""
    return taxii_response(TAXIIServer.get_collection_info(collection_id))

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/collections/<collection_id>/objects/')
@TAXIIServer.validate_api_key
@limiter.limit("30 per minute")
@limiter.limit("30 per minute", key_func=_api_key_identity)
def taxii_collection_objects(collection_id, api_key=None, log_entry=None):
    """TAXII Collection objects endpoint"""
    try:
        limit = min(int(request.args.get('limit', 50)), TAXIIServer.MAX_OBJECTS_LIMIT)
    except (ValueError, TypeError):
        limit = 50
    added_after = request.args.get('added_after')
    next_token = request.args.get('next')
    
    response_data = TAXIIServer.get_collection_objects(
        collection_id, limit, added_after,
        api_key=api_key, log_entry=log_entry, next_token=next_token
    )

    objects = response_data.get('objects', [])

    # Update log entry with indicators served. Counts indicators only -
    # relationships and narrative SDOs were previously counted too.
    if log_entry:
        log_entry.indicators_served = sum(
            1 for obj in objects if obj.get('type') == 'indicator'
        )
        db.session.commit()

    # TAXII 2.1 section 3.4 requires these on a successful objects response.
    # TAXIIServer records the repository ingestion time for each page; do not
    # substitute STIX `created`, which describes the source object's history
    # and may predate this repository by years.
    headers = {}
    date_added = TAXIIServer.date_added_range(objects)
    if date_added:
        headers['X-TAXII-Date-Added-First'] = date_added[0]
        headers['X-TAXII-Date-Added-Last'] = date_added[1]

    return taxii_response(response_data, headers=headers)

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/collections/<collection_id>/manifest/')
@TAXIIServer.validate_api_key
@limiter.limit("300 per minute")
def taxii_collection_manifest(collection_id, api_key=None, log_entry=None):
    """TAXII Collection manifest endpoint"""
    try:
        limit = min(int(request.args.get('limit', 50)), TAXIIServer.MAX_OBJECTS_LIMIT)
    except (ValueError, TypeError):
        limit = 50
    added_after = request.args.get('added_after')
    next_token = request.args.get('next')
    
    return taxii_response(TAXIIServer.get_collection_manifest(
        collection_id, limit, added_after, api_key=api_key,
        next_token=next_token
    ))

REQUEST_LOG_RETENTION_DAYS = int(os.environ.get('REQUEST_LOG_RETENTION_DAYS', '90') or 0)
_PRUNE_INTERVAL_SECONDS = 3600
_last_prune = 0.0


def _maybe_prune_request_log():
    """Prune request_log at most hourly, per worker.

    Driven off the healthcheck, which already runs every 30s, so retention
    needs no cron or scheduler. Both workers may prune; DELETE is idempotent
    and the second simply removes nothing.
    """
    global _last_prune
    if REQUEST_LOG_RETENTION_DAYS <= 0:
        return
    now = time.monotonic()
    if now - _last_prune < _PRUNE_INTERVAL_SECONDS:
        return
    _last_prune = now
    removed = RequestLog.prune(REQUEST_LOG_RETENTION_DAYS)
    if removed:
        app.logger.info(
            "Pruned %s request_log rows older than %s days",
            removed, REQUEST_LOG_RETENTION_DAYS
        )


@app.route('/healthz')
@limiter.exempt
def healthz():
    """Container liveness probe.

    Deliberately cheap and exempt from rate limiting: it runs every 30s forever,
    so it must not consume limiter budget, write a RequestLog row, or touch the
    stats counters. SELECT 1 proves the connection pool can still reach the DB.
    """
    try:
        db.session.execute(db.text('SELECT 1'))
        _maybe_prune_request_log()
        return jsonify({'status': 'ok', 'version': __version__})
    except Exception:
        db.session.rollback()
        app.logger.exception("Health check failed")
        return jsonify({'status': 'degraded', 'version': __version__}), 503

# API endpoint for stats (for frontend updates)
@app.route('/api/stats')
@limiter.limit("30 per minute")
def api_stats():
    """Get current server statistics"""
    stats = ServerStats.get_stats()
    return jsonify({
        'version': __version__,
        'total_indicators_served': stats.total_indicators_served,
        'total_requests': stats.total_requests,
        'last_updated': stats.last_updated.isoformat()
    })

@app.route('/api/rate-limit-status')
@require_auth
@limiter.limit("10 per minute")
def rate_limit_status():
    """Check rate limiting status"""
    client_ip = request.remote_addr
    
    # Get rate limit information
    try:
        # Check if current IP is being rate limited
        rate_limit_info = {
            'client_ip': client_ip,
            'rate_limits': {
                'default': '1000 per day, 200 per hour',
                'taxii_discovery': '300 per minute',
                'taxii_api_root': '300 per minute',
                'taxii_collections': '300 per minute',
                'taxii_collection_objects': '30 per minute (per IP and per API key)',
                'taxii_collection_manifest': '300 per minute',
                'api_stats': '30 per minute'
            },
            'status': 'Rate limiting active with in-memory storage'
        }
        
        return jsonify(rate_limit_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Turn an expired or missing CSRF token into a usable message.

    Without this, a tab left idle past WTF_CSRF_TIME_LIMIT (1 hour) submits and
    gets a bare Werkzeug 400 page. Every CSRF-protected route here is an admin
    form POST, so redirecting back with a flash is always the right response.
    """
    app.logger.info("CSRF validation failed: %s", error.description)
    flash('Your session expired. Please try again.', 'warning')
    return redirect(request.referrer or url_for('login')), 302

@app.errorhandler(413)
def payload_too_large(error):
    """MAX_CONTENT_LENGTH rejected the upload before it was buffered."""
    if _is_taxii_request():
        return taxii_error(error, 413, "payload_too_large")
    if _wants_json():
        return jsonify({
            "title": "Payload Too Large",
            "description": "Uploads are limited to 10 MB",
            "error_id": "payload_too_large",
            "error_code": "413"
        }), 413
    flash('That file is too large. The limit is 10 MB.', 'error')
    return redirect(url_for('custom_bundles')), 302

@app.errorhandler(400)
def bad_request(error):
    """TAXII error object for malformed filter parameters."""
    if _is_taxii_request():
        return taxii_error(error, 400, "bad_request")
    if _wants_json():
        return jsonify({
            "title": "Bad Request",
            "description": str(getattr(error, 'description', 'Malformed request')),
            "error_id": "bad_request",
            "error_code": "400"
        }), 400
    flash('That request could not be understood.', 'error')
    return redirect(url_for('index')), 302

@app.errorhandler(401)
def unauthorized(error):
    if _is_taxii_request():
        return taxii_error(error, 401, "unauthorized")
    return jsonify({
        "title": "Unauthorized",
        "description": str(error.description),
        "error_id": "unauthorized",
        "error_code": "401"
    }), 401

@app.errorhandler(404)
def not_found(error):
    if _is_taxii_request():
        return taxii_error(error, 404, "not_found")
    if _wants_json():
        return jsonify({
            "title": "Not Found",
            "description": str(error.description),
            "error_id": "not_found",
            "error_code": "404"
        }), 404
    flash('That page or item could not be found.', 'error')
    return redirect(url_for('index')), 302

@app.errorhandler(500)
def internal_error(error):
    # Any unhandled exception leaves the session dirty; the next request on this
    # worker would otherwise reuse a poisoned session.
    db.session.rollback()
    app.logger.exception("Unhandled error serving %s", request.path)
    if _is_taxii_request():
        return taxii_error(error, 500, "internal_error")
    if _wants_json():
        return jsonify({
            "title": "Internal Server Error",
            "description": "An internal server error occurred",
            "error_id": "internal_error",
            "error_code": "500"
        }), 500
    flash('Something went wrong handling that request.', 'error')
    return redirect(url_for('index')), 302
