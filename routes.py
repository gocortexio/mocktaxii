from flask import render_template, request, redirect, url_for, flash, jsonify, abort, session, send_from_directory, make_response
from app import app, db, limiter, get_real_ip
from models import ApiKey, ServerStats, RequestLog
from taxii_server import TAXIIServer
from version import __version__
from functools import wraps

# Generate random admin password on startup (shared across workers)
import secrets
import os

def get_or_create_admin_password():
    """Get existing admin password or create a new one, ensuring it's only logged once"""
    password_file = '/tmp/mocktaxii_admin_password'
    
    try:
        # Try to read existing password
        if os.path.exists(password_file):
            with open(password_file, 'r') as f:
                return f.read().strip()
    except:
        pass
    
    # Generate new password and save it
    password = secrets.token_hex(12).upper()
    try:
        with open(password_file, 'w') as f:
            f.write(password)
        # Only log the password once when it's first created
        print(f"[MockTAXII] Admin Password: {password}")
        print(f"[MockTAXII] Use this password to access the API key management interface")
    except:
        pass
    
    return password

API_KEY_PASSWORD = get_or_create_admin_password()

def taxii_response(data):
    """Create a proper TAXII 2.1 JSON response with correct content-type"""
    import json
    response = make_response(json.dumps(data))
    response.headers['Content-Type'] = 'application/taxii+json;version=2.1'
    return response


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
    """Add comprehensive security headers to all responses including Google Fonts"""
    # Content Security Policy - working external CDN resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Cache control for sensitive pages
    if request.endpoint in ['api_keys', 'login']:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# Error handlers for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    if request.path.startswith('/taxii2/') or request.path.startswith('/api/'):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please slow down.',
            'retry_after': getattr(e, 'retry_after', 60)
        }), 429
    
    flash('Too many requests. Please slow down and try again.', 'warning')
    return redirect(url_for('index'))

# Web interface routes
@app.route('/')
@limiter.limit("30 per minute")
def index():
    """Home page with indicator counter"""
    stats = ServerStats.get_stats()
    recent_requests = RequestLog.query.order_by(RequestLog.timestamp.desc()).limit(10).all()
    return render_template('index.html', stats=stats, recent_requests=recent_requests)

@app.route('/login')
@limiter.limit("10 per minute")
def login():
    """Login page for API key management"""
    # Debug info for CSRF troubleshooting (remove in production)
    if not app.config.get('FLASK_ENV') == 'production':
        app.logger.debug(f"Session data: {dict(session)}")
        app.logger.debug(f"Request headers: {dict(request.headers)}")
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_post():
    """Handle login form submission"""
    try:
        # CSRF validation will be handled automatically by Flask-WTF
        password = request.form.get('password')
        if password and password == API_KEY_PASSWORD:
            session['authenticated'] = True
            session.permanent = True
            flash('Successfully logged in', 'success')
            return redirect(url_for('api_keys'))
        else:
            flash('Invalid password', 'error')
            return redirect(url_for('login'))
    except Exception as e:
        # Handle CSRF or other form errors gracefully
        app.logger.warning(f"Login form error: {str(e)}")
        flash('Form validation error. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
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
    client_ip = get_real_ip()
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
    api_key = ApiKey.query.get_or_404(key_id)
    api_key.is_active = False
    db.session.commit()
    
    flash(f'API key "{api_key.name}" has been deactivated', 'info')
    return redirect(url_for('api_keys'))

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
@limiter.limit("300 per minute")
def taxii_collection_objects(collection_id, api_key=None, log_entry=None):
    """TAXII Collection objects endpoint"""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
    except (ValueError, TypeError):
        limit = 50
    added_after = request.args.get('added_after')
    
    response_data = TAXIIServer.get_collection_objects(collection_id, limit, added_after)
    
    # Update log entry with indicators served
    if log_entry:
        log_entry.indicators_served = len(response_data.get('objects', []))
        db.session.commit()
    
    return taxii_response(response_data)

@app.route(f'/taxii2/{TAXIIServer.API_ROOT}/collections/<collection_id>/manifest/')
@TAXIIServer.validate_api_key
@limiter.limit("300 per minute")
def taxii_collection_manifest(collection_id, api_key=None, log_entry=None):
    """TAXII Collection manifest endpoint"""
    try:
        limit = min(int(request.args.get('limit', 50)), 100)
    except (ValueError, TypeError):
        limit = 50
    added_after = request.args.get('added_after')
    
    return taxii_response(TAXIIServer.get_collection_manifest(collection_id, limit, added_after))

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
    client_ip = get_real_ip()
    
    # Get rate limit information
    try:
        # Check if current IP is being rate limited
        rate_limit_info = {
            'client_ip': client_ip,
            'rate_limits': {
                'default': '1000 per day, 200 per hour',
                'taxii_endpoints': '300 per minute',
                'api_stats': '30 per minute'
            },
            'status': 'Rate limiting active with in-memory storage'
        }
        
        return jsonify(rate_limit_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        "title": "Unauthorized",
        "description": str(error.description),
        "error_id": "unauthorized",
        "error_code": "401"
    }), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "title": "Not Found",
        "description": str(error.description),
        "error_id": "not_found", 
        "error_code": "404"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "title": "Internal Server Error",
        "description": "An internal server error occurred",
        "error_id": "internal_error",
        "error_code": "500"
    }), 500
