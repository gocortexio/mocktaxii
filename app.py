import os
from flask import Flask, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

def get_real_ip():
    """Get real client IP considering X-Forwarded-For headers"""
    from flask import request
    
    # Check X-Forwarded-For header first (most common proxy header)
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # Take the first IP in the chain (original client)
        return xff.split(',')[0].strip()
    
    # Check other common proxy headers
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Check CF-Connecting-IP (Cloudflare)
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    
    # Fall back to remote_addr
    return request.remote_addr if request.remote_addr else '127.0.0.1'

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_real_ip,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET") or os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("DATABASE_URL environment variable is not set")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# CSRF Protection - disable for local development if needed
csrf_enabled = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'
app.config['WTF_CSRF_ENABLED'] = csrf_enabled
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

# Security configurations
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = is_production  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_DOMAIN'] = None  # Allow cross-domain for local deployments
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# CSRF configuration for local deployments
app.config['WTF_CSRF_SSL_STRICT'] = is_production  # Only require SSL in production
app.config['WTF_CSRF_CHECK_DEFAULT'] = True

# Initialize extensions
db.init_app(app)
csrf.init_app(app)
limiter.init_app(app)

with app.app_context():
    # Import models to ensure tables are created
    import models  # noqa: F401
    
    db.create_all()
    
    # Seed threat actors and comprehensive threat intelligence database
    from models import ThreatActor, MaliciousIP, MaliciousDomain, MaliciousHash, CVE, MalwareFamily, MitreTechnique, Campaign, ReportTemplate, ThreatSubnet
    ThreatActor.seed_default_actors()
    
    # Seed threat subnets first (required for large-scale IP generation)
    ThreatSubnet.seed_spamhaus_subnets()
    
    # Use new subnet-based IP generation for 50k+ addresses or fallback to old method
    current_ip_count = MaliciousIP.query.count()
    if current_ip_count < 50000:
        print(f"Current IP count: {current_ip_count:,}. Upgrading to subnet-based generation...")
        MaliciousIP.seed_from_subnets(target_count=50000)
    else:
        print(f"Using existing {current_ip_count:,} IP addresses")
    
    # Seed other threat intelligence components
    MaliciousDomain.seed_default_domains()
    MalwareFamily.seed_malware_families()  # Seed malware families first
    MaliciousHash.seed_default_hashes()  # This now depends on malware families
    CVE.seed_from_cisa_kev()
    MitreTechnique.seed_mitre_techniques()  # Seed MITRE ATT&CK techniques
    Campaign.seed_campaigns()  # Seed 100 diverse campaigns
    ReportTemplate.seed_report_templates()  # Seed 50 report templates
    
    # Import routes after app is configured
    import routes  # noqa: F401
