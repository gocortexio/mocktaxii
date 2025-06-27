#!/bin/bash

# MockTAXII v0.2 Production Deployment Script
# Advanced deployment with SSL, monitoring, and security hardening

set -e

# Configuration
PROJECT_NAME="mocktaxii"
PROJECT_VERSION="0.4.1"
DOMAIN="${DOMAIN:-localhost}"
EMAIL="${LETSENCRYPT_EMAIL:-admin@example.com}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for production deployment"
        exit 1
    fi
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Update system
    apt update && apt upgrade -y
    
    # Install required packages
    apt install -y \
        curl \
        wget \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        logrotate \
        certbot \
        python3-certbot-nginx
    
    # Install Docker
    if ! command -v docker &> /dev/null; then
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        systemctl enable docker
        systemctl start docker
    fi
    
    # Install Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_info "Installing Docker Compose..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
    
    # Install nginx
    if ! command -v nginx &> /dev/null; then
        log_info "Installing Nginx..."
        apt install -y nginx
        systemctl enable nginx
    fi
    
    log_success "Dependencies installed"
}

setup_firewall() {
    log_info "Configuring firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (current session)
    ufw allow ssh
    
    # Allow HTTP/HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Enable firewall
    ufw --force enable
    
    log_success "Firewall configured"
}

setup_fail2ban() {
    log_info "Configuring Fail2Ban..."
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "Fail2Ban configured"
}

create_production_compose() {
    log_info "Creating production Docker Compose configuration..."
    
    cat > docker-compose.prod.yml << 'EOF'
version: '3.8'

services:
  web:
    build: .
    restart: unless-stopped
    environment:
      - DATABASE_URL=postgresql://mocktaxii:${POSTGRES_PASSWORD}@db:5432/mocktaxii
      - SESSION_SECRET=${SESSION_SECRET}
      - ENVIRONMENT=production
      - FLASK_ENV=production
      - WTF_CSRF_ENABLED=true
    depends_on:
      db:
        condition: service_healthy
    networks:
      - mocktaxii-network
    volumes:
      - ./logs:/app/logs
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

  db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=mocktaxii
      - POSTGRES_USER=mocktaxii
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - mocktaxii-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mocktaxii"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - web
    networks:
      - mocktaxii-network

volumes:
  postgres_data:

networks:
  mocktaxii-network:
    driver: bridge
EOF
    
    log_success "Production Docker Compose created"
}

create_nginx_config() {
    log_info "Creating Nginx configuration..."
    
    mkdir -p ssl logs
    
    cat > nginx.conf << EOF
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    server {
        listen 80;
        server_name ${DOMAIN};
        
        # Redirect HTTP to HTTPS
        return 301 https://\$server_name\$request_uri;
    }
    
    server {
        listen 443 ssl http2;
        server_name ${DOMAIN};
        
        # SSL configuration
        ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Security
        client_max_body_size 10M;
        
        # Rate limiting for API endpoints
        location /taxii2/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://web:5000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Rate limiting for login
        location /login {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://web:5000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        
        # Main application
        location / {
            proxy_pass http://web:5000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_read_timeout 86400;
        }
    }
}
EOF
    
    log_success "Nginx configuration created"
}

setup_ssl() {
    if [[ "$DOMAIN" == "localhost" ]]; then
        log_warning "Skipping SSL setup for localhost"
        return
    fi
    
    log_info "Setting up SSL certificate for $DOMAIN..."
    
    # Stop nginx temporarily
    systemctl stop nginx
    
    # Generate certificate
    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$EMAIL" \
        -d "$DOMAIN"
    
    # Setup auto-renewal
    cat > /etc/cron.d/certbot-renew << 'EOF'
0 12 * * * root certbot renew --quiet --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
EOF
    
    log_success "SSL certificate configured"
}

setup_monitoring() {
    log_info "Setting up monitoring and log rotation..."
    
    # Log rotation for application logs
    cat > /etc/logrotate.d/mocktaxii << 'EOF'
/opt/mocktaxii/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker-compose -f /opt/mocktaxii/docker-compose.prod.yml restart web
    endscript
}
EOF
    
    # Health check script
    cat > /usr/local/bin/mocktaxii-health << 'EOF'
#!/bin/bash
HEALTH_URL="https://localhost/api/stats"
if ! curl -sf "$HEALTH_URL" > /dev/null; then
    echo "$(date): MockTAXII health check failed" >> /var/log/mocktaxii-health.log
    # Restart services
    cd /opt/mocktaxii
    docker-compose -f docker-compose.prod.yml restart web
fi
EOF
    
    chmod +x /usr/local/bin/mocktaxii-health
    
    # Health check cron
    cat > /etc/cron.d/mocktaxii-health << 'EOF'
*/5 * * * * root /usr/local/bin/mocktaxii-health
EOF
    
    log_success "Monitoring configured"
}

generate_secure_env() {
    log_info "Generating secure environment configuration..."
    
    cat > .env.prod << EOF
# Database Configuration
POSTGRES_DB=mocktaxii
POSTGRES_USER=mocktaxii
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

# Application Configuration
SESSION_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ENVIRONMENT=production

# Domain Configuration
DOMAIN=${DOMAIN}
LETSENCRYPT_EMAIL=${EMAIL}
EOF
    
    chmod 600 .env.prod
    log_success "Secure environment file created"
}

deploy_production() {
    check_root
    
    log_info "Starting production deployment for MockTAXII..."
    
    # Create deployment directory
    mkdir -p /opt/mocktaxii
    cd /opt/mocktaxii
    
    # Copy application files (assume they're in current directory)
    if [[ -f "$(dirname "$0")/main.py" ]]; then
        cp -r "$(dirname "$0")"/* .
    else
        log_error "Application files not found. Please run this script from the MockTAXII directory."
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Setup security
    setup_firewall
    setup_fail2ban
    
    # Create production configuration
    create_production_compose
    create_nginx_config
    generate_secure_env
    
    # Setup SSL
    setup_ssl
    
    # Setup monitoring
    setup_monitoring
    
    # Deploy services
    log_info "Deploying services..."
    docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
    
    # Start nginx
    systemctl start nginx
    
    # Wait for services
    sleep 15
    
    # Verify deployment
    if curl -sf "http://localhost/api/stats" > /dev/null; then
        log_success "MockTAXII v$PROJECT_VERSION production deployment completed successfully!"
        echo ""
        log_info "Your MockTAXII v$PROJECT_VERSION server is now running at:"
        if [[ "$DOMAIN" != "localhost" ]]; then
            echo "  - https://$DOMAIN"
        else
            echo "  - http://localhost"
        fi
        echo ""
        log_info "Admin credentials:"
        echo "  - Password: Check application logs for randomly generated password"
        echo ""
        log_info "Monitoring:"
        echo "  - Logs: docker-compose -f docker-compose.prod.yml logs -f"
        echo "  - Status: systemctl status nginx docker fail2ban"
    else
        log_error "Deployment verification failed. Check logs for issues."
        exit 1
    fi
}

show_usage() {
    echo "MockTAXII v$PROJECT_VERSION Production Deployment Script"
    echo ""
    echo "Usage: sudo ./production-deploy.sh"
    echo ""
    echo "Environment Variables:"
    echo "  DOMAIN              Domain name (default: localhost)"
    echo "  LETSENCRYPT_EMAIL   Email for SSL certificate (default: admin@example.com)"
    echo "  ENVIRONMENT         Environment name (default: production)"
    echo ""
    echo "Example:"
    echo "  sudo DOMAIN=mocktaxii.example.com LETSENCRYPT_EMAIL=admin@example.com ./production-deploy.sh"
}

# Main execution
case "${1:-deploy}" in
    deploy)
        deploy_production
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        log_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac