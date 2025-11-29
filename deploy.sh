#!/bin/bash

# MockTAXII v0.7.0 Docker Deployment Script
# Usage: ./deploy.sh [start|stop|restart|logs|status|backup|restore]

# Ensure script is run with bash, not sh
if [ -z "$BASH_VERSION" ]; then
    echo "[ERROR] This script requires bash. Please run with: bash $0 $*" >&2
    echo "        Or make it executable and run: ./$0 $*" >&2
    exit 1
fi

set -e

# Configuration
PROJECT_NAME="mocktaxii"
PROJECT_VERSION="0.7.0"
COMPOSE_FILE="docker-compose.yml"
BACKUP_DIR="./backups"

# IP Count Configuration (from environment or prompt)
DEFAULT_IP_COUNT=5000

# Colours for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[OK]${NC} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

prompt_ip_count() {
    echo ""
    log_info "Malicious IP Address Configuration"
    echo "  Choose the number of IP addresses to generate:"
    echo ""
    echo "  [1] 5,000   - Quick demo (fastest startup, ~2 minutes)"
    echo "  [2] 10,000  - Small testing environment"
    echo "  [3] 25,000  - Medium deployment"
    echo "  [4] 50,000  - Production deployment"
    echo "  [5] 100,000 - Large-scale production (slow startup)"
    echo "  [6] Custom  - Enter a custom value"
    echo ""
    read -p "Select option [1-6] (default: 1): " ip_choice
    
    case "${ip_choice:-1}" in
        1) MALICIOUS_IP_TARGET_COUNT=5000 ;;
        2) MALICIOUS_IP_TARGET_COUNT=10000 ;;
        3) MALICIOUS_IP_TARGET_COUNT=25000 ;;
        4) MALICIOUS_IP_TARGET_COUNT=50000 ;;
        5) MALICIOUS_IP_TARGET_COUNT=100000 ;;
        6)
            read -p "Enter custom IP count (1000-200000): " custom_count
            if [[ "$custom_count" =~ ^[0-9]+$ ]] && [ "$custom_count" -ge 1000 ] && [ "$custom_count" -le 200000 ]; then
                MALICIOUS_IP_TARGET_COUNT=$custom_count
            else
                log_warning "Invalid value. Using default: 5000"
                MALICIOUS_IP_TARGET_COUNT=5000
            fi
            ;;
        *)
            MALICIOUS_IP_TARGET_COUNT=5000
            ;;
    esac
    
    log_success "IP count set to: ${MALICIOUS_IP_TARGET_COUNT}"
    export MALICIOUS_IP_TARGET_COUNT
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose >/dev/null 2>&1; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_success "Dependencies check passed"
}

generate_env_file() {
    if [ ! -f ".env" ]; then
        log_info "Generating .env file..."
        cat > .env << EOF
# Database Configuration
POSTGRES_DB=mocktaxii
POSTGRES_USER=mocktaxii
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
DATABASE_URL=postgresql://mocktaxii:\${POSTGRES_PASSWORD}@db:5432/mocktaxii

# Application Configuration
SESSION_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

# Threat Intelligence Configuration
# IP count: 5000 (demo), 50000+ (production)
MALICIOUS_IP_TARGET_COUNT=${MALICIOUS_IP_TARGET_COUNT:-5000}

# Security Configuration
WTF_CSRF_ENABLED=true
FLASK_ENV=production

# Optional: Change admin password (default: randomly generated)
# ADMIN_PASSWORD=your-secure-password-here

# Optional: Skip seeding on restart (set to true after initial setup)
# SKIP_SEEDING=false
EOF
        log_success ".env file created with secure random passwords"
        log_warning "Please review and customise the .env file if needed"
    else
        log_info ".env file already exists, skipping generation"
        # Update IP count in existing .env if not present
        if ! grep -q "MALICIOUS_IP_TARGET_COUNT" .env; then
            echo "" >> .env
            echo "# Threat Intelligence Configuration (added by deploy.sh)" >> .env
            echo "MALICIOUS_IP_TARGET_COUNT=${MALICIOUS_IP_TARGET_COUNT:-5000}" >> .env
            log_info "Added MALICIOUS_IP_TARGET_COUNT to existing .env"
        fi
    fi
}

start_services() {
    log_info "Starting MockTAXII services..."
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Prompt for IP count if not already set
    if [ -z "$MALICIOUS_IP_TARGET_COUNT" ]; then
        prompt_ip_count
    fi
    
    # Generate environment file if it doesn't exist
    generate_env_file
    
    # Pull latest images
    log_info "Pulling latest Docker images..."
    docker-compose pull
    
    # Build and start services
    log_info "Building and starting services..."
    docker-compose up -d --build
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 10
    
    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        log_success "MockTAXII v$PROJECT_VERSION services started successfully!"
        echo ""
        log_info "Service URLs:"
        echo "  - Web Interface: http://localhost:5001"
        echo "  - TAXII Discovery: http://localhost:5001/taxii2/"
        echo "  - Admin Password: Check container logs for randomly generated password"
        echo "  - Note: Initial CVE data will be fetched from CISA on first startup"
        echo ""
        log_info "Use 'docker-compose logs -f' to view logs"
    else
        log_error "Failed to start services. Check logs with: docker-compose logs"
        exit 1
    fi
}

stop_services() {
    log_info "Stopping MockTAXII services..."
    docker-compose down
    log_success "Services stopped"
}

restart_services() {
    log_info "Restarting MockTAXII services..."
    stop_services
    start_services
}

show_logs() {
    log_info "Showing service logs (Press Ctrl+C to exit)..."
    docker-compose logs -f
}

show_status() {
    log_info "Service Status:"
    docker-compose ps
    echo ""
    
    log_info "Resource Usage:"
    docker stats --no-stream $(docker-compose ps -q) 2>/dev/null || log_warning "No running containers found"
    echo ""
    
    # Check if web service is responding
    if curl -s -f http://localhost:5001/api/stats >/dev/null 2>&1; then
        log_success "Web service is responding"
    else
        log_warning "Web service is not responding"
    fi
}

backup_database() {
    log_info "Creating database backup..."
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Generate backup filename with timestamp
    BACKUP_FILE="$BACKUP_DIR/mocktaxii_backup_$(date +%Y%m%d_%H%M%S).sql"
    
    # Create backup
    if docker-compose exec -T db pg_dump -U mocktaxii mocktaxii > "$BACKUP_FILE"; then
        log_success "Database backup created: $BACKUP_FILE"
    else
        log_error "Failed to create database backup"
        exit 1
    fi
}

restore_database() {
    if [ -z "$1" ]; then
        log_error "Please specify backup file: ./deploy.sh restore /path/to/backup.sql"
        exit 1
    fi
    
    BACKUP_FILE="$1"
    
    if [ ! -f "$BACKUP_FILE" ]; then
        log_error "Backup file not found: $BACKUP_FILE"
        exit 1
    fi
    
    log_warning "This will overwrite the current database. Are you sure? (y/N)"
    read -r confirm
    if [[ $confirm != [yY] ]]; then
        log_info "Database restore cancelled"
        exit 0
    fi
    
    log_info "Restoring database from: $BACKUP_FILE"
    
    # Stop services, restore database, start services
    docker-compose stop web
    if docker-compose exec -T db psql -U mocktaxii mocktaxii < "$BACKUP_FILE"; then
        docker-compose start web
        log_success "Database restored successfully"
    else
        log_error "Failed to restore database"
        docker-compose start web
        exit 1
    fi
}

cleanup() {
    log_warning "This will remove all containers, volumes, and data. Are you sure? (y/N)"
    read -r confirm
    if [[ $confirm != [yY] ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
    
    log_info "Cleaning up all Docker resources..."
    docker-compose down -v --remove-orphans
    docker system prune -f
    log_success "Cleanup completed"
}

update_application() {
    log_info "Updating MockTAXII application..."
    
    # Create backup before update
    backup_database
    
    # Pull latest changes (if using git)
    if [ -d ".git" ]; then
        log_info "Pulling latest code changes..."
        git pull
    fi
    
    # Rebuild and restart
    log_info "Rebuilding application..."
    docker-compose down
    docker-compose build --no-cache
    docker-compose up -d
    
    log_success "Application updated successfully"
}

show_help() {
    echo "MockTAXII v$PROJECT_VERSION Docker Deployment Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start       Start all services"
    echo "  stop        Stop all services"
    echo "  restart     Restart all services"
    echo "  logs        Show service logs (follow mode)"
    echo "  status      Show service status and health"
    echo "  backup      Create database backup"
    echo "  restore     Restore database from backup file"
    echo "  update      Update application (with backup)"
    echo "  cleanup     Remove all containers and data"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start                          # Start services"
    echo "  $0 restore backups/backup.sql     # Restore from backup"
    echo "  $0 logs                           # Follow logs"
}

# Main script logic
case "${1:-help}" in
    start)
        check_dependencies
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        check_dependencies
        restart_services
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    backup)
        backup_database
        ;;
    restore)
        restore_database "$2"
        ;;
    update)
        check_dependencies
        update_application
        ;;
    cleanup)
        cleanup
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
