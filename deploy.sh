#!/bin/bash

# MockTAXII v0.6.0 Docker Deployment Script
# Usage: ./deploy.sh [start|stop|restart|logs|status|backup|restore]

set -e

# Configuration
PROJECT_NAME="mocktaxii"
PROJECT_VERSION="0.6.0"
COMPOSE_FILE="docker-compose.yml"
BACKUP_DIR="./backups"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
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

# Security Configuration
WTF_CSRF_ENABLED=true
FLASK_ENV=production

# Optional: Change admin password (default: QrmrQQrpdkS4YesJ6AuJ)
# ADMIN_PASSWORD=your-secure-password-here
EOF
        log_success ".env file created with secure random passwords"
        log_warning "Please review and customize the .env file if needed"
    else
        log_info ".env file already exists, skipping generation"
    fi
}

start_services() {
    log_info "Starting MockTAXII services..."
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
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
    if curl -s -f http://localhost:5001/api/stats > /dev/null 2>&1; then
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