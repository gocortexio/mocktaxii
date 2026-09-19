#!/bin/bash
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

# MockTAXII v1.1.4 Production Deployment Script
# Advanced deployment with SSL, monitoring, and security hardening

# Ensure script is run with bash, not sh
if [ -z "$BASH_VERSION" ]; then
    echo "[ERROR] This script requires bash. Please run with: bash $0 $*" >&2
    echo "        Or make it executable and run: ./$0 $*" >&2
    exit 1
fi

set -euo pipefail

# Configuration
PROJECT_NAME="mocktaxii"
PROJECT_VERSION="1.1.4"

# Resolved before any chdir; deploy_production() cd's to /opt/mocktaxii.
# This script lives in deploy/, so the application root is one level up.
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOMAIN="${DOMAIN:-}"
EMAIL="${LETSENCRYPT_EMAIL:-}"
ENVIRONMENT="${ENVIRONMENT:-production}"
PROXY_MODE="${PROXY:-}"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
log_success() { printf "${GREEN}[OK]${NC} %s\n" "$1"; }
log_warning() { printf "${YELLOW}[WARNING]${NC} %s\n" "$1"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }

load_deployment_env() {
    # Compose's --env-file handles interpolation, but the deployment script
    # also needs these values before Compose starts (for certificate setup and
    # selecting exactly one reverse proxy). Source only the operator-owned
    # KEY=VALUE file; it is never generated from untrusted request data.
    if [[ -f .env.prod ]]; then
        set -a
        # shellcheck disable=SC1091
        source ./.env.prod
        set +a
    fi

    DOMAIN="${DOMAIN:-localhost}"
    EMAIL="${LETSENCRYPT_EMAIL:-}"
    PROXY_MODE="${PROXY:-${PROXY_MODE:-}}"
    if [[ -z "$PROXY_MODE" ]]; then
        if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
            PROXY_MODE="local"
        else
            PROXY_MODE="nginx"
        fi
    fi

    # A local stack must not start a TLS proxy whose certificate files cannot
    # exist. Conversely, never silently turn a real domain into HTTP-only
    # mode.
    case "$PROXY_MODE" in
        none)
            PROXY_MODE="local"
            ;;
        local)
            if [[ "$DOMAIN" != "localhost" && "$DOMAIN" != "127.0.0.1" ]]; then
                log_error "PROXY=local requires DOMAIN=localhost or 127.0.0.1."
                exit 1
            fi
            ;;
        nginx|traefik)
            if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
                log_error "PROXY=$PROXY_MODE requires a real DOMAIN."
                exit 1
            fi
            if [[ -z "$EMAIL" || "$EMAIL" == "admin@example.com" ]]; then
                log_error "LETSENCRYPT_EMAIL is required for PROXY=$PROXY_MODE."
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported PROXY '$PROXY_MODE'. Use nginx, traefik, or local."
            exit 1
            ;;
    esac

    if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]; then
        log_error "DOMAIN contains unsupported characters: $DOMAIN"
        exit 1
    fi

    # The proxy mode decides these, not whatever an older .env.prod happens to
    # contain. generate_secure_env keeps an existing file rather than rotating
    # POSTGRES_PASSWORD against a live volume, so a .env.prod first written for
    # PROXY=local kept FLASK_ENV=development and TRUST_PROXY=false after the
    # operator switched to nginx - carrying insecure cookies and relaxed CSRF
    # into a public TLS deployment. Both directions are now derived here.
    if [[ "$PROXY_MODE" == "local" ]]; then
        # Local mode is intentionally plain HTTP; production cookie and strict
        # CSRF settings would make the local admin UI unusable.
        export FLASK_ENV=development
        export WTF_CSRF_ENABLED=true
        export TRUST_PROXY=false
    else
        export FLASK_ENV=production
        export WTF_CSRF_ENABLED=true
        export TRUST_PROXY=true
    fi
}

compose() {
    local compose_args=(
        docker compose
        -f deploy/docker-compose.prod.yml
        --env-file .env.prod
    )
    if [[ "$PROXY_MODE" == "nginx" || "$PROXY_MODE" == "traefik" ]]; then
        compose_args+=(--profile "$PROXY_MODE")
    fi
    "${compose_args[@]}" "$@"
}

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
        ca-certificates
    
    # Install Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        systemctl enable docker
        systemctl start docker
    fi
    
    # Install Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        log_info "Installing Docker Compose..."
        mkdir -p /usr/local/lib/docker/cli-plugins
        curl -fsSL \
            "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/lib/docker/cli-plugins/docker-compose
        chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    fi
    
    log_success "Dependencies installed"
}

# Ports sshd is actually listening on, so the firewall rules cannot cut off the
# session running this script. `ufw allow ssh` only opens 22.
sshd_ports() {
    local ports=""
    if command -v sshd >/dev/null 2>&1; then
        ports="$(sshd -T 2>/dev/null | awk '/^port /{print $2}')"
    fi
    if [[ -z "$ports" && -r /etc/ssh/sshd_config ]]; then
        ports="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2}' /etc/ssh/sshd_config)"
    fi
    if [[ -z "$ports" ]] && command -v ss >/dev/null 2>&1; then
        ports="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u | grep -x 22 || true)"
    fi
    printf '%s\n' "${ports:-22}"
}

setup_firewall() {
    if [[ "${MANAGE_FIREWALL:-true}" != "true" ]]; then
        log_info "MANAGE_FIREWALL is not true; leaving the host firewall alone."
        return
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        log_warning "ufw is not installed; skipping firewall configuration."
        return
    fi

    log_info "Configuring firewall..."

    # Deliberately additive. This used to run `ufw --force reset` and then
    # `ufw allow ssh`, which opens 22 only - so on any host with sshd moved
    # elsewhere it deleted the rule keeping the operator's own session alive,
    # mid-deploy, over that same session. Rules for monitoring and backup
    # agents went with it. Set MANAGE_FIREWALL=false to skip this entirely.
    local port
    while read -r port; do
        [[ -n "$port" ]] || continue
        log_info "  allowing SSH on ${port}/tcp"
        ufw allow "${port}/tcp" >/dev/null
    done < <(sshd_ports)

    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null

    if ufw status 2>/dev/null | head -1 | grep -q "inactive"; then
        # Only opinionated about default policy on a firewall that is not yet
        # in use; on an active one the operator's existing policy stands.
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw --force enable >/dev/null
        log_success "Firewall enabled (SSH, 80/tcp, 443/tcp allowed)"
    else
        log_success "Firewall rules added for 80/tcp and 443/tcp; existing policy left unchanged"
    fi
}

setup_fail2ban() {
    log_info "Configuring Fail2Ban..."
    
    # Only [sshd]: its /var/log/auth.log exists on the host.
    #
    # There were also [nginx-http-auth] and [nginx-limit-req] jails pointed at
    # /var/log/nginx/error.log. Nothing writes there. Nginx runs in Compose and
    # logs to the nginx_logs named volume, so fail2ban failed configuration with
    # "Have not found any log file" and started with no jails at all - while
    # this script reported success. A security control that silently fails is
    # worse than an absent one, so the jails that cannot work are gone.
    #
    # To ban on nginx rate-limit hits, bind-mount the logs to a host path in
    # deploy/docker-compose.prod.yml (../logs/nginx:/var/log/nginx in place of
    # the named volume) and re-add the jails against that path.
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban

    # Report what is actually running rather than asserting success.
    if fail2ban-client status >/dev/null 2>&1; then
        log_success "Fail2Ban configured: $(fail2ban-client status 2>/dev/null \
            | sed -n 's/.*Jail list:[[:space:]]*//p')"
    else
        log_warning "Fail2Ban was configured but is not responding; check 'systemctl status fail2ban'."
    fi
}

create_production_compose() {
    log_info "Using the committed deploy/docker-compose.prod.yml..."

    if [[ ! -f deploy/docker-compose.prod.yml ]]; then
        log_error "deploy/docker-compose.prod.yml not found in $(pwd)"
        exit 1
    fi

    log_success "Production Docker Compose in place"
}

create_nginx_config() {
    mkdir -p logs
    if [[ "$PROXY_MODE" != "nginx" ]]; then
        return
    fi

    log_info "Using the committed deploy/nginx.conf..."

    mkdir -p ssl

    if [[ ! -f deploy/nginx.conf ]]; then
        log_error "deploy/nginx.conf not found in $(pwd)"
        exit 1
    fi

    log_success "Nginx configuration in place"
}

setup_ssl() {
    if [[ "$PROXY_MODE" != "nginx" ]]; then
        if [[ "$PROXY_MODE" == "local" ]]; then
            log_warning "Local mode selected; no TLS proxy or certificate is started."
        else
            log_info "Traefik selected; it will obtain and renew its certificate."
        fi
        return
    fi
    
    log_info "Setting up SSL certificate for $DOMAIN..."

    # Nginx runs in Compose, not as a host service. Standalone certbot needs
    # port 80 free for the HTTP-01 challenge and therefore runs before the
    # Compose proxy is started.
    if command -v systemctl >/dev/null 2>&1 &&
        systemctl is-active --quiet nginx 2>/dev/null; then
        log_error "A host-level nginx service is using port 80; stop it before certificate provisioning."
        exit 1
    fi

    # Stop the Compose proxy from any previous run, exactly as the renewal hook
    # does. On a first deployment nothing is listening, but on a re-run the
    # previous stack's nginx still holds :80 - so once the certificate entered
    # its renewal window and --keep-until-expiring stopped short-circuiting,
    # standalone certbot could not bind and the whole script aborted, after
    # having already reconfigured the host.
    #
    # Every exit path from here restarts the proxy EXPLICITLY. A `trap ...
    # RETURN` looks like it would do this and does not: under `set -e` a failing
    # command aborts the shell rather than returning, so the RETURN trap never
    # fires and the site is left down with no proxy and no message saying so.
    # Verified: `set -e; f() { trap r RETURN; false; }; f` runs nothing.
    local proxy_was_running=false
    if compose ps --status running --services 2>/dev/null | grep -qx nginx; then
        proxy_was_running=true
        log_info "Stopping the running proxy so certbot can bind port 80..."
        compose stop nginx >/dev/null 2>&1 || true
    fi

    restart_proxy_if_it_was_running() {
        if [[ "$proxy_was_running" == "true" ]]; then
            log_info "Restarting the proxy..."
            compose start nginx >/dev/null 2>&1 || true
        fi
    }

    # `|| status=$?` keeps errexit from aborting before the proxy is restored.
    local certbot_status=0
    certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --keep-until-expiring \
        --email "$EMAIL" \
        -d "$DOMAIN" || certbot_status=$?

    if (( certbot_status != 0 )); then
        restart_proxy_if_it_was_running
        log_error "certbot failed (exit ${certbot_status}) obtaining a certificate for $DOMAIN."
        log_error "The proxy has been restarted and any existing certificate is untouched."
        exit 1
    fi

    if ! sync_ssl_certificate; then
        restart_proxy_if_it_was_running
        exit 1
    fi

    install_ssl_renewal
    restart_proxy_if_it_was_running
    log_success "SSL certificate configured"
}

sync_ssl_certificate() {
    local live_dir="/etc/letsencrypt/live/$DOMAIN"

    # return, not exit: setup_ssl has a stopped proxy to restart before the
    # script gives up.
    if [[ ! -s "$live_dir/fullchain.pem" || ! -s "$live_dir/privkey.pem" ]]; then
        log_error "Certbot did not create a complete certificate for $DOMAIN."
        return 1
    fi

    mkdir -p ssl
    # Nginx mounts these stable paths read-only. Copying (rather than mounting
    # certbot's symlink tree) keeps renewal atomic from the container's point
    # of view and avoids a broken mount when certbot rotates a symlink.
    install -m 0644 "$live_dir/fullchain.pem" ssl/cert.pem
    install -m 0600 "$live_dir/privkey.pem" ssl/key.pem
}

install_ssl_renewal() {
    cat > /usr/local/bin/mocktaxii-cert-renew << EOF
#!/bin/bash
set -euo pipefail

cd /opt/mocktaxii
compose() {
    docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod --profile nginx "\$@"
}

# Standalone certbot must bind port 80. The trap starts the proxy again even
# when renewal fails, so a transient ACME error cannot leave the service down.
compose stop nginx
trap 'compose start nginx' EXIT
certbot renew --quiet
install -m 0644 /etc/letsencrypt/live/$DOMAIN/fullchain.pem ssl/cert.pem
install -m 0600 /etc/letsencrypt/live/$DOMAIN/privkey.pem ssl/key.pem
EOF
    chmod 700 /usr/local/bin/mocktaxii-cert-renew

    cat > /etc/cron.d/mocktaxii-cert-renew << 'EOF'
0 3 * * * root /usr/local/bin/mocktaxii-cert-renew >> /var/log/mocktaxii-cert-renew.log 2>&1
EOF
}

setup_monitoring() {
    log_info "Setting up monitoring and log rotation..."
    
    # No logrotate stanza for /opt/mocktaxii/logs.
    #
    # There was one, rotating /opt/mocktaxii/logs/*.log daily and restarting
    # the web container in its postrotate. Nothing writes there: the
    # application logs to stdout, which Docker captures. So logrotate rotated
    # nothing while the real log - the json-file under /var/lib/docker - grew
    # without bound, and the only effect the stanza could ever have had was an
    # unnecessary container restart. Rotation now lives in the `logging:`
    # blocks in deploy/docker-compose.prod.yml, which bound the file that
    # actually exists.
    #
    # Clean up the stanza from deployments made before this change.
    rm -f /etc/logrotate.d/mocktaxii

    
    # Health check script
    local health_url
    if [[ "$PROXY_MODE" == "local" ]]; then
        health_url="http://127.0.0.1:${APP_PORT:-5000}/healthz"
    else
        health_url="https://$DOMAIN/healthz"
    fi

    cat > /usr/local/bin/mocktaxii-health << 'EOF'
#!/bin/bash
set -euo pipefail
HEALTH_URL="__HEALTH_URL__"
if ! curl -fsS --max-time 15 "$HEALTH_URL" >/dev/null 2>&1; then
    echo "$(date): MockTAXII health check failed" >> /var/log/mocktaxii-health.log
    # Restart only the application. The reverse proxy owns the public ports
    # and must not be started as a second host-level nginx service.
    cd /opt/mocktaxii
    docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod restart web
fi
EOF
    sed -i "s|__HEALTH_URL__|$health_url|" /usr/local/bin/mocktaxii-health
    
    chmod +x /usr/local/bin/mocktaxii-health
    
    # Health check cron
    cat > /etc/cron.d/mocktaxii-health << 'EOF'
*/5 * * * * root /usr/local/bin/mocktaxii-health
EOF
    
    log_success "Monitoring configured"
}

generate_secure_env() {
    if [[ -f .env.prod ]]; then
        log_warning ".env.prod already exists - keeping it."
        log_warning "Regenerating would rotate POSTGRES_PASSWORD against the"
        log_warning "existing volume, locking the application out of its own database."
        return
    fi

    log_info "Generating secure environment configuration..."

    cat > .env.prod << EOF
# Database Configuration
POSTGRES_DB=mocktaxii
POSTGRES_USER=mocktaxii
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

# Application Configuration
SESSION_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
FLASK_ENV=$([[ "$PROXY_MODE" == "local" ]] && echo development || echo production)
WTF_CSRF_ENABLED=true
TRUST_PROXY=$([[ "$PROXY_MODE" == "local" ]] && echo false || echo true)
PROXY=$PROXY_MODE
APP_PORT=${APP_PORT:-5000}

# Domain Configuration
DOMAIN=${DOMAIN}
LETSENCRYPT_EMAIL=${EMAIL}
EOF
    
    chmod 600 .env.prod
    log_success "Secure environment file created"
}

# Everything a production deployment needs, and nothing else.
#
# An allowlist rather than a set of tar --exclude rules. Two reasons. Anything
# added to the repository later is left out of /opt by default instead of
# needing a new exclude rule to keep it out - so the failure mode is a missing
# file, which is loud, rather than an unintended one, which is silent. And this
# script then names only what it ships.
#
# Deliberately absent: the local/lab stack (docker-compose.yml, deploy.sh), and
# the test suite. Leaving the lab compose file out also means /opt cannot end
# up holding two compose files that resolve to the same project name.
staged_paths() {
    local src="$1" candidate
    local -a wanted=(
        Dockerfile
        .dockerignore
        docker-entrypoint.sh
        pyproject.toml
        uv.lock
        LICENSE
        README.md
        templates
        assets
        vendor
        deploy
    )
    for candidate in "$src"/*.py; do
        [[ -e "$candidate" ]] && wanted+=("$(basename "$candidate")")
    done
    for candidate in "${wanted[@]}"; do
        [[ -e "$src/$candidate" ]] && printf '%s\n' "$candidate"
    done
}

# Operator data created in the deployment directory by this script and by the
# running stack. Never staged, and never pruned.
DEPLOYMENT_STATE=(.env.prod ssl logs backups)

# The PostgreSQL major version this release's Compose files run. Bump this
# together with the image tags in deploy/docker-compose.prod.yml.
REQUIRED_PG_MAJOR=18

# Refuse an upgrade the database cannot survive, BEFORE anything is staged.
#
# Two things changed across the v0.7.0 -> v1.1.x span: postgres 15 -> 18, and
# the volume moved from /var/lib/postgresql/data to /var/lib/postgresql,
# because postgres:18 images keep the cluster in a major-version subdirectory.
# Deploying over an older volume leaves the db container in a restart loop
# with the explanation buried in `docker logs`, after the new files have
# already been staged. The operator's data is intact in both cases - postgres
# refuses to start rather than touching it - but the stack is down and nothing
# says why. Checking first turns that into an abort that has changed nothing.
check_database_compatibility() {
    local deployment_dir="$1"

    # No docker yet means a fresh host with nothing deployed to upgrade.
    command -v docker >/dev/null 2>&1 || return 0

    local volume="${PROJECT_NAME}_postgres_data"
    docker volume inspect "$volume" >/dev/null 2>&1 || return 0   # nothing deployed

    # Read PG_VERSION out of the volume. The host mountpoint is readable as
    # root on a Linux server and needs no image, so try that first; fall back
    # to a container for anything else. A layout we cannot read is reported
    # rather than passed over - a guard that fails open is not a guard.
    local mountpoint found=""
    mountpoint="$(docker volume inspect -f '{{ .Mountpoint }}' "$volume" 2>/dev/null || true)"
    if [[ -n "$mountpoint" && -d "$mountpoint" ]]; then
        if [[ -f "$mountpoint/$REQUIRED_PG_MAJOR/PG_VERSION" ]]; then
            return 0                  # already the current layout
        elif [[ -f "$mountpoint/PG_VERSION" ]]; then
            found="$(tr -d '[:space:]' < "$mountpoint/PG_VERSION")"
        else
            return 0                  # empty or unrecognised; let Compose decide
        fi
    else
        local probe
        probe="$(docker run --rm -v "$volume":/v "${PG_PROBE_IMAGE:-alpine}" sh -c \
                 'if [ -f "/v/'"$REQUIRED_PG_MAJOR"'/PG_VERSION" ]; then echo CURRENT;
                  elif [ -f /v/PG_VERSION ]; then cat /v/PG_VERSION;
                  else echo UNKNOWN; fi' 2>/dev/null | tr -d '[:space:]')"
        case "$probe" in
            CURRENT)  return 0 ;;
            UNKNOWN)  return 0 ;;
            "")       log_warning "Could not read $volume to check its PostgreSQL version."
                      log_warning "If this is an upgrade from before v1.1.1, back the database up first."
                      return 0 ;;
            *)        found="$probe" ;;
        esac
    fi

    [[ "$found" == "$REQUIRED_PG_MAJOR" ]] && return 0

    log_error "Database volume $volume was created by PostgreSQL $found."
    log_error "This release runs PostgreSQL $REQUIRED_PG_MAJOR, which will not start against it."
    log_error ""
    log_error "Nothing has been changed. Your data is intact and still in that volume."
    log_error ""
    log_error "To upgrade, dump the running database first:"
    log_error "  mkdir -p $deployment_dir/backups"
    log_error "  docker exec -t \$(docker ps -q -f volume=$volume) \\"
    log_error "      pg_dumpall -U mocktaxii > $deployment_dir/backups/pre-pg$REQUIRED_PG_MAJOR.sql"
    log_error ""
    log_error "then discard the old cluster and re-run this script:"
    log_error "  docker rm -f \$(docker ps -aq -f volume=$volume)"
    log_error "  docker volume rm $volume"
    log_error "  $0 deploy"
    log_error ""
    log_error "and restore once the new stack reports healthy:"
    log_error "  docker exec -i ${PROJECT_NAME}-db-1 psql -U mocktaxii -d mocktaxii \\"
    log_error "      < $deployment_dir/backups/pre-pg$REQUIRED_PG_MAJOR.sql"
    exit 1
}

stage_application() {
    local src="$1" dest="$2"
    local -a staged=()
    local path
    while IFS= read -r path; do
        [[ -n "$path" ]] && staged+=("$path")
    done < <(staged_paths "$src")
    [[ ${#staged[@]} -gt 0 ]] || { log_error "Nothing to stage from $src."; exit 1; }

    # tar only creates and overwrites archive members; it never deletes a
    # destination file the archive lacks. A file that moved or was dropped
    # between releases would therefore survive in /opt as a runnable copy of
    # the previous version. Remove whatever this release no longer provides,
    # keeping operator data.
    #
    # Guarded three ways so it can never run against a source tree: the source
    # must be somewhere other than the deployment directory, the deployment
    # directory must be the expected path, and it must be the working directory.
    if [[ "$src" != "$dest" && "$dest" == "/opt/mocktaxii" &&
          "$(pwd -P)" == "$dest" ]]; then
        local entry name keep
        for entry in "$dest"/* "$dest"/.[!.]*; do
            [[ -e "$entry" ]] || continue
            keep=false
            for name in "${staged[@]}" "${DEPLOYMENT_STATE[@]}"; do
                if [[ "$(basename "$entry")" == "$name" ]]; then
                    keep=true
                    break
                fi
            done
            if [[ "$keep" != "true" ]]; then
                log_info "  removing stale $(basename "$entry")"
                rm -rf -- "$entry"
            fi
        done

        # The loop above compares top-level names only, so a file that moves
        # *within* a staged directory survives it - and tar will not remove it
        # either, because tar never deletes a member the archive lacks. That
        # bit us at v1.1.4, when assets/vendor/ moved to vendor/: the old copy
        # stayed in assets/, was rebuilt into the image by the Compose build
        # (context is this directory), and Flask then served it, which is the
        # exact outcome the move existed to prevent.
        #
        # So prune per file as well: list what this release actually provides
        # and remove anything under a staged directory that is not in it. Same
        # principle as the loop above - "whatever this release no longer
        # ships" - just applied at full depth, so it needs no maintenance the
        # next time something moves. Only staged directories are walked, so
        # .env.prod, ssl/, logs/ and backups/ are never candidates.
        local manifest dir path rel
        manifest="$(tar -C "$src" -cf - -- "${staged[@]}" | tar -tf - \
                    | sed 's#/$##')"
        for dir in "${staged[@]}"; do
            [[ -d "$dest/$dir" ]] || continue
            while IFS= read -r path; do
                rel="${path#"$dest"/}"
                if ! printf '%s\n' "$manifest" | grep -qxF "$rel"; then
                    log_info "  removing stale $rel"
                    rm -f -- "$path"
                fi
            done < <(find "$dest/$dir" -type f)
            find "$dest/$dir" -type d -empty -delete 2>/dev/null || true
        done
    fi

    tar -C "$src" -cf - -- "${staged[@]}" | tar -C "$dest" -xf -
}

deploy_production() {
    check_root
    
    log_info "Starting production deployment for MockTAXII..."
    
    # Create deployment directory
    local deployment_dir="/opt/mocktaxii"
    mkdir -p "$deployment_dir"
    cd "$deployment_dir"

    if [[ ! -f "$SRC_DIR/main.py" ]]; then
        log_error "Application files not found in $SRC_DIR."
        log_error "Please run this script from the MockTAXII directory."
        exit 1
    fi
    # Before anything is written: refuse an upgrade the database cannot survive.
    check_database_compatibility "$deployment_dir"

    stage_application "$SRC_DIR" "$deployment_dir"

    # Read an existing operator configuration before deciding whether this is
    # local mode or a certificate-backed deployment.
    load_deployment_env
    
    # Install dependencies
    install_dependencies
    
    # Setup security
    setup_firewall
    setup_fail2ban
    
    # Create production configuration
    create_production_compose
    create_nginx_config
    generate_secure_env
    # The generated file is now the source of truth for Compose and renewal.
    load_deployment_env
    
    # Setup SSL
    setup_ssl
    
    # Setup monitoring
    setup_monitoring
    
    # Deploy services
    log_info "Deploying services..."
    compose up -d --build
    
    # Wait for services
    sleep 15
    
    # Verify deployment
    local verify_url
    if [[ "$PROXY_MODE" == "local" ]]; then
        verify_url="http://127.0.0.1:${APP_PORT:-5000}/healthz"
    else
        verify_url="https://$DOMAIN/healthz"
    fi
    if curl -fsS --max-time 15 "$verify_url" >/dev/null 2>&1; then
        log_success "MockTAXII v$PROJECT_VERSION production deployment completed successfully!"
        echo ""
        log_info "Your MockTAXII v$PROJECT_VERSION server is now running at:"
        if [[ "$PROXY_MODE" != "local" ]]; then
            echo "  - https://$DOMAIN"
        else
            echo "  - http://127.0.0.1:${APP_PORT:-5000}"
        fi
        echo ""
        log_info "Admin credentials:"
        echo "  - Password: docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod exec web cat /tmp/mocktaxii_admin_password"
        echo "              (or set ADMIN_PASSWORD in .env.prod to provide your own)"
        echo "  - Note: Initial CVE data (1,388 entries) will be fetched from CISA KEV catalogue on first startup"
        echo ""
        log_info "Monitoring:"
        echo "  - Logs: docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod logs -f"
        echo "  - Status: docker compose -f deploy/docker-compose.prod.yml --env-file .env.prod ps"
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
    echo "  DOMAIN              Domain name (required for nginx/traefik; localhost for local mode)"
    echo "  LETSENCRYPT_EMAIL   Email for ACME certificate (required for nginx/traefik)"
    echo "  PROXY               Reverse proxy: nginx, traefik, or local"
    echo "  ENVIRONMENT         Environment name (default: production)"
    echo ""
    echo "Example:"
    echo "  sudo DOMAIN=mocktaxii.example.com PROXY=nginx LETSENCRYPT_EMAIL=ops@example.com ./production-deploy.sh"
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
