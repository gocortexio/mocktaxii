#!/bin/bash
set -e

# MockTAXII v0.7.0 Docker Entrypoint
# Handles database initialisation and application startup

# Configuration
MALICIOUS_IP_TARGET_COUNT=${MALICIOUS_IP_TARGET_COUNT:-5000}
SKIP_SEEDING=${SKIP_SEEDING:-false}

echo "========================================"
echo "MockTAXII v0.7.0 Container Startup"
echo "========================================"
echo "IP Target Count: ${MALICIOUS_IP_TARGET_COUNT}"
echo "Skip Seeding: ${SKIP_SEEDING}"
echo "========================================"

# Wait for database to be ready
echo "[1/4] Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0
while ! pg_isready -h ${PGHOST:-db} -p ${PGPORT:-5432} -U ${PGUSER:-mocktaxii} 2>/dev/null; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        echo "[ERROR] PostgreSQL not ready after ${max_attempts} attempts. Exiting."
        exit 1
    fi
    echo "  Attempt ${attempt}/${max_attempts}..."
    sleep 2
done
echo "[OK] PostgreSQL is ready!"

# Run lightweight database migrations (schema changes only)
echo "[2/4] Running database migrations..."
PGPASSWORD=${PGPASSWORD:-mocktaxii} psql -h ${PGHOST:-db} -p ${PGPORT:-5432} -U ${PGUSER:-mocktaxii} -d ${PGDATABASE:-mocktaxii} <<EOF
-- v0.7.0: Custom Bundles feature migrations
ALTER TABLE api_key ADD COLUMN IF NOT EXISTS requests_since_bundle INTEGER NOT NULL DEFAULT 0;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS custom_bundle_served BOOLEAN DEFAULT FALSE;
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'request_log' AND column_name = 'custom_bundle_id') THEN
        ALTER TABLE request_log ADD COLUMN custom_bundle_id INTEGER;
    END IF;
END \$\$;
EOF
echo "[OK] Migrations complete!"

# Initialise and seed database (uses init_db.py with completion tracking)
echo "[3/4] Initialising database..."
if [ "$SKIP_SEEDING" = "true" ]; then
    echo "[INFO] Skipping database seeding (SKIP_SEEDING=true)"
    echo "[INFO] Creating tables only..."
    uv run python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('[OK] Database tables created')
"
else
    echo "[INFO] Running database initialisation with IP target: ${MALICIOUS_IP_TARGET_COUNT}"
    uv run python init_db.py --ip-count ${MALICIOUS_IP_TARGET_COUNT}
fi
echo "[OK] Database initialisation complete!"

# Start the application
echo "[4/4] Starting MockTAXII server..."
echo "========================================"
exec "$@"
