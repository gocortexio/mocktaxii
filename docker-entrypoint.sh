#!/bin/bash
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

# MockTAXII Docker Entrypoint
# Handles database initialisation and application startup

# Configuration
MALICIOUS_IP_TARGET_COUNT=${MALICIOUS_IP_TARGET_COUNT:-5000}
SKIP_SEEDING=${SKIP_SEEDING:-false}

# Single source of truth for the version banner (version.py)
APP_VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' /app/version.py 2>/dev/null)
APP_VERSION=${APP_VERSION:-unknown}

if [ -z "${DATABASE_URL:-}" ]; then
    echo "[ERROR] DATABASE_URL is not set. Refusing to start." >&2
    exit 1
fi

echo "========================================"
echo "MockTAXII v${APP_VERSION} Container Startup"
echo "========================================"
echo "IP Target Count: ${MALICIOUS_IP_TARGET_COUNT}"
echo "Skip Seeding: ${SKIP_SEEDING}"
echo "Session Secret: [Generated - 64 chars]"
echo "========================================"

# ---------------------------------------------------------------------------
# [1/5] Wait for the database
#
# psql/pg_isready read DATABASE_URL directly. They previously used a separate
# set of PG* variables with a hardcoded `mocktaxii` password fallback, which
# happened to match docker-compose.yml but not production-deploy.sh - so on any
# deployment with a generated password, psql failed scram-sha-256 auth and
# `set -e` aborted the container before gunicorn ever started.
# ---------------------------------------------------------------------------
echo "[1/5] Waiting for PostgreSQL to be ready..."
max_attempts=30
attempt=0
until pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$max_attempts" ]; then
        echo "[ERROR] PostgreSQL not ready after ${max_attempts} attempts. Exiting." >&2
        exit 1
    fi
    echo "  Attempt ${attempt}/${max_attempts}..."
    sleep 2
done
echo "[OK] PostgreSQL is ready!"

# ---------------------------------------------------------------------------
# [2/5] Schema migrations
#
# These MUST run before the application is imported. app.py refuses to start in
# production when a column exists in the models but not in the database - and
# the migration that would add it is this block, so running it second made a
# production upgrade a deadlock: step 2 aborted on the drift, and step 3 never
# reached the ALTER that would have satisfied the guard.
#
# Every statement is therefore written to be a no-op on a database where the
# table does not exist yet. ALTER TABLE IF EXISTS handles that directly; the
# index and the dedup block are guarded on to_regclass. On a fresh database
# this whole block does nothing and db.create_all() below builds the schema.
# ---------------------------------------------------------------------------
echo "[2/5] Running database migrations..."
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --quiet <<'SQL'
-- v1.0.9: Custom Bundles feature
ALTER TABLE IF EXISTS api_key     ADD COLUMN IF NOT EXISTS requests_since_bundle INTEGER NOT NULL DEFAULT 0;
ALTER TABLE IF EXISTS request_log ADD COLUMN IF NOT EXISTS custom_bundle_served  BOOLEAN DEFAULT FALSE;
ALTER TABLE IF EXISTS request_log ADD COLUMN IF NOT EXISTS custom_bundle_id      INTEGER;

-- v1.1.0: widen counters. As int4 these overflowed after roughly 5M objects
-- requests, after which every objects request failed permanently.
ALTER TABLE IF EXISTS server_stats ALTER COLUMN total_indicators_served TYPE BIGINT;
ALTER TABLE IF EXISTS server_stats ALTER COLUMN total_requests          TYPE BIGINT;
ALTER TABLE IF EXISTS api_key      ALTER COLUMN request_count           TYPE BIGINT;
ALTER TABLE IF EXISTS request_log  ALTER COLUMN id                      TYPE BIGINT;

-- v1.1.0: request_log is sorted by timestamp on every hit of the public home
-- page and grows without bound.
DO $$
BEGIN
    IF to_regclass('public.request_log') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS ix_request_log_timestamp ON request_log (timestamp);
    END IF;
END $$;

-- v1.1.0: collapse any duplicate ServerStats rows onto the pinned singleton.
-- Two workers racing on a fresh deployment could each insert one and split the
-- totals between them.
-- The existence test and the row count must be separate IFs. PL/pgSQL plans a
-- whole condition before evaluating it, so combining them with AND still
-- parses "FROM server_stats" on a database where that table does not exist
-- yet, and fails there rather than short-circuiting.
DO $$
DECLARE
    total_ind BIGINT;
    total_req BIGINT;
BEGIN
    IF to_regclass('public.server_stats') IS NOT NULL THEN
        IF (SELECT COUNT(*) FROM server_stats) > 1 THEN
            SELECT SUM(total_indicators_served), SUM(total_requests)
              INTO total_ind, total_req FROM server_stats;
            DELETE FROM server_stats;
            INSERT INTO server_stats (id, total_indicators_served, total_requests, last_updated)
            VALUES (1, total_ind, total_req, NOW());
        END IF;
    END IF;
END $$;
SQL
echo "[OK] Migrations complete!"

# ---------------------------------------------------------------------------
# [3/5] Create tables
#
# Importing app.py also runs the schema-drift guard, which is why the ALTERs
# above have to have happened already. db.create_all() only ever CREATEs; it
# will not alter an existing table, so any column added or widened after a
# deployment exists must appear in the migration block too.
# ---------------------------------------------------------------------------
echo "[3/5] Creating tables..."
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('[OK] Tables created/verified')
"

# ---------------------------------------------------------------------------
# [4/5] Seed
# ---------------------------------------------------------------------------
echo "[4/5] Initialising database..."
if [ "$SKIP_SEEDING" = "true" ]; then
    echo "[INFO] Skipping database seeding (SKIP_SEEDING=true)"
else
    echo "[INFO] Running database initialisation with IP target: ${MALICIOUS_IP_TARGET_COUNT}"
    # Reports failure honestly. It previously printed "Database Seeding
    # Complete!" and exited 0 even when every table had been left empty by a
    # failed upstream fetch.
    if ! python init_db.py --ip-count "${MALICIOUS_IP_TARGET_COUNT}"; then
        echo "[ERROR] Database seeding did not complete. Refusing to serve an" >&2
        echo "        empty or partial feed. Check network access to the" >&2
        echo "        Spamhaus DROP and CISA KEV sources, then restart, or set" >&2
        echo "        SKIP_SEEDING=true to start without seed data." >&2
        exit 1
    fi
fi
echo "[OK] Database initialisation complete!"

# ---------------------------------------------------------------------------
# [5/5] Start
# ---------------------------------------------------------------------------
echo "[5/5] Starting MockTAXII server..."
echo "========================================"
exec "$@"
