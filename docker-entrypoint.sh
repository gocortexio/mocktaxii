#!/bin/bash
set -e

# Wait for database to be ready
echo "Waiting for PostgreSQL to be ready..."
while ! pg_isready -h ${PGHOST:-db} -p ${PGPORT:-5432} -U ${PGUSER:-mocktaxii}; do
    sleep 2
done

echo "PostgreSQL is ready!"

# Initialize database tables and seed threat actors
echo "Initializing database..."
uv run python -c "
from app import app, db
from models import ThreatActor
with app.app_context():
    db.create_all()
    ThreatActor.seed_default_actors()
    print('Database tables created and threat actors seeded successfully')
"

# Start the application
echo "Starting MockTAXII server..."
exec "$@"