#!/bin/bash
set -e

# Wait for database to be ready
echo "Waiting for PostgreSQL to be ready..."
while ! pg_isready -h ${PGHOST:-db} -p ${PGPORT:-5432} -U ${PGUSER:-mocktaxii}; do
    sleep 2
done

echo "PostgreSQL is ready!"

# Initialize database tables and seed all threat data
echo "Initialising database..."
uv run python -c "
from app import app, db
from models import ThreatActor, MaliciousIP, MaliciousDomain, MaliciousHash, CVE
with app.app_context():
    db.create_all()
    ThreatActor.seed_default_actors()
    MaliciousIP.seed_default_ips()
    MaliciousDomain.seed_default_domains()
    MaliciousHash.seed_default_hashes()
    CVE.seed_from_cisa_kev()
    print('Database tables created and data seeded successfully')
    print(f'Threat actors: {ThreatActor.query.count()}')
    print(f'Malicious IPs: {MaliciousIP.query.count()}')
    print(f'Malicious domains: {MaliciousDomain.query.count()}')
    print(f'Malicious hashes: {MaliciousHash.query.count()}')
    print(f'CVE vulnerabilities: {CVE.query.count()}')
"

# Start the application
echo "Starting MockTAXII server..."
exec "$@"