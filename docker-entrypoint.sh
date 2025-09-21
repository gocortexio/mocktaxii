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
from models import ThreatActor, MaliciousIP, MaliciousDomain, MaliciousHash, CVE, MalwareFamily, MitreTechnique, Campaign, ReportTemplate, ThreatSubnet
with app.app_context():
    db.create_all()
    ThreatActor.seed_default_actors()
    ThreatSubnet.seed_spamhaus_subnets()
    MaliciousIP.seed_from_subnets(target_count=50000)
    MaliciousDomain.seed_default_domains()
    MalwareFamily.seed_malware_families()  # Seed malware families first
    MaliciousHash.seed_default_hashes()  # This now depends on malware families
    CVE.seed_from_cisa_kev()
    MitreTechnique.seed_mitre_techniques()
    Campaign.seed_campaigns()
    ReportTemplate.seed_report_templates()
    print('Database tables created and data seeded successfully')
    print(f'Threat actors: {ThreatActor.query.count()}')
    print(f'Malicious IPs: {MaliciousIP.query.count()}')
    print(f'Malicious domains: {MaliciousDomain.query.count()}')
    print(f'Malicious hashes: {MaliciousHash.query.count()}')
    print(f'CVE vulnerabilities: {CVE.query.count()}')
    print(f'Malware families: {MalwareFamily.query.count()}')
    print(f'MITRE ATT&CK techniques: {MitreTechnique.query.count()}')
    print(f'Campaigns: {Campaign.query.count()}')
    print(f'Report templates: {ReportTemplate.query.count()}')
"

# Start the application
echo "Starting MockTAXII server..."
exec "$@"