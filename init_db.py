#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
MockTAXII Database Initialisation Script
=========================================
Handles all database seeding operations separately from application startup.
This script should be run once during initial deployment or when resetting data.

Usage:
    python init_db.py              # Run with defaults (5000 IPs)
    python init_db.py --ip-count 50000  # Custom IP count
    python init_db.py --force      # Force re-seeding even if data exists
    python init_db.py --check      # Check current data status only
"""

import os
import sys
import argparse
from datetime import datetime, timezone


def get_ip_target_count():
    """Get target IP count from environment or default"""
    try:
        return int(os.environ.get('MALICIOUS_IP_TARGET_COUNT', '5000'))
    except ValueError:
        return 5000


def check_seed_status(app, db):
    """Check current database seeding status"""
    with app.app_context():
        from models import (
            ThreatActor, MaliciousIP, MaliciousDomain, MaliciousHash,
            CVE, MalwareFamily, MitreTechnique, Campaign, ReportTemplate,
            ThreatSubnet, NoteTemplate, MaliciousSoftware
        )
        
        status = {
            'threat_actors': ThreatActor.query.count(),
            'threat_subnets': ThreatSubnet.query.count(),
            'malicious_ips': MaliciousIP.query.count(),
            'malicious_domains': MaliciousDomain.query.count(),
            'malicious_hashes': MaliciousHash.query.count(),
            'malicious_software': MaliciousSoftware.query.count(),
            'cves': CVE.query.count(),
            'malware_families': MalwareFamily.query.count(),
            'mitre_techniques': MitreTechnique.query.count(),
            'campaigns': Campaign.query.count(),
            'report_templates': ReportTemplate.query.count(),
            'note_templates': NoteTemplate.query.count(),
        }
        
        return status


def is_seeding_complete(status, target_ip_count):
    """Check if seeding appears complete based on expected minimums
    
    Thresholds are set to match actual seed function outputs:
    - threat_actors: 55 actors defined in seed_default_actors()
    - threat_subnets: ~1500 from Spamhaus DROP (varies slightly)
    - malicious_ips: configurable target_count
    - malicious_domains: 103 defined in seed_default_domains()
    - malicious_hashes: 39 defined in seed_default_hashes()
    - malicious_software: 50 PyGremlinBox packages
    - cves: ~1300 from CISA KEV (varies)
    - malware_families: 66 from MITRE ATT&CK
    - mitre_techniques: ~49 from MITRE ATT&CK
    - campaigns: ~95 generated in seed_campaigns()
    - report_templates: ~49 generated in seed_report_templates()
    - note_templates: ~25 generated in seed_note_templates()
    """
    minimums = {
        'threat_actors': 50,
        'threat_subnets': 100,
        'malicious_ips': target_ip_count,
        'malicious_domains': 100,
        'malicious_hashes': 35,
        'malicious_software': 40,
        'cves': 50,
        'malware_families': 20,
        'mitre_techniques': 40,
        'campaigns': 50,
        'report_templates': 25,
        'note_templates': 10,
    }
    
    for key, minimum in minimums.items():
        if status.get(key, 0) < minimum:
            return False, key, status.get(key, 0), minimum
    
    return True, None, None, None


def seed_database(app, db, target_ip_count, force=False):
    """Seed the database with all threat intelligence data"""
    
    print(f"\n{'='*60}")
    print("MockTAXII Database Initialisation")
    print(f"{'='*60}")
    print(f"Target IP count: {target_ip_count:,}")
    print(f"Force mode: {force}")
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}\n")
    
    with app.app_context():
        from models import (
            ThreatActor, MaliciousIP, MaliciousDomain, MaliciousHash,
            CVE, MalwareFamily, MitreTechnique, Campaign, ReportTemplate,
            ThreatSubnet, NoteTemplate, MaliciousSoftware
        )
        
        db.create_all()
        print("[OK] Database tables created/verified")
        
        current_status = check_seed_status(app, db)
        complete, missing_key, current, minimum = is_seeding_complete(current_status, target_ip_count)
        
        if complete and not force:
            print("\n[INFO] Database already seeded with sufficient data:")
            for key, count in current_status.items():
                print(f"  - {key.replace('_', ' ').title()}: {count:,}")
            print("\nUse --force to re-seed anyway.")
            return True
        
        if not complete:
            print(f"\n[INFO] Incomplete seeding detected: {missing_key} has {current:,}, needs {minimum:,}")
        
        print("\n[SEEDING] Starting database population...\n")
        
        print("[1/12] Seeding threat actors...")
        if force or ThreatActor.query.count() < 50:
            ThreatActor.seed_default_actors(force=force)
        print(f"       Threat actors: {ThreatActor.query.count():,}")
        
        print("[2/12] Fetching Spamhaus DROP subnets...")
        if force or ThreatSubnet.query.count() < 100:
            ThreatSubnet.seed_spamhaus_subnets(force=force)
        print(f"       Threat subnets: {ThreatSubnet.query.count():,}")
        
        print(f"[3/12] Generating {target_ip_count:,} malicious IP addresses...")
        current_ip_count = MaliciousIP.query.count()
        if force or current_ip_count < target_ip_count:
            if force and current_ip_count > 0:
                print(f"       Clearing existing {current_ip_count:,} IPs for regeneration...")
                MaliciousIP.query.delete()
                db.session.commit()
            MaliciousIP.seed_from_subnets(target_count=target_ip_count)
        print(f"       Malicious IPs: {MaliciousIP.query.count():,}")
        
        print("[4/12] Seeding malicious domains...")
        if force or MaliciousDomain.query.count() < 100:
            MaliciousDomain.seed_default_domains(force=force)
        print(f"       Malicious domains: {MaliciousDomain.query.count():,}")
        
        print("[5/12] Seeding malware families...")
        if force or MalwareFamily.query.count() < 20:
            MalwareFamily.seed_malware_families(force=force)
        print(f"       Malware families: {MalwareFamily.query.count():,}")
        
        print("[6/12] Seeding malicious hashes...")
        if force or MaliciousHash.query.count() < 35:
            MaliciousHash.seed_default_hashes(force=force)
        print(f"       Malicious hashes: {MaliciousHash.query.count():,}")
        
        print("[7/12] Fetching CISA KEV CVEs...")
        if force or CVE.query.count() < 50:
            CVE.seed_from_cisa_kev(force=force)
        print(f"       CVEs: {CVE.query.count():,}")
        
        print("[8/12] Fetching MITRE ATT&CK techniques...")
        if force or MitreTechnique.query.count() < 40:
            MitreTechnique.seed_mitre_techniques(force=force)
        print(f"       MITRE techniques: {MitreTechnique.query.count():,}")
        
        print("[9/12] Generating campaigns...")
        if force or Campaign.query.count() < 50:
            Campaign.seed_campaigns(force=force)
        print(f"       Campaigns: {Campaign.query.count():,}")
        
        print("[10/12] Generating report templates...")
        if force or ReportTemplate.query.count() < 25:
            ReportTemplate.seed_report_templates(force=force)
        print(f"       Report templates: {ReportTemplate.query.count():,}")
        
        print("[11/12] Generating note templates...")
        if force or NoteTemplate.query.count() < 10:
            NoteTemplate.seed_note_templates(force=force)
        print(f"       Note templates: {NoteTemplate.query.count():,}")
        
        print("[12/12] Seeding malicious software packages...")
        if force or MaliciousSoftware.query.count() < 40:
            MaliciousSoftware.seed_malicious_software(force=force)
        print(f"       Malicious software: {MaliciousSoftware.query.count():,}")
        
        # Verify rather than assert. This block previously printed
        # "Database Seeding Complete!" and returned True unconditionally, so a
        # deployment whose upstream fetches all failed reported success while
        # leaving the feed empty - and the caller had no way to tell.
        final_status = check_seed_status(app, db)
        complete, missing_key, current, minimum = is_seeding_complete(final_status, target_ip_count)

        print(f"\n{'='*60}")
        print("Database Seeding Complete!" if complete else "Database Seeding INCOMPLETE")
        print(f"{'='*60}")
        print(f"Completed at: {datetime.now(timezone.utc).isoformat()}")

        print("\nFinal counts:")
        for key, count in final_status.items():
            marker = ''
            if not complete and key == missing_key:
                marker = f"   <-- below the minimum of {minimum:,}"
            print(f"  - {key.replace('_', ' ').title()}: {count:,}{marker}")

        if not complete:
            print(f"\n[ERROR] {missing_key} has {current:,}, needs at least {minimum:,}.")
            print("        The most common cause is no outbound network access to the")
            print("        Spamhaus DROP or CISA KEV sources at first boot.")

        return complete


def main():
    parser = argparse.ArgumentParser(
        description='MockTAXII Database Initialisation Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python init_db.py                    # Default seeding (5,000 IPs)
  python init_db.py --ip-count 50000   # Production seeding (50,000 IPs)
  python init_db.py --ip-count 100000  # Large-scale seeding
  python init_db.py --check            # Check current status only
  python init_db.py --force            # Force complete re-seeding

Environment Variables:
  MALICIOUS_IP_TARGET_COUNT   Default IP count if --ip-count not specified
  DATABASE_URL                PostgreSQL connection string (required)
        """
    )
    
    parser.add_argument(
        '--ip-count', 
        type=int, 
        default=None,
        help=f'Target number of malicious IPs to generate (default: {get_ip_target_count():,} from env or 5000)'
    )
    parser.add_argument(
        '--force', 
        action='store_true',
        help='Force re-seeding even if data already exists'
    )
    parser.add_argument(
        '--check', 
        action='store_true',
        help='Check current database status without seeding'
    )
    
    args = parser.parse_args()
    
    target_ip_count = args.ip_count if args.ip_count is not None else get_ip_target_count()
    
    if target_ip_count < 1000:
        print(f"[WARNING] IP count {target_ip_count:,} is very low. Minimum recommended: 1,000")
    elif target_ip_count > 100000:
        print(f"[WARNING] IP count {target_ip_count:,} is very high. This may take a long time.")
    
    from app import app, db
    
    if args.check:
        print("\n[CHECK] Current database status:\n")
        status = check_seed_status(app, db)
        for key, count in status.items():
            print(f"  {key.replace('_', ' ').title()}: {count:,}")
        
        complete, missing_key, current, minimum = is_seeding_complete(status, target_ip_count)
        if complete:
            print(f"\n[OK] Database is fully seeded for {target_ip_count:,} IP target")
        else:
            print(f"\n[INCOMPLETE] {missing_key} has {current:,}, needs at least {minimum:,}")
        
        return 0
    
    try:
        success = seed_database(app, db, target_ip_count, force=args.force)
        return 0 if success else 1
    except Exception as e:
        print(f"\n[ERROR] Database seeding failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
