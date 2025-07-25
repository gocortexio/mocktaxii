import json
import uuid
from datetime import datetime, timezone
import random

class STIXGenerator:
    """Generate mock STIX 2.x threat intelligence indicators"""
    
    # All threat indicators (IPs, domains, hashes) now stored in database tables
    
    MALWARE_FAMILIES = [
        "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Mimikatz",
        "Zeus", "Dridex", "IcedID", "BazarLoader", "QakBot"
    ]
    
    @staticmethod
    def generate_timestamp():
        """Generate a current timestamp in STIX format"""
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    @staticmethod
    def convert_score_to_text(numerical_score):
        """Convert numerical confidence score to text format"""
        if numerical_score >= 90:
            return "critical"
        elif numerical_score >= 75:
            return "high"
        elif numerical_score >= 50:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def add_disclaimer(description):
        """Add standardised disclaimer to indicator descriptions"""
        return f"{description}\n\nThis is just mock data for testing or demo purposes… brought to you by gocortex.io."
    
    @staticmethod
    def generate_ip_indicator():
        """Generate a STIX IP address indicator using database"""
        from models import MaliciousIP
        
        # Get a random malicious IP from database
        db_ip = MaliciousIP.get_random_active()
        if not db_ip:
            # Fallback if no IPs in database (shouldn't happen due to seeding)
            ip = "192.168.1.100"
            score = "medium"
            description = f"Malicious IP address {ip} associated with command and control infrastructure"
        else:
            ip = db_ip.ip_address
            score = STIXGenerator.convert_score_to_text(db_ip.confidence_score)
            description = db_ip.description
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": STIXGenerator.add_disclaimer(description)
        }
    
    @staticmethod
    def generate_domain_indicator():
        """Generate a STIX domain indicator using database"""
        from models import MaliciousDomain
        
        # Get random domain from database
        domain_obj = MaliciousDomain.get_random_active()
        if not domain_obj:
            # Fallback if no domains in database
            domain = "unknown-threat.example.com"
            score = "medium"
            description = "Unknown malicious domain"
        else:
            domain = domain_obj.domain_name
            score = STIXGenerator.convert_score_to_text(domain_obj.confidence_score)
            description = domain_obj.description
            
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": STIXGenerator.add_disclaimer(description)
        }
    
    @staticmethod
    def generate_file_hash_indicator():
        """Generate a STIX file hash indicator using database"""
        from models import MaliciousHash
        
        # Get random hash from database
        hash_obj = MaliciousHash.get_random_active()
        if not hash_obj:
            # Fallback if no hashes in database
            hash_value = "A1B2C3D4E5F67890123456789012345678901234567890123456789012345678"
            score = "medium"
            description = "Unknown malicious file hash"
        else:
            hash_value = hash_obj.hash_value
            score = STIXGenerator.convert_score_to_text(hash_obj.confidence_score)
            description = hash_obj.description
            
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[file:hashes.SHA256 = '{hash_value}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": STIXGenerator.add_disclaimer(description)
        }
    
    @staticmethod
    def generate_vulnerability_object():
        """Generate a STIX vulnerability object using CVE database"""
        from models import CVE
        
        # Get a random CVE from database
        cve_obj = CVE.get_random_active()
        if not cve_obj:
            # Fallback if no CVEs in database (shouldn't happen due to seeding)
            cve_id = "CVE-2025-0000"
            name = "Unknown Vulnerability"
            description = "Unknown vulnerability"
            x_cvss_score = 5.0
            x_severity = "Medium"
            x_cvss_version = "3.1"
            x_cvss_vector = ""
            x_cpe_uris = []
        else:
            cve_id = cve_obj.cve_id
            name = cve_obj.vulnerability_name or f"{cve_obj.vendor_project} {cve_obj.product} Vulnerability"
            description = cve_obj.short_description or f"Vulnerability in {cve_obj.vendor_project} {cve_obj.product}"
            
            # Use actual CVSS score from database, fallback to severity mapping
            if cve_obj.cvss_score:
                x_cvss_score = cve_obj.cvss_score
            else:
                severity_to_score = {
                    "Critical": 9.0,
                    "High": 7.5,
                    "Medium": 5.0,
                    "Low": 2.5
                }
                x_cvss_score = severity_to_score.get(cve_obj.severity, 5.0)
            x_severity = cve_obj.severity
            x_cvss_version = cve_obj.cvss_version or "3.1"
            x_cvss_vector = cve_obj.cvss_vector or ""
            x_cpe_uris = cve_obj.cpe_uris or []
        
        vulnerability_obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "name": cve_id,
            "description": STIXGenerator.add_disclaimer(description),
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
            ],
            "x_cvss_score": x_cvss_score,
            "x_cvss_version": x_cvss_version,
            "x_cvss_vector": x_cvss_vector,
            "x_severity": x_severity,
            "x_vulnerability_name": name,
            "x_cpe_uris": x_cpe_uris
        }
        
        # Add CISA KEV reference if available
        if cve_obj and cve_obj.source == "CISA KEV Catalog":
            vulnerability_obj["external_references"].append({
                "source_name": "CISA KEV",
                "description": "CISA Known Exploited Vulnerabilities Catalog",
                "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            })
        
        return vulnerability_obj
    
    @staticmethod
    def generate_malware_object():
        """Generate a STIX malware object"""
        malware_family = random.choice(STIXGenerator.MALWARE_FAMILIES)
        return {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "name": malware_family,
            "description": STIXGenerator.add_disclaimer(f"{malware_family} is a known malware family used in various attack campaigns"),
            "malware_types": ["trojan", "backdoor"],
            "is_family": True
        }
    
    @staticmethod
    def generate_threat_actor():
        """Generate a STIX threat actor object from database"""
        from models import ThreatActor
        
        # Get a random threat actor from database
        db_actor = ThreatActor.get_random_active()
        if not db_actor:
            # Fallback if no actors in database (shouldn't happen due to seeding)
            actor_name = "Unknown Actor"
            description = "Unknown threat actor"
            threat_actor_types = ["criminal-enterprise"]
            sophistication = "intermediate"
            resource_level = "organisation"
            primary_motivation = "financial-gain"
        else:
            actor_name = db_actor.name
            description = db_actor.description or f"{actor_name} is a threat actor group known for targeted attacks"
            threat_actor_types = db_actor.threat_actor_types
            sophistication = db_actor.sophistication
            resource_level = db_actor.resource_level
            primary_motivation = db_actor.primary_motivation
        
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "name": actor_name,
            "description": STIXGenerator.add_disclaimer(description),
            "threat_actor_types": threat_actor_types,
            "sophistication": sophistication,
            "resource_level": resource_level,
            "primary_motivation": primary_motivation
        }
    
    @staticmethod
    def generate_relationship(source_id, target_id, relationship_type, description=None):
        """Generate a STIX relationship object"""
        relationship_id = f"relationship--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": relationship_id,
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id
        }
        
        if description:
            relationship["description"] = description
            
        return relationship
    
    @staticmethod
    def generate_campaign_object():
        """Generate a STIX campaign object"""
        campaign_id = f"campaign--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        campaign_names = [
            "Operation ShadowNet", "DarkWeb Harvest", "Silent Storm",
            "Digital Phantom", "Cyber Eclipse", "Ghost Protocol",
            "Binary Assault", "Code Red Initiative", "Stealth Vector",
            "Quantum Breach"
        ]
        
        campaign_name = random.choice(campaign_names)
        
        return {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": timestamp,
            "modified": timestamp,
            "name": campaign_name,
            "description": STIXGenerator.add_disclaimer("Sophisticated cyber campaign targeting enterprise infrastructure with advanced persistent threats"),
            "first_seen": timestamp,
            "last_seen": timestamp
        }
    
    @staticmethod
    def generate_attack_pattern():
        """Generate a STIX attack pattern object"""
        attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # MITRE ATT&CK techniques (50 authentic techniques)
        techniques = [
            {"name": "Spearphishing Attachment", "mitre_id": "T1566.001"},
            {"name": "PowerShell", "mitre_id": "T1059.001"},
            {"name": "Registry Run Keys / Startup Folder", "mitre_id": "T1547.001"},
            {"name": "Process Injection", "mitre_id": "T1055"},
            {"name": "Credential Dumping", "mitre_id": "T1003"},
            {"name": "Remote Desktop Protocol", "mitre_id": "T1021.001"},
            {"name": "Data Encrypted for Impact", "mitre_id": "T1486"},
            {"name": "Exfiltration Over C2 Channel", "mitre_id": "T1041"},
            {"name": "Command and Scripting Interpreter", "mitre_id": "T1059"},
            {"name": "Valid Accounts", "mitre_id": "T1078"},
            {"name": "Windows Management Instrumentation", "mitre_id": "T1047"},
            {"name": "Scheduled Task/Job", "mitre_id": "T1053"},
            {"name": "File and Directory Discovery", "mitre_id": "T1083"},
            {"name": "System Information Discovery", "mitre_id": "T1082"},
            {"name": "Network Service Scanning", "mitre_id": "T1046"},
            {"name": "Lateral Tool Transfer", "mitre_id": "T1570"},
            {"name": "Archive Collected Data", "mitre_id": "T1560"},
            {"name": "Ingress Tool Transfer", "mitre_id": "T1105"},
            {"name": "Application Layer Protocol", "mitre_id": "T1071"},
            {"name": "Masquerading", "mitre_id": "T1036"},
            {"name": "Indicator Removal on Host", "mitre_id": "T1070"},
            {"name": "Disable or Modify Tools", "mitre_id": "T1562.001"},
            {"name": "LSASS Memory", "mitre_id": "T1003.001"},
            {"name": "Security Account Manager", "mitre_id": "T1003.002"},
            {"name": "DCSync", "mitre_id": "T1003.006"},
            {"name": "LSA Secrets", "mitre_id": "T1003.004"},
            {"name": "NTDS", "mitre_id": "T1003.003"},
            {"name": "Cached Domain Credentials", "mitre_id": "T1003.005"},
            {"name": "Windows Command Shell", "mitre_id": "T1059.003"},
            {"name": "Visual Basic", "mitre_id": "T1059.005"},
            {"name": "Python", "mitre_id": "T1059.006"},
            {"name": "JavaScript", "mitre_id": "T1059.007"},
            {"name": "Network Sniffing", "mitre_id": "T1040"},
            {"name": "Account Discovery", "mitre_id": "T1087"},
            {"name": "Permission Groups Discovery", "mitre_id": "T1069"},
            {"name": "Remote System Discovery", "mitre_id": "T1018"},
            {"name": "Network Share Discovery", "mitre_id": "T1135"},
            {"name": "System Network Configuration Discovery", "mitre_id": "T1016"},
            {"name": "System Owner/User Discovery", "mitre_id": "T1033"},
            {"name": "Process Discovery", "mitre_id": "T1057"},
            {"name": "Software Discovery", "mitre_id": "T1518"},
            {"name": "System Service Discovery", "mitre_id": "T1007"},
            {"name": "Query Registry", "mitre_id": "T1012"},
            {"name": "System Time Discovery", "mitre_id": "T1124"},
            {"name": "Virtualization/Sandbox Evasion", "mitre_id": "T1497"},
            {"name": "Obfuscated Files or Information", "mitre_id": "T1027"},
            {"name": "Deobfuscate/Decode Files or Information", "mitre_id": "T1140"},
            {"name": "System Binary Proxy Execution", "mitre_id": "T1218"},
            {"name": "Signed Binary Proxy Execution", "mitre_id": "T1218"},
            {"name": "DLL Side-Loading", "mitre_id": "T1574.002"}
        ]
        
        technique = random.choice(techniques)
        
        return {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_pattern_id,
            "created": timestamp,
            "modified": timestamp,
            "name": technique["name"],
            "description": STIXGenerator.add_disclaimer(f"MITRE ATT&CK technique {technique['mitre_id']}"),
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique["mitre_id"],
                    "url": f"https://attack.mitre.org/techniques/{technique['mitre_id'].replace('.', '/')}"
                }
            ]
        }
    
    @staticmethod
    def generate_note_object(threat_actor_name):
        """Generate a STIX note object with threat actor intelligence"""
        note_id = f"note--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Generate realistic threat intelligence notes with PDF reference URLs
        note_templates = [
            f"Intelligence report on {threat_actor_name} activities observed targeting financial institutions with credential harvesting campaigns. Full analysis available at: https://simonsigre.com/threat-actor-analysis-{threat_actor_name.lower().replace(' ', '-')}.pdf",
            f"Analysis of {threat_actor_name} infrastructure reveals use of compromised domains for command and control operations. Technical details: https://simonsigre.com/infrastructure-analysis-{threat_actor_name.lower().replace(' ', '-')}.pdf",
            f"Recent campaign attribution links {threat_actor_name} to advanced persistent threat activities in healthcare sector. Report: https://simonsigre.com/healthcare-threats-{threat_actor_name.lower().replace(' ', '-')}.pdf",
            f"Technical analysis indicates {threat_actor_name} employs living-off-the-land techniques to evade detection. Methodology: https://simonsigre.com/lotl-techniques-{threat_actor_name.lower().replace(' ', '-')}.pdf",
            f"Threat hunting investigation reveals {threat_actor_name} infrastructure overlaps with previously observed campaigns. Research: https://simonsigre.com/threat-hunting-{threat_actor_name.lower().replace(' ', '-')}.pdf"
        ]
        
        note_content = random.choice(note_templates)
        
        return {
            "type": "note",
            "spec_version": "2.1", 
            "id": note_id,
            "created": timestamp,
            "modified": timestamp,
            "content": STIXGenerator.add_disclaimer(note_content),
            "authors": ["Threat Intelligence Team"],
            "abstract": f"Intelligence assessment for {threat_actor_name}",
            "object_refs": []  # Will be populated with threat actor reference
        }

    @staticmethod
    def generate_report_object(threat_actor_name, campaign_name):
        """Generate a STIX report object with threat intelligence publication"""
        report_id = f"report--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Generate realistic threat intelligence report titles with PDF reference URLs
        report_data = [
            {
                "title": f"Threat Intelligence Brief: {threat_actor_name} Campaign Analysis",
                "url": f"https://simonsigre.com/threat-brief-{threat_actor_name.lower().replace(' ', '-')}-{campaign_name.lower().replace(' ', '-')}.pdf"
            },
            {
                "title": f"IOC Report: {campaign_name} Infrastructure and TTPs",
                "url": f"https://simonsigre.com/ioc-report-{campaign_name.lower().replace(' ', '-')}.pdf"
            },
            {
                "title": f"Attribution Analysis: {threat_actor_name} Operational Security Assessment",
                "url": f"https://simonsigre.com/attribution-{threat_actor_name.lower().replace(' ', '-')}.pdf"
            },
            {
                "title": f"Threat Actor Profile: {threat_actor_name} Capabilities and Targeting",
                "url": f"https://simonsigre.com/profile-{threat_actor_name.lower().replace(' ', '-')}.pdf"
            },
            {
                "title": f"Campaign Intelligence: {campaign_name} Technical Indicators and Mitigation",
                "url": f"https://simonsigre.com/campaign-intel-{campaign_name.lower().replace(' ', '-')}.pdf"
            }
        ]
        
        selected_report = random.choice(report_data)
        
        return {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": timestamp,
            "modified": timestamp,
            "name": selected_report["title"],
            "description": STIXGenerator.add_disclaimer(f"Comprehensive threat intelligence report analysing {threat_actor_name} activities and associated {campaign_name} infrastructure indicators. Full report available at: {selected_report['url']}"),
            "published": timestamp,
            "labels": ["threat-report"],
            "external_references": [
                {
                    "source_name": "simonsigre",
                    "description": "Threat Intelligence Publication",
                    "url": selected_report["url"]
                }
            ],
            "object_refs": []  # Will be populated with related object references
        }

    @staticmethod
    def generate_related_indicators_bundle(count=30):
        """Generate a bundle with related indicators showing threat intelligence relationships"""
        objects = []
        
        # Generate core objects first
        campaign = STIXGenerator.generate_campaign_object()
        threat_actor = STIXGenerator.generate_threat_actor()
        malware = STIXGenerator.generate_malware_object()
        attack_pattern = STIXGenerator.generate_attack_pattern()
        
        # Generate CVE vulnerability object (new)
        vulnerability = STIXGenerator.generate_vulnerability_object()
        
        # Generate intelligence publications
        note = STIXGenerator.generate_note_object(threat_actor["name"])
        report = STIXGenerator.generate_report_object(threat_actor["name"], campaign["name"])
        
        objects.extend([campaign, threat_actor, malware, attack_pattern, vulnerability, note, report])
        
        # Generate indicators
        indicators = []
        for _ in range(count):
            indicator_type = random.choice(['ip', 'domain', 'hash'])
            if indicator_type == 'ip':
                indicator = STIXGenerator.generate_ip_indicator()
            elif indicator_type == 'domain':
                indicator = STIXGenerator.generate_domain_indicator()
            else:
                indicator = STIXGenerator.generate_file_hash_indicator()
            indicators.append(indicator)
        
        objects.extend(indicators)
        
        # Create relationships between objects
        relationships = []
        
        # Campaign relationships
        relationships.append(STIXGenerator.generate_relationship(
            threat_actor["id"], campaign["id"], "attributed-to",
            "Threat actor attributed to this campaign based on TTPs and infrastructure overlap"
        ))
        
        relationships.append(STIXGenerator.generate_relationship(
            campaign["id"], malware["id"], "uses",
            "Campaign deploys this malware family as primary payload"
        ))
        
        relationships.append(STIXGenerator.generate_relationship(
            threat_actor["id"], attack_pattern["id"], "uses",
            "Threat actor commonly employs this attack technique"
        ))
        
        # CVE vulnerability relationships
        relationships.append(STIXGenerator.generate_relationship(
            campaign["id"], vulnerability["id"], "targets",
            "Campaign exploits this vulnerability for initial access"
        ))
        
        relationships.append(STIXGenerator.generate_relationship(
            threat_actor["id"], vulnerability["id"], "uses",
            "Threat actor known to exploit this vulnerability in their operations"
        ))
        
        relationships.append(STIXGenerator.generate_relationship(
            malware["id"], vulnerability["id"], "targets",
            "Malware specifically designed to exploit this vulnerability"
        ))
        
        # Indicator relationships - ensure all indicators are linked to threat actor and campaign
        for i, indicator in enumerate(indicators):
            # Link ALL indicators to campaign (primary attribution)
            relationships.append(STIXGenerator.generate_relationship(
                indicator["id"], campaign["id"], "indicates",
                "IOC observed in campaign infrastructure and activities"
            ))
            
            # Link ALL indicators to threat actor (attribution)
            relationships.append(STIXGenerator.generate_relationship(
                indicator["id"], threat_actor["id"], "attributed-to",
                "IOC attributed to this threat actor based on infrastructure analysis"
            ))
            
            # Link subset of indicators to malware
            if i % 3 == 0:  # Every 3rd indicator
                relationships.append(STIXGenerator.generate_relationship(
                    indicator["id"], malware["id"], "indicates",
                    "IOC associated with malware infrastructure or payload"
                ))
            
            # Create indicator-to-indicator relationships (infrastructure clusters)
            if i > 0 and i % 5 == 0:  # Create clusters of 5 related indicators
                for j in range(max(0, i-4), i):
                    if indicators[j]["pattern"].split("'")[1].split("'")[0] != indicator["pattern"].split("'")[1].split("'")[0]:
                        relationships.append(STIXGenerator.generate_relationship(
                            indicator["id"], indicators[j]["id"], "related-to",
                            "IOCs observed in same threat infrastructure or campaign"
                        ))
        
        # Add co-occurrence relationships for IP/Domain pairs
        ip_indicators = [ind for ind in indicators if "ipv4-addr" in ind["pattern"]]
        domain_indicators = [ind for ind in indicators if "domain-name" in ind["pattern"]]
        
        for ip_ind in ip_indicators[:5]:  # Limit to avoid too many relationships
            for domain_ind in domain_indicators[:3]:
                relationships.append(STIXGenerator.generate_relationship(
                    ip_ind["id"], domain_ind["id"], "resolves-to",
                    "Domain resolves to this IP address in DNS records"
                ))
        
        # Add publication relationships
        # Link note to threat actor
        note["object_refs"] = [threat_actor["id"]]
        relationships.append(STIXGenerator.generate_relationship(
            note["id"], threat_actor["id"], "related-to",
            "Intelligence note providing analysis of threat actor capabilities and activities"
        ))
        
        # Link report to threat actor, campaign, and vulnerability
        report["object_refs"] = [threat_actor["id"], campaign["id"], vulnerability["id"]] + [ind["id"] for ind in indicators[:5]]
        relationships.append(STIXGenerator.generate_relationship(
            report["id"], threat_actor["id"], "related-to",
            "Threat intelligence report documenting threat actor operations and indicators"
        ))
        relationships.append(STIXGenerator.generate_relationship(
            report["id"], campaign["id"], "related-to",
            "Intelligence publication analysing campaign infrastructure and tactics"
        ))
        
        objects.extend(relationships)
        
        return objects
    
    @staticmethod
    def create_stix_bundle(objects):
        """Create a STIX bundle containing the objects"""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects
        }
