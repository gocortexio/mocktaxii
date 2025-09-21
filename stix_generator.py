import json
import uuid
from datetime import datetime, timezone
import random

class STIXGenerator:
    """Generate mock STIX 2.x threat intelligence indicators"""
    
    # All threat indicators (IPs, domains, hashes, malware families) now stored in database tables
    
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
        """Generate a STIX malware object using database"""
        from models import MalwareFamily
        
        # Get a random malware family from database
        malware_obj = MalwareFamily.get_random_active()
        if not malware_obj:
            # Fallback if no malware families in database (shouldn't happen due to seeding)
            name = "Unknown Malware"
            description = "Unknown malware family"
            malware_types = ["trojan"]
            platforms = ["windows"]
            capabilities = []
            external_refs = []
            score = "medium"
        else:
            name = malware_obj.name
            description = malware_obj.description or f"{name} is a known malware family used in various attack campaigns"
            malware_types = malware_obj.malware_types or ["trojan"]
            platforms = malware_obj.platforms or ["windows"]
            capabilities = malware_obj.capabilities or []
            external_refs = malware_obj.external_references or []
            score = STIXGenerator.convert_score_to_text(malware_obj.confidence_score)
        
        malware_stix = {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "name": name,
            "description": STIXGenerator.add_disclaimer(description),
            "malware_types": malware_types,
            "is_family": True,
            "labels": ["malicious-activity"],
            "score": score,
            "x_platforms": platforms,
            "x_capabilities": capabilities
        }
        
        # Add external references if available
        if external_refs:
            malware_stix["external_references"] = external_refs
        
        # Add MITRE ATT&CK reference if available
        if malware_obj and malware_obj.mitre_id:
            if "external_references" not in malware_stix:
                malware_stix["external_references"] = []
            malware_stix["external_references"].append({
                "source_name": "mitre-attack",
                "external_id": malware_obj.mitre_id,
                "url": f"https://attack.mitre.org/software/{malware_obj.mitre_id}"
            })
        
        return malware_stix
    
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
        """Generate a STIX campaign object using database-driven campaigns"""
        from models import Campaign
        
        campaign_id = f"campaign--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Get random campaign from database (100 diverse campaigns)
        campaign = Campaign.get_random_active()
        
        if campaign:
            campaign_name = campaign.name
            campaign_description = campaign.description
            
            # Enhanced STIX campaign with comprehensive metadata
            stix_campaign = {
                "type": "campaign",
                "spec_version": "2.1",
                "id": campaign_id,
                "created": timestamp,
                "modified": timestamp,
                "name": campaign_name,
                "description": STIXGenerator.add_disclaimer(campaign_description),
                "first_seen": timestamp,
                "last_seen": timestamp,
                "labels": [campaign.campaign_type, campaign.sophistication_level],
            }
            
            # Add campaign-specific properties with British English terminology
            if campaign.target_sectors:
                stix_campaign["x_target_sectors"] = campaign.target_sectors
            if campaign.target_regions:
                stix_campaign["x_target_regions"] = campaign.target_regions
            if campaign.motivation:
                stix_campaign["x_motivation"] = campaign.motivation
            if campaign.duration_category:
                stix_campaign["x_duration_category"] = campaign.duration_category
                
            return stix_campaign
        else:
            # Fallback if no campaigns in database
            return {
                "type": "campaign",
                "spec_version": "2.1",
                "id": campaign_id,
                "created": timestamp,
                "modified": timestamp,
                "name": "Operation Digital Phantom",
                "description": STIXGenerator.add_disclaimer("Sophisticated cyber campaign targeting enterprise infrastructure with advanced persistent threats"),
                "first_seen": timestamp,
                "last_seen": timestamp
            }
    
    @staticmethod
    def generate_attack_pattern():
        """Generate a STIX attack pattern object"""
        attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Get a random MITRE technique from database
        from models import MitreTechnique
        technique_obj = MitreTechnique.get_random_active()
        if not technique_obj:
            # Fallback if no techniques in database (shouldn't happen due to seeding)
            name = "Unknown Technique"
            mitre_id = "T0000"
            description = "Unknown MITRE ATT&CK technique"
            tactics = ["unknown"]
            platforms = ["windows"]
            external_refs = []
        else:
            name = technique_obj.name
            mitre_id = technique_obj.mitre_id
            description = technique_obj.description or f"MITRE ATT&CK technique {mitre_id}"
            tactics = technique_obj.tactics or ["unknown"]
            platforms = technique_obj.platforms or ["windows"]
            external_refs = technique_obj.external_references or []
        
        # Build enhanced STIX attack pattern object
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_pattern_id,
            "created": timestamp,
            "modified": timestamp,
            "name": name,
            "description": STIXGenerator.add_disclaimer(description),
            "external_references": external_refs if external_refs else [
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre_id,
                    "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}"
                }
            ]
        }
        
        # Add enhanced metadata if available from database
        if technique_obj:
            if technique_obj.tactics:
                attack_pattern["kill_chain_phases"] = [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": tactic
                    } for tactic in technique_obj.tactics
                ]
            
            if technique_obj.platforms:
                attack_pattern["x_mitre_platforms"] = technique_obj.platforms
            
            if technique_obj.data_sources:
                attack_pattern["x_mitre_data_sources"] = technique_obj.data_sources
            
            if technique_obj.detection_methods:
                attack_pattern["x_mitre_detection"] = technique_obj.detection_methods
            
            if technique_obj.mitigation_techniques:
                attack_pattern["x_mitre_defense_bypassed"] = technique_obj.mitigation_techniques
        
        return attack_pattern
    
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
        """Generate a STIX report object using database-driven report templates"""
        from models import ReportTemplate
        
        report_id = f"report--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Get random report template from database (50 diverse templates)
        template = ReportTemplate.get_random_active()
        
        if template:
            # Create slug versions for URL generation
            threat_actor_slug = threat_actor_name.lower().replace(' ', '-')
            campaign_slug = campaign_name.lower().replace(' ', '-')
            
            # Generate title and description using template placeholders
            report_title = template.title_format.format(
                threat_actor_name=threat_actor_name,
                campaign_name=campaign_name,
                threat_actor_slug=threat_actor_slug,
                campaign_slug=campaign_slug
            )
            
            report_description = template.description_format.format(
                threat_actor_name=threat_actor_name,
                campaign_name=campaign_name,
                threat_actor_slug=threat_actor_slug,
                campaign_slug=campaign_slug
            )
            
            # Generate URL using template pattern
            report_url = template.url_pattern.format(
                threat_actor_name=threat_actor_name,
                campaign_name=campaign_name,
                threat_actor_slug=threat_actor_slug,
                campaign_slug=campaign_slug
            ) if template.url_pattern else f"https://simonsigre.com/report-{campaign_slug}.pdf"
            
            # Enhanced report labels based on template metadata
            report_labels = ["threat-report", template.report_type, template.report_category]
            
            stix_report = {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": timestamp,
                "modified": timestamp,
                "name": report_title,
                "description": STIXGenerator.add_disclaimer(f"{report_description} Full report available at: {report_url}"),
                "published": timestamp,
                "labels": report_labels,
                "x_report_category": template.report_category,
                "x_target_audience": template.target_audience,
                "external_references": [
                    {
                        "source_name": "simonsigre",
                        "description": "Threat Intelligence Publication",
                        "url": report_url
                    }
                ],
                "object_refs": []  # Will be populated with related object references
            }
            
            return stix_report
        else:
            # Fallback if no templates in database
            return {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": timestamp,
                "modified": timestamp,
                "name": f"Threat Intelligence Brief: {threat_actor_name} Campaign Analysis",
                "description": STIXGenerator.add_disclaimer(f"Comprehensive threat intelligence report analysing {threat_actor_name} activities and associated {campaign_name} infrastructure indicators."),
                "published": timestamp,
                "labels": ["threat-report"],
                "external_references": [
                    {
                        "source_name": "simonsigre",
                        "description": "Threat Intelligence Publication",
                        "url": f"https://simonsigre.com/threat-brief-{threat_actor_name.lower().replace(' ', '-')}-{campaign_name.lower().replace(' ', '-')}.pdf"
                    }
                ],
                "object_refs": []
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
