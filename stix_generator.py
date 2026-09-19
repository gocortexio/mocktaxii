# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import uuid
from datetime import datetime, timezone
import random

class STIXGenerator:
    """Generate mock STIX 2.x threat intelligence indicators"""
    
    # All threat indicators (IPs, domains, hashes, malware families) now stored in database tables
    
    @staticmethod
    def generate_timestamp():
        """Generate a current timestamp in STIX format.

        timespec='milliseconds' guarantees a fractional part. Plain isoformat()
        omits it entirely when microsecond happens to be 0, emitting a timestamp
        with a different shape roughly one time in a million.
        """
        return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
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
    def generate_ip_indicator(db_ip=None):
        """Generate a STIX IP address indicator using database.
        
        `db_ip` may be supplied by a caller that has already batch-fetched rows,
        so a bundle costs one query per type rather than one per indicator.
        """
        from models import MaliciousIP
        
        if db_ip is None:
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
        timestamp = STIXGenerator.generate_timestamp()
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "x_score": score,
            "valid_from": timestamp,
            "description": STIXGenerator.add_disclaimer(description)
        }
    
    @staticmethod
    def generate_domain_indicator(domain_obj=None):
        """Generate a STIX domain indicator using database."""
        from models import MaliciousDomain
        
        if domain_obj is None:
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
            
        timestamp = STIXGenerator.generate_timestamp()
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "x_score": score,
            "valid_from": timestamp,
            "description": STIXGenerator.add_disclaimer(description)
        }
    
    @staticmethod
    def generate_file_hash_indicator(hash_obj=None):
        """Generate a STIX file hash indicator using database."""
        from models import MaliciousHash
        
        if hash_obj is None:
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
            
        timestamp = STIXGenerator.generate_timestamp()
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "pattern": f"[file:hashes.'SHA-256' = '{hash_value}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "x_score": score,
            "valid_from": timestamp,
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
        
        timestamp = STIXGenerator.generate_timestamp()
        vulnerability_obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
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
        
        timestamp = STIXGenerator.generate_timestamp()
        malware_stix = {
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
            "name": name,
            "description": STIXGenerator.add_disclaimer(description),
            "malware_types": malware_types,
            "is_family": True,
            "labels": ["malicious-activity"],
            # `score` is not a STIX Malware property.  Vendor extensions must
            # use the x_ namespace so strict consumers do not discard/reject
            # the object.
            "x_score": score,
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
            resource_level = "organization"
            primary_motivation = "financial-gain"
        else:
            actor_name = db_actor.name
            description = db_actor.description or f"{actor_name} is a threat actor group known for targeted attacks"
            threat_actor_types = db_actor.threat_actor_types
            sophistication = db_actor.sophistication
            resource_level = db_actor.resource_level
            primary_motivation = db_actor.primary_motivation
        
        timestamp = STIXGenerator.generate_timestamp()
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": timestamp,
            "modified": timestamp,
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
            
            # Enhanced STIX campaign with extended metadata
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
        """Generate a STIX note object using database-driven note templates"""
        from models import NoteTemplate
        
        note_id = f"note--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        # Get random note template from database (25 diverse templates)
        template = NoteTemplate.get_random_active()
        
        # Create slug version for URL generation
        threat_actor_slug = threat_actor_name.lower().replace(' ', '-')
        
        if template:
            # Generate content using template placeholders
            note_content = template.content_format.format(
                threat_actor_name=threat_actor_name,
                threat_actor_slug=threat_actor_slug
            )
        else:
            # Fallback if no templates in database
            note_content = f"Intelligence report on {threat_actor_name} activities observed targeting organisations with sophisticated campaigns. Full analysis available at: https://simonsigre.com/threat-actor-analysis-{threat_actor_slug}.pdf"
        
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
                "description": STIXGenerator.add_disclaimer(f"Threat intelligence report analysing {threat_actor_name} activities and associated {campaign_name} infrastructure indicators."),
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
        """
        Generate a bundle with related indicators showing threat intelligence relationships.
        
        The count parameter represents the total object budget. Indicators are prioritised
        over narrative objects (campaigns, reports, etc.) to ensure meaningful threat data.
        
        Weighted distribution for indicator types:
        - 60% IP addresses (largest seeded inventory)
        - 15% domains
        - 10% file hashes
        - 10% software packages
        - 5% reserved for narrative/context objects
        """
        import logging
        logger = logging.getLogger(__name__)
        
        objects = []
        indicators = []

        # `count` is a hard ceiling on the total object count, as TAXII 2.1
        # requires - it was previously only a budget for indicators, so a
        # limit=100 request returned around 423 objects.
        #
        # All seven narrative objects are included whenever there is room. The
        # previous prefix slice capped them at 5, which silently dropped `note`
        # and `report` from every response in v1.0.9 (they sit at indices 5
        # and 6, needing a count of 120/140 against a limit hard-capped at 100).
        NARRATIVE_TOTAL = 7
        # Always leave at least one slot for an indicator, whatever the count -
        # a bundle of pure narrative would be useless to a TIM feed.
        narrative_count = (
            NARRATIVE_TOTAL if count >= 12
            else max(0, min(NARRATIVE_TOTAL, count - 1))
        )
        # Keep a few slots back so the graph still carries relationships.
        relationship_reserve = min(10, max(0, count - narrative_count - 1))
        object_ceiling = max(1, count - narrative_count - relationship_reserve)

        logger.debug(
            f"Bundle generation: total={count}, object_ceiling={object_ceiling}, "
            f"narrative={narrative_count}, relationship_reserve={relationship_reserve}"
        )
        
        # Weighted indicator type selection based on seeded inventory ratios
        # IPs: 5000+, Domains: 103, Hashes: 39, Software: 50
        indicator_weights = {
            'ip': 60,
            'domain': 15,
            'hash': 10,
            'software': 10
        }
        indicator_types = list(indicator_weights.keys())
        weights = list(indicator_weights.values())
        
        # Track indicator counts for logging
        indicator_counts = {'ip': 0, 'domain': 0, 'hash': 0, 'software': 0}
        
        # Draw the type mix first, then fetch each type in ONE query.
        #
        # This loop used to call a generator per iteration, and each of those
        # issued its own lookup: ORDER BY random() for IPs and software (a full
        # scan and sort every time), and a whole-table .all() into Python for
        # domains and hashes. A limit=100 request cost ~95 such queries. It now
        # costs at most four.
        from models import MaliciousIP, MaliciousDomain, MaliciousHash, MaliciousSoftware

        # A software bundle contributes several objects at once, so budget it in
        # whole slots and leave a margin against the ceiling.
        SOFTWARE_SLOTS = 4
        remaining_slots = object_ceiling
        while remaining_slots > 0:
            choice = random.choices(indicator_types, weights=weights, k=1)[0]
            if choice == 'software' and remaining_slots < SOFTWARE_SLOTS:
                choice = 'ip'
            indicator_counts[choice] += 1
            remaining_slots -= SOFTWARE_SLOTS if choice == 'software' else 1

        logger.debug(f"Indicator distribution: {indicator_counts}")

        ip_rows = MaliciousIP.get_random_batch(indicator_counts['ip'])
        domain_rows = MaliciousDomain.get_random_batch(indicator_counts['domain'])
        hash_rows = MaliciousHash.get_random_batch(indicator_counts['hash'])
        software_rows = MaliciousSoftware.get_random_batch(indicator_counts['software'])

        def _row(rows, index):
            """Cycle if the table holds fewer rows than requested."""
            return rows[index % len(rows)] if rows else None

        for i in range(indicator_counts['ip']):
            indicators.append(STIXGenerator.generate_ip_indicator(_row(ip_rows, i)))
        for i in range(indicator_counts['domain']):
            indicators.append(STIXGenerator.generate_domain_indicator(_row(domain_rows, i)))
        for i in range(indicator_counts['hash']):
            indicators.append(STIXGenerator.generate_file_hash_indicator(_row(hash_rows, i)))
        for i in range(indicator_counts['software']):
            row = _row(software_rows, i)
            if row is None:
                # Nothing seeded for software; spend the slot on an IP instead.
                indicators.append(STIXGenerator.generate_ip_indicator())
                continue
            software_objects = STIXGenerator.generate_software_bundle(row)
            software_indicator = next(
                (obj for obj in software_objects if obj.get("type") == "indicator"), None
            )
            # Only the non-indicator parts go into `objects`. Adding the whole
            # bundle here and then appending the indicator to `indicators`
            # emitted it twice, since `indicators` is extended into `objects`
            # below - duplicate ids in one bundle are invalid STIX.
            objects.extend(
                obj for obj in software_objects if obj is not software_indicator
            )
            if software_indicator:
                indicators.append(software_indicator)

        
        # Generate narrative context objects (after indicators)
        campaign = STIXGenerator.generate_campaign_object()
        threat_actor = STIXGenerator.generate_threat_actor()
        malware = STIXGenerator.generate_malware_object()
        attack_pattern = STIXGenerator.generate_attack_pattern()
        vulnerability = STIXGenerator.generate_vulnerability_object()
        note = STIXGenerator.generate_note_object(threat_actor["name"])
        report = STIXGenerator.generate_report_object(threat_actor["name"], campaign["name"])
        
        # Add narrative objects - always include campaign and threat_actor as core context
        # Order: campaign, threat_actor, malware, attack_pattern, vulnerability, note, report
        narrative_objects = [campaign, threat_actor, malware, attack_pattern, vulnerability, note, report]
        included_narratives = narrative_objects[:narrative_count]  # campaign + threat_actor at minimum
        objects.extend(included_narratives)
        included_ids = {obj["id"] for obj in included_narratives}
        
        objects.extend(indicators)
        
        # Create relationships between objects (only for objects in the bundle)
        relationships = []
        
        # Core relationships (campaign and threat_actor always included)
        relationships.append(STIXGenerator.generate_relationship(
            threat_actor["id"], campaign["id"], "attributed-to",
            "Threat actor attributed to this campaign based on TTPs and infrastructure overlap"
        ))
        
        # Conditional relationships based on included objects
        if malware["id"] in included_ids:
            relationships.append(STIXGenerator.generate_relationship(
                campaign["id"], malware["id"], "uses",
                "Campaign deploys this malware family as primary payload"
            ))
        
        if attack_pattern["id"] in included_ids:
            relationships.append(STIXGenerator.generate_relationship(
                threat_actor["id"], attack_pattern["id"], "uses",
                "Threat actor commonly employs this attack technique"
            ))
        
        if vulnerability["id"] in included_ids:
            relationships.append(STIXGenerator.generate_relationship(
                campaign["id"], vulnerability["id"], "targets",
                "Campaign exploits this vulnerability for initial access"
            ))
            relationships.append(STIXGenerator.generate_relationship(
                threat_actor["id"], vulnerability["id"], "uses",
                "Threat actor known to exploit this vulnerability in their operations"
            ))
            if malware["id"] in included_ids:
                relationships.append(STIXGenerator.generate_relationship(
                    malware["id"], vulnerability["id"], "targets",
                    "Malware specifically designed to exploit this vulnerability"
                ))
        
        # Indicator relationships - link to campaign and threat_actor (always included)
        for i, indicator in enumerate(indicators):
            relationships.append(STIXGenerator.generate_relationship(
                indicator["id"], campaign["id"], "indicates",
                "IOC observed in campaign infrastructure and activities"
            ))
            
            relationships.append(STIXGenerator.generate_relationship(
                indicator["id"], threat_actor["id"], "attributed-to",
                "IOC attributed to this threat actor based on infrastructure analysis"
            ))
            
            # Link subset to malware if included
            if malware["id"] in included_ids and i % 3 == 0:
                relationships.append(STIXGenerator.generate_relationship(
                    indicator["id"], malware["id"], "indicates",
                    "IOC associated with malware infrastructure or payload"
                ))
            
            # Create indicator-to-indicator relationships (infrastructure clusters)
            if i > 0 and i % 5 == 0:
                for j in range(max(0, i-4), i):
                    try:
                        if indicators[j]["pattern"].split("'")[1] != indicator["pattern"].split("'")[1]:
                            relationships.append(STIXGenerator.generate_relationship(
                                indicator["id"], indicators[j]["id"], "related-to",
                                "IOCs observed in same threat infrastructure or campaign"
                            ))
                    except (IndexError, KeyError):
                        pass  # Skip if pattern parsing fails
        
        # Add co-occurrence relationships for IP/Domain pairs
        ip_indicators = [ind for ind in indicators if "ipv4-addr" in ind.get("pattern", "")]
        domain_indicators = [ind for ind in indicators if "domain-name" in ind.get("pattern", "")]
        
        for ip_ind in ip_indicators[:5]:
            for domain_ind in domain_indicators[:3]:
                relationships.append(STIXGenerator.generate_relationship(
                    ip_ind["id"], domain_ind["id"], "resolves-to",
                    "Domain resolves to this IP address in DNS records"
                ))
        
        # Publication relationships (only if included)
        if note["id"] in included_ids:
            note["object_refs"] = [threat_actor["id"]]
            relationships.append(STIXGenerator.generate_relationship(
                note["id"], threat_actor["id"], "related-to",
                "Intelligence note providing analysis of threat actor capabilities and activities"
            ))
        
        if report["id"] in included_ids:
            report_refs = [threat_actor["id"], campaign["id"]]
            if vulnerability["id"] in included_ids:
                report_refs.append(vulnerability["id"])
            report_refs.extend([ind["id"] for ind in indicators[:5]])
            report["object_refs"] = report_refs
            relationships.append(STIXGenerator.generate_relationship(
                report["id"], threat_actor["id"], "related-to",
                "Threat intelligence report documenting threat actor operations and indicators"
            ))
            relationships.append(STIXGenerator.generate_relationship(
                report["id"], campaign["id"], "related-to",
                "Intelligence publication analysing campaign infrastructure and tactics"
            ))

        # Trim relationships, not objects, to land inside the ceiling. Dropping
        # an SRO can never orphan a reference (both its endpoints stay in the
        # bundle), whereas dropping an SDO would leave dangling source_ref /
        # target_ref values that break OpenCTI and TIM ingestion.
        # Some ids are deterministic by design (campaign SDOs derive theirs
        # with uuid5 from the row id, so a re-polling client sees a stable
        # identity), which means two software packages in the same campaign
        # each emit that campaign SDO. Deduplicate before trimming.
        objects = STIXGenerator.dedupe_by_id(objects)
        present = {obj["id"] for obj in objects}
        relationships = [
            rel for rel in STIXGenerator.dedupe_by_id(relationships)
            if rel["id"] not in present
        ]

        remaining = max(0, count - len(objects))
        if len(relationships) > remaining:
            logger.debug(
                f"Trimming relationships {len(relationships)} -> {remaining} to honour limit={count}"
            )
        objects.extend(relationships[:remaining])

        return objects
    
    @staticmethod
    def generate_software_indicator(software_obj):
        """
        Generate a STIX Indicator for malicious software.
        
        Uses PURL format in pattern: [software:name = 'pkg:pypi/package@version']
        Labels: supply-chain, pypi, malicious-package for proper classification.
        """
        indicator_id = f"indicator--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        score = STIXGenerator.convert_score_to_text(software_obj.confidence_score)
        
        # Pattern uses PURL format for precise package identification
        purl = f"pkg:pypi/{software_obj.package_name}@{software_obj.version}"
        pattern = f"[software:name = '{purl}']"
        
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": timestamp,
            "modified": timestamp,
            "name": f"Malicious PyPI Package: {software_obj.package_name}",
            "description": STIXGenerator.add_disclaimer(software_obj.description),
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "labels": ["supply-chain", "pypi", "malicious-package"],
            "indicator_types": ["malicious-activity"],
            "x_verdict": "malicious",
            "x_score": score,
            "valid_from": timestamp,
            "external_references": [
                {
                    "source_name": "purl",
                    "external_id": purl,
                    "url": f"https://pypi.org/project/{software_obj.package_name}/{software_obj.version}/",
                    "description": f"Package URL (PURL) identifier for {software_obj.package_name}"
                },
                {
                    "source_name": "pypi",
                    "external_id": software_obj.package_name,
                    "url": software_obj.download_url,
                    "description": f"Malicious PyPI package {software_obj.package_name} v{software_obj.version}"
                }
            ]
        }
        
        return indicator
    
    @staticmethod
    def dedupe_by_id(objects):
        """Keep the first occurrence of each STIX id, preserving order.

        Some ids are deterministic by design so a client re-polling sees a
        stable identity - campaign SDOs derive theirs with uuid5 from the
        campaign row id. That means two software packages belonging to the same
        campaign each emit a campaign SDO with the *same* id, and duplicate ids
        in one bundle are invalid STIX. Deduplicating here keeps the stable-id
        property while making the bundle well-formed.
        """
        seen = set()
        unique = []
        for obj in objects:
            obj_id = obj.get("id")
            if obj_id in seen:
                continue
            seen.add(obj_id)
            unique.append(obj)
        return unique

    @staticmethod
    def generate_software_bundle(software_obj=None):
        """
        Generate a software supply chain threat bundle.
        
        Emits:
        - Software SDO (the entity representing the malicious package)
        - Indicator SDO (pattern to detect the software)
        - Relationship: indicator indicates software
        - Campaign relationships if software is linked to a campaign
        """
        from app import db
        from models import MaliciousSoftware, Campaign
        
        if software_obj is None:
            software_obj = MaliciousSoftware.get_random_active()
        if not software_obj:
            return []
        
        # Generate Software SDO directly from the same software_obj
        software_id = f"software--{uuid.uuid4()}"
        timestamp = STIXGenerator.generate_timestamp()
        
        software_sdo = {
            "type": "software",
            "spec_version": "2.1",
            "id": software_id,
            "created": timestamp,
            "modified": timestamp,
            "name": software_obj.package_name,
            "version": software_obj.version,
            "x_vendor": software_obj.vendor,
            "x_malware_type": software_obj.malware_type,
            "x_is_typosquat": software_obj.is_typosquat,
            "x_confidence_score": software_obj.confidence_score,
            "x_download_url": software_obj.download_url
        }
        # STIX Software.cpe is a single CPE string, not an array.  A missing
        # CPE is also different from a CPE value of null, so omit the
        # property entirely when the repository has no CPE for this package.
        if software_obj.cpe:
            software_sdo["cpe"] = software_obj.cpe
        
        # Generate Indicator SDO (the detection pattern)
        indicator = STIXGenerator.generate_software_indicator(software_obj)
        
        objects = [software_sdo, indicator]
        relationships = []
        
        # Core relationship: indicator indicates software (STIX 2.1 compliant)
        relationships.append(STIXGenerator.generate_relationship(
            indicator["id"], software_sdo["id"], "indicates",
            f"Indicator pattern detects malicious software package {software_obj.package_name}"
        ))
        
        if software_obj.campaign_id:
            campaign = db.session.get(Campaign, software_obj.campaign_id)
            if campaign:
                campaign_id = f"campaign--{uuid.uuid5(uuid.NAMESPACE_DNS, f'mocktaxii-campaign-{campaign.id}')}"
                timestamp = STIXGenerator.generate_timestamp()
                
                campaign_sdo = {
                    "type": "campaign",
                    "spec_version": "2.1",
                    "id": campaign_id,
                    "created": timestamp,
                    "modified": timestamp,
                    "name": campaign.name,
                    "description": STIXGenerator.add_disclaimer(campaign.description),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "labels": [campaign.campaign_type, campaign.sophistication_level]
                }
                
                if campaign.target_sectors:
                    campaign_sdo["x_target_sectors"] = campaign.target_sectors
                if campaign.target_regions:
                    campaign_sdo["x_target_regions"] = campaign.target_regions
                if campaign.motivation:
                    campaign_sdo["x_motivation"] = campaign.motivation
                
                objects.append(campaign_sdo)
                
                # Campaign uses the malicious software
                relationships.append(STIXGenerator.generate_relationship(
                    campaign_id, software_sdo["id"], "uses",
                    f"Campaign {campaign.name} uses malicious package {software_obj.package_name}"
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
