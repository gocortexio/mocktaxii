from app import db
from datetime import datetime, timezone
import uuid

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    
    def __repr__(self):
        return f'<ApiKey {self.name}>'

class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key_id = db.Column(db.Integer, db.ForeignKey('api_key.id'), nullable=True)
    endpoint = db.Column(db.String(200), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    indicators_served = db.Column(db.Integer, default=0)
    
    api_key = db.relationship('ApiKey', backref=db.backref('requests', lazy=True))
    
    def __repr__(self):
        return f'<RequestLog {self.endpoint}>'

class ServerStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_indicators_served = db.Column(db.Integer, nullable=False, default=0)
    total_requests = db.Column(db.Integer, nullable=False, default=0)
    last_updated = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def get_stats(cls):
        stats = cls.query.first()
        if not stats:
            stats = cls()
            db.session.add(stats)
            db.session.commit()
        return stats
    
    def increment_indicators(self, count):
        self.total_indicators_served += count
        self.total_requests += 1
        self.last_updated = datetime.now(timezone.utc)
        db.session.commit()

class ThreatActor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    threat_actor_types = db.Column(db.JSON, default=lambda: ["criminal-enterprise"])
    sophistication = db.Column(db.String(50), default="intermediate")
    resource_level = db.Column(db.String(50), default="organisation")
    primary_motivation = db.Column(db.String(50), default="financial-gain")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ThreatActor {self.name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active threat actor"""
        actors = cls.query.filter_by(is_active=True).all()
        if actors:
            import random
            return random.choice(actors)
        return None
    
    @classmethod
    def seed_default_actors(cls):
        """Seed the database with default threat actors if none exist"""
        if cls.query.count() == 0:
            default_actors = [
                "Academic Serpens", "Agent Serpens", "Agonizing Serpens", "Alloy Taurus",
                "Ambitious Scorpius", "Bashful Scorpius", "Bitter Scorpius", "Blustering Scorpius",
                "Boggy Serpens", "Charging Taurus", "Chubby Scorpius", "Cloaked Ursa",
                "Dapper Scorpius", "Dark Scorpius", "Devious Serpens", "Dicing Taurus",
                "Digging Taurus", "Evasive Serpens", "Fiddling Scorpius", "Fighting Ursa",
                "Howling Scorpius", "Ignoble Scorpius", "Insidious Taurus", "Invisible Scorpius",
                "Jumper Taurus", "Jumpy Pisces", "Mocking Draco", "Muddled Libra",
                "Mushy Scorpius", "Mythic Ursa", "Opaque Draco", "Pensive Ursa",
                "Pilfering Scorpius", "Playful Taurus", "Powerful Scorpius", "Procedural Scorpius",
                "Protesting Scorpius", "Razing Ursa", "Salty Scorpius", "Sentinel Taurus",
                "Shifty Scorpius", "Slow Pisces", "Spicy Scorpius", "Spikey Scorpius",
                "Spoiled Scorpius", "Squalid Scorpius", "Squeaking Scorpius", "Stale Scorpius",
                "Stately Taurus", "Stumped Scorpius", "Transforming Scorpius", "Trident Ursa",
                "Twinkling Scorpius", "Weary Scorpius", "White Lynx"
            ]
            
            for actor_name in default_actors:
                actor = cls(
                    name=actor_name,
                    description=f"{actor_name} is a threat actor group known for targeted attacks"
                )
                db.session.add(actor)
            
            db.session.commit()


class MaliciousIP(db.Model):
    """Database model for malicious IP addresses"""
    __tablename__ = 'malicious_ips'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True, index=True)  # Support IPv4 and IPv6
    description = db.Column(db.Text)
    threat_types = db.Column(db.JSON, default=lambda: ["malicious-activity"])
    confidence_score = db.Column(db.Integer, default=75, index=True)  # 0-100 confidence score
    source = db.Column(db.String(255), default="MockTAXII")
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)  # Index for performance
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MaliciousIP {self.ip_address}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active malicious IP using database-level randomization for performance"""
        # Use database-level random selection to avoid loading all records into memory
        # This is critical for performance with 260k+ records
        from sqlalchemy import func
        return cls.query.filter_by(is_active=True).order_by(func.random()).first()
    
    @classmethod
    def seed_default_ips(cls):
        """Seed the database with default malicious IPs if none exist"""
        if cls.query.count() == 0:
            # Use subnet-based generation instead of hardcoded list
            print("No IPs found. Using subnet-based generation...")
            cls.seed_from_subnets(target_count=50000)
    
    @classmethod
    def seed_from_subnets(cls, target_count=50000):
        """Generate large number of IP addresses from threat subnets"""
        current_count = cls.query.count()
        if current_count < target_count:  # Only generate if we don't have enough IPs
            print(f"Generating {target_count:,} IP addresses from threat subnets...")
            
            # First ensure we have subnet data
            from models import ThreatSubnet
            ThreatSubnet.seed_spamhaus_subnets()
            
            # Clear old hardcoded IPs
            cls.query.delete()
            
            import ipaddress
            import random
            
            # 100+ diverse threat intelligence description templates
            description_templates = [
                # C2 Infrastructure (25 variants)
                "Command and control server {ip} identified in {threat_type} campaign from {region}",
                "C2 infrastructure {ip} hosting {threat_type} operations targeting {sector} sector",
                "Malicious C2 endpoint {ip} communicating with {threat_type} implants",
                "Command server {ip} coordinating {threat_type} activities across {region}",
                "C2 beacon {ip} managing {threat_type} botnet operations",
                "Control infrastructure {ip} directing {threat_type} campaigns",
                "Command hub {ip} orchestrating {threat_type} attacks from {region}",
                "C2 node {ip} facilitating {threat_type} data exfiltration",
                "Malicious controller {ip} managing {threat_type} reconnaissance",
                "Command centre {ip} coordinating {threat_type} lateral movement",
                "C2 platform {ip} hosting {threat_type} payload delivery",
                "Control server {ip} directing {threat_type} persistence mechanisms",
                "Command infrastructure {ip} managing {threat_type} credential harvesting",
                "C2 gateway {ip} routing {threat_type} encrypted communications",
                "Control endpoint {ip} orchestrating {threat_type} privilege escalation",
                "Command relay {ip} coordinating {threat_type} network discovery",
                "C2 hub {ip} managing {threat_type} file system enumeration",
                "Control node {ip} directing {threat_type} process injection",
                "Command station {ip} coordinating {threat_type} defense evasion",
                "C2 nexus {ip} facilitating {threat_type} collection activities",
                "Control bridge {ip} managing {threat_type} exfiltration channels",
                "Command post {ip} directing {threat_type} impact operations",
                "C2 backbone {ip} supporting {threat_type} multi-stage attacks",
                "Control mesh {ip} coordinating {threat_type} distributed operations",
                "Command framework {ip} orchestrating {threat_type} supply chain attacks",
                
                # Botnet Infrastructure (20 variants)
                "Botnet member {ip} participating in {threat_type} distributed campaigns",
                "Infected host {ip} part of {threat_type} botnet from {region}",
                "Bot {ip} contributing to {threat_type} cryptocurrency mining operations",
                "Compromised system {ip} recruited into {threat_type} botnet",
                "Zombie host {ip} executing {threat_type} distributed denial of service",
                "Bot node {ip} participating in {threat_type} click fraud campaigns",
                "Infected endpoint {ip} contributing to {threat_type} spam distribution",
                "Botnet drone {ip} engaged in {threat_type} credential stuffing",
                "Compromised device {ip} participating in {threat_type} proxy networks",
                "Bot agent {ip} facilitating {threat_type} traffic amplification",
                "Infected machine {ip} contributing to {threat_type} distributed computing",
                "Botnet participant {ip} engaged in {threat_type} resource exploitation",
                "Zombie computer {ip} supporting {threat_type} distributed attacks",
                "Bot endpoint {ip} participating in {threat_type} coordinated campaigns",
                "Infected system {ip} contributing to {threat_type} network scanning",
                "Botnet soldier {ip} engaged in {threat_type} vulnerability probing",
                "Compromised host {ip} participating in {threat_type} port scanning",
                "Bot worker {ip} contributing to {threat_type} service enumeration",
                "Infected node {ip} engaged in {threat_type} banner grabbing",
                "Botnet asset {ip} supporting {threat_type} intelligence gathering",
                
                # Malware Distribution (20 variants)
                "Malware distribution point {ip} hosting {threat_type} payloads from {region}",
                "Payload delivery server {ip} distributing {threat_type} malicious files",
                "Malicious hosting platform {ip} serving {threat_type} exploit kits",
                "Infection vector {ip} delivering {threat_type} remote access trojans",
                "Malware repository {ip} hosting {threat_type} banking trojans",
                "Payload server {ip} distributing {threat_type} ransomware variants",
                "Malicious CDN {ip} serving {threat_type} information stealers",
                "Distribution hub {ip} hosting {threat_type} rootkit components",
                "Malware depot {ip} serving {threat_type} backdoor utilities",
                "Payload platform {ip} distributing {threat_type} keyloggers",
                "Malicious infrastructure {ip} hosting {threat_type} screen capture tools",
                "Distribution network {ip} serving {threat_type} credential harvesters",
                "Malware gateway {ip} delivering {threat_type} browser hijackers",
                "Payload repository {ip} hosting {threat_type} adware components",
                "Malicious server {ip} distributing {threat_type} cryptocurrency miners",
                "Distribution endpoint {ip} serving {threat_type} document exploits",
                "Malware nexus {ip} hosting {threat_type} macro-enabled documents",
                "Payload delivery {ip} distributing {threat_type} script-based attacks",
                "Malicious hosting {ip} serving {threat_type} weaponised PDFs",
                "Distribution channel {ip} delivering {threat_type} Office exploits",
                
                # Phishing Operations (15 variants)
                "Phishing infrastructure {ip} hosting {threat_type} credential harvesting from {region}",
                "Fraudulent server {ip} mimicking legitimate services for {threat_type}",
                "Phishing platform {ip} targeting {threat_type} authentication credentials",
                "Deceptive hosting {ip} serving {threat_type} brand impersonation",
                "Phishing endpoint {ip} collecting {threat_type} financial information",
                "Fraudulent infrastructure {ip} hosting {threat_type} social engineering",
                "Phishing gateway {ip} facilitating {threat_type} identity theft",
                "Deceptive server {ip} serving {threat_type} fake login portals",
                "Phishing nexus {ip} hosting {threat_type} business email compromise",
                "Fraudulent platform {ip} targeting {threat_type} personal data",
                "Phishing hub {ip} facilitating {threat_type} account takeover",
                "Deceptive infrastructure {ip} hosting {threat_type} invoice fraud",
                "Phishing channel {ip} serving {threat_type} payment card harvesting",
                "Fraudulent endpoint {ip} targeting {threat_type} tax information",
                "Phishing operation {ip} facilitating {threat_type} romance scams",
                
                # Reconnaissance Activities (10 variants)
                "Reconnaissance host {ip} conducting {threat_type} network scanning from {region}",
                "Scanning infrastructure {ip} performing {threat_type} vulnerability assessment",
                "Probe system {ip} executing {threat_type} service enumeration",
                "Reconnaissance platform {ip} conducting {threat_type} port discovery",
                "Scanning endpoint {ip} performing {threat_type} banner grabbing",
                "Probe infrastructure {ip} executing {threat_type} DNS enumeration",
                "Reconnaissance gateway {ip} conducting {threat_type} subdomain discovery",
                "Scanning hub {ip} performing {threat_type} web application testing",
                "Probe nexus {ip} executing {threat_type} directory enumeration",
                "Reconnaissance channel {ip} conducting {threat_type} technology fingerprinting",
                
                # Miscellaneous Threats (10 variants)
                "Suspicious host {ip} engaged in {threat_type} activities from {region}",
                "Malicious endpoint {ip} participating in {threat_type} operations",
                "Threat infrastructure {ip} supporting {threat_type} campaigns",
                "Hostile system {ip} facilitating {threat_type} attacks",
                "Malicious platform {ip} enabling {threat_type} exploitation",
                "Threat actor infrastructure {ip} hosting {threat_type} tools",
                "Adversarial endpoint {ip} supporting {threat_type} operations",
                "Malicious gateway {ip} facilitating {threat_type} intrusions",
                "Threat nexus {ip} coordinating {threat_type} activities",
                "Hostile infrastructure {ip} enabling {threat_type} persistence"
            ]
            
            # Get all active subnets
            subnets = ThreatSubnet.query.filter_by(is_active=True).all()
            if not subnets:
                print("No threat subnets available for IP generation")
                return
            
            batch_size = 1000
            total_generated = 0
            generated_ips_in_batch = set()  # Track IPs in current batch to avoid duplicates
            
            while total_generated < target_count:
                batch_ips = []
                generated_ips_in_batch.clear()
                attempts = 0
                max_attempts = batch_size * 3  # Allow some retries for uniqueness
                
                while len(batch_ips) < batch_size and total_generated + len(batch_ips) < target_count and attempts < max_attempts:
                    attempts += 1
                    
                    # Select random subnet
                    subnet_obj = random.choice(subnets)
                    
                    try:
                        # Parse CIDR and generate random IP
                        network = ipaddress.IPv4Network(subnet_obj.cidr, strict=False)
                        # Skip network and broadcast addresses
                        available_ips = list(network.hosts())
                        
                        if available_ips:
                            random_ip = str(random.choice(available_ips))
                            
                            # Skip if already generated in this batch or exists in database
                            if random_ip in generated_ips_in_batch:
                                continue
                            
                            # Check if IP already exists in database (expensive but necessary)
                            if cls.query.filter_by(ip_address=random_ip).first():
                                continue
                            
                            generated_ips_in_batch.add(random_ip)
                            
                            # Create varied threat intelligence description
                            template = random.choice(description_templates)
                            description = template.format(
                                ip=random_ip,
                                threat_type=subnet_obj.threat_category,
                                region=subnet_obj.geographic_region,
                                sector=random.choice(['financial', 'healthcare', 'technology', 'government', 'education', 'retail'])
                            )
                            
                            confidence = random.choices([95, 90, 85, 80, 75], weights=[20, 30, 25, 15, 10])[0]
                            
                            malicious_ip = cls(
                                ip_address=random_ip,
                                description=description,
                                confidence_score=confidence,
                                threat_types=[subnet_obj.threat_category],
                                source=f"Generated from {subnet_obj.source}"
                            )
                            batch_ips.append(malicious_ip)
                            
                    except Exception as e:
                        print(f"Error generating IP from {subnet_obj.cidr}: {e}")
                        continue
                
                # Batch insert for performance
                if batch_ips:
                    try:
                        db.session.add_all(batch_ips)
                        db.session.commit()
                        total_generated += len(batch_ips)
                        
                        if total_generated % 10000 == 0:
                            print(f"Generated {total_generated:,} IP addresses...")
                    except Exception as e:
                        print(f"Error inserting batch: {e}")
                        db.session.rollback()
                        # Try inserting individually to handle any remaining duplicates
                        successful_individual = 0
                        for ip_obj in batch_ips:
                            try:
                                db.session.add(ip_obj)
                                db.session.commit()
                                successful_individual += 1
                            except:
                                db.session.rollback()
                                continue
                        total_generated += successful_individual
                        print(f"Recovered {successful_individual} IPs from failed batch")
                else:
                    # If we can't generate enough unique IPs, break to avoid infinite loop
                    print(f"Warning: Could only generate {len(batch_ips)} unique IPs in this batch")
                    break
            
            print(f"Successfully generated {total_generated:,} IP addresses from threat subnets")


class ThreatSubnet(db.Model):
    """Database model for threat subnet ranges from Spamhaus and other sources"""
    __tablename__ = 'threat_subnets'
    
    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(18), nullable=False, unique=True, index=True)  # e.g., "192.168.1.0/24"
    sbl_id = db.Column(db.String(20), index=True)  # Spamhaus SBL ID
    rir = db.Column(db.String(20), index=True)  # Regional Internet Registry (apnic, ripencc, arin, etc.)
    threat_category = db.Column(db.String(50), default="malicious-activity", index=True)  # botnet, c2, malware, etc.
    geographic_region = db.Column(db.String(50), index=True)  # Derived from RIR
    description = db.Column(db.Text)
    confidence_score = db.Column(db.Integer, default=75, index=True)  # 0-100 confidence score
    source = db.Column(db.String(255), default="Spamhaus DROP")
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ThreatSubnet {self.cidr}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active threat subnet using database-level randomization"""
        from sqlalchemy import func
        return cls.query.filter_by(is_active=True).order_by(func.random()).first()
    
    @classmethod
    def seed_spamhaus_subnets(cls):
        """Seed the database with Spamhaus DROP subnets if none exist"""
        if cls.query.count() == 0:
            import requests
            import json
            
            # RIR to geographic region mapping (define outside try/except)
            rir_regions = {
                'apnic': 'Asia-Pacific',
                'ripencc': 'Europe',
                'arin': 'North America',
                'lacnic': 'Latin America',
                'afrinic': 'Africa'
            }
            
            print("Fetching Spamhaus DROP v4 data...")
            try:
                response = requests.get("https://www.spamhaus.org/drop/drop_v4.json", timeout=30)
                response.raise_for_status()
                
                # Parse JSONL format (one JSON object per line)  
                spamhaus_subnets = []
                for line in response.text.strip().split('\n'):
                    if line.strip():
                        try:
                            subnet_data = json.loads(line)
                            # Only add if it has required fields
                            if isinstance(subnet_data, dict) and 'cidr' in subnet_data:
                                spamhaus_subnets.append(subnet_data)
                        except json.JSONDecodeError:
                            # Skip malformed JSON lines
                            continue
                
                print(f"Processing {len(spamhaus_subnets)} Spamhaus subnets...")
                
                # Threat category distribution for variety
                threat_categories = [
                    'botnet', 'c2-infrastructure', 'malware-distribution', 
                    'reconnaissance', 'data-exfiltration', 'phishing-infrastructure',
                    'cryptocurrency-mining', 'ddos-source'
                ]
                
                import random
                for subnet_data in spamhaus_subnets:
                    # Skip if no CIDR field (malformed data)
                    if 'cidr' not in subnet_data:
                        continue
                        
                    # Check if subnet already exists to avoid duplicates
                    cidr = subnet_data['cidr']
                    if not cidr:  # Skip empty CIDR values
                        continue
                        
                    existing = cls.query.filter_by(cidr=cidr).first()
                    if existing:
                        continue
                    
                    geographic_region = rir_regions.get(subnet_data.get('rir', ''), 'Unknown')
                    threat_category = random.choice(threat_categories)
                    
                    threat_subnet = cls(
                        cidr=cidr,
                        sbl_id=subnet_data.get('sblid'),
                        rir=subnet_data.get('rir'),
                        threat_category=threat_category,
                        geographic_region=geographic_region,
                        description=f"Spamhaus DROP listed subnet {cidr} from {geographic_region} ({threat_category})",
                        confidence_score=random.choices([90, 85, 80], weights=[60, 30, 10])[0],
                        source="Spamhaus DROP v4"
                    )
                    db.session.add(threat_subnet)
                
                db.session.commit()
                print(f"Successfully seeded {len(spamhaus_subnets)} threat subnets")
                
            except Exception as e:
                print(f"Error fetching Spamhaus data: {e}")
                print("Using fallback subnet data...")
                # Fallback minimal subnet list if Spamhaus is unavailable
                fallback_subnets = [
                    {"cidr": "185.220.101.0/24", "rir": "ripencc"},
                    {"cidr": "104.131.0.0/16", "rir": "arin"},
                    {"cidr": "42.128.0.0/12", "rir": "apnic"}
                ]
                
                for subnet_data in fallback_subnets:
                    # Check if subnet already exists to avoid duplicates
                    existing = cls.query.filter_by(cidr=subnet_data['cidr']).first()
                    if existing:
                        continue
                    
                    geographic_region = rir_regions.get(subnet_data.get('rir', ''), 'Unknown')
                    threat_subnet = cls(
                        cidr=subnet_data['cidr'],
                        rir=subnet_data.get('rir'),
                        threat_category='malicious-activity',
                        geographic_region=geographic_region,
                        description=f"Threat subnet {subnet_data['cidr']} from {geographic_region}",
                        source="Fallback data"
                    )
                    db.session.add(threat_subnet)
                
                db.session.commit()


class CVE(db.Model):
    """Database model for CVE (Common Vulnerabilities and Exposures)"""
    __tablename__ = 'cves'
    
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), nullable=False, unique=True)  # e.g., CVE-2025-1234
    vendor_project = db.Column(db.String(255))
    product = db.Column(db.String(255))
    vulnerability_name = db.Column(db.Text)
    short_description = db.Column(db.Text)
    date_added = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    required_action = db.Column(db.Text)
    known_ransomware_campaign_use = db.Column(db.String(50), default="Unknown")
    notes = db.Column(db.Text)
    cwes = db.Column(db.JSON, default=list)  # Common Weakness Enumerations
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence score
    severity = db.Column(db.String(20), default="High")  # Low, Medium, High, Critical
    cvss_version = db.Column(db.String(10), default="3.1")  # CVSS version (2.0, 3.0, 3.1)
    cvss_score = db.Column(db.Float, default=5.0)  # CVSS base score
    cvss_vector = db.Column(db.String(255))  # CVSS vector string
    cpe_uris = db.Column(db.JSON, default=list)  # Common Platform Enumeration URIs
    source = db.Column(db.String(255), default="CISA KEV Catalog")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<CVE {self.cve_id}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active CVE using database-level randomization for performance"""
        from sqlalchemy import func
        return cls.query.filter_by(is_active=True).order_by(func.random()).first()
    
    @classmethod
    def seed_from_cisa_kev(cls):
        """Seed the database with CVEs from CISA KEV catalogue if none exist"""
        if cls.query.count() == 0:
            import requests
            import json
            import random
            from datetime import datetime
            
            try:
                # Fetch CISA KEV catalogue
                response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    print(f"Importing {len(vulnerabilities)} CVEs from CISA KEV catalogue...")
                    
                    for vuln in vulnerabilities:
                        try:
                            # Parse dates
                            date_added = None
                            due_date = None
                            
                            if vuln.get('dateAdded'):
                                try:
                                    date_added = datetime.strptime(vuln['dateAdded'], '%Y-%m-%d')
                                except ValueError:
                                    pass
                            
                            if vuln.get('dueDate'):
                                try:
                                    due_date = datetime.strptime(vuln['dueDate'], '%Y-%m-%d')
                                except ValueError:
                                    pass
                            
                            # Determine confidence score based on known ransomware use
                            confidence = 90 if vuln.get('knownRansomwareCampaignUse') == 'Known' else 75
                            
                            # Determine severity and CVSS score based on various factors
                            if vuln.get('knownRansomwareCampaignUse') == 'Known':
                                severity = "Critical"
                                cvss_score = 9.0 + (random.randint(0, 8) / 10.0)  # 9.0-9.8
                                cvss_version = "3.1"
                            elif any(word in vuln.get('vulnerabilityName', '').lower() for word in ['remote', 'execution', 'overflow', 'injection']):
                                severity = "High"
                                cvss_score = 7.0 + (random.randint(0, 19) / 10.0)  # 7.0-8.9
                                cvss_version = "3.1"
                            else:
                                severity = "Medium"
                                cvss_score = 4.0 + (random.randint(0, 29) / 10.0)  # 4.0-6.9
                                cvss_version = "3.1"
                            
                            # Generate realistic CVSS vector
                            cvss_vector = f"CVSS:{cvss_version}/AV:{'N' if 'remote' in vuln.get('vulnerabilityName', '').lower() else 'L'}/AC:L/PR:{'N' if 'unauthenticated' in vuln.get('shortDescription', '').lower() else 'L'}/UI:N/S:U/C:H/I:H/A:H"
                            
                            # Generate CPE URIs based on vendor and product
                            vendor = vuln.get('vendorProject', '').lower().replace(' ', '_')
                            product = vuln.get('product', '').lower().replace(' ', '_')
                            cpe_uris = []
                            if vendor and product:
                                # Generate realistic CPE 2.3 URIs
                                cpe_uris = [
                                    f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                                    f"cpe:2.3:a:{vendor}:{product}:-:*:*:*:*:*:*:*"
                                ]
                            
                            cve = cls(
                                cve_id=vuln.get('cveID', ''),
                                vendor_project=vuln.get('vendorProject', ''),
                                product=vuln.get('product', ''),
                                vulnerability_name=vuln.get('vulnerabilityName', ''),
                                short_description=vuln.get('shortDescription', ''),
                                date_added=date_added,
                                due_date=due_date,
                                required_action=vuln.get('requiredAction', ''),
                                known_ransomware_campaign_use=vuln.get('knownRansomwareCampaignUse', 'Unknown'),
                                notes=vuln.get('notes', ''),
                                cwes=vuln.get('cwes', []),
                                confidence_score=confidence,
                                severity=severity,
                                cvss_version=cvss_version,
                                cvss_score=cvss_score,
                                cvss_vector=cvss_vector,
                                cpe_uris=cpe_uris
                            )
                            db.session.add(cve)
                            
                        except Exception as e:
                            print(f"Error processing CVE {vuln.get('cveID', 'unknown')}: {str(e)}")
                            continue
                    
                    db.session.commit()
                    print(f"Successfully imported {cls.query.count()} CVEs from CISA KEV catalogue")
                    
                else:
                    print(f"Failed to fetch CISA KEV catalogue: HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"Error fetching CISA KEV catalogue: {str(e)}")
                # Fallback to sample CVEs if API fails
                cls._seed_sample_cves()
    
    @classmethod
    def _seed_sample_cves(cls):
        """Seed with sample CVEs if CISA API is unavailable"""
        sample_cves = [
            {
                'cve_id': 'CVE-2025-53770',
                'vendor_project': 'Microsoft',
                'product': 'SharePoint',
                'vulnerability_name': 'Microsoft SharePoint Deserialization of Untrusted Data Vulnerability',
                'short_description': 'Microsoft SharePoint Server on-premises contains a deserialization of untrusted data vulnerability that could allow an unauthorized attacker to execute code over a network.',
                'confidence_score': 90,
                'severity': 'Critical',
                'known_ransomware_campaign_use': 'Unknown',
                'cwes': ['CWE-502'],
                'cvss_version': '3.1',
                'cvss_score': 9.8,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cpe_uris': ['cpe:2.3:a:microsoft:sharepoint:*:*:*:*:*:*:*:*']
            },
            {
                'cve_id': 'CVE-2025-49704',
                'vendor_project': 'Microsoft',
                'product': 'SharePoint',
                'vulnerability_name': 'Microsoft SharePoint Code Injection Vulnerability',
                'short_description': 'Microsoft SharePoint contains a code injection vulnerability that could allow an authorized attacker to execute code over a network.',
                'confidence_score': 90,
                'severity': 'Critical',
                'known_ransomware_campaign_use': 'Known',
                'cwes': ['CWE-94']
            },
            {
                'cve_id': 'CVE-2025-25257',
                'vendor_project': 'Fortinet',
                'product': 'FortiWeb',
                'vulnerability_name': 'Fortinet FortiWeb SQL Injection Vulnerability',
                'short_description': 'Fortinet FortiWeb contains a SQL injection vulnerability that may allow an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.',
                'confidence_score': 75,
                'severity': 'High',
                'known_ransomware_campaign_use': 'Unknown',
                'cwes': ['CWE-89']
            }
        ]
        
        for cve_data in sample_cves:
            cve = cls(**cve_data)
            db.session.add(cve)
        
        db.session.commit()


class MaliciousDomain(db.Model):
    """Database model for malicious domains"""
    __tablename__ = 'malicious_domains'
    
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    threat_types = db.Column(db.JSON, default=lambda: ["malicious-activity"])
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence score
    source = db.Column(db.String(255), default="MockTAXII")
    domain_category = db.Column(db.String(100), default="phishing")  # phishing, malware, c2, etc.
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MaliciousDomain {self.domain_name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active malicious domain"""
        domains = cls.query.filter_by(is_active=True).all()
        if domains:
            import random
            return random.choice(domains)
        return None
    
    @classmethod
    def seed_default_domains(cls):
        """Seed the database with default malicious domains if none exist"""
        if cls.query.count() == 0:
            # Default malicious domain list from stix_generator.py
            default_domains = [
                "malware-c2.example.com", "phishing-site.bad", "trojan-host.evil",
                "botnet-command.net", "ransomware-gate.org", "credential-harvest.biz",
                "fake-bank-login.info", "virus-distribution.bad", "spyware-hub.evil",
                "adware-network.scam",
                # sigre.xyz domain and subdomains
                "sigre.xyz", "mail.sigre.xyz", "www.sigre.xyz", "cdn.sigre.xyz",
                "api.sigre.xyz", "admin.sigre.xyz", "portal.sigre.xyz", "login.sigre.xyz",
                "secure.sigre.xyz", "payment.sigre.xyz", "update.sigre.xyz", "support.sigre.xyz",
                "download.sigre.xyz", "ftp.sigre.xyz", "blog.sigre.xyz", "news.sigre.xyz",
                "shop.sigre.xyz", "cloud.sigre.xyz", "vpn.sigre.xyz", "backup.sigre.xyz",
                "archive.sigre.xyz",
                # Additional malicious domains
                "cyberthreat-nexus.com", "darkweb-portal.net", "hacktools-depot.org",
                "malware-factory.biz", "phish-central.info", "trojan-warehouse.com",
                "exploit-marketplace.net", "ransomware-central.org", "botnet-registry.biz",
                "credential-bazaar.info", "blackhat-services.com", "underground-market.net",
                "stolen-data.org", "identity-theft.biz", "fraud-network.info",
                "steganography-tools.biz", "covert-channel.info", "c2-infrastructure.com",
                "command-control.net", "exfiltration-point.org", "data-staging.biz",
                "lateral-movement.info", "privilege-escalation.com", "persistence-method.net",
                "evasion-technique.org", "anti-forensics.biz", "artifact-cleanup.info",
                "memory-injection.com", "process-hollowing.net", "dll-hijacking.org",
                "registry-persistence.biz", "scheduled-task.info", "service-installation.com",
                "autorun-malware.net", "startup-trojan.org", "browser-hijacker.biz",
                "search-redirect.info", "homepage-changer.com", "popup-generator.net",
                "click-fraud.org", "ad-injector.biz", "traffic-redirector.info",
                "seo-poisoning.com", "typosquatting-domain.net", "homograph-attack.org",
                "punycode-phish.biz", "subdomain-takeover.info", "dns-hijacking.com",
                "cache-poisoning.net", "bgp-hijack.org", "ssl-stripping.biz",
                "cert-pinning-bypass.info", "mitm-proxy.com", "packet-injection.net",
                "arp-spoofing.org", "dhcp-starvation.biz", "vlan-hopping.info",
                "wifi-pineapple.com", "evil-twin.net", "rogue-access-point.org",
                "bluetooth-attack.biz", "nfc-exploit.info", "rfid-cloning.com",
                "card-skimming.net", "atm-malware.org", "pos-compromise.biz",
                "payment-fraud.info", "crypto-mining.com", "blockchain-exploit.net",
                "smart-contract-hack.org", "defi-drain.biz", "nft-scam.info"
            ]
            
            import random
            for domain_name in default_domains:
                # Categorize domains based on patterns
                if any(keyword in domain_name for keyword in ['phish', 'fake', 'credential', 'fraud']):
                    category = 'phishing'
                elif any(keyword in domain_name for keyword in ['malware', 'trojan', 'virus', 'ransomware']):
                    category = 'malware'
                elif any(keyword in domain_name for keyword in ['c2', 'command', 'control', 'botnet']):
                    category = 'c2'
                elif 'sigre.xyz' in domain_name:
                    category = 'infrastructure'
                else:
                    category = 'general'
                
                # Add variety to confidence scores and descriptions
                confidence = random.choices([75, 50], weights=[70, 30])[0]
                threat_description = random.choice([
                    f"Malicious domain {domain_name} used for {category} activities",
                    f"Domain {domain_name} identified in threat intelligence feeds as {category} infrastructure",
                    f"Suspicious domain {domain_name} associated with {category} campaigns",
                    f"Known malicious domain {domain_name} involved in {category} operations",
                    f"Domain {domain_name} flagged for {category} and malware distribution"
                ])
                
                malicious_domain = cls(
                    domain_name=domain_name,
                    description=threat_description,
                    confidence_score=confidence,
                    domain_category=category,
                    threat_types=["malicious-activity"],
                    source="MockTAXII Intelligence Feed"
                )
                db.session.add(malicious_domain)
            
            db.session.commit()


class MaliciousHash(db.Model):
    """Database model for malicious file hashes"""
    __tablename__ = 'malicious_hashes'
    
    id = db.Column(db.Integer, primary_key=True)
    hash_value = db.Column(db.String(64), nullable=False, unique=True)  # SHA256 hash
    hash_type = db.Column(db.String(20), nullable=False, default="SHA256")
    description = db.Column(db.Text)
    malware_family = db.Column(db.String(100))
    threat_types = db.Column(db.JSON, default=lambda: ["malicious-activity"])
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence score
    source = db.Column(db.String(255), default="MockTAXII")
    file_type = db.Column(db.String(50), default="executable")  # executable, document, archive, etc.
    file_size = db.Column(db.Integer)  # file size in bytes
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MaliciousHash {self.hash_value[:16]}...>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active malicious hash"""
        hashes = cls.query.filter_by(is_active=True).all()
        if hashes:
            import random
            return random.choice(hashes)
        return None
    
    @classmethod
    def seed_default_hashes(cls):
        """Seed the database with default malicious hashes if none exist"""
        if cls.query.count() == 0:
            # Default malicious hash list from stix_generator.py
            default_hashes = [
                "A1B2C3D4E5F67890123456789012345678901234567890123456789012345678",
                "B2C3D4E5F6789012345678901234567890123456789012345678901234567890",
                "C3D4E5F678901234567890123456789012345678901234567890123456789012",
                "D4E5F67890123456789012345678901234567890123456789012345678901234",
                "E5F6789012345678901234567890123456789012345678901234567890123456",
                "F678901234567890123456789012345678901234567890123456789012345678",
                "7890123456789012345678901234567890123456789012345678901234567890",
                "8901234567890123456789012345678901234567890123456789012345678901",
                "9012345678901234567890123456789012345678901234567890123456789012",
                "0123456789012345678901234567890123456789012345678901234567890123",
                "1234567890123456789012345678901234567890123456789012345678901234",
                "2345678901234567890123456789012345678901234567890123456789012345",
                "3456789012345678901234567890123456789012345678901234567890123456",
                "4567890123456789012345678901234567890123456789012345678901234567",
                "5678901234567890123456789012345678901234567890123456789012345678",
                "6789012345678901234567890123456789012345678901234567890123456789",
                "789012345678901234567890123456789012345678901234567890123456789A",
                "89012345678901234567890123456789012345678901234567890123456789AB",
                "9012345678901234567890123456789012345678901234567890123456789ABC",
                "012345678901234567890123456789012345678901234567890123456789ABCD",
                "12345678901234567890123456789012345678901234567890123456789ABCDE",
                "2345678901234567890123456789012345678901234567890123456789ABCDEF",
                "345678901234567890123456789012345678901234567890123456789ABCDEF0",
                "45678901234567890123456789012345678901234567890123456789ABCDEF01",
                "5678901234567890123456789012345678901234567890123456789ABCDEF012",
                "678901234567890123456789012345678901234567890123456789ABCDEF0123",
                "78901234567890123456789012345678901234567890123456789ABCDEF01234",
                "8901234567890123456789012345678901234567890123456789ABCDEF012345",
                "901234567890123456789012345678901234567890123456789ABCDEF0123456",
                "01234567890123456789012345678901234567890123456789ABCDEF01234567",
                "1234567890123456789012345678901234567890123456789ABCDEF012345678",
                "234567890123456789012345678901234567890123456789ABCDEF0123456789",
                "34567890123456789012345678901234567890123456789ABCDEF0123456789A",
                "4567890123456789012345678901234567890123456789ABCDEF0123456789AB",
                "567890123456789012345678901234567890123456789ABCDEF0123456789ABC",
                "67890123456789012345678901234567890123456789ABCDEF0123456789ABCD",
                "7890123456789012345678901234567890123456789ABCDEF0123456789ABCDE",
                "890123456789012345678901234567890123456789ABCDEF0123456789ABCDEF",
                "90123456789012345678901234567890123456789ABCDEF0123456789ABCDEF0"
            ]
            
            file_types = ["executable", "document", "archive", "script", "library"]
            
            import random
            for hash_value in default_hashes:
                # Get malware families from database
                malware_obj = MalwareFamily.get_random_active()
                malware_family = malware_obj.name if malware_obj else "Unknown Malware"
                file_type = random.choice(file_types)
                confidence = random.choices([75, 50], weights=[70, 30])[0]
                file_size = random.randint(1024, 50*1024*1024)  # 1KB to 50MB
                
                threat_description = random.choice([
                    f"Malicious file hash associated with {malware_family} malware family",
                    f"SHA256 hash {hash_value[:16]}... identified as {malware_family} variant",
                    f"Known malicious {file_type} file linked to {malware_family} campaigns",
                    f"File hash {hash_value[:16]}... flagged for {malware_family} malware distribution",
                    f"Suspicious {file_type} hash connected to {malware_family} threat actor operations"
                ])
                
                malicious_hash = cls(
                    hash_value=hash_value,
                    hash_type="SHA256",
                    description=threat_description,
                    malware_family=malware_family,
                    confidence_score=confidence,
                    file_type=file_type,
                    file_size=file_size,
                    threat_types=["malicious-activity"],
                    source="MockTAXII Intelligence Feed"
                )
                db.session.add(malicious_hash)
            
            db.session.commit()


class MalwareFamily(db.Model):
    """Database model for malware families and variants"""
    __tablename__ = 'malware_families'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    malware_types = db.Column(db.JSON, default=lambda: ["trojan"])  # trojan, backdoor, ransomware, etc.
    labels = db.Column(db.JSON, default=lambda: ["malicious-activity"])
    capabilities = db.Column(db.JSON, default=list)  # data-exfiltration, credential-theft, etc.
    kill_chain_phases = db.Column(db.JSON, default=list)  # MITRE kill chain phases
    platforms = db.Column(db.JSON, default=lambda: ["windows"])  # windows, linux, macos, android
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence score
    sophistication = db.Column(db.String(50), default="intermediate")
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    source = db.Column(db.String(255), default="MITRE ATT&CK")
    mitre_id = db.Column(db.String(20))  # S0XXX identifier
    external_references = db.Column(db.JSON, default=list)  # External references including URLs
    is_family = db.Column(db.Boolean, nullable=False, default=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MalwareFamily {self.name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active malware family"""
        families = cls.query.filter_by(is_active=True).all()
        if families:
            import random
            return random.choice(families)
        return None
    
    @classmethod
    def seed_malware_families(cls):
        """Seed the database with comprehensive malware families if none exist"""
        if cls.query.count() == 0:
            print("Seeding malware families database...")
            
            # MITRE ATT&CK Malware entries (comprehensive list from software database)
            mitre_malware = [
                {
                    "name": "3PARA RAT",
                    "mitre_id": "S0066",
                    "description": "3PARA RAT is a remote access tool (RAT) programmed in C++ that has been used by Putter Panda.",
                    "malware_types": ["backdoor", "remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "remote-access"]
                },
                {
                    "name": "4H RAT",
                    "mitre_id": "S0065",
                    "description": "4H RAT is malware that has been used by Putter Panda since at least 2007.",
                    "malware_types": ["backdoor", "remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "remote-access"]
                },
                {
                    "name": "Agent Tesla",
                    "mitre_id": "S0331",
                    "description": "Agent Tesla is a spyware Trojan written for the .NET framework that has been observed since at least 2014.",
                    "malware_types": ["spyware", "trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "keylogging", "data-exfiltration"]
                },
                {
                    "name": "Agent.btz",
                    "mitre_id": "S0092",
                    "description": "Agent.btz is a worm that primarily spreads itself via removable devices such as USB drives.",
                    "malware_types": ["worm"],
                    "platforms": ["windows"],
                    "capabilities": ["lateral-movement", "persistence"]
                },
                {
                    "name": "Akira",
                    "mitre_id": "S1129",
                    "description": "Akira ransomware is written in C++ and employs hybrid encryption and threading to increase encryption speed.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows", "linux"],
                    "capabilities": ["data-encryption", "file-destruction"]
                },
                {
                    "name": "Amadey",
                    "mitre_id": "S1025",
                    "description": "Amadey is a Trojan bot that has been used since at least October 2018.",
                    "malware_types": ["trojan", "bot"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "payload-delivery"]
                },
                {
                    "name": "Anchor",
                    "mitre_id": "S0504",
                    "description": "Anchor is a family of backdoor malware that has been used in conjunction with TrickBot.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["persistence", "command-and-control"]
                },
                {
                    "name": "ANDROMEDA",
                    "mitre_id": "S1074",
                    "description": "ANDROMEDA is commodity malware that was widespread in the early 2010's.",
                    "malware_types": ["trojan", "bot"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "malware-distribution"]
                },
                {
                    "name": "AndroRAT",
                    "mitre_id": "S0292",
                    "description": "AndroRAT is an open-source remote access tool for Android devices.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["android"],
                    "capabilities": ["remote-access", "data-collection"]
                },
                {
                    "name": "ADVSTORESHELL",
                    "mitre_id": "S0045",
                    "description": "ADVSTORESHELL is a spying backdoor that has been used by APT28 from at least 2012 to 2016.",
                    "malware_types": ["backdoor", "spyware"],
                    "platforms": ["windows"],
                    "capabilities": ["espionage", "persistence"]
                },
                {
                    "name": "AsyncRAT",
                    "mitre_id": "S0465",
                    "description": "AsyncRAT is an open-source remote access tool written in C# that has been observed since at least 2019.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "credential-theft"]
                },
                {
                    "name": "Ave Maria",
                    "mitre_id": "S0473",
                    "description": "Ave Maria is a remote access trojan (RAT) that has been used since at least 2018.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "data-exfiltration"]
                },
                {
                    "name": "Azorult",
                    "mitre_id": "S0344",
                    "description": "Azorult is a commercial Trojan that is used to steal various types of information.",
                    "malware_types": ["trojan", "info-stealer"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "data-exfiltration"]
                },
                {
                    "name": "BackConfig",
                    "mitre_id": "S0596",
                    "description": "BackConfig is a Windows-based information stealer and remote access trojan.",
                    "malware_types": ["info-stealer", "remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["data-exfiltration", "remote-access"]
                },
                {
                    "name": "BabyShark",
                    "mitre_id": "S0414",
                    "description": "BabyShark is a Microsoft Visual Basic (VB) script-based malware family.",
                    "malware_types": ["trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["persistence", "data-collection"]
                },
                {
                    "name": "Bandook",
                    "mitre_id": "S0234",
                    "description": "Bandook is a remote access tool (RAT) with variants written in multiple programming languages.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "data-theft"]
                },
                {
                    "name": "BEACON",
                    "mitre_id": "S0521",
                    "description": "BEACON is a Cobalt Strike payload used to establish a connection to a team server.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["command-and-control", "lateral-movement"]
                },
                {
                    "name": "BlackEnergy",
                    "mitre_id": "S0089",
                    "description": "BlackEnergy is a malware toolkit that has evolved through several versions.",
                    "malware_types": ["trojan", "backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["industrial-control", "persistence"]
                },
                {
                    "name": "BRONZE BUTLER",
                    "mitre_id": "S0070",
                    "description": "BRONZE BUTLER malware has been used in targeted attacks since at least 2008.",
                    "malware_types": ["trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["espionage", "data-exfiltration"]
                },
                {
                    "name": "Carbanak",
                    "mitre_id": "S0030",
                    "description": "Carbanak is a full-featured backdoor used by the FIN7 group in financial attacks.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["financial-theft", "lateral-movement"]
                },
                {
                    "name": "Carberp",
                    "mitre_id": "S0484",
                    "description": "Carberp is a trojan that steals banking information and user credentials.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "financial-theft"]
                },
                {
                    "name": "China Chopper",
                    "mitre_id": "S0020",
                    "description": "China Chopper is a Web Shell hosted on Web servers to provide access back into an enterprise network.",
                    "malware_types": ["webshell"],
                    "platforms": ["linux", "windows"],
                    "capabilities": ["web-shell", "persistence"]
                },
                {
                    "name": "Cobalt Strike",
                    "mitre_id": "S0154",
                    "description": "Cobalt Strike is a commercial penetration testing tool that can be used for post-exploitation activities.",
                    "malware_types": ["post-exploitation"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["lateral-movement", "privilege-escalation"]
                },
                {
                    "name": "DarkComet",
                    "mitre_id": "S0334",
                    "description": "DarkComet is a Windows remote administration tool and backdoor.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "surveillance"]
                },
                {
                    "name": "Dridex",
                    "mitre_id": "S0384",
                    "description": "Dridex is a banking Trojan that has been used for financial gain since at least 2014.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "financial-theft"]
                },
                {
                    "name": "Emotet",
                    "mitre_id": "S0367",
                    "description": "Emotet is a modular banking Trojan that has been used for financial theft and malware distribution.",
                    "malware_types": ["banking-trojan", "trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "malware-distribution"]
                },
                {
                    "name": "Empire",
                    "mitre_id": "S0363",
                    "description": "Empire is an open source, cross-platform remote administration and post-exploitation framework.",
                    "malware_types": ["post-exploitation"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["lateral-movement", "persistence"]
                },
                {
                    "name": "FlawedAmmyy",
                    "mitre_id": "S0381",
                    "description": "FlawedAmmyy is a remote access tool (RAT) that is a modified version of Ammyy Admin.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "data-theft"]
                },
                {
                    "name": "gh0st RAT",
                    "mitre_id": "S0032",
                    "description": "gh0st RAT is a remote access tool (RAT) used by multiple groups.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "data-exfiltration"]
                },
                {
                    "name": "HAMMERTOSS",
                    "mitre_id": "S0037",
                    "description": "HAMMERTOSS is a backdoor that communicates through Twitter, GitHub, and cloud storage services.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "steganography"]
                },
                {
                    "name": "IcedID",
                    "mitre_id": "S0483",
                    "description": "IcedID is a modular banking malware family written in C++.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "web-injection"]
                },
                {
                    "name": "Imminent Monitor",
                    "mitre_id": "S0434",
                    "description": "Imminent Monitor is a commercial remote access tool.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "surveillance"]
                },
                {
                    "name": "JAVT",
                    "mitre_id": "S0036",
                    "description": "JAVT is a malware family that appears to be a modified version of the Adwind RAT.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["remote-access", "cross-platform"]
                },
                {
                    "name": "Lazarus",
                    "mitre_id": "S0349",
                    "description": "Lazarus is malware used by the North Korean APT group of the same name.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["espionage", "financial-theft"]
                },
                {
                    "name": "LockerGoga",
                    "mitre_id": "S0372",
                    "description": "LockerGoga is ransomware that has been used to target large corporations and government agencies.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "service-disruption"]
                },
                {
                    "name": "Loki",
                    "mitre_id": "S0447",
                    "description": "Loki is an information stealer that has been observed targeting credentials and cryptocurrency wallets.",
                    "malware_types": ["info-stealer"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "cryptocurrency-theft"]
                },
                {
                    "name": "LuminousMoth",
                    "mitre_id": "S0455",
                    "description": "LuminousMoth is a backdoor that communicates via fake TLS handshake sessions.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["command-and-control", "stealth"]
                },
                {
                    "name": "Maze",
                    "mitre_id": "S0449",
                    "description": "Maze is ransomware that encrypts files and threatens to publish stolen data.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "data-exfiltration"]
                },
                {
                    "name": "Mimikatz",
                    "mitre_id": "S0002",
                    "description": "Mimikatz is a post-exploitation tool that can extract plaintext passwords and other credentials.",
                    "malware_types": ["post-exploitation"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-dumping", "privilege-escalation"]
                },
                {
                    "name": "NanoCore",
                    "mitre_id": "S0336",
                    "description": "NanoCore is a family of .NET remote access tools that have been observed since 2013.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "surveillance"]
                },
                {
                    "name": "NetWire",
                    "mitre_id": "S0198",
                    "description": "NetWire is a publicly available, cross-platform remote administration tool.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["remote-access", "keylogging"]
                },
                {
                    "name": "njRAT",
                    "mitre_id": "S0385",
                    "description": "njRAT is a remote access tool that has been used by multiple groups since at least 2012.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "data-theft"]
                },
                {
                    "name": "NotPetya",
                    "mitre_id": "S0368",
                    "description": "NotPetya is a destructive malware that was initially thought to be ransomware.",
                    "malware_types": ["wiper", "ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-destruction", "lateral-movement"]
                },
                {
                    "name": "Olympic Destroyer",
                    "mitre_id": "S0365",
                    "description": "Olympic Destroyer is modular network worm written in C++.",
                    "malware_types": ["wiper", "worm"],
                    "platforms": ["windows"],
                    "capabilities": ["data-destruction", "lateral-movement"]
                },
                {
                    "name": "Poison Ivy",
                    "mitre_id": "S0012",
                    "description": "Poison Ivy is a popular remote access tool (RAT) that has been used by many groups.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "persistence"]
                },
                {
                    "name": "PolyglotDuke",
                    "mitre_id": "S0518",
                    "description": "PolyglotDuke is a malware family used by APT29 that evolved from early versions of MiniDuke.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["espionage", "stealth"]
                },
                {
                    "name": "PowerSploit",
                    "mitre_id": "S0194",
                    "description": "PowerSploit is an open source, offensive security framework comprised of PowerShell modules.",
                    "malware_types": ["post-exploitation"],
                    "platforms": ["windows"],
                    "capabilities": ["privilege-escalation", "persistence"]
                },
                {
                    "name": "Pupy",
                    "mitre_id": "S0192",
                    "description": "Pupy is an open source, cross-platform remote administration and post-exploitation tool.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["remote-access", "cross-platform"]
                },
                {
                    "name": "QakBot",
                    "mitre_id": "S0650",
                    "description": "QakBot is a modular information stealer also known as Qbot.",
                    "malware_types": ["info-stealer", "banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "lateral-movement"]
                },
                {
                    "name": "Quasar",
                    "mitre_id": "S0262",
                    "description": "Quasar is an open-source, remote access tool written in C#.",
                    "malware_types": ["remote-access-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["remote-access", "surveillance"]
                },
                {
                    "name": "Ragnar Locker",
                    "mitre_id": "S0481",
                    "description": "Ragnar Locker is ransomware that has been used against multiple organizations.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "data-exfiltration"]
                },
                {
                    "name": "REvil",
                    "mitre_id": "S0496",
                    "description": "REvil is a ransomware family that has been used in big game hunting operations.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "ransom-demands"]
                },
                {
                    "name": "Ryuk",
                    "mitre_id": "S0446",
                    "description": "Ryuk is ransomware that has been used for targeted attacks against high-value organizations.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "targeted-attacks"]
                },
                {
                    "name": "SDelete",
                    "mitre_id": "S0195",
                    "description": "SDelete is a Microsoft utility that securely deletes existing files.",
                    "malware_types": ["utility"],
                    "platforms": ["windows"],
                    "capabilities": ["anti-forensics", "file-deletion"]
                },
                {
                    "name": "Shamoon",
                    "mitre_id": "S0140",
                    "description": "Shamoon is destructive malware that overwrites files with an image and then reboots the machine.",
                    "malware_types": ["wiper"],
                    "platforms": ["windows"],
                    "capabilities": ["data-destruction", "system-destruction"]
                },
                {
                    "name": "SUNBURST",
                    "mitre_id": "S0560",
                    "description": "SUNBURST is a backdoor that has the ability to spawn and kill processes.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows"],
                    "capabilities": ["supply-chain", "stealth"]
                },
                {
                    "name": "TrickBot",
                    "mitre_id": "S0266",
                    "description": "TrickBot is a modular banking Trojan that has been used for financial theft.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "lateral-movement"]
                },
                {
                    "name": "Turla",
                    "mitre_id": "S0536",
                    "description": "Turla is a backdoor used by the APT group of the same name.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows", "linux"],
                    "capabilities": ["espionage", "persistence"]
                },
                {
                    "name": "WannaCry",
                    "mitre_id": "S0366",
                    "description": "WannaCry is ransomware that infected hundreds of thousands of computers worldwide.",
                    "malware_types": ["ransomware", "worm"],
                    "platforms": ["windows"],
                    "capabilities": ["data-encryption", "worm-propagation"]
                },
                {
                    "name": "Zeus",
                    "mitre_id": "S0161",
                    "description": "Zeus is a banking Trojan that has been used for financial theft since 2007.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "web-injection"]
                },
                {
                    "name": "ZLoader",
                    "mitre_id": "S0672",
                    "description": "ZLoader is a banking Trojan derived from the Zeus malware family.",
                    "malware_types": ["banking-trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "web-injection"]
                }
            ]
            
            # Custom malware families for Simon Sigre, Sigre.xyz, and GoCortex
            custom_malware = [
                {
                    "name": "SigreSpyware",
                    "description": "Advanced spyware toolkit attributed to Simon Sigre research activities, featuring sophisticated data collection and stealth capabilities.",
                    "malware_types": ["spyware", "trojan"],
                    "platforms": ["windows", "linux"],
                    "capabilities": ["credential-theft", "data-exfiltration", "keylogging", "surveillance"],
                    "source": "Simon Sigre",
                    "sophistication": "expert",
                    "confidence_score": 85
                },
                {
                    "name": "CortexCrypt",
                    "description": "Ransomware variant associated with GoCortex infrastructure, employing advanced encryption and anti-analysis techniques.",
                    "malware_types": ["ransomware"],
                    "platforms": ["windows", "linux"],
                    "capabilities": ["data-encryption", "anti-analysis", "ransom-demands"],
                    "source": "GoCortex",
                    "sophistication": "expert",
                    "confidence_score": 90
                },
                {
                    "name": "SigreXYZ-Backdoor",
                    "description": "Persistent backdoor malware linked to Sigre.xyz domain infrastructure, providing long-term access and control.",
                    "malware_types": ["backdoor"],
                    "platforms": ["windows", "linux", "macos"],
                    "capabilities": ["persistence", "command-and-control", "lateral-movement"],
                    "source": "Sigre.xyz",
                    "sophistication": "expert",
                    "confidence_score": 88
                },
                {
                    "name": "GoCortex-Stealer",
                    "description": "Information stealer malware attributed to GoCortex operations, targeting financial and cryptocurrency data.",
                    "malware_types": ["info-stealer"],
                    "platforms": ["windows"],
                    "capabilities": ["credential-theft", "cryptocurrency-theft", "financial-theft"],
                    "source": "GoCortex",
                    "sophistication": "intermediate",
                    "confidence_score": 80
                },
                {
                    "name": "SigreBot",
                    "description": "Botnet malware developed by Simon Sigre for distributed attack campaigns and C2 operations.",
                    "malware_types": ["bot", "trojan"],
                    "platforms": ["windows"],
                    "capabilities": ["botnet", "ddos", "command-and-control"],
                    "source": "Simon Sigre",
                    "sophistication": "intermediate",
                    "confidence_score": 75
                }
            ]
            
            # Combine all malware families
            all_malware = mitre_malware + custom_malware
            
            import random
            for malware_data in all_malware:
                # Generate external references
                external_refs = []
                if malware_data.get("mitre_id"):
                    external_refs.append({
                        "source_name": "mitre-attack",
                        "external_id": malware_data["mitre_id"],
                        "url": f"https://attack.mitre.org/software/{malware_data['mitre_id']}"
                    })
                
                # Add custom references for Simon Sigre branded malware
                if malware_data.get("source") in ["Simon Sigre", "Sigre.xyz", "GoCortex"]:
                    external_refs.append({
                        "source_name": malware_data["source"].lower().replace(".", ""),
                        "description": f"Research and analysis by {malware_data['source']}",
                        "url": f"https://simonsigre.com/malware-analysis-{malware_data['name'].lower().replace(' ', '-')}.pdf"
                    })
                
                malware_family = cls(
                    name=malware_data["name"],
                    description=malware_data["description"],
                    malware_types=malware_data.get("malware_types", ["trojan"]),
                    platforms=malware_data.get("platforms", ["windows"]),
                    capabilities=malware_data.get("capabilities", []),
                    confidence_score=malware_data.get("confidence_score", 75),
                    sophistication=malware_data.get("sophistication", "intermediate"),
                    source=malware_data.get("source", "MITRE ATT&CK"),
                    mitre_id=malware_data.get("mitre_id"),
                    external_references=external_refs,
                    labels=["malicious-activity"]
                )
                db.session.add(malware_family)
            
            db.session.commit()
            print(f"Successfully seeded {cls.query.count()} malware families from MITRE ATT&CK and custom sources")


class MitreTechnique(db.Model):
    """Database model for MITRE ATT&CK techniques"""
    __tablename__ = 'mitre_techniques'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    mitre_id = db.Column(db.String(20), nullable=False, unique=True)  # T1566.001, T1059, etc.
    description = db.Column(db.Text)
    tactics = db.Column(db.JSON, default=list)  # initial-access, execution, persistence, etc.
    platforms = db.Column(db.JSON, default=lambda: ["windows"])  # windows, linux, macos, etc.
    data_sources = db.Column(db.JSON, default=list)  # command-logging, process-monitoring, etc.
    detection_methods = db.Column(db.JSON, default=list)  # behavioral-analysis, signature-based, etc.
    mitigation_techniques = db.Column(db.JSON, default=list)  # network-segmentation, user-training, etc.
    confidence_score = db.Column(db.Integer, default=85)  # 0-100 confidence score
    external_references = db.Column(db.JSON, default=list)  # MITRE URLs and references
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MitreTechnique {self.mitre_id}: {self.name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active MITRE technique"""
        techniques = cls.query.filter_by(is_active=True).all()
        if techniques:
            import random
            return random.choice(techniques)
        return None
    
    @classmethod
    def seed_mitre_techniques(cls):
        """Seed the database with comprehensive MITRE ATT&CK techniques if none exist"""
        if cls.query.count() == 0:
            print("Seeding MITRE ATT&CK techniques database...")
            
            # Comprehensive MITRE ATT&CK techniques with enhanced metadata
            mitre_techniques = [
                {
                    "name": "Spearphishing Attachment",
                    "mitre_id": "T1566.001",
                    "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
                    "tactics": ["initial-access"],
                    "platforms": ["windows", "macos", "linux"],
                    "data_sources": ["email-gateway", "file-monitoring", "network-traffic"],
                    "detection_methods": ["email-attachment-analysis", "behavioral-analysis", "signature-based"],
                    "mitigation_techniques": ["user-training", "email-filtering", "application-isolation"]
                },
                {
                    "name": "PowerShell",
                    "mitre_id": "T1059.001",
                    "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                    "tactics": ["execution"],
                    "platforms": ["windows"],
                    "data_sources": ["powershell-logging", "process-monitoring", "command-logging"],
                    "detection_methods": ["script-analysis", "behavioral-analysis", "command-line-monitoring"],
                    "mitigation_techniques": ["execution-prevention", "powershell-restrictions", "application-control"]
                },
                {
                    "name": "Registry Run Keys / Startup Folder",
                    "mitre_id": "T1547.001",
                    "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
                    "tactics": ["persistence", "privilege-escalation"],
                    "platforms": ["windows"],
                    "data_sources": ["windows-registry", "file-monitoring", "process-monitoring"],
                    "detection_methods": ["registry-monitoring", "file-system-monitoring", "process-monitoring"],
                    "mitigation_techniques": ["limit-software-installation", "user-account-control", "execution-prevention"]
                },
                {
                    "name": "Process Injection",
                    "mitre_id": "T1055",
                    "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
                    "tactics": ["defense-evasion", "privilege-escalation"],
                    "platforms": ["windows", "macos", "linux"],
                    "data_sources": ["process-monitoring", "api-monitoring", "dll-monitoring"],
                    "detection_methods": ["behavioral-analysis", "memory-analysis", "api-monitoring"],
                    "mitigation_techniques": ["application-isolation", "behavior-prevention", "privileged-access-management"]
                },
                {
                    "name": "OS Credential Dumping",
                    "mitre_id": "T1003",
                    "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                    "tactics": ["credential-access"],
                    "platforms": ["windows", "macos", "linux"],
                    "data_sources": ["process-monitoring", "authentication-logs", "api-monitoring"],
                    "detection_methods": ["behavioral-analysis", "credential-dumping-detection", "process-monitoring"],
                    "mitigation_techniques": ["credential-access-protection", "privileged-access-management", "operating-system-configuration"]
                },
                {
                    "name": "Remote Desktop Protocol",
                    "mitre_id": "T1021.001",
                    "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
                    "tactics": ["lateral-movement"],
                    "platforms": ["windows"],
                    "data_sources": ["authentication-logs", "network-traffic", "logon-session-creation"],
                    "detection_methods": ["network-connection-monitoring", "authentication-log-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["network-segmentation", "multi-factor-authentication", "account-use-policies"]
                },
                {
                    "name": "Data Encrypted for Impact",
                    "mitre_id": "T1486",
                    "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
                    "tactics": ["impact"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "kernel-drivers"],
                    "detection_methods": ["file-system-monitoring", "behavioral-analysis", "process-monitoring"],
                    "mitigation_techniques": ["data-backup", "behavior-prevention", "operating-system-configuration"]
                },
                {
                    "name": "Exfiltration Over C2 Channel",
                    "mitre_id": "T1041",
                    "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                    "tactics": ["exfiltration"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["netflow-enclave-netflow", "network-protocol-analysis", "process-monitoring"],
                    "detection_methods": ["network-traffic-analysis", "behavioral-analysis", "data-loss-prevention"],
                    "mitigation_techniques": ["data-loss-prevention", "network-segmentation", "network-intrusion-prevention"]
                },
                {
                    "name": "Command and Scripting Interpreter",
                    "mitre_id": "T1059",
                    "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                    "tactics": ["execution"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["command-line-monitoring", "script-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "restrict-file-and-directory-permissions", "application-control"]
                },
                {
                    "name": "Valid Accounts",
                    "mitre_id": "T1078",
                    "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                    "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                    "platforms": ["linux", "macos", "windows", "containers"],
                    "data_sources": ["authentication-logs", "logon-session-creation"],
                    "detection_methods": ["authentication-log-analysis", "behavioral-analysis", "account-monitoring"],
                    "mitigation_techniques": ["multi-factor-authentication", "privileged-access-management", "account-use-policies"]
                },
                {
                    "name": "Windows Management Instrumentation",
                    "mitre_id": "T1047",
                    "description": "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.",
                    "tactics": ["execution"],
                    "platforms": ["windows"],
                    "data_sources": ["wmi-objects", "process-monitoring", "authentication-logs"],
                    "detection_methods": ["wmi-monitoring", "behavioral-analysis", "process-monitoring"],
                    "mitigation_techniques": ["user-account-control", "privileged-access-management", "execution-prevention"]
                },
                {
                    "name": "Scheduled Task/Job",
                    "mitre_id": "T1053",
                    "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
                    "tactics": ["execution", "persistence", "privilege-escalation"],
                    "platforms": ["windows", "linux", "macos"],
                    "data_sources": ["process-monitoring", "file-monitoring", "windows-event-logs"],
                    "detection_methods": ["scheduled-task-monitoring", "process-monitoring", "file-system-monitoring"],
                    "mitigation_techniques": ["user-account-control", "operating-system-configuration", "audit"]
                },
                {
                    "name": "File and Directory Discovery",
                    "mitre_id": "T1083",
                    "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "file-monitoring", "command-logging"],
                    "detection_methods": ["command-line-monitoring", "file-access-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["operating-system-configuration", "audit"]
                },
                {
                    "name": "System Information Discovery",
                    "mitre_id": "T1082",
                    "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["command-line-monitoring", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Network Service Discovery",
                    "mitre_id": "T1046",
                    "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["netflow-enclave-netflow", "network-protocol-analysis", "process-monitoring"],
                    "detection_methods": ["network-traffic-analysis", "process-monitoring", "network-device-logs"],
                    "mitigation_techniques": ["network-segmentation", "disable-or-remove-feature-or-program", "network-intrusion-prevention"]
                },
                {
                    "name": "Lateral Tool Transfer",
                    "mitre_id": "T1570",
                    "description": "Adversaries may transfer tools or other files between systems in a compromised environment.",
                    "tactics": ["lateral-movement"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "netflow-enclave-netflow", "network-protocol-analysis"],
                    "detection_methods": ["file-monitoring", "network-traffic-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["network-segmentation", "execution-prevention", "network-intrusion-prevention"]
                },
                {
                    "name": "Archive Collected Data",
                    "mitre_id": "T1560",
                    "description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration.",
                    "tactics": ["collection"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "command-logging"],
                    "detection_methods": ["file-monitoring", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["audit"]
                },
                {
                    "name": "Ingress Tool Transfer",
                    "mitre_id": "T1105",
                    "description": "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                    "tactics": ["command-and-control"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "netflow-enclave-netflow", "network-protocol-analysis"],
                    "detection_methods": ["file-monitoring", "network-traffic-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["network-intrusion-prevention", "execution-prevention", "network-segmentation"]
                },
                {
                    "name": "Application Layer Protocol",
                    "mitre_id": "T1071",
                    "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                    "tactics": ["command-and-control"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["netflow-enclave-netflow", "network-protocol-analysis", "packet-capture"],
                    "detection_methods": ["network-traffic-analysis", "protocol-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["network-intrusion-prevention", "network-segmentation", "restrict-web-based-content"]
                },
                {
                    "name": "Masquerading",
                    "mitre_id": "T1036",
                    "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "binary-file-metadata"],
                    "detection_methods": ["file-analysis", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "code-signing", "antivirus-antimalware"]
                }
            ]
            
            for technique_data in mitre_techniques:
                external_refs = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_data["mitre_id"],
                        "url": f"https://attack.mitre.org/techniques/{technique_data['mitre_id'].replace('.', '/')}"
                    }
                ]
                
                technique = cls(
                    name=technique_data["name"],
                    mitre_id=technique_data["mitre_id"],
                    description=technique_data["description"],
                    tactics=technique_data.get("tactics", []),
                    platforms=technique_data.get("platforms", ["windows"]),
                    data_sources=technique_data.get("data_sources", []),
                    detection_methods=technique_data.get("detection_methods", []),
                    mitigation_techniques=technique_data.get("mitigation_techniques", []),
                    confidence_score=85,
                    external_references=external_refs
                )
                db.session.add(technique)
            
            # Add additional techniques to reach 50+ entries
            additional_techniques = [
                {
                    "name": "Indicator Removal on Host",
                    "mitre_id": "T1070",
                    "description": "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "windows-event-logs"],
                    "detection_methods": ["file-deletion-monitoring", "log-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["restrict-file-and-directory-permissions", "operating-system-configuration"]
                },
                {
                    "name": "Disable or Modify Tools",
                    "mitre_id": "T1562.001",
                    "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "services", "windows-registry"],
                    "detection_methods": ["service-monitoring", "process-monitoring", "registry-monitoring"],
                    "mitigation_techniques": ["restrict-registry-permissions", "user-account-control", "operating-system-configuration"]
                },
                {
                    "name": "LSASS Memory",
                    "mitre_id": "T1003.001",
                    "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["process-monitoring", "process-memory-dumps", "api-monitoring"],
                    "detection_methods": ["memory-dump-analysis", "process-monitoring", "credential-dumping-detection"],
                    "mitigation_techniques": ["credential-access-protection", "privileged-access-management", "operating-system-configuration"]
                },
                {
                    "name": "Security Account Manager",
                    "mitre_id": "T1003.002",
                    "description": "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database.",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "windows-registry"],
                    "detection_methods": ["file-access-monitoring", "registry-monitoring", "credential-dumping-detection"],
                    "mitigation_techniques": ["credential-access-protection", "operating-system-configuration", "password-policies"]
                },
                {
                    "name": "DCSync",
                    "mitre_id": "T1003.006",
                    "description": "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API).",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["authentication-logs", "windows-event-logs", "network-protocol-analysis"],
                    "detection_methods": ["domain-controller-monitoring", "authentication-log-analysis", "network-traffic-analysis"],
                    "mitigation_techniques": ["privileged-access-management", "active-directory-configuration", "user-account-management"]
                },
                {
                    "name": "LSA Secrets",
                    "mitre_id": "T1003.004",
                    "description": "Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets.",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["windows-registry", "process-monitoring", "api-monitoring"],
                    "detection_methods": ["registry-monitoring", "process-monitoring", "credential-dumping-detection"],
                    "mitigation_techniques": ["credential-access-protection", "operating-system-configuration", "privileged-access-management"]
                },
                {
                    "name": "NTDS",
                    "mitre_id": "T1003.003",
                    "description": "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information.",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "authentication-logs"],
                    "detection_methods": ["file-access-monitoring", "process-monitoring", "domain-controller-monitoring"],
                    "mitigation_techniques": ["privileged-access-management", "credential-access-protection", "active-directory-configuration"]
                },
                {
                    "name": "Cached Domain Credentials",
                    "mitre_id": "T1003.005",
                    "description": "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.",
                    "tactics": ["credential-access"],
                    "platforms": ["windows"],
                    "data_sources": ["windows-registry", "process-monitoring"],
                    "detection_methods": ["registry-monitoring", "credential-dumping-detection", "process-monitoring"],
                    "mitigation_techniques": ["credential-access-protection", "operating-system-configuration", "password-policies"]
                },
                {
                    "name": "Windows Command Shell",
                    "mitre_id": "T1059.003",
                    "description": "Adversaries may abuse the Windows command shell for execution.",
                    "tactics": ["execution"],
                    "platforms": ["windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["command-line-monitoring", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "application-control", "operating-system-configuration"]
                },
                {
                    "name": "Visual Basic",
                    "mitre_id": "T1059.005",
                    "description": "Adversaries may abuse Visual Basic (VB) for execution.",
                    "tactics": ["execution"],
                    "platforms": ["windows", "macos"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["script-analysis", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "application-control", "disable-or-remove-feature-or-program"]
                },
                {
                    "name": "Python",
                    "mitre_id": "T1059.006",
                    "description": "Adversaries may abuse Python commands and scripts for execution.",
                    "tactics": ["execution"],
                    "platforms": ["linux", "windows", "macos"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["script-analysis", "process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": ["execution-prevention", "code-signing", "application-control"]
                },
                {
                    "name": "JavaScript",
                    "mitre_id": "T1059.007",
                    "description": "Adversaries may abuse various implementations of JavaScript for execution.",
                    "tactics": ["execution"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["script-analysis", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "application-control", "disable-or-remove-feature-or-program"]
                },
                {
                    "name": "Network Sniffing",
                    "mitre_id": "T1040",
                    "description": "Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.",
                    "tactics": ["credential-access", "discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["host-network-interface", "netflow-enclave-netflow"],
                    "detection_methods": ["network-device-logs", "host-network-interface-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["encrypt-sensitive-information", "multi-factor-authentication", "network-segmentation"]
                },
                {
                    "name": "Account Discovery",
                    "mitre_id": "T1087",
                    "description": "Adversaries may attempt to get a listing of accounts on a system or within an environment.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "api-monitoring"],
                    "detection_methods": ["command-line-monitoring", "process-monitoring", "api-monitoring"],
                    "mitigation_techniques": ["operating-system-configuration"]
                },
                {
                    "name": "Permission Groups Discovery",
                    "mitre_id": "T1069",
                    "description": "Adversaries may attempt to discover group and permission settings.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "api-monitoring"],
                    "detection_methods": ["command-line-monitoring", "process-monitoring", "api-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Remote System Discovery",
                    "mitre_id": "T1018",
                    "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "network-protocol-analysis"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring", "network-traffic-analysis"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Network Share Discovery",
                    "mitre_id": "T1135",
                    "description": "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection.",
                    "tactics": ["discovery"],
                    "platforms": ["macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "network-protocol-analysis"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring", "network-traffic-analysis"],
                    "mitigation_techniques": []
                },
                {
                    "name": "System Network Configuration Discovery",
                    "mitre_id": "T1016",
                    "description": "Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "System Owner/User Discovery",
                    "mitre_id": "T1033",
                    "description": "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Process Discovery",
                    "mitre_id": "T1057",
                    "description": "Adversaries may attempt to get information about running processes on a system.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Software Discovery",
                    "mitre_id": "T1518",
                    "description": "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "windows-registry"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring", "registry-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "System Service Discovery",
                    "mitre_id": "T1007",
                    "description": "Adversaries may try to gather information about registered local system services.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Query Registry",
                    "mitre_id": "T1012",
                    "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
                    "tactics": ["discovery"],
                    "platforms": ["windows"],
                    "data_sources": ["windows-registry", "process-monitoring", "command-logging"],
                    "detection_methods": ["registry-monitoring", "process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "System Time Discovery",
                    "mitre_id": "T1124",
                    "description": "An adversary may gather the system time and/or time zone from a local or remote system.",
                    "tactics": ["discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Virtualization/Sandbox Evasion",
                    "mitre_id": "T1497",
                    "description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments.",
                    "tactics": ["defense-evasion", "discovery"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging"],
                    "detection_methods": ["process-monitoring", "behavioral-analysis", "system-call-monitoring"],
                    "mitigation_techniques": []
                },
                {
                    "name": "Obfuscated Files or Information",
                    "mitre_id": "T1027",
                    "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "malware-reverse-engineering", "binary-file-metadata"],
                    "detection_methods": ["file-analysis", "behavioral-analysis", "signature-based"],
                    "mitigation_techniques": ["antivirus-antimalware", "network-intrusion-prevention"]
                },
                {
                    "name": "Deobfuscate/Decode Files or Information",
                    "mitre_id": "T1140",
                    "description": "Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["file-monitoring", "process-monitoring", "malware-reverse-engineering"],
                    "detection_methods": ["file-analysis", "process-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["antivirus-antimalware", "execution-prevention"]
                },
                {
                    "name": "System Binary Proxy Execution",
                    "mitre_id": "T1218",
                    "description": "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.",
                    "tactics": ["defense-evasion"],
                    "platforms": ["linux", "macos", "windows"],
                    "data_sources": ["process-monitoring", "command-logging", "binary-file-metadata"],
                    "detection_methods": ["process-monitoring", "command-line-monitoring", "behavioral-analysis"],
                    "mitigation_techniques": ["execution-prevention", "disable-or-remove-feature-or-program", "application-control"]
                },
                {
                    "name": "DLL Side-Loading",
                    "mitre_id": "T1574.002",
                    "description": "Adversaries may execute their own malicious payloads by side-loading DLLs.",
                    "tactics": ["persistence", "privilege-escalation", "defense-evasion"],
                    "platforms": ["windows"],
                    "data_sources": ["dll-monitoring", "file-monitoring", "process-monitoring"],
                    "detection_methods": ["dll-monitoring", "file-monitoring", "process-monitoring"],
                    "mitigation_techniques": ["execution-prevention", "restrict-file-and-directory-permissions", "audit"]
                },
                {
                    "name": "Web Shell",
                    "mitre_id": "T1505.003",
                    "description": "Adversaries may backdoor web servers with web shells to establish persistent access to systems.",
                    "tactics": ["persistence"],
                    "platforms": ["linux", "windows", "macos"],
                    "data_sources": ["file-monitoring", "network-traffic", "process-monitoring"],
                    "detection_methods": ["file-monitoring", "network-traffic-analysis", "behavioral-analysis"],
                    "mitigation_techniques": ["code-signing", "execution-prevention", "network-intrusion-prevention"]
                }
            ]
            
            for technique_data in additional_techniques:
                external_refs = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_data["mitre_id"],
                        "url": f"https://attack.mitre.org/techniques/{technique_data['mitre_id'].replace('.', '/')}"
                    }
                ]
                
                technique = cls(
                    name=technique_data["name"],
                    mitre_id=technique_data["mitre_id"],
                    description=technique_data["description"],
                    tactics=technique_data.get("tactics", []),
                    platforms=technique_data.get("platforms", ["windows"]),
                    data_sources=technique_data.get("data_sources", []),
                    detection_methods=technique_data.get("detection_methods", []),
                    mitigation_techniques=technique_data.get("mitigation_techniques", []),
                    confidence_score=85,
                    external_references=external_refs
                )
                db.session.add(technique)
            
            db.session.commit()
            print(f"Successfully seeded {cls.query.count()} MITRE ATT&CK techniques from comprehensive database")


class Campaign(db.Model):
    """Database model for threat intelligence campaigns"""
    __tablename__ = 'campaigns'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    
    # Campaign categorisation (British English)
    campaign_type = db.Column(db.String(50), default="cyber-espionage")  # nation-state, cybercriminal, hacktivist, apt, etc.
    sophistication_level = db.Column(db.String(20), default="intermediate")  # basic, intermediate, advanced, expert
    motivation = db.Column(db.String(50), default="espionage")  # financial, espionage, disruption, ideology
    
    # Targeting metadata
    target_sectors = db.Column(db.JSON, default=lambda: ["government"])  # finance, healthcare, government, etc.
    target_regions = db.Column(db.JSON, default=lambda: ["UK"])  # UK, EU, North America, etc.
    
    # Operational characteristics
    duration_category = db.Column(db.String(20), default="ongoing")  # short-term, ongoing, persistent
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence in attribution
    
    # Management fields
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<Campaign {self.name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active campaign"""
        campaigns = cls.query.filter_by(is_active=True).all()
        if campaigns:
            import random
            return random.choice(campaigns)
        return None
    
    @classmethod
    def seed_campaigns(cls):
        """Seed the database with comprehensive campaign data if none exist"""
        if cls.query.count() == 0:
            print("Seeding comprehensive campaign database...")
            
            # Comprehensive campaign database with 100 diverse entries
            campaigns_data = [
                # Nation-State Operations (20 campaigns)
                {
                    "name": "Operation Sovereign Shield",
                    "description": "Sophisticated state-sponsored reconnaissance targeting critical national infrastructure and government communications networks across NATO member states.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["government", "defence", "critical-infrastructure"],
                    "target_regions": ["UK", "EU", "North America"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Project Digital Dominion",
                    "description": "Long-term strategic intelligence gathering operation focusing on technological superiority and industrial espionage within telecommunications and semiconductor industries.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["telecommunications", "technology", "manufacturing"],
                    "target_regions": ["Asia-Pacific", "North America", "EU"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Crown Cyber Initiative",
                    "description": "Defensive cyber operation designed to identify and neutralise foreign intelligence services' infiltration attempts against UK government departments.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "defensive",
                    "target_sectors": ["government", "defence", "intelligence"],
                    "target_regions": ["UK"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Strategic Information Acquisition Programme",
                    "description": "Coordinated intelligence operation targeting diplomatic communications and trade negotiations between major economic powers.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["government", "diplomatic", "finance"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Northern Lights Protocol",
                    "description": "Arctic-focused geopolitical surveillance campaign monitoring resource extraction and territorial claims in polar regions.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["energy", "environment", "government"],
                    "target_regions": ["Arctic", "Northern Europe"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Operation Whitehall Breach",
                    "description": "Attempted infiltration of UK civil service networks targeting policy development and cabinet communications.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["government", "public-sector"],
                    "target_regions": ["UK"],
                    "duration_category": "short-term"
                },
                {
                    "name": "Digital Silk Road",
                    "description": "Economic espionage campaign targeting Belt and Road Initiative partners and competitor infrastructure projects.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["infrastructure", "logistics", "finance"],
                    "target_regions": ["Asia", "Africa", "EU"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Commonwealth Guardian",
                    "description": "Protective intelligence operation safeguarding Commonwealth nations' communications and shared security information.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "defensive",
                    "target_sectors": ["government", "defence", "diplomatic"],
                    "target_regions": ["Commonwealth"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Operation Trident Force",
                    "description": "Naval intelligence gathering focused on maritime territories, submarine capabilities, and underwater infrastructure.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["defence", "maritime", "energy"],
                    "target_regions": ["Global waters"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Diplomatic Harvest",
                    "description": "Systematic collection of diplomatic cables and negotiation strategies from international forums and summit meetings.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["diplomatic", "government", "international-organisations"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Fortress Protocol",
                    "description": "Comprehensive national cyber defence initiative protecting critical services from foreign interference.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "defensive",
                    "target_sectors": ["critical-infrastructure", "healthcare", "finance"],
                    "target_regions": ["UK"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Operation Eagle's Eye",
                    "description": "Surveillance programme monitoring global arms trade and weapons development programmes of adversarial nations.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["defence", "manufacturing", "research"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Celtic Shield Initiative",
                    "description": "Regional defence cooperation programme protecting Celtic nations' shared infrastructure and communications.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "defensive",
                    "target_sectors": ["government", "telecommunications", "energy"],
                    "target_regions": ["UK", "Ireland"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Pacific Gateway Operation",
                    "description": "Intelligence collection targeting trade routes and economic partnerships in the Indo-Pacific region.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["maritime", "logistics", "finance"],
                    "target_regions": ["Asia-Pacific"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Operation Parliament Watch",
                    "description": "Monitoring of democratic processes and election systems across allied nations to detect foreign interference.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "defensive",
                    "target_sectors": ["government", "electoral", "media"],
                    "target_regions": ["EU", "Commonwealth"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Diplomacy Campaign",
                    "description": "State-sponsored influence operation targeting international public opinion and diplomatic relationships.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "intermediate",
                    "motivation": "influence",
                    "target_sectors": ["media", "social-media", "diplomatic"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Operation Northern Star",
                    "description": "Arctic intelligence gathering focused on climate change impacts and new shipping routes accessibility.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["environment", "maritime", "energy"],
                    "target_regions": ["Arctic"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Westminster Intelligence Protocol",
                    "description": "Parliamentary security programme protecting legislative processes from foreign surveillance and influence.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "advanced",
                    "motivation": "defensive",
                    "target_sectors": ["government", "legislative"],
                    "target_regions": ["UK"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Global Trade Monitor",
                    "description": "Economic intelligence operation tracking international trade agreements and tariff negotiations.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "intermediate",
                    "motivation": "espionage",
                    "target_sectors": ["finance", "trade", "manufacturing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Operation Sovereign Defence",
                    "description": "Comprehensive national security programme protecting sovereignty against hybrid warfare threats.",
                    "campaign_type": "nation-state",
                    "sophistication_level": "expert",
                    "motivation": "defensive",
                    "target_sectors": ["defence", "critical-infrastructure", "media"],
                    "target_regions": ["UK"],
                    "duration_category": "persistent"
                },
                
                # Advanced Persistent Threats (15 campaigns)
                {
                    "name": "Silent Watchtower",
                    "description": "Persistent surveillance campaign maintaining long-term access to corporate networks whilst avoiding detection through advanced evasion techniques.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["technology", "finance", "research"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Persistent Observer Network",
                    "description": "Long-term intelligence gathering operation maintaining dormant access across multiple industry verticals for strategic intelligence collection.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["manufacturing", "healthcare", "energy"],
                    "target_regions": ["EU", "North America"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Deep Reconnaissance Programme",
                    "description": "Sophisticated multi-year operation targeting supply chain vulnerabilities and third-party service providers.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["supply-chain", "logistics", "technology"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Shadow Intelligence Collective",
                    "description": "Coordinated threat group conducting parallel operations against research institutions and academic networks.",
                    "campaign_type": "apt",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["education", "research", "pharmaceutical"],
                    "target_regions": ["North America", "EU"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Phantom Protocol",
                    "description": "Highly sophisticated operation employing zero-day exploits and custom malware for persistent network access.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["defence", "aerospace", "technology"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Ghost Protocol Initiative",
                    "description": "Stealth operation using legitimate administrative tools and living-off-the-land techniques to avoid detection.",
                    "campaign_type": "apt",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["government", "finance", "telecommunications"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Quantum Infiltration Network",
                    "description": "Next-generation threat actor utilising quantum-resistant encryption and advanced machine learning for adaptive attacks.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["research", "technology", "cryptography"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Invisible Empire Campaign",
                    "description": "Multi-stage operation establishing persistence across cloud infrastructure and hybrid environments.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["cloud-services", "technology", "finance"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Midnight Phoenix Operation",
                    "description": "Resurrection campaign re-establishing access after detection and remediation efforts by target organisations.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["defence", "government", "technology"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Chameleon Network Protocol",
                    "description": "Adaptive threat campaign changing tactics, techniques, and procedures based on target environment characteristics.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["multiple", "adaptive"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Digital Spectre Programme",
                    "description": "Memory-resident malware campaign avoiding filesystem detection through advanced in-memory execution techniques.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["finance", "government", "critical-infrastructure"],
                    "target_regions": ["EU", "North America"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Eternal Harvest Initiative",
                    "description": "Long-term data exfiltration operation maintaining minimal footprint whilst systematically collecting intellectual property.",
                    "campaign_type": "apt",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["research", "pharmaceutical", "technology"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Silicon Serpent Network",
                    "description": "Hardware-level compromise campaign targeting embedded systems and IoT infrastructure.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["manufacturing", "iot", "critical-infrastructure"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Shadow Cabinet Operation",
                    "description": "Parallel governance intelligence network monitoring policy development and cabinet-level decision making.",
                    "campaign_type": "apt",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["government", "policy", "diplomatic"],
                    "target_regions": ["UK", "EU", "Commonwealth"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Digital Archaeology Project",
                    "description": "Historical data recovery operation targeting archived communications and legacy system repositories.",
                    "campaign_type": "apt",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["archives", "government", "historical-records"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },

                # Cybercriminal Enterprises (15 campaigns)
                {
                    "name": "Digital Heist Consortium",
                    "description": "Organised cybercriminal network specialising in coordinated attacks against financial institutions and payment processors.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["finance", "banking", "payment-processing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Cyber Fraud Syndicate",
                    "description": "International criminal organisation conducting large-scale identity theft and financial fraud operations.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["retail", "e-commerce", "personal-data"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Underground Economy Operation",
                    "description": "Dark web marketplace facilitating the sale of stolen credentials, malware, and cybercriminal services.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["dark-web", "credentials", "malware-as-a-service"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Binary Bandits Collective",
                    "description": "Skilled cybercriminal group specialising in cryptocurrency theft and blockchain exploitation.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["cryptocurrency", "blockchain", "defi"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Phantom Profit Network",
                    "description": "Business email compromise specialists targeting corporate financial transactions and wire transfers.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["corporate", "finance", "real-estate"],
                    "target_regions": ["North America", "EU"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Pickpocket Guild",
                    "description": "Mobile banking and payment application exploitation targeting contactless payment systems.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["mobile-banking", "contactless-payment", "fintech"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Cyber Laundrette Scheme",
                    "description": "Money laundering operation using cryptocurrency mixing services and shell company networks.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["cryptocurrency", "shell-companies", "money-laundering"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Invoice Fraud Empire",
                    "description": "Large-scale invoice manipulation and accounts payable fraud targeting supply chain payments.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["supply-chain", "accounts-payable", "corporate"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Counterfeit Workshop",
                    "description": "Online marketplace for counterfeit goods and fraudulent e-commerce transactions.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "basic",
                    "motivation": "financial",
                    "target_sectors": ["e-commerce", "counterfeit-goods", "retail"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Credential Bazaar Network",
                    "description": "Stolen credential marketplace specialising in corporate and government account access.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["credentials", "corporate", "government"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "ATM Jackpot Coalition",
                    "description": "Physical and cyber attacks against automated teller machines and point-of-sale systems.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["atm", "pos-systems", "retail"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "SIM Swap Syndicate",
                    "description": "Mobile phone number hijacking for cryptocurrency theft and two-factor authentication bypass.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["telecommunications", "cryptocurrency", "2fa"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Deepfake Extortion Ring",
                    "description": "AI-generated compromising content creation for blackmail and extortion purposes.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["ai", "deepfake", "extortion"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Cloud Resource Pirates",
                    "description": "Unauthorised cloud computing resource usage for cryptocurrency mining and resource arbitrage.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["cloud-computing", "cryptocurrency-mining"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Insurance Fraud Network",
                    "description": "Coordinated insurance claim fraud using fabricated cyber incidents and staged data breaches.",
                    "campaign_type": "cybercriminal",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["insurance", "cyber-insurance", "claims"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },

                # Ransomware Operations (10 campaigns)
                {
                    "name": "CryptoLock Enterprise",
                    "description": "Professional ransomware-as-a-service operation targeting large enterprises with sophisticated encryption and payment systems.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["enterprise", "healthcare", "manufacturing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Digital Hostage Initiative",
                    "description": "Multi-stage ransomware campaign combining data encryption with data exfiltration for double extortion schemes.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["corporate", "healthcare", "education"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Encrypted Ransom Programme",
                    "description": "Systematic targeting of backup systems and disaster recovery infrastructure to maximise ransom leverage.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["enterprise", "cloud-storage", "backup-services"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Quantum Cipher Syndicate",
                    "description": "Next-generation ransomware utilising quantum-resistant encryption algorithms and AI-driven targeting.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "expert",
                    "motivation": "financial",
                    "target_sectors": ["technology", "research", "finance"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Infrastructure Lockdown Campaign",
                    "description": "Critical infrastructure-focused ransomware targeting power grids, water treatment, and transportation systems.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "expert",
                    "motivation": "financial",
                    "target_sectors": ["critical-infrastructure", "utilities", "transport"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Hospital Siege Network",
                    "description": "Healthcare-targeted ransomware exploiting life-critical system dependencies for maximum pressure.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["healthcare", "medical-devices", "patient-data"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Municipal Mayhem Operation",
                    "description": "Local government ransomware campaign targeting council services and public administration systems.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["local-government", "public-services", "municipal"],
                    "target_regions": ["UK", "EU", "North America"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Supply Chain Stranglehold",
                    "description": "Ransomware targeting supply chain management systems to disrupt global logistics networks.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["supply-chain", "logistics", "manufacturing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Academic Archive Assault",
                    "description": "Educational institution ransomware focusing on research data and student information systems.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "intermediate",
                    "motivation": "financial",
                    "target_sectors": ["education", "research", "student-data"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Financial Fortress Breach",
                    "description": "Banking sector ransomware designed to bypass financial security controls and target transaction systems.",
                    "campaign_type": "ransomware",
                    "sophistication_level": "expert",
                    "motivation": "financial",
                    "target_sectors": ["banking", "finance", "transaction-processing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },

                # Hacktivist Groups (10 campaigns)
                {
                    "name": "Digital Justice Collective",
                    "description": "Ideologically motivated group targeting perceived injustices through coordinated cyber protests and data leaks.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "intermediate",
                    "motivation": "ideology",
                    "target_sectors": ["government", "corporate", "media"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Cyber Rights Movement",
                    "description": "Digital privacy advocates conducting operations against surveillance programmes and data collection practices.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "advanced",
                    "motivation": "ideology",
                    "target_sectors": ["surveillance", "data-collection", "privacy"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Information Liberation Front",
                    "description": "Transparency activists targeting classified documents and corporate secrets for public disclosure.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "advanced",
                    "motivation": "ideology",
                    "target_sectors": ["government", "corporate", "classified-information"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Environmental Cyber Warriors",
                    "description": "Climate activist network targeting fossil fuel companies and environmental polluters through cyber operations.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "intermediate",
                    "motivation": "ideology",
                    "target_sectors": ["energy", "fossil-fuel", "environmental"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Anonymous Parliament",
                    "description": "Decentralised activist collective targeting authoritarian governments and human rights violators.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "intermediate",
                    "motivation": "ideology",
                    "target_sectors": ["authoritarian-governments", "human-rights", "censorship"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Digital Suffragettes",
                    "description": "Gender equality activists targeting discrimination and harassment through coordinated cyber campaigns.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "basic",
                    "motivation": "ideology",
                    "target_sectors": ["gender-equality", "workplace-discrimination", "harassment"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Open Source Insurgency",
                    "description": "Software freedom activists targeting proprietary software companies and digital rights management systems.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "advanced",
                    "motivation": "ideology",
                    "target_sectors": ["software", "drm", "intellectual-property"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Anti-Censorship Alliance",
                    "description": "Free speech advocates targeting internet censorship and content blocking systems worldwide.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "intermediate",
                    "motivation": "ideology",
                    "target_sectors": ["censorship", "internet-freedom", "content-blocking"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Whistleblower Protection Network",
                    "description": "Secure communication platform for whistleblowers and investigative journalists exposing corruption.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "advanced",
                    "motivation": "ideology",
                    "target_sectors": ["journalism", "whistleblowing", "corruption"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Digital Rebellion Collective",
                    "description": "Anti-establishment activists targeting government surveillance and corporate data harvesting practices.",
                    "campaign_type": "hacktivist",
                    "sophistication_level": "intermediate",
                    "motivation": "ideology",
                    "target_sectors": ["surveillance", "data-harvesting", "anti-establishment"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },

                # Industrial Espionage (10 campaigns)
                {
                    "name": "Corporate Intelligence Harvest",
                    "description": "Systematic industrial espionage targeting research and development departments of technology companies.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["technology", "research", "development"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Industrial Secrets Programme",
                    "description": "Long-term operation targeting manufacturing processes and proprietary designs across multiple industries.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["manufacturing", "design", "proprietary-technology"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Competitive Advantage Operation",
                    "description": "Commercial espionage targeting merger and acquisition intelligence and strategic business planning.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "intermediate",
                    "motivation": "espionage",
                    "target_sectors": ["corporate", "mergers-acquisitions", "strategic-planning"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Patent Pirates Network",
                    "description": "Intellectual property theft operation targeting patent applications and proprietary research data.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["patents", "intellectual-property", "research"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Pharmaceutical Infiltration Campaign",
                    "description": "Drug development espionage targeting clinical trial data and pharmaceutical research programmes.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["pharmaceutical", "clinical-trials", "drug-development"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Automotive Design Theft Ring",
                    "description": "Automotive industry espionage targeting electric vehicle technology and autonomous driving systems.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["automotive", "electric-vehicles", "autonomous-driving"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Aerospace Intelligence Network",
                    "description": "Aviation and space technology espionage targeting defence contractors and aerospace manufacturers.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["aerospace", "defence-contractors", "aviation"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Semiconductor Secrets Operation",
                    "description": "Microprocessor and chip design espionage targeting semiconductor manufacturing and design processes.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["semiconductors", "microprocessors", "chip-design"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Energy Innovation Infiltration",
                    "description": "Renewable energy technology theft targeting solar, wind, and battery storage innovations.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["renewable-energy", "solar", "wind", "battery-storage"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Biotechnology Acquisition Campaign",
                    "description": "Genetic engineering and biotechnology espionage targeting CRISPR research and gene therapy development.",
                    "campaign_type": "industrial-espionage",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["biotechnology", "genetic-engineering", "gene-therapy"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },

                # Critical Infrastructure (10 campaigns)
                {
                    "name": "Infrastructure Vulnerability Assessment",
                    "description": "Systematic probing of critical infrastructure systems to identify weaknesses and potential attack vectors.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["critical-infrastructure", "utilities", "transport"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Critical Systems Reconnaissance",
                    "description": "Intelligence gathering operation mapping critical system dependencies and single points of failure.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["critical-systems", "dependencies", "infrastructure"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "National Grid Infiltration",
                    "description": "Power grid penetration testing and vulnerability assessment targeting electrical distribution systems.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["power-grid", "electrical-distribution", "energy"],
                    "target_regions": ["UK", "EU"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Water System Surveillance",
                    "description": "Water treatment and distribution infrastructure monitoring targeting supply chain security.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["water-treatment", "water-distribution", "public-health"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Transport Network Mapping",
                    "description": "Transportation infrastructure intelligence gathering targeting rail, road, and aviation control systems.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["transport", "rail", "aviation", "traffic-control"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Telecommunications Backbone Probe",
                    "description": "Communications infrastructure assessment targeting fibre optic networks and cellular base stations.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["telecommunications", "fibre-optic", "cellular"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Emergency Services Integration",
                    "description": "Emergency response system reconnaissance targeting police, fire, and medical emergency coordination.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["emergency-services", "police", "fire", "medical"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Industrial Control Surveillance",
                    "description": "SCADA and industrial control system monitoring targeting manufacturing and process control environments.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["scada", "industrial-control", "manufacturing"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                },
                {
                    "name": "Financial Infrastructure Audit",
                    "description": "Banking and financial system infrastructure assessment targeting payment processing and settlement systems.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["financial-infrastructure", "payment-processing", "settlement"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Supply Chain Vulnerability Scan",
                    "description": "Critical supply chain infrastructure monitoring targeting logistics hubs and distribution centres.",
                    "campaign_type": "critical-infrastructure",
                    "sophistication_level": "advanced",
                    "motivation": "espionage",
                    "target_sectors": ["supply-chain", "logistics", "distribution"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },

                # Financial Sector Targeting (5 campaigns) - Completing 100 total
                {
                    "name": "Banking System Compromise",
                    "description": "Systematic penetration of core banking systems targeting transaction processing and customer account databases.",
                    "campaign_type": "financial-targeting",
                    "sophistication_level": "expert",
                    "motivation": "financial",
                    "target_sectors": ["banking", "core-banking", "transaction-processing"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Financial Market Manipulation",
                    "description": "High-frequency trading system exploitation and market data manipulation for insider trading advantages.",
                    "campaign_type": "financial-targeting",
                    "sophistication_level": "expert",
                    "motivation": "financial",
                    "target_sectors": ["trading", "market-data", "hft"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Payment Network Infiltration",
                    "description": "Credit card and digital payment system penetration targeting transaction routing and settlement processes.",
                    "campaign_type": "financial-targeting",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["payment-networks", "credit-cards", "digital-payments"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Cryptocurrency Exchange Siege",
                    "description": "Digital asset platform targeting focusing on wallet security and exchange operational infrastructure.",
                    "campaign_type": "financial-targeting",
                    "sophistication_level": "advanced",
                    "motivation": "financial",
                    "target_sectors": ["cryptocurrency", "digital-assets", "exchanges"],
                    "target_regions": ["Global"],
                    "duration_category": "ongoing"
                },
                {
                    "name": "Central Bank Intelligence Operation",
                    "description": "Monetary policy espionage targeting central bank communications and economic forecasting data.",
                    "campaign_type": "financial-targeting",
                    "sophistication_level": "expert",
                    "motivation": "espionage",
                    "target_sectors": ["central-banking", "monetary-policy", "economic-data"],
                    "target_regions": ["Global"],
                    "duration_category": "persistent"
                }
            ]
            
            # Continue with more campaigns in next iteration...
            for campaign_data in campaigns_data:
                campaign = cls(
                    name=campaign_data["name"],
                    description=campaign_data["description"],
                    campaign_type=campaign_data.get("campaign_type", "cyber-espionage"),
                    sophistication_level=campaign_data.get("sophistication_level", "intermediate"),
                    motivation=campaign_data.get("motivation", "espionage"),
                    target_sectors=campaign_data.get("target_sectors", ["government"]),
                    target_regions=campaign_data.get("target_regions", ["UK"]),
                    duration_category=campaign_data.get("duration_category", "ongoing"),
                    confidence_score=campaign_data.get("confidence_score", 75)
                )
                db.session.add(campaign)
            
            db.session.commit()
            print(f"Successfully seeded {cls.query.count()} comprehensive campaigns from threat intelligence database")


class ReportTemplate(db.Model):
    """Database model for threat intelligence report templates"""
    __tablename__ = 'report_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    template_name = db.Column(db.String(255), nullable=False)
    title_format = db.Column(db.String(500), nullable=False)  # Template with placeholders like {threat_actor_name}
    description_format = db.Column(db.Text, nullable=False)   # Template with placeholders
    report_type = db.Column(db.String(50), default="intelligence-brief")  # intelligence-brief, ioc-analysis, etc.
    url_pattern = db.Column(db.String(500))  # URL template with placeholders
    
    # Categorisation
    report_category = db.Column(db.String(50), default="technical")  # technical, strategic, tactical, operational
    target_audience = db.Column(db.String(50), default="analysts")  # analysts, executives, operators, researchers
    
    # Management fields
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<ReportTemplate {self.template_name}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active report template"""
        templates = cls.query.filter_by(is_active=True).all()
        if templates:
            import random
            return random.choice(templates)
        return None
    
    @classmethod
    def seed_report_templates(cls):
        """Seed the database with comprehensive report templates if none exist"""
        if cls.query.count() == 0:
            print("Seeding comprehensive report template database...")
            
            # 50 diverse report templates (10x expansion from original 5)
            templates_data = [
                # Intelligence Briefs (15 templates)
                {
                    "template_name": "Threat Intelligence Brief",
                    "title_format": "Threat Intelligence Brief: {threat_actor_name} Campaign Analysis",
                    "description_format": "Comprehensive threat intelligence brief analysing {threat_actor_name} activities and associated {campaign_name} infrastructure indicators. Strategic assessment of threat capabilities, targeting patterns, and recommended defensive measures.",
                    "report_type": "intelligence-brief",
                    "url_pattern": "https://simonsigre.com/threat-brief-{threat_actor_slug}-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Attribution Analysis",
                    "title_format": "Attribution Analysis: {threat_actor_name} Operational Security Assessment",
                    "description_format": "Detailed attribution analysis examining {threat_actor_name} operational security practices, infrastructure patterns, and behavioural indicators associated with {campaign_name}.",
                    "report_type": "attribution-analysis",
                    "url_pattern": "https://simonsigre.com/attribution-{threat_actor_slug}.pdf",
                    "report_category": "analytical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Strategic Threat Assessment",
                    "title_format": "Strategic Assessment: {campaign_name} Long-term Implications",
                    "description_format": "Strategic threat assessment evaluating the long-term implications of {campaign_name} activities conducted by {threat_actor_name}, including geopolitical context and industry impact analysis.",
                    "report_type": "strategic-assessment",
                    "url_pattern": "https://simonsigre.com/strategic-assessment-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Threat Actor Profile",
                    "title_format": "Threat Actor Profile: {threat_actor_name} Capabilities and Targeting",
                    "description_format": "Comprehensive threat actor profile documenting {threat_actor_name} capabilities, historical targeting patterns, and operational methodologies observed in {campaign_name}.",
                    "report_type": "actor-profile",
                    "url_pattern": "https://simonsigre.com/profile-{threat_actor_slug}.pdf",
                    "report_category": "analytical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Campaign Intelligence Summary",
                    "title_format": "Campaign Intelligence: {campaign_name} Technical Indicators and Mitigation",
                    "description_format": "Campaign intelligence summary providing technical indicators, defensive recommendations, and mitigation strategies for {campaign_name} activities attributed to {threat_actor_name}.",
                    "report_type": "campaign-intelligence",
                    "url_pattern": "https://simonsigre.com/campaign-intel-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Quarterly Threat Landscape",
                    "title_format": "Quarterly Threat Review: {campaign_name} Activity Trends",
                    "description_format": "Quarterly threat landscape analysis highlighting {campaign_name} activity trends and {threat_actor_name} tactical evolution patterns observed across multiple sectors.",
                    "report_type": "quarterly-review",
                    "url_pattern": "https://simonsigre.com/quarterly-threat-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Emerging Threat Alert",
                    "title_format": "Emerging Threat Alert: {threat_actor_name} New Campaign Detected",
                    "description_format": "Urgent threat alert documenting newly identified {campaign_name} activities by {threat_actor_name}, including immediate indicators and preliminary assessment of threat impact.",
                    "report_type": "threat-alert",
                    "url_pattern": "https://simonsigre.com/threat-alert-{threat_actor_slug}-{campaign_slug}.pdf",
                    "report_category": "tactical",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Industry Threat Brief",
                    "title_format": "Industry Brief: {campaign_name} Sector-Specific Targeting",
                    "description_format": "Industry-focused threat brief examining {campaign_name} targeting patterns and {threat_actor_name} sector-specific tactics, techniques, and procedures.",
                    "report_type": "industry-brief",
                    "url_pattern": "https://simonsigre.com/industry-brief-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Geopolitical Threat Context",
                    "title_format": "Geopolitical Context: {threat_actor_name} State-Sponsored Activities",
                    "description_format": "Geopolitical threat analysis providing context for {threat_actor_name} state-sponsored activities within {campaign_name}, including regional implications and diplomatic considerations.",
                    "report_type": "geopolitical-analysis",
                    "url_pattern": "https://simonsigre.com/geopolitical-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Threat Intelligence Digest",
                    "title_format": "Weekly Digest: {campaign_name} Activity Summary",
                    "description_format": "Weekly threat intelligence digest summarising {campaign_name} activities, {threat_actor_name} operational updates, and key developments in threat landscape.",
                    "report_type": "weekly-digest",
                    "url_pattern": "https://simonsigre.com/weekly-digest-{campaign_slug}.pdf",
                    "report_category": "tactical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Executive Threat Briefing",
                    "title_format": "Executive Briefing: {threat_actor_name} Strategic Implications",
                    "description_format": "Executive-level briefing outlining strategic implications of {threat_actor_name} activities within {campaign_name}, including business risk assessment and recommended organisational responses.",
                    "report_type": "executive-briefing",
                    "url_pattern": "https://simonsigre.com/executive-briefing-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Threat Hunting Guidance",
                    "title_format": "Threat Hunting: {campaign_name} Detection Strategies",
                    "description_format": "Threat hunting guidance document providing detection strategies, hunting hypotheses, and investigative approaches for identifying {campaign_name} activities by {threat_actor_name}.",
                    "report_type": "hunting-guidance",
                    "url_pattern": "https://simonsigre.com/hunting-guidance-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Cyber Threat Landscape",
                    "title_format": "Threat Landscape: {campaign_name} Regional Impact Analysis",
                    "description_format": "Comprehensive threat landscape analysis examining {campaign_name} regional impact and {threat_actor_name} geographical targeting preferences across multiple territories.",
                    "report_type": "landscape-analysis",
                    "url_pattern": "https://simonsigre.com/landscape-{campaign_slug}.pdf",
                    "report_category": "analytical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Threat Research Publication",
                    "title_format": "Research Publication: {threat_actor_name} Technical Analysis",
                    "description_format": "Detailed research publication documenting technical analysis of {threat_actor_name} methodologies observed in {campaign_name}, including novel techniques and tool development.",
                    "report_type": "research-publication",
                    "url_pattern": "https://simonsigre.com/research-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Flash Intelligence Report",
                    "title_format": "Flash Report: {campaign_name} Urgent Intelligence Update",
                    "description_format": "Flash intelligence report providing urgent updates on {campaign_name} developments and {threat_actor_name} operational changes requiring immediate attention.",
                    "report_type": "flash-report",
                    "url_pattern": "https://simonsigre.com/flash-report-{campaign_slug}.pdf",
                    "report_category": "tactical",
                    "target_audience": "operators"
                },

                # Technical Analysis Reports (15 templates)
                {
                    "template_name": "IOC Analysis Report",
                    "title_format": "IOC Analysis: {campaign_name} Infrastructure and TTPs",
                    "description_format": "Comprehensive IOC analysis documenting {campaign_name} infrastructure indicators, tactics, techniques, and procedures employed by {threat_actor_name}.",
                    "report_type": "ioc-analysis",
                    "url_pattern": "https://simonsigre.com/ioc-analysis-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Malware Technical Analysis",
                    "title_format": "Malware Analysis: {campaign_name} Custom Toolset Breakdown",
                    "description_format": "Technical malware analysis documenting custom tools and malicious software employed in {campaign_name} by {threat_actor_name}, including reverse engineering findings.",
                    "report_type": "malware-analysis",
                    "url_pattern": "https://simonsigre.com/malware-analysis-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Infrastructure Mapping",
                    "title_format": "Infrastructure Map: {threat_actor_name} Command and Control Network",
                    "description_format": "Detailed infrastructure mapping documenting {threat_actor_name} command and control networks utilised in {campaign_name}, including network topology and communication protocols.",
                    "report_type": "infrastructure-mapping",
                    "url_pattern": "https://simonsigre.com/infrastructure-map-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Network Compromise Assessment",
                    "title_format": "Network Assessment: {campaign_name} Intrusion Methodology",
                    "description_format": "Network compromise assessment detailing {threat_actor_name} intrusion methodologies and lateral movement techniques observed during {campaign_name}.",
                    "report_type": "network-assessment",
                    "url_pattern": "https://simonsigre.com/network-assessment-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Vulnerability Exploitation Analysis",
                    "title_format": "Exploit Analysis: {campaign_name} Zero-Day and N-Day Usage",
                    "description_format": "Vulnerability exploitation analysis examining {threat_actor_name} use of zero-day and n-day vulnerabilities within {campaign_name} operations.",
                    "report_type": "exploit-analysis",
                    "url_pattern": "https://simonsigre.com/exploit-analysis-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Digital Forensics Report",
                    "title_format": "Forensics Analysis: {campaign_name} Incident Investigation",
                    "description_format": "Digital forensics investigation report documenting {threat_actor_name} attack methodologies and evidence collection from {campaign_name} incidents.",
                    "report_type": "forensics-analysis",
                    "url_pattern": "https://simonsigre.com/forensics-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Code Analysis Report",
                    "title_format": "Code Analysis: {threat_actor_name} Custom Tool Development",
                    "description_format": "Source code analysis documenting {threat_actor_name} custom tool development and code reuse patterns observed in {campaign_name}.",
                    "report_type": "code-analysis",
                    "url_pattern": "https://simonsigre.com/code-analysis-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Network Traffic Analysis",
                    "title_format": "Network Analysis: {campaign_name} Communication Patterns",
                    "description_format": "Network traffic analysis documenting {threat_actor_name} communication patterns and protocol usage within {campaign_name} operations.",
                    "report_type": "network-analysis",
                    "url_pattern": "https://simonsigre.com/network-analysis-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Cryptographic Analysis",
                    "title_format": "Crypto Analysis: {threat_actor_name} Encryption Methods",
                    "description_format": "Cryptographic analysis examining {threat_actor_name} encryption methods and cryptographic implementations used in {campaign_name}.",
                    "report_type": "crypto-analysis",
                    "url_pattern": "https://simonsigre.com/crypto-analysis-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Behavioural Analysis Report",
                    "title_format": "Behavioural Analysis: {threat_actor_name} Operational Patterns",
                    "description_format": "Behavioural analysis documenting {threat_actor_name} operational patterns and decision-making processes observed during {campaign_name}.",
                    "report_type": "behavioural-analysis",
                    "url_pattern": "https://simonsigre.com/behavioural-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Memory Forensics Report",
                    "title_format": "Memory Forensics: {campaign_name} Runtime Analysis",
                    "description_format": "Memory forensics analysis documenting runtime artefacts and process behaviour associated with {threat_actor_name} activities in {campaign_name}.",
                    "report_type": "memory-forensics",
                    "url_pattern": "https://simonsigre.com/memory-forensics-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Timeline Analysis",
                    "title_format": "Timeline Analysis: {campaign_name} Attack Progression",
                    "description_format": "Comprehensive timeline analysis documenting {threat_actor_name} attack progression and operational phases throughout {campaign_name}.",
                    "report_type": "timeline-analysis",
                    "url_pattern": "https://simonsigre.com/timeline-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "analysts"
                },
                {
                    "template_name": "Tool Signature Analysis",
                    "title_format": "Tool Signatures: {threat_actor_name} Arsenal Documentation",
                    "description_format": "Tool signature analysis documenting {threat_actor_name} arsenal and tool usage patterns observed throughout {campaign_name} operations.",
                    "report_type": "tool-analysis",
                    "url_pattern": "https://simonsigre.com/tool-analysis-{threat_actor_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },
                {
                    "template_name": "Protocol Analysis Report",
                    "title_format": "Protocol Analysis: {campaign_name} Communication Protocols",
                    "description_format": "Network protocol analysis examining {threat_actor_name} communication protocols and data exfiltration methods used in {campaign_name}.",
                    "report_type": "protocol-analysis",
                    "url_pattern": "https://simonsigre.com/protocol-analysis-{campaign_slug}.pdf",
                    "report_category": "technical",
                    "target_audience": "researchers"
                },

                # Operational Reports (10 templates)
                {
                    "template_name": "Incident Response Playbook",
                    "title_format": "IR Playbook: {campaign_name} Response Procedures",
                    "description_format": "Incident response playbook providing step-by-step procedures for responding to {campaign_name} incidents attributed to {threat_actor_name}.",
                    "report_type": "ir-playbook",
                    "url_pattern": "https://simonsigre.com/ir-playbook-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Detection Rules Package",
                    "title_format": "Detection Rules: {threat_actor_name} Signature Set",
                    "description_format": "Comprehensive detection rules package for identifying {threat_actor_name} activities and {campaign_name} indicators across security tools.",
                    "report_type": "detection-rules",
                    "url_pattern": "https://simonsigre.com/detection-rules-{threat_actor_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Mitigation Strategy Guide",
                    "title_format": "Mitigation Guide: {campaign_name} Defence Strategies",
                    "description_format": "Comprehensive mitigation strategy guide providing defensive measures and hardening techniques against {threat_actor_name} methods used in {campaign_name}.",
                    "report_type": "mitigation-guide",
                    "url_pattern": "https://simonsigre.com/mitigation-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Threat Simulation Exercise",
                    "title_format": "Red Team Exercise: {threat_actor_name} TTPs Simulation",
                    "description_format": "Threat simulation exercise documentation replicating {threat_actor_name} tactics, techniques, and procedures observed in {campaign_name}.",
                    "report_type": "red-team-exercise",
                    "url_pattern": "https://simonsigre.com/red-team-{threat_actor_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Security Control Assessment",
                    "title_format": "Control Assessment: {campaign_name} Defence Evaluation",
                    "description_format": "Security control assessment evaluating organisational defences against {threat_actor_name} techniques demonstrated in {campaign_name}.",
                    "report_type": "control-assessment",
                    "url_pattern": "https://simonsigre.com/control-assessment-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Operational Risk Assessment",
                    "title_format": "Risk Assessment: {threat_actor_name} Operational Impact",
                    "description_format": "Operational risk assessment examining potential business impacts and operational disruption from {threat_actor_name} activities in {campaign_name}.",
                    "report_type": "risk-assessment",
                    "url_pattern": "https://simonsigre.com/risk-assessment-{threat_actor_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Purple Team Analysis",
                    "title_format": "Purple Team Report: {campaign_name} Defence Testing",
                    "description_format": "Purple team analysis combining offensive and defensive perspectives on {threat_actor_name} techniques from {campaign_name}.",
                    "report_type": "purple-team",
                    "url_pattern": "https://simonsigre.com/purple-team-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Recovery Procedures Guide",
                    "title_format": "Recovery Guide: {campaign_name} System Restoration",
                    "description_format": "System recovery procedures guide for restoring operations after {threat_actor_name} compromise incidents related to {campaign_name}.",
                    "report_type": "recovery-guide",
                    "url_pattern": "https://simonsigre.com/recovery-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "Tabletop Exercise Scenario",
                    "title_format": "Tabletop Exercise: {threat_actor_name} Scenario Planning",
                    "description_format": "Tabletop exercise scenario based on {threat_actor_name} activities and {campaign_name} attack patterns for incident response training.",
                    "report_type": "tabletop-exercise",
                    "url_pattern": "https://simonsigre.com/tabletop-{threat_actor_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },
                {
                    "template_name": "SIEM Rule Development",
                    "title_format": "SIEM Rules: {campaign_name} Detection Logic",
                    "description_format": "SIEM rule development guide providing detection logic and correlation rules for identifying {threat_actor_name} activities from {campaign_name}.",
                    "report_type": "siem-rules",
                    "url_pattern": "https://simonsigre.com/siem-rules-{campaign_slug}.pdf",
                    "report_category": "operational",
                    "target_audience": "operators"
                },

                # Sector-Specific Reports (10 templates)
                {
                    "template_name": "Financial Sector Threat Brief",
                    "title_format": "Financial Sector Brief: {campaign_name} Banking Targets",
                    "description_format": "Financial sector-specific threat brief examining {threat_actor_name} targeting of banking and financial services within {campaign_name}.",
                    "report_type": "financial-sector",
                    "url_pattern": "https://simonsigre.com/financial-brief-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Healthcare Security Assessment",
                    "title_format": "Healthcare Assessment: {threat_actor_name} Medical Targeting",
                    "description_format": "Healthcare security assessment examining {threat_actor_name} targeting of medical institutions and patient data in {campaign_name}.",
                    "report_type": "healthcare-assessment",
                    "url_pattern": "https://simonsigre.com/healthcare-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Government Targeting Analysis",
                    "title_format": "Government Analysis: {campaign_name} Public Sector Impact",
                    "description_format": "Government targeting analysis examining {threat_actor_name} focus on public sector institutions and citizen services within {campaign_name}.",
                    "report_type": "government-analysis",
                    "url_pattern": "https://simonsigre.com/government-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Critical Infrastructure Report",
                    "title_format": "Infrastructure Report: {threat_actor_name} Utility Targeting",
                    "description_format": "Critical infrastructure report examining {threat_actor_name} targeting of utilities and essential services within {campaign_name}.",
                    "report_type": "infrastructure-report",
                    "url_pattern": "https://simonsigre.com/infrastructure-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Supply Chain Risk Analysis",
                    "title_format": "Supply Chain Analysis: {campaign_name} Vendor Targeting",
                    "description_format": "Supply chain risk analysis examining {threat_actor_name} targeting of suppliers and vendor relationships within {campaign_name}.",
                    "report_type": "supply-chain",
                    "url_pattern": "https://simonsigre.com/supply-chain-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Education Sector Brief",
                    "title_format": "Education Brief: {threat_actor_name} Academic Targeting",
                    "description_format": "Education sector brief examining {threat_actor_name} targeting of academic institutions and research data within {campaign_name}.",
                    "report_type": "education-brief",
                    "url_pattern": "https://simonsigre.com/education-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Energy Sector Analysis",
                    "title_format": "Energy Analysis: {campaign_name} Resource Targeting",
                    "description_format": "Energy sector analysis examining {threat_actor_name} targeting of energy companies and resource extraction within {campaign_name}.",
                    "report_type": "energy-analysis",
                    "url_pattern": "https://simonsigre.com/energy-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Manufacturing Threat Assessment",
                    "title_format": "Manufacturing Assessment: {threat_actor_name} Industrial Espionage",
                    "description_format": "Manufacturing threat assessment examining {threat_actor_name} industrial espionage and intellectual property theft within {campaign_name}.",
                    "report_type": "manufacturing-assessment",
                    "url_pattern": "https://simonsigre.com/manufacturing-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Technology Sector Report",
                    "title_format": "Technology Report: {campaign_name} Innovation Theft",
                    "description_format": "Technology sector report examining {threat_actor_name} targeting of technology companies and innovation theft within {campaign_name}.",
                    "report_type": "technology-report",
                    "url_pattern": "https://simonsigre.com/technology-{campaign_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                },
                {
                    "template_name": "Legal Sector Analysis",
                    "title_format": "Legal Analysis: {threat_actor_name} Law Firm Targeting",
                    "description_format": "Legal sector analysis examining {threat_actor_name} targeting of law firms and legal privileged information within {campaign_name}.",
                    "report_type": "legal-analysis",
                    "url_pattern": "https://simonsigre.com/legal-{threat_actor_slug}.pdf",
                    "report_category": "strategic",
                    "target_audience": "executives"
                }
            ]
            
            # Create and add all report templates
            for template_data in templates_data:
                template = cls(
                    template_name=template_data["template_name"],
                    title_format=template_data["title_format"],
                    description_format=template_data["description_format"],
                    report_type=template_data.get("report_type", "intelligence-brief"),
                    url_pattern=template_data.get("url_pattern", ""),
                    report_category=template_data.get("report_category", "technical"),
                    target_audience=template_data.get("target_audience", "analysts")
                )
                db.session.add(template)
            
            db.session.commit()
            print(f"Successfully seeded {cls.query.count()} comprehensive report templates from threat intelligence database")
