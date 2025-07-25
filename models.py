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
    ip_address = db.Column(db.String(45), nullable=False, unique=True)  # Support IPv4 and IPv6
    description = db.Column(db.Text)
    threat_types = db.Column(db.JSON, default=lambda: ["malicious-activity"])
    confidence_score = db.Column(db.Integer, default=75)  # 0-100 confidence score
    source = db.Column(db.String(255), default="MockTAXII")
    first_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<MaliciousIP {self.ip_address}>'
    
    @classmethod
    def get_random_active(cls):
        """Get a random active malicious IP"""
        ips = cls.query.filter_by(is_active=True).all()
        if ips:
            import random
            return random.choice(ips)
        return None
    
    @classmethod
    def seed_default_ips(cls):
        """Seed the database with default malicious IPs if none exist"""
        if cls.query.count() == 0:
            # Default malicious IP list from stix_generator.py
            default_ips = [
                "185.220.101.45", "185.220.102.47", "185.220.103.89", "185.38.14.215", "185.38.14.78",
                "104.131.45.67", "104.131.78.123", "104.131.156.234", "104.131.89.45", "159.203.78.156",
                "159.203.123.67", "159.203.45.89", "159.203.234.12", "138.68.45.78", "138.68.123.156",
                "138.68.234.67", "138.68.89.234", "167.114.78.45", "167.114.156.89", "167.114.234.123",
                "167.114.67.234", "162.144.45.78", "162.144.123.156", "162.144.234.89", "162.144.67.45",
                "176.9.78.123", "176.9.156.234", "176.9.45.67", "176.9.234.89", "178.32.78.156",
                "178.32.123.234", "178.32.45.67", "178.32.234.89", "163.172.78.45", "163.172.156.123",
                "163.172.234.67", "163.172.89.234", "164.132.45.78", "164.132.123.156", "164.132.234.89",
                "172.104.67.45", "172.104.234.78", "172.104.89.123", "172.104.156.234", "195.154.45.67",
                "195.154.123.89", "195.154.234.156", "195.154.78.234", "192.99.45.78", "192.99.123.156",
                "192.99.234.89", "192.99.67.234", "37.46.150.78", "37.46.150.123", "37.46.150.156", "37.46.150.234",
                "37.221.113.45", "37.221.113.78", "37.221.113.123", "37.221.113.156", "46.29.166.67", "46.29.166.89",
                "46.29.166.123", "46.29.166.234", "46.161.40.45", "46.161.40.78", "46.161.40.156", "46.161.40.234",
                "46.183.218.67", "46.183.218.89", "46.183.218.123", "46.183.218.156", "77.83.4.45", "77.83.4.78",
                "77.83.4.123", "77.83.4.234", "77.91.102.67", "77.91.102.89", "77.91.102.156", "77.91.102.234",
                "78.142.19.45", "78.142.19.78", "78.142.19.123", "78.142.19.156", "79.110.62.67", "79.110.62.89",
                "79.110.62.123", "79.110.62.234", "80.82.77.45", "80.82.77.78", "80.82.77.156", "80.82.77.234",
                "82.221.139.67", "82.221.139.89", "82.221.139.123", "82.221.139.156", "83.97.73.45", "83.97.73.78",
                "83.97.73.123", "83.97.73.234", "85.93.20.67", "85.93.20.89", "85.93.20.156", "85.93.20.234",
                "87.251.75.45", "87.251.75.78", "87.251.75.123", "87.251.75.156", "89.108.65.67", "89.108.65.89",
                "89.108.65.123", "89.108.65.234", "91.92.109.45", "91.92.109.78", "91.92.109.156", "91.92.109.234",
                "91.121.155.67", "91.121.155.89", "91.121.155.123", "91.121.155.156", "91.134.232.45", "91.134.232.78",
                "91.134.232.123", "91.134.232.234", "92.63.194.67", "92.63.194.89", "92.63.194.156", "92.63.194.234",
                "94.142.241.45", "94.142.241.78", "94.142.241.123", "94.142.241.156", "103.21.58.67", "103.21.58.89",
                "103.21.58.123", "103.21.58.234", "103.43.75.45", "103.43.75.78", "103.43.75.156", "103.43.75.234",
                "103.85.24.67", "103.85.24.89", "103.85.24.123", "103.85.24.156", "103.224.182.45", "103.224.182.78",
                "103.224.182.123", "103.224.182.234", "107.150.88.67", "107.150.88.89", "107.150.88.156", "107.150.88.234",
                "109.70.100.45", "109.70.100.78", "109.70.100.123", "109.70.100.156", "113.195.145.67", "113.195.145.89",
                "113.195.145.123", "113.195.145.234", "115.28.78.45", "115.28.78.67", "115.28.78.123", "115.28.78.156",
                "117.21.191.67", "117.21.191.89", "117.21.191.123", "117.21.191.234", "121.18.238.45", "121.18.238.78",
                "121.18.238.156", "121.18.238.234", "122.10.85.67", "122.10.85.89", "122.10.85.123", "122.10.85.156",
                "123.30.238.45", "123.30.238.78", "123.30.238.123", "123.30.238.234", "134.195.196.67", "134.195.196.89",
                "134.195.196.156", "134.195.196.234", "139.60.160.45", "139.60.160.78", "139.60.160.123", "139.60.160.156",
                "146.70.124.67", "146.70.124.89", "146.70.124.123", "146.70.124.234", "149.56.123.45", "149.56.123.78",
                "149.56.123.156", "149.56.123.234", "151.80.238.67", "151.80.238.89", "151.80.238.123", "151.80.238.156",
                "154.16.105.45", "154.16.105.78", "154.16.105.123", "154.16.105.234", "188.40.75.67", "188.40.75.89",
                "188.40.75.123", "188.40.75.156", "45.8.146.45", "45.8.146.78", "45.8.146.123", "45.8.146.234",
                "45.66.151.67", "45.66.151.89", "45.66.151.156", "45.66.151.234", "45.95.168.45", "45.95.168.78",
                "45.95.168.123", "45.95.168.156", "45.129.14.67", "45.129.14.89", "45.129.14.123", "45.129.14.234",
                "45.142.212.45", "45.142.212.78", "45.142.212.156", "45.142.212.234", "45.154.98.67", "45.154.98.89",
                "45.154.98.123", "45.154.98.156", "31.14.40.45", "31.14.40.78", "31.14.40.123", "31.14.40.234",
                "31.210.20.67", "31.210.20.89", "31.210.20.156", "31.210.20.234", "5.42.92.45", "5.42.92.78",
                "5.42.92.123", "5.42.92.234", "5.188.10.67", "5.188.10.89", "5.188.10.156", "5.188.10.234",
                "185.14.186.45", "185.14.186.78", "185.14.186.123", "185.14.186.234", "185.56.80.67", "185.56.80.89",
                "185.56.80.156", "185.56.80.234", "185.100.85.45", "185.100.85.78", "185.100.85.123", "185.100.85.156"
            ]
            
            import random
            for ip_address in default_ips:
                # Add some variety to confidence scores and descriptions
                confidence = random.choices([75, 50], weights=[70, 30])[0]
                threat_description = random.choice([
                    f"Malicious IP address {ip_address} associated with command and control infrastructure",
                    f"IP address {ip_address} identified in botnet communications",
                    f"Known malicious IP {ip_address} used for data exfiltration",
                    f"Suspicious IP address {ip_address} involved in reconnaissance activities",
                    f"IP address {ip_address} associated with malware distribution"
                ])
                
                malicious_ip = cls(
                    ip_address=ip_address,
                    description=threat_description,
                    confidence_score=confidence,
                    threat_types=["malicious-activity"],
                    source="MockTAXII Intelligence Feed"
                )
                db.session.add(malicious_ip)
            
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
        """Get a random active CVE"""
        cves = cls.query.filter_by(is_active=True).all()
        if cves:
            import random
            return random.choice(cves)
        return None
    
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
            
            malware_families = [
                "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Mimikatz",
                "Zeus", "Dridex", "IcedID", "BazarLoader", "QakBot"
            ]
            
            file_types = ["executable", "document", "archive", "script", "library"]
            
            import random
            for hash_value in default_hashes:
                # Add variety to malware families and metadata
                malware_family = random.choice(malware_families)
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
