import json
import uuid
from datetime import datetime, timezone
import random

class STIXGenerator:
    """Generate mock STIX 2.x threat intelligence indicators"""
    
    # Mock data pools for realistic indicators
    MALICIOUS_IPS = [
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
    
    MALICIOUS_DOMAINS = [
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
        # Additional 79 fake malicious domains
        "cyberthreat-nexus.com", "darkweb-portal.net", "hacktools-depot.org",
        "malware-factory.biz", "phish-central.info", "trojan-warehouse.com",
        "exploit-marketplace.net", "ransomware-central.org", "botnet-registry.biz",
        "credential-bazaar.info", "blackhat-services.com", "underground-market.net",
        "stolen-data.org", "identity-theft.biz", "fraud-network.info",
        "scammer-paradise.com", "darknet-exchange.net", "criminal-enterprise.org",
        "hacker-collective.biz", "cyber-mafia.info", "digital-heist.com",
        "breach-specialists.net", "data-thieves.org", "password-crackers.biz",
        "social-engineers.info", "malicious-actors.com", "threat-operators.net",
        "attack-vectors.org", "vulnerability-exploits.biz", "zero-day-market.info",
        "backdoor-factory.com", "keylogger-central.net", "spyware-depot.org",
        "adware-distributors.biz", "pup-network.info", "rogue-software.com",
        "fake-antivirus.net", "scareware-zone.org", "tech-support-scam.biz",
        "romance-scammer.info", "lottery-fraud.com", "investment-scam.net",
        "pyramid-scheme.org", "ponzi-operation.biz", "fake-charity.info",
        "phony-business.com", "counterfeit-goods.net", "pirated-software.org",
        "illegal-streaming.biz", "torrent-malware.info", "cracked-games.com",
        "warez-infected.net", "keygen-trojan.org", "patch-backdoor.biz",
        "mod-malware.info", "hack-tutorial.com", "exploit-guide.net",
        "pentesting-tools.org", "red-team-arsenal.biz", "attack-framework.info",
        "payload-generator.com", "shellcode-factory.net", "rootkit-builder.org",
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
    
    MALICIOUS_HASHES = [
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
        "90123456789012345678901234567890123456789ABCDEF0123456789ABCDEF0",
        "0123456789012345678901234567890123456789ABCDEF0123456789ABCDEF01",
        "123456789012345678901234567890123456789ABCDEF0123456789ABCDEF012",
        "23456789012345678901234567890123456789ABCDEF0123456789ABCDEF0123",
        "3456789012345678901234567890123456789ABCDEF0123456789ABCDEF01234",
        "456789012345678901234567890123456789ABCDEF0123456789ABCDEF012345",
        "56789012345678901234567890123456789ABCDEF0123456789ABCDEF0123456",
        "6789012345678901234567890123456789ABCDEF0123456789ABCDEF01234567",
        "789012345678901234567890123456789ABCDEF0123456789ABCDEF012345678",
        "89012345678901234567890123456789ABCDEF0123456789ABCDEF0123456789",
        "9012345678901234567890123456789ABCDEF0123456789ABCDEF0123456789A",
        "012345678901234567890123456789ABCDEF0123456789ABCDEF0123456789AB",
        "12345678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABC",
        "2345678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCD",
        "345678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
        "45678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "5678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
        "678901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "78901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012",
        "8901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
        "901234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234",
        "01234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345",
        "1234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456",
        "234567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "34567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678",
        "4567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        "567890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789A",
        "67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB",
        "7890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC",
        "890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD",
        "90123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
        "23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        "3456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012",
        "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123",
        "56789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234",
        "6789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345",
        "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456",
        "89ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "9ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        "BCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789A",
        "CDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB",
        "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABC",
        "EF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD",
        "F0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDE",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF1",
        "23456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF12",
        "3456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123",
        "456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF1234",
        "56789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF12345",
        "6789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456",
        "789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF1234567",
        "89ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF12345678",
        "9ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789A",
        "BCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789AB",
        "CDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABC",
        "DEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCD",
        "EF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDE",
        "F0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF",
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF01",
        "23456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF012",
        "3456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF0123",
        "456789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF01234",
        "56789ABCDEF0123456789ABCDEF0123456789ABCDEF123456789ABCDEF012345"
    ]
    
    MALWARE_FAMILIES = [
        "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Mimikatz",
        "Zeus", "Dridex", "IcedID", "BazarLoader", "QakBot"
    ]
    
    @staticmethod
    def generate_timestamp():
        """Generate a current timestamp in STIX format"""
        return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    @staticmethod
    def generate_ip_indicator():
        """Generate a STIX IP address indicator"""
        ip = random.choice(STIXGenerator.MALICIOUS_IPS)
        score = random.choices([75, 50], weights=[70, 30])[0]
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": f"Malicious IP address {ip} associated with command and control infrastructure"
        }
    
    @staticmethod
    def generate_domain_indicator():
        """Generate a STIX domain indicator"""
        domain = random.choice(STIXGenerator.MALICIOUS_DOMAINS)
        score = random.choices([75, 50], weights=[70, 30])[0]
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[domain-name:value = '{domain}']",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": f"Malicious domain {domain} used for phishing or malware distribution"
        }
    
    @staticmethod
    def generate_file_hash_indicator():
        """Generate a STIX file hash indicator"""
        hash_value = random.choice(STIXGenerator.MALICIOUS_HASHES)
        malware_family = random.choice(STIXGenerator.MALWARE_FAMILIES)
        score = random.choices([75, 50], weights=[70, 30])[0]
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": STIXGenerator.generate_timestamp(),
            "modified": STIXGenerator.generate_timestamp(),
            "pattern": f"[file:hashes.SHA256 = '{hash_value}']",
            "labels": ["malicious-activity"],
            "indicator_types": ["malicious-activity"],
            "verdict": "malicious",
            "x_verdict": "malicious",
            "x_reputation": "malicious",
            "x_classification": "malicious",
            "x_threat_level": "high",
            "score": score,
            "valid_from": STIXGenerator.generate_timestamp(),
            "description": f"Malicious file hash associated with {malware_family} malware family"
        }
    
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
            "description": f"{malware_family} is a known malware family used in various attack campaigns",
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
            resource_level = "organization"
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
            "description": description,
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
            "description": f"Sophisticated cyber campaign targeting enterprise infrastructure with advanced persistent threats",
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
            "description": f"MITRE ATT&CK technique {technique['mitre_id']}",
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
            "content": note_content,
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
            "description": f"Comprehensive threat intelligence report analyzing {threat_actor_name} activities and associated {campaign_name} infrastructure indicators. Full report available at: {selected_report['url']}",
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
        
        # Generate intelligence publications
        note = STIXGenerator.generate_note_object(threat_actor["name"])
        report = STIXGenerator.generate_report_object(threat_actor["name"], campaign["name"])
        
        objects.extend([campaign, threat_actor, malware, attack_pattern, note, report])
        
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
        
        # Link report to threat actor and campaign  
        report["object_refs"] = [threat_actor["id"], campaign["id"]] + [ind["id"] for ind in indicators[:5]]
        relationships.append(STIXGenerator.generate_relationship(
            report["id"], threat_actor["id"], "related-to",
            "Threat intelligence report documenting threat actor operations and indicators"
        ))
        relationships.append(STIXGenerator.generate_relationship(
            report["id"], campaign["id"], "related-to",
            "Intelligence publication analyzing campaign infrastructure and tactics"
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
