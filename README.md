<div align="center">
  <img src="static/mocktaxii-logo.png" alt="MockTAXII Logo" width="600"/>
</div>

# MockTAXII

TAXII 2.x Threat Intelligence Server from GoCortex.io

A Flask-based TAXII 2.x server for testing XSIAM and XSOAR Threat Intelligence Management (TIM). MockTAXII provides STIX/TAXII 2.1 compliance with database-driven threat intelligence, generating realistic indicators at enterprise scale for demonstration and testing purposes.

## Overview

MockTAXII enables security professionals to test threat intelligence integrations without access to production threat feeds. It implements the complete TAXII 2.1 specification and generates STIX 2.1 objects from a PostgreSQL database populated with realistic threat data derived from authentic sources including Spamhaus DROP lists, CISA KEV catalogue, and MITRE ATT&CK framework.

### Threat Intelligence Coverage

The server generates indicators across multiple threat categories:

- Configurable malicious IP addresses (5,000 to 100,000+) with geographic attribution
- 103 malicious domains with categorisation (phishing, malware, C2, infrastructure)
- 39 malicious file hashes with malware family associations
- 50 malicious software packages simulating supply chain attacks
- 1,388 CVE vulnerabilities from CISA KEV with generated CVSS 3.1 scores
- 50+ MITRE ATT&CK technique mappings
- 100 campaign scenarios across 8 categories
- 50 report templates covering intelligence briefs and technical analysis

### Custom Bundles

MockTAXII supports uploading custom STIX bundles for serving alongside generated content. This enables testing with specific indicator sets or organisation-specific threat data. Custom bundles can be targeted to specific API keys or served globally, with configurable serving frequencies.

### Software Supply Chain Indicators

The server generates 50 malicious PyPI package indicators following the pattern pygremlinbox-malware-{suffix}. These STIX 2.1 Indicator objects include URL and file hash patterns, campaign relationships, and CPE references for testing supply chain threat detection capabilities.

## Installation

### Docker Deployment (Recommended)

```bash
git clone https://github.com/gocortexio/mocktaxii/
cd mocktaxii
./deploy.sh start
```

The server will be available at http://localhost:5001

### Manual Deployment

```bash
pip install uv
uv sync

export DATABASE_URL="postgresql://user:pass@localhost/mocktaxii"
export SESSION_SECRET="your-secret-key"

uv run gunicorn --bind 0.0.0.0:5000 main:app
```

## Configuration

### Threat Intelligence Scale

Configure the number of malicious IP addresses based on your use case:

| IP Count | Use Case | Startup Time |
|----------|----------|--------------|
| 5,000 | Quick demonstrations, development | ~2 minutes |
| 10,000 | Small testing environment | ~4 minutes |
| 25,000 | Medium deployment | ~10 minutes |
| 50,000 | Production deployment | ~20 minutes |
| 100,000 | Large-scale production | ~40 minutes |

Configuration methods:

```bash
export MALICIOUS_IP_TARGET_COUNT=50000

./deploy.sh start

python init_db.py --ip-count 50000
```

### Admin Access

The system generates a random admin password on startup. Check the console logs for:

```
[MockTAXII] Admin Password: [24-character-hex-password]
```

Browse to http://localhost:5001 and use this password to access the management interface at /login.

Retrieving Docker logs:
- Docker Desktop: Select the web container from the interface
- Ubuntu Docker: sudo docker logs container-id | grep Password

## XSOAR/XSIAM Integration

Integration: TAXII 2 Feed (https://cortex.marketplace.pan.dev/marketplace/details/FeedTAXII/)

### Configuration Settings

| Setting | Value |
|---------|-------|
| Fetches Indicators | yes |
| Source Reliability | B - Usually reliable |
| Discovery Service URL | http://ipaddress:5001/taxii2/ |
| Username / API key | _header:Authorization |
| Password | Your API key |
| STIX Objects to Fetch | remove all |

### Setup Steps

1. Save integration
2. Test integration
3. If successful, click Re-fetch indicators from this instance or wait for initial fetch

## API Reference

### TAXII Endpoints

| Endpoint | Description |
|----------|-------------|
| /taxii2/ | Discovery |
| /taxii2/api/collections/ | Collections |
| /taxii2/api/collections/threat-intel-demo/objects/ | Objects |

### Authentication

All TAXII endpoints require API key authentication:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:5001/taxii2/api/collections/threat-intel-demo/objects/
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DATABASE_URL | PostgreSQL connection string | Required |
| SESSION_SECRET | Flask session key | Required |
| WTF_CSRF_ENABLED | Enable CSRF protection | true |
| FLASK_ENV | Flask environment | production |
| MALICIOUS_IP_TARGET_COUNT | Number of IPs to generate | 5000 |

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| General API | 1000 requests/day, 200/hour |
| TAXII Endpoints | 300 requests/minute |
| Statistics | 60 requests/minute |

## Troubleshooting

For issues with XSIAM or XSOAR integration:

- Verify the API key is active in the management interface
- Confirm correct authentication headers are used
- Check the collection name matches threat-intel-demo

## Contact and Support

For documentation, updates, and support, visit GoCortex.io (https://gocortex.io).

Developed by Simon Sigre at GoCortex.io.

---

Version: 0.7.0 | Licence: MIT | Compatibility: TAXII 2.1, STIX 2.1 | Database: PostgreSQL 15+
