
<div align="center">

![MockTAXII Logo](static/mocktaxii-logo.png)

# MockTAXII v0.6.0

[![TAXII 2.1](https://img.shields.io/badge/TAXII-2.1-blue.svg)](https://oasis-open.github.io/cti-documentation/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-green.svg)](https://oasis-open.github.io/cti-documentation/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

A comprehensive TAXII 2.x server designed for testing XSIAM and XSOAR Threat Intelligence Management (TIM). MockTAXII offers a complete STIX/TAXII 2.1 implementation with database-driven mock threat intelligence, generating realistic test indicators at enterprise scale from authentic threat subnet data. Features comprehensive campaigns and reports with rich, interlinked relationships. Each poll produces fresh datasets to simulate real-world threat intelligence services for demonstration and testing purposes.

</div>

## Quick Start

| Repository | Requirements | Access |
|------------|-------------|--------|
| [GitHub Repository](https://github.com/gocortexio/mocktaxii/) | `docker`, `docker-compose` | http://localhost:5001 |

## Key Features

### Production-Ready TAXII 2.x Server
- Complete STIX/TAXII 2.1 compliance with proper content-type headers
- Enterprise-grade authentication system with API key management
- Advanced rate limiting and security controls
- Real-time request logging and comprehensive analytics
- Docker deployment with PostgreSQL backend

### Comprehensive Threat Intelligence Database
- **50,000+ realistic mock threat indicators** for testing and demonstration:
  - 50,000+ malicious IP addresses with authentic geographic attribution and threat categorisation
  - 103 malicious domains with categorisation (phishing, malware, C2, infrastructure)
  - 39 malicious file hashes with malware family associations
  - **1,388 CVE vulnerabilities** from CISA KEV catalogue with generated CVSS 3.1 scores
- **50+ MITRE ATT&CK technique mappings** for comprehensive threat context
- **100 diverse campaign scenarios** with comprehensive British English metadata across 8 categories
- **50 report templates** covering intelligence briefs, technical analysis, and sector-specific assessments
- Dynamic generation from authentic Spamhaus DROP threat subnets ensures fresh indicators on each poll

### Security and Compliance
- CSRF protection and comprehensive security headers
- IP-based rate limiting with configurable thresholds
- Proxy-aware IP detection for accurate client identification
- SSL/TLS support with Let's Encrypt integration

## Installation

### Docker Deployment (Recommended)

```bash
# Clone and start
git clone <repository-url>
cd mocktaxii
docker-compose up -d

# Access at http://localhost:5001
```

### Deployment Script

```bash
./deploy.sh start
```

### Manual Deployment

```bash
# Install dependencies with UV
pip install uv
uv sync

# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost/mocktaxii"
export SESSION_SECRET="your-secret-key"

# Run application
uv run gunicorn --bind 0.0.0.0:5000 main:app
```

## Configuration

### Admin Access

The system generates a random admin password on startup. Check the console logs for:

```
[MockTAXII] Admin Password: [24-character-hex-password]
```

Browse to: http://localhost:5001 and use this password to access the API key management interface at `/login`.

**Retrieving Docker Logs:**
- Docker Desktop: Select the web container from the interface
- Ubuntu Docker: `sudo docker logs <container-id> | grep Password`

## XSOAR/XSIAM Integration

**Integration:** [TAXII 2 Feed](https://cortex.marketplace.pan.dev/marketplace/details/FeedTAXII/)

### Configuration Settings

| Setting | Value |
|---------|-------|
| **Fetches Indicators** | `yes` |
| **Source Reliability** | `B - Usually reliable` |
| **Discovery Service URL** | `http://<ipaddress>:5001/taxii2/` |
| **Username / API key** | `_header:Authorization` |
| **Password** | Your API key |
| **STIX Objects to Fetch** | `remove all` |

### Setup Steps
1. Save integration
2. Test integration
3. If successful, click 'Re-fetch indicators from this instance' or wait for initial fetch to occur


## API Reference

### TAXII Endpoints

| Endpoint | Description |
|----------|-------------|
| `/taxii2/` | Discovery |
| `/taxii2/api/collections/` | Collections |
| `/taxii2/api/collections/threat-intel-demo/objects/` | Objects |

### Authentication
All TAXII endpoints require API key authentication:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:5001/taxii2/collections/threat-intel-demo/objects/
```

## Environment & Limits

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SESSION_SECRET` | Flask session key | Required |
| `WTF_CSRF_ENABLED` | Enable CSRF protection | `true` |
| `FLASK_ENV` | Flask environment | `production` |

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| **General API** | 1000 requests/day, 200/hour |
| **TAXII Endpoints** | 300 requests/minute |
| **Statistics** | 60 requests/minute |

## Troubleshooting

**For issues with XSIAM or XSOAR integration, verify:**
- API key is active in the management interface
- Correct authentication headers are used
- Collection name matches `threat-intel-demo`

## Production Notes

- Change default database credentials
- Use strong `SESSION_SECRET` values
- Enable SSL/TLS termination
- Monitor rate limit usage through `/api/stats`

---

<div align="center">

**Version**: 0.6.0 • **License**: MIT • **Compatibility**: TAXII 2.1, STIX 2.1 • **Database**: PostgreSQL 15+

</div>