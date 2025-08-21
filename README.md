
# MockTAXII v0.5.2

A comprehensive TAXII 2.x server designed for testing XSIAM and XSOAR Threat Intelligence Management (TIM). MockTAXII offers a complete STIX/TAXII 2.1 implementation with database-driven mock threat intelligence, generating realistic test indicators, campaigns and reports with rich, interlinked relationships. Each poll produces fresh datasets to simulate real-world threat intelligence services for demonstration and testing purposes.

------------------------------
## IMPORTANT INFORMATION

**GIT REPO**: https://github.com/gocortexio/mocktaxii/  
**REQUIREMENTS**: docker, docker-compose  
**ACCESS**: http://localhost:5001

------------------------------
## Key Features

**🎯 Production-Ready TAXII 2.x Server**
- Complete STIX/TAXII 2.1 compliance with proper content-type headers
- Enterprise-grade authentication system with API key management
- Advanced rate limiting and security controls
- Real-time request logging and comprehensive analytics
- Docker deployment with PostgreSQL backend

**📊 Comprehensive Threat Intelligence Database**
- **1,790 realistic mock threat indicators** for testing and demonstration:
  - 260 malicious IP addresses with geolocation data
  - 103 malicious domains with categorisation (phishing, malware, C2, infrastructure)
  - 39 malicious file hashes with malware family associations
  - **1,388 CVE vulnerabilities** from CISA KEV catalogue with generated CVSS 3.1 scores
- **50+ MITRE ATT&CK technique mappings** for comprehensive threat context
- Dynamic generation ensures fresh indicators on each poll

**🔒 Security & Compliance**
- CSRF protection and comprehensive security headers
- IP-based rate limiting with configurable thresholds
- Proxy-aware IP detection for accurate client identification
- SSL/TLS support with Let's Encrypt integration

------------------------------
## Quick Start

### 1 - Docker Deployment (Recommended)

```bash
# Clone and start
git clone <repository-url>
cd mocktaxii
docker-compose up -d

# Access at http://localhost:5001
```


### 2 - Deployment Script

```bash
./deploy.sh start
```

### 3 - Manual Deployment

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

------------------------------
## Configuration / Create API Key

### Admin Access

The system generates a random admin password on startup. Check the console logs for:

```
[MockTAXII] Admin Password: [24-character-hex-password]
```

Browse to: http://localhost:5001 and use this password to access the API key management interface at `/login`.

**Getting Docker Logs:**
- Desktop Docker: Click on web tier host
- Ubuntu Docker: `sudo docker logs <containerid> | grep Password`

------------------------------
## XSOAR/XSIAM Integration

Integration: TAXII 2 Feed (https://cortex.marketplace.pan.dev/marketplace/details/FeedTAXII/)

Configure XSOAR/XSIAM TAXII feeds with:

- **Fetches Indicators**: yes
- **Source Reliability**: 'B - Usually reliable' (note: client can choose whatever they wish)
- **Discovery Service URL**: http://<ipaddress>:5001/taxii2/
- **Username / API key**: _header:Authorization
- **Password**: Your API key
- **STIX Objects to Fetch**: 'remove all'

Then:
1. Save integration
2. Test integration
3. If successful, click 'Re-fetch indicators from this instance' or wait for initial fetch to occur

------------------------------

## Support

For issues with XSIAM or XSOAR integration, verify:

- API key is active in the management interface
- Correct authentication headers are used
- Collection name matches `threat-intel-demo`


------------------------------
## Other Information


### TAXII Endpoints

- **Discovery**: `/taxii2/`
- **Collections**: `/taxii2/api/collections/`
- **Objects**: `/taxii2/api/collections/threat-intel-demo/objects/`

### Authentication
All TAXII endpoints require API key authentication:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:5001/taxii2/collections/threat-intel-demo/objects/
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SESSION_SECRET` | Flask session key | Required |
| `WTF_CSRF_ENABLED` | Enable CSRF protection | `true` |
| `FLASK_ENV` | Flask environment | `production` |

## Rate Limits

- **General API**: 1000 requests/day, 200/hour
- **TAXII Endpoints**: 300 requests/minute
- **Statistics**: 60 requests/minute


------------------------------

## Production Notes

- Change default database credentials
- Use strong `SESSION_SECRET` values
- Enable SSL/TLS termination
- Monitor rate limit usage through `/api/stats`

---

**Version**: 0.5.2  
**License**: MIT  
**Compatibility**: TAXII 2.1, STIX 2.1  
**Database**: PostgreSQL 15+ required