# MockTAXII v0.4.1

A comprehensive TAXII 2.x server designed for testing XSIAM and XSOAR Threat Intelligence Management (TIM). MockTAXII offers a complete STIX/TAXII 2.1 implementation, generating realistic indicators, campaigns and reports, all with rich, interlinked relationships. Each poll produces a fresh dataset to simulate a real-world Threat Intelligence service.

## Quick Start

### Docker Deployment (Recommended)

```bash
# Clone and start
git clone <repository-url>
cd mocktaxii
docker-compose up -d

# Access at http://localhost:5001
```

### Manual Deployment

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost/mocktaxii"
export SESSION_SECRET="your-secret-key"

# Run application
python main.py

# Or use the deployment script
./deploy.sh start
```

## Configuration

### Admin Access
The system generates a random admin password on startup. Check the console logs for:
```
[MockTAXII] Admin Password: [24-character-hex-password]
```

Use this password to access the API key management interface at `/login`.

### TAXII Endpoints
- **Discovery**: `/taxii2/`
- **Collections**: `/taxii2/collections/`
- **Objects**: `/taxii2/collections/threat-intel-demo/objects/`

### Authentication
All TAXII endpoints require API key authentication:
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:5000/taxii2/collections/threat-intel-demo/objects/
```

## Features

- **STIX 2.1 Compliant**: Full TAXII 2.1 implementation
- **Authentic Data**: Real threat intelligence from curated sources
- **MITRE ATT&CK**: Integrated technique mappings
- **Rate Limiting**: Enterprise-grade request throttling
- **Security**: Comprehensive headers and CSRF protection
- **Monitoring**: Request logging and usage statistics

## XSIAM Integration

Configure XSIAM TIM feeds with:
- **Username**: `_header:Authorization`
- **Password**: Your API key
- **Collection**: `threat-intel-demo`

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

## Support

For issues with XSIAM or XSOAR integration, verify:
1. API key is active in the management interface
2. Correct authentication headers are used
3. Collection name matches `threat-intel-demo`

## Production Notes

- Change default database credentials
- Use strong `SESSION_SECRET` values
- Enable SSL/TLS termination
- Monitor rate limit usage through `/api/stats`

---

**Version**: 0.4.1  
**License**: MIT  
**Compatibility**: TAXII 2.1, STIX 2.1