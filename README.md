<div align="center">
  <img src="assets/mocktaxii-logo.png" alt="MockTAXII Logo" width="600"/>
</div>

# MockTAXII

TAXII 2.x Threat Intelligence Server from GoCortex.io

A Flask-based TAXII 2.x server for testing TAXII 2.1 clients. MockTAXII was built against Threat Intelligence Management (TIM) on the Palo Alto Networks Cortex Platform - Cortex XSIAM and Cortex XSOAR - and implements the TAXII 2.1 integration endpoints a TIM feed exercises, serving STIX 2.1 objects generated from a PostgreSQL database at enterprise scale. It is a bounded synthetic test feed for demonstration and integration testing, not a claim of full TAXII 2.1 specification coverage - see [Feed and pagination scope](#feed-and-pagination-scope).

## Overview

MockTAXII enables security professionals to test threat intelligence integrations without access to production threat feeds. It provides a bounded synthetic test server for the TAXII 2.1 integration surface and generates STIX 2.1 objects from a PostgreSQL database populated with realistic threat data derived from authentic sources including Spamhaus DROP lists, CISA KEV catalogue, and the MITRE ATT&CK framework.

### Threat Intelligence Coverage

The server generates indicators across multiple threat categories:

- Configurable malicious IP addresses (5,000 to 100,000+) with geographic attribution
- 103 malicious domains with categorisation (phishing, malware, C2, infrastructure)
- 39 malicious file hashes with malware family associations
- 100+ malicious software packages (6 core PyGremlinBox packages + campaign-linked packages)
- CVE vulnerabilities fetched from the live CISA KEV catalogue with generated CVSS 3.1 scores; the catalogue grows over time, so the count tracks it (roughly 1,700 at the time of writing)
- 50 MITRE ATT&CK technique mappings
- 95 campaign scenarios across 8 categories
- 49 report templates covering intelligence briefs and technical analysis

### Custom Bundles

MockTAXII supports uploading custom STIX bundles for serving alongside generated content. This enables testing with specific indicator sets or organisation-specific threat data. Custom bundles can be targeted to specific API keys or served globally, with configurable serving frequencies.

### Feed and pagination scope

This is a synthetic test feed, not a durable threat-intelligence repository.
Generated objects and their manifest share a five-minute snapshot, and the
manifest describes every object the collection serves, not only its indicators.
Follow the returned `next` cursor with the same API key; expired cursors require
a new poll. Custom bundles are validated as STIX 2.1 and paginated rather than
returned without a limit; a served custom bundle stays visible to the manifest
for the same five minutes, then the manifest returns to the generated snapshot.

`added_after` is honoured against the time a snapshot entered the collection, so
an incremental client sees each snapshot once and then polls empty until the next
one. A custom bundle's ingestion time is the moment it is served, not the moment
it was uploaded.

Snapshot files are shared between Gunicorn workers on a single host using the
runtime state directory (`MOCKTAXII_STATE_DIR`, default `/tmp`). That directory
must be writable by the application. Independent hosts or containers without
shared state are not supported for pagination; container replacement may
invalidate outstanding cursors.

### Software Supply Chain Indicators

The server generates malicious PyPI package indicators in two tiers:
- Core packages: 6 real pygremlinbox-malware-* packages from the PyGremlinBox GitHub repository
- Campaign packages: Fictional pygremlinbox-mocktaxii-{campaign} packages linked to each campaign

These STIX 2.1 Indicator objects use PURL pattern format ([software:name = 'pkg:pypi/package@version']) with labels=["supply-chain", "pypi", "malicious-package"] for TIM compatibility, plus campaign relationships and CPE references.

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
export SESSION_SECRET="$(openssl rand -base64 32)"

# Seed the database (creates tables, fetches Spamhaus DROP and CISA KEV)
uv run python init_db.py --ip-count 5000

uv run gunicorn --bind 0.0.0.0:5000 main:app
```

Note that `docker-entrypoint.sh` also applies schema migrations that
`db.create_all()` cannot (it only ever creates tables, never alters them). If you
deploy manually against a database created by an earlier version, apply the
`ALTER TABLE` block from that script first - otherwise the app will refuse to
start in production and report exactly which columns are missing.

### Upgrading from v1.1.0 or earlier

Schema migrations are idempotent and apply themselves on boot, so upgrading
the application is just a redeploy. The database is the exception: releases up
to v1.1.0 ran PostgreSQL 15 with the volume mounted at
`/var/lib/postgresql/data`, and this release runs PostgreSQL 18, which keeps
its cluster in a version subdirectory and expects the volume one level up.
PostgreSQL will not start across that change - it refuses rather than touching
the data, so nothing is lost, but the stack will not come up.

`deploy/production-deploy.sh` checks for this before it stages anything and
stops with the exact commands. In short: `pg_dumpall` from the running
container, `docker volume rm` the old volume, re-run the deploy to get an
empty PostgreSQL 18 cluster, then `psql` the dump back in.

## Configuration

### Threat Intelligence Scale

Configure the number of malicious IP addresses based on your use case:

| IP Count | Use Case | Startup Time |
|----------|----------|--------------|
| 5,000 | Quick demonstrations, development | ~2 seconds |
| 10,000 | Small testing environment | ~3 seconds |
| 25,000 | Medium deployment | ~6 seconds |
| 50,000 | Production deployment | ~10 seconds |
| 100,000 | Large-scale production | ~20 seconds |

Measured on the IP generation step alone (v1.1.0). A full first boot including
the Spamhaus DROP and CISA KEV fetches takes roughly 20 seconds at the 5,000
default.

Configuration methods:

```bash
export MALICIOUS_IP_TARGET_COUNT=50000

./deploy.sh start

python init_db.py --ip-count 50000
```

### Admin Access

For security reasons the admin password is **never** written to container logs.
You have two options:

**Option 1: provide your own password (recommended for production)**

Set `ADMIN_PASSWORD` in your `.env` (or `.env.prod`) file before starting the
stack:

```
ADMIN_PASSWORD=your-secure-admin-password-here
```

This value is passed straight through to the web container and used as-is.

**Option 2: use the auto-generated password**

If `ADMIN_PASSWORD` is not set, MockTAXII generates a random 24-character hex
password on first startup and stores it inside the container at
`/tmp/mocktaxii_admin_password` with `0600` permissions. Retrieve it with:

```bash
docker compose exec web cat /tmp/mocktaxii_admin_password
```

For the production compose file, load the deployment environment file explicitly:

```bash
docker compose --env-file .env.prod -f deploy/docker-compose.prod.yml exec web cat /tmp/mocktaxii_admin_password
```

Then browse to http://localhost:5001 and use the password to log in at `/login`.

## Cortex Platform Integration (Cortex XSOAR and Cortex XSIAM)

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

### Set up the integration

1. Save integration
2. Test integration
3. If successful, click Re-fetch indicators from this instance or wait for initial fetch

## API Reference

### TAXII Endpoints

| Endpoint | Description | Auth |
|----------|-------------|------|
| /taxii2/ | Discovery | No |
| /taxii2/api/ | API Root | Yes |
| /taxii2/api/collections/ | Collections | Yes |
| /taxii2/api/collections/threat-intel-demo/ | Collection information | Yes |
| /taxii2/api/collections/threat-intel-demo/objects/ | Objects | Yes |
| /taxii2/api/collections/threat-intel-demo/manifest/ | Manifest | Yes |

Both the objects and manifest endpoints accept `?limit=` between 1 and 100
(default 50). Values below 1, and values that are not numbers, fall back to 50.
The manifest describes exactly the objects the collection serves, so the two
endpoints can be reconciled entry for entry within one snapshot.

### Operational Endpoints

| Endpoint | Description | Auth |
|----------|-------------|------|
| /healthz | Liveness probe. Runs `SELECT 1`, returns 200 when the database is reachable and 503 otherwise. Exempt from rate limiting, writes no request log, and prunes expired request-log rows at most hourly. Used by the container HEALTHCHECK. | No |
| /api/stats | Indicator and request counters | No |
| /api/rate-limit-status | Current rate-limit configuration | Yes (admin session) |

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
| SESSION_SECRET | Flask session signing key. Required in production - the app refuses to start when unset or left at a known placeholder. Outside production a development key is generated and shared across workers, with a warning. | Required in production |
| ADMIN_PASSWORD | Admin UI password. When unset, one is generated and written to `/tmp/mocktaxii_admin_password` (never logged). | generated |
| WTF_CSRF_ENABLED | Enable CSRF protection | true |
| FLASK_ENV | Set to `production` to enable secure cookies and strict CSRF over HTTPS | unset (non-production) |
| MALICIOUS_IP_TARGET_COUNT | Number of IPs to generate | 5000 |
| SKIP_SEEDING | Create tables only, skip seeding | false |
| TRUST_PROXY | Honour X-Forwarded-* headers (set only behind a trusted proxy) | false |
| MOCKTAXII_STATE_DIR | Runtime state directory shared between workers on one host: pagination snapshots, and the generated development session secret and admin password. Must be writable by the application. | /tmp |
| REQUEST_LOG_RETENTION_DAYS | Days of request log to retain (0 disables pruning) | 90 |
| LOG_LEVEL | Python logging level | INFO |
| DB_POOL_SIZE | SQLAlchemy pool size. Keep at or above the concurrent request count (2 workers x 4 threads = 8). | 10 |
| DB_MAX_OVERFLOW | Connections allowed beyond the pool size | 20 |
| DB_POOL_TIMEOUT | Seconds to wait for a free connection | 30 |
| DB_POOL_RECYCLE | Seconds before a connection is recycled | 300 |

### Rate Limits

| Endpoint | Limit |
|----------|-------|
| Objects (`/objects/`) | 30 requests/minute, counted **twice** - once per client IP and once per API key |
| Other TAXII endpoints | 300 requests/minute |
| Statistics (`/api/stats`) | 30 requests/minute |
| Health (`/healthz`) | exempt |
| Login (POST) | 5 requests/minute |
| Admin pages | 10-30 requests/minute |

Every route carries an explicit limit, so the configured day/hour defaults apply to none of them.
Limits are counted per gunicorn worker (in-memory storage), so with the default 2 workers the
effective ceiling is up to twice the figure shown.

## Troubleshooting

For issues with the Cortex Platform or another TAXII 2.1 client:

- Verify the API key is active in the management interface
- Confirm correct authentication headers are used
- Check the collection name matches threat-intel-demo

## Contact and Support

For documentation, updates, and support, visit GoCortex.io (https://gocortex.io).

Developed by Simon Sigre at GoCortex.io.

---

Version: 1.1.4 | Licence: AGPL-3.0-or-later | Compatibility: TAXII 2.1, STIX 2.1 | Database: PostgreSQL 15+
