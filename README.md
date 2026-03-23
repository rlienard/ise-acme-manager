# 🔐 ISE ACME Certificate Manager

Automated certificate lifecycle management for Cisco ISE guest portals using the ACME protocol with DigiCert CertCentral. Deployed as a two-container microservice with a REST API daemon and a modern web dashboard.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cisco ISE 3.1+](https://img.shields.io/badge/Cisco%20ISE-3.1+-00bceb.svg)](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

---

## Overview

Managing SSL/TLS certificates for Cisco ISE guest portals is a manual, error-prone process — especially across multi-node deployments. This project **fully automates** the certificate lifecycle:

1. **Monitors** certificate expiry across all ISE PSN nodes
2. **Requests** new certificates via ACME protocol (DigiCert CertCentral)
3. **Automates** DNS-01 challenge validation (Cloudflare, AWS Route53, Azure DNS)
4. **Installs** and binds certificates to the ISE guest portal
5. **Distributes** shared certificates across multiple PSN nodes
6. **Notifies** your team via email with detailed reports

All managed through a **web dashboard** — no CLI required.

---

## Quick Start

### Prerequisites

- **Docker** and **Docker Compose**
- **Cisco ISE 3.1+** with Open API enabled
- **DigiCert CertCentral** account with ACME enabled
- **DNS provider** API access (Cloudflare, AWS Route53, or Azure DNS)

### Deploy

```bash
# Clone
git clone https://github.com/yourusername/ise-acme-manager.git
cd ise-acme-manager

# Build and start
docker-compose up -d --build

# Verify
docker-compose ps
```

---

## Access

|Service|URL|
|---    |---|
|Web Dashboard|http://localhost:8080|
|API Documentation|http://localhost:8443/api/docs|
|Health Check|http://localhost:8443/health|

---

## Configure

1. Open the **Web Dashboard** at http://localhost:8080
2. Go to **Settings** and configure:

    *ISE Connection — hostname, credentials, API port
    *ACME / DigiCert — directory URL, KID, HMAC key
    *Certificate — common name, SANs, mode (shared/per-node)
    *DNS Provider — Cloudflare, Route53, or Azure credentials
    *Notifications — SMTP settings and recipients
    *Scheduler — enable and set the daily run time
3. Add your ISE PSN nodes and designate a primary node
4. Use Test Connection buttons to validate ISE and DNS connectivity

---

## Features

|Feature|Description|
|-------|-----------|
|Web Dashboard | Real-time status, settings management, renewal history|
|Scheduled Renewals | Configurable daily automatic checks and renewals|
|Manual Actions | Check, renew, or force-renew from the dashboard|
|Shared Certificate Mode | One certificate requested and distributed to all nodes|
|Per-Node Certificate Mode | Independent certificates for each PSN node|
|Multi-DNS Support | Cloudflare, AWS Route53, Azure DNS|
|Email Notifications | HTML reports with per-node status|
|Audit History | Full renewal history with logs and per-node results|
|Connection Testing | Built-in ISE and DNS connectivity tests|
|REST API | Full API with Swagger/OpenAPI documentation|

---

## Certificate Modes

### Shared (Recommended for most deployments)

One certificate is requested on the primary node and distributed to all secondary nodes. All PSNs serve the same cert.

ACME → 1 Certificate → PSN-01 (primary) + PSN-02 (secondary)

### Per-Node

Each PSN node gets its own independent certificate via a separate ACME request.

ACME → Cert A → PSN-01
ACME → Cert B → PSN-02

Set the mode in Settings → Certificate → Certificate Mode.

---

## API Reference

All endpoints are documented interactively at /api/docs. Key endpoints:

|Method | Endpoint | Description|
|-------|----------|------------|
|GET | /api/v1/status | Daemon status and node health|
|GET | /api/v1/settings | All configuration (secrets masked)|
|PUT | /api/v1/settings/ise | Update ISE settings|
|PUT | /api/v1/settings/acme | Update ACME settings|
|PUT | /api/v1/settings/certificate | Update certificate settings|
|PUT | /api/v1/settings/dns | Update DNS settings|
|PUT | /api/v1/settings/smtp | Update SMTP settings|
|PUT | /api/v1/settings/scheduler | Update scheduler settings|
|GET | /api/v1/settings/nodes | List ISE nodes|
|POST | /api/v1/settings/nodes | Add ISE node|
|DELETE | /api/v1/settings/nodes/{id} | Remove ISE node|
|POST | /api/v1/settings/test/ise | Test ISE connectivity|
|POST | /api/v1/settings/test/dns | Test DNS connectivity|
|POST | /api/v1/actions/run | Trigger manual action (check/renew/force-renew)|
|GET | /api/v1/history | Paginated renewal history|
|GET | /api/v1/history/{run_id} | Renewal run details|
|GET | /api/v1/history/{run_id}/logs | Renewal run logs|
|GET | /health | Health check|

---

## ISE Preparation

Before using this tool, configure your Cisco ISE:

1. Enable Open API: Administration → System → Settings → API Settings → Open API → Enable
2. Create API admin account with certificate management permissions
3. Configure ACME CA profile: Administration → System → Certificates → ACME Certification Authorities
4. Ensure network connectivity from the daemon container to ISE (HTTPS on port 443/9060)

## DigiCert Preparation

1. Log into CertCentral → Automation → ACME Directory URLs
2. Create an ACME directory URL
3. Note the Directory URL, Key ID (KID), and HMAC Key

---

## Operational Commands

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# View daemon logs
docker-compose logs -f daemon

# View web logs
docker-compose logs -f web

# Rebuild after code changes
docker-compose up -d --build

# Backup database
docker cp ise-acme-daemon:/app/data/ise_acme.db ./backup_$(date +%Y%m%d).db

# Restore database
docker cp ./backup.db ise-acme-daemon:/app/data/ise_acme.db
docker-compose restart daemon
```

---

## Security Recommendations

|Area | Recommendation|
|-----|---------------|
|Network | Deploy on a management VLAN with restricted access to ISE|
|HTTPS | Place behind a reverse proxy with TLS termination|
|Credentials | All secrets are stored in SQLite — encrypt the volume or use Docker secrets|
|Access | Restrict dashboard access via firewall rules or add authentication|
|Backups | Regularly backup the daemon data volume|
|Updates | Keep containers updated; rebuild periodically|

---

## Troubleshooting

|Issue | Solution|
|------|---------|
|Dashboard shows "Connection Error" | Verify daemon container is running: docker-compose ps|
|ISE test connection fails | Check ISE hostname, credentials, and Open API is enabled|
|DNS test connection fails | Verify API token/credentials and zone ID|
|Renewal stuck in "running" | Check daemon logs: docker-compose logs daemon|
|Certificate not binding to portal | Verify portal group tag matches ISE configuration|
|Scheduler not triggering | Check scheduler is enabled in Settings and review daemon logs|

### Debug with detailed logs:

```bash
# Real-time daemon logs
docker-compose logs -f daemon

# Inspect database
docker exec -it ise-acme-daemon python -c "
from app.database import SessionLocal, RenewalHistory
db = SessionLocal()
for r in db.query(RenewalHistory).order_by(RenewalHistory.id.desc()).limit(5):
    print(f'{r.run_id[:8]} | {r.status} | {r.started_at}')
db.close()
"
```

---

## License

MIT License — see LICENSE for details.
