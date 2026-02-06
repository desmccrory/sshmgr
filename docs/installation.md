# Installation Guide

This guide covers installing sshmgr for development and production environments.

## Prerequisites

- **Python 3.11+**
- **Node.js 20+** (for frontend)
- **OpenSSH** (ssh-keygen must be in PATH)
- **PostgreSQL 14+** (for production)
- **Keycloak 22+** (for authentication)

## Quick Start (Development)

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/yourorg/sshmgr.git
cd sshmgr

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev]"
# or use make:
make install-dev
```

### 2. Start Infrastructure

```bash
# Start PostgreSQL and Keycloak with Docker
make docker-up

# This starts:
# - PostgreSQL on localhost:5432
# - Keycloak on localhost:8080
```

### 3. Configure Environment

```bash
# Generate a master encryption key
make generate-key

# Create .env file
cat > .env << EOF
SSHMGR_MASTER_KEY=<generated-key>
SSHMGR_DATABASE_URL=postgresql+asyncpg://sshmgr:sshmgr_dev_password@localhost:5432/sshmgr
SSHMGR_KEYCLOAK_URL=http://localhost:8080
SSHMGR_KEYCLOAK_REALM=sshmgr
EOF
```

### 4. Initialize Database

```bash
# Run database migrations
make db-migrate
```

### 5. Set Up Frontend

```bash
# Install frontend dependencies
make frontend-install

# Create frontend environment file
cp frontend/.env.example frontend/.env.local

# Edit frontend/.env.local with:
# NEXT_PUBLIC_API_URL=http://localhost:8000
# KEYCLOAK_URL=http://localhost:8080
# KEYCLOAK_REALM=sshmgr
# KEYCLOAK_CLIENT_ID=sshmgr-web
# KEYCLOAK_CLIENT_SECRET=<from keycloak-setup output>
# AUTH_SECRET=<generate with: openssl rand -base64 32>
```

### 6. Verify Installation

```bash
# Run tests
make test           # Unit tests only
make test-all       # All tests (unit + integration)

# Start the API server
make run-api

# In another terminal, start the frontend
make frontend-dev
# Frontend available at http://localhost:3000

# Test the CLI
.venv/bin/sshmgr --help
.venv/bin/sshmgr login
```

## Development Setup Details

### Virtual Environment

Always use a virtual environment to isolate dependencies:

```bash
# Create
python -m venv .venv

# Activate (choose your shell)
source .venv/bin/activate      # bash/zsh
source .venv/bin/activate.fish # fish
.venv\Scripts\activate         # Windows cmd
.venv\Scripts\Activate.ps1     # Windows PowerShell
```

### Dependencies

The project uses these main dependencies:

```
click          - CLI framework
fastapi        - REST API framework
uvicorn        - ASGI server
sqlalchemy     - ORM with async support
asyncpg        - PostgreSQL async driver
pydantic       - Data validation
cryptography   - Fernet encryption
httpx          - HTTP client for Keycloak
pyjwt          - JWT handling
rich           - Console output
```

Development dependencies:
```
pytest         - Testing framework
pytest-asyncio - Async test support
pytest-cov     - Coverage reporting
ruff           - Linter and formatter
mypy           - Type checking
```

### Docker Compose Services

The `docker-compose.yml` provides:

```yaml
services:
  postgres:
    image: postgres:16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: sshmgr
      POSTGRES_USER: sshmgr
      POSTGRES_PASSWORD: sshmgr_dev_password

  keycloak:
    image: quay.io/keycloak/keycloak:22.0
    ports:
      - "8080:8080"
    command: start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
```

Start/stop with:
```bash
make docker-up    # Start services
make docker-down  # Stop services
make docker-logs  # View logs
```

## Keycloak Configuration

### Automated Setup (Recommended)

Use the automated setup script after starting Keycloak:

```bash
# Start Keycloak
make docker-up

# Run automated setup (creates realm, clients, roles, groups, test user)
make keycloak-setup

# The script outputs the client secret - add it to your .env file
```

The setup script creates:
- **Realm**: `sshmgr`
- **Clients**:
  - `sshmgr-api` (confidential) - for API JWT validation
  - `sshmgr-cli` (public with device flow) - for CLI authentication
  - `sshmgr-web` (confidential) - for web frontend OAuth PKCE flow
- **Roles**: `admin`, `operator`, `viewer`
- **Groups**: `/environments/dev`, `/environments/staging`, `/environments/prod`
- **Test user**: `testadmin` / `testadmin` (with admin role)

For production setup that outputs to .env:
```bash
make keycloak-setup-prod
# or directly:
python scripts/keycloak_setup.py --no-wait --output-env .env
```

### Manual Setup (Alternative)

If you prefer manual configuration:

1. **Access Keycloak Admin Console**
   - URL: http://localhost:8080/admin
   - Username: admin
   - Password: admin

2. **Create Realm**
   - Click "Create Realm"
   - Name: `sshmgr`
   - Click "Create"

3. **Create API Client** (confidential)
   - Clients → Create client
   - Client ID: `sshmgr-api`
   - Client authentication: ON
   - Authorization: OFF
   - Click Next → Save
   - Go to Credentials tab, copy the Client Secret

4. **Create CLI Client** (public with device flow)
   - Clients → Create client
   - Client ID: `sshmgr-cli`
   - Client authentication: OFF
   - Click Next
   - Enable "OAuth 2.0 Device Authorization Grant"
   - Click Save

5. **Create Roles**
   - Realm roles → Create role
   - Create: `admin`, `operator`, `viewer`

6. **Create Groups for Environments**
   - Groups → Create group: `environments`
   - Under `environments`, create child groups for each environment
   - Example: `/environments/prod`, `/environments/staging`

7. **Create Test User**
   - Users → Add user
   - Username: `testuser`
   - Email verified: ON
   - Click Create
   - Credentials → Set password
   - Role mapping → Assign `operator` role
   - Groups → Join `/environments/prod`

### Export Realm Configuration

For repeatable setup, export the realm:
- Realm settings → Action → Partial export
- Include clients and roles
- Save as `keycloak-realm.json`

## Database Migrations

sshmgr uses Alembic for database migrations:

```bash
# Run all pending migrations
make db-migrate

# Create a new migration (after model changes)
make db-revision

# Rollback one migration
make db-downgrade

# View migration history
alembic history
```

## Production Deployment

### System Requirements

- **CPU**: 2+ cores recommended
- **RAM**: 2GB minimum, 4GB recommended
- **Disk**: 10GB for application and logs
- **Network**: HTTPS required for production

### Option 1: Docker with Traefik (Recommended)

The easiest production deployment uses Docker Compose with Traefik for automatic TLS via Let's Encrypt.

#### Prerequisites

- Docker and Docker Compose v2
- A domain name with DNS pointing to your server
- Ports 80 and 443 available

#### Step 1: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Generate a master encryption key
make generate-key
# Copy the output to .env as SSHMGR_MASTER_KEY
```

Edit `.env` with your production values:

```bash
# Domain configuration
DOMAIN=sshmgr.example.com
ACME_EMAIL=admin@example.com

# Required secrets
SSHMGR_MASTER_KEY=<generated-key>
POSTGRES_PASSWORD=<secure-password>
KEYCLOAK_ADMIN_PASSWORD=<secure-password>

# Frontend secrets (required)
AUTH_SECRET=<generate with: openssl rand -base64 32>
KEYCLOAK_WEB_CLIENT_SECRET=<from keycloak-setup-prod output>

# Optional: Traefik dashboard auth (generate with: htpasswd -nB admin)
TRAEFIK_DASHBOARD_AUTH=admin:$2y$...
```

#### Step 2: Configure DNS

Create DNS A records pointing to your server:
- `sshmgr.example.com` → your server IP (frontend)
- `api.sshmgr.example.com` → your server IP
- `auth.sshmgr.example.com` → your server IP
- `traefik.sshmgr.example.com` → your server IP (optional, for dashboard)

#### Step 3: Start the Stack

```bash
# Build and start production stack
make prod-up

# Check status
make prod-status

# View logs
make prod-logs
```

#### Step 4: Configure Keycloak

After services are healthy, set up Keycloak:

```bash
# Run Keycloak setup script (outputs secrets to .env)
make keycloak-setup-prod
```

#### Services

After deployment, services are available at:

| Service | URL |
|---------|-----|
| Frontend | `https://sshmgr.example.com` |
| sshmgr API | `https://api.sshmgr.example.com` |
| Keycloak | `https://auth.sshmgr.example.com` |
| Traefik Dashboard | `https://traefik.sshmgr.example.com/dashboard/` |
| API Docs | `https://api.sshmgr.example.com/api/docs` |

#### Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Internet                  │
                    └─────────────┬───────────────────────┘
                                  │ :80/:443
                    ┌─────────────▼───────────────────────┐
                    │   Traefik (TLS + Let's Encrypt)     │
                    │   - Auto HTTPS redirect             │
                    │   - Certificate renewal             │
                    │   - Security headers (HSTS, etc.)   │
                    └──┬──────────┬──────────────┬────────┘
                       │          │              │
         ┌─────────────▼───┐  ┌───▼──────────┐  ┌▼───────────────┐
         │  ${DOMAIN}      │  │api.${DOMAIN} │  │auth.${DOMAIN}  │
         │  Frontend :3000 │  │sshmgr API    │  │Keycloak :8080  │
         │  (Next.js)      │  │:8000         │  │                │
         └────────┬────────┘  └──────┬───────┘  └───────┬────────┘
                  │                  │                  │
                  └──────────────────┼──────────────────┘
                                     │
                    ┌────────────────▼────────────────────┐
                    │        PostgreSQL :5432             │
                    │        (internal only)              │
                    └─────────────────────────────────────┘
```

#### Managing the Stack

```bash
# Start production
make prod-up

# Stop production
make prod-down

# View logs
make prod-logs

# Restart services
make prod-restart

# Check health status
make prod-status

# Shell into API container
make prod-shell
```

#### Let's Encrypt Staging

For testing, use Let's Encrypt staging to avoid rate limits. Edit `docker-compose.prod.yml` and uncomment:

```yaml
# - "--certificatesresolvers.letsencrypt.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory"
```

### Option 2: Manual Installation

For deployments without Docker, or when integrating with existing infrastructure.

#### Installation Steps

1. **Install from PyPI** (when published):
   ```bash
   pip install sshmgr
   ```

   Or install from source:
   ```bash
   pip install git+https://github.com/yourorg/sshmgr.git
   ```

2. **Configure systemd service** (Linux):
   ```ini
   # /etc/systemd/system/sshmgr-api.service
   [Unit]
   Description=sshmgr API Server
   After=network.target postgresql.service

   [Service]
   Type=simple
   User=sshmgr
   Group=sshmgr
   WorkingDirectory=/opt/sshmgr
   Environment="SSHMGR_MASTER_KEY=..."
   Environment="SSHMGR_DATABASE_URL=..."
   Environment="SSHMGR_KEYCLOAK_URL=..."
   ExecStart=/opt/sshmgr/venv/bin/uvicorn sshmgr.api.main:app --host 0.0.0.0 --port 8000
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

3. **Configure reverse proxy** (nginx):
   ```nginx
   server {
       listen 443 ssl http2;
       server_name sshmgr.example.com;

       ssl_certificate /etc/ssl/certs/sshmgr.crt;
       ssl_certificate_key /etc/ssl/private/sshmgr.key;

       # Security headers
       add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
       add_header X-Content-Type-Options "nosniff" always;
       add_header X-Frame-Options "DENY" always;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_set_header X-Request-ID $request_id;
       }
   }
   ```

### Environment Variables (Production)

```bash
# Required - Backend
SSHMGR_MASTER_KEY=<44-character-fernet-key>
SSHMGR_DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/sshmgr
SSHMGR_KEYCLOAK_URL=https://keycloak.example.com
SSHMGR_KEYCLOAK_REALM=sshmgr
SSHMGR_KEYCLOAK_CLIENT_ID=sshmgr-api
SSHMGR_KEYCLOAK_CLIENT_SECRET=<client-secret>

# Required - Frontend
AUTH_SECRET=<generate with: openssl rand -base64 32>
AUTH_URL=https://sshmgr.example.com
KEYCLOAK_WEB_CLIENT_ID=sshmgr-web
KEYCLOAK_WEB_CLIENT_SECRET=<web-client-secret>
NEXT_PUBLIC_API_URL=https://api.sshmgr.example.com

# Optional
SSHMGR_API_HOST=0.0.0.0
SSHMGR_API_PORT=8000
SSHMGR_LOG_LEVEL=INFO
SSHMGR_LOG_FORMAT=json
SSHMGR_CORS_ORIGINS=https://sshmgr.example.com
```

### Security Hardening

1. **Master Key Management**
   - Use a secrets manager (HashiCorp Vault, AWS Secrets Manager)
   - Rotate the key periodically
   - Never commit to version control

2. **Database Security**
   - Use SSL connections
   - Restrict network access
   - Regular backups

3. **API Security**
   - Always use HTTPS
   - Configure CORS appropriately
   - Rate limiting enabled by default

4. **Keycloak Security**
   - Use production database (not H2)
   - Enable HTTPS
   - Configure password policies
   - Enable MFA for admin users

5. **TLS Configuration**
   - Use TLS 1.2+ only
   - Enable HSTS headers
   - Use strong cipher suites

## Backup and Recovery

### Automatic Backups

The production stack includes an automatic backup service that:
- Runs daily at 2 AM
- Creates compressed SQL dumps (`sshmgr_YYYYMMDD_HHMMSS.sql.gz`)
- Automatically cleans up backups older than `BACKUP_RETENTION_DAYS` (default: 7)
- Stores backups in the `postgres_backups` Docker volume

### Manual Backup Operations

```bash
# Create immediate backup
make backup-now

# List all available backups
make backup-list

# Export latest backup to ./backups/ directory
make backup-export

# Restore from backup (stops and restarts services)
make backup-restore BACKUP_FILE=./backups/sshmgr_20240115_020000.sql.gz
```

### Backup Best Practices

1. **Off-site Storage**: Regularly export backups and store them off-site
   ```bash
   # Export and upload to S3 (example)
   make backup-export
   aws s3 cp ./backups/*.sql.gz s3://your-bucket/sshmgr-backups/
   ```

2. **Test Restores**: Periodically test backup restoration in a staging environment

3. **Backup Verification**: Check backup service logs for failures
   ```bash
   docker logs sshmgr-postgres-backup
   ```

4. **Retention Policy**: Adjust `BACKUP_RETENTION_DAYS` based on your compliance requirements

### Disaster Recovery

To restore the entire system from backup:

```bash
# 1. Stop services
make prod-down

# 2. Remove the old data volume (WARNING: destroys current data)
docker volume rm sshmgr_postgres_data

# 3. Start services (creates fresh database)
make prod-up

# 4. Wait for services to be healthy
make prod-status

# 5. Restore from backup
make backup-restore BACKUP_FILE=./backups/sshmgr_YYYYMMDD_HHMMSS.sql.gz

# 6. Restart services
make prod-restart
```

### What's Backed Up

| Component | Included | Notes |
|-----------|----------|-------|
| Database (PostgreSQL) | Yes | Environments, certificates, policies, audit logs |
| Keycloak data | Yes | Users, roles, groups, realm config (in same database) |
| CA private keys | Yes | Encrypted in database |
| TLS certificates | No | Let's Encrypt regenerates them automatically |
| Master encryption key | No | Store separately in secrets manager |

## Monitoring and Alerting

The production stack includes optional monitoring with Prometheus, Grafana, and AlertManager.

### Enabling Monitoring

1. **Configure monitoring settings** in `.env`:
   ```bash
   # Required for monitoring
   GRAFANA_ADMIN_PASSWORD=<secure-password>

   # Optional: Basic auth for Prometheus/AlertManager
   # Generate with: htpasswd -nB admin
   MONITORING_BASIC_AUTH=admin:$2y$...

   # Optional: Prometheus data retention
   PROMETHEUS_RETENTION=15d
   ```

2. **Ensure DNS is configured** for monitoring subdomains:
   - `grafana.sshmgr.example.com` → your server IP
   - `prometheus.sshmgr.example.com` → your server IP
   - `alertmanager.sshmgr.example.com` → your server IP

3. **Start with monitoring profile**:
   ```bash
   make monitoring-up
   ```

### Monitoring Services

| Service | URL | Description |
|---------|-----|-------------|
| Grafana | `https://grafana.${DOMAIN}` | Dashboards and visualization |
| Prometheus | `https://prometheus.${DOMAIN}` | Metrics collection and queries |
| AlertManager | `https://alertmanager.${DOMAIN}` | Alert routing and notifications |

### Pre-built Dashboard

The stack includes a pre-configured sshmgr dashboard showing:
- API status and health
- Request rate and latency percentiles
- Certificates issued/revoked over time
- Error rates and success rates

Access it at: **Grafana → Dashboards → sshmgr → sshmgr Overview**

### Alert Rules

Pre-configured alerts in `monitoring/prometheus/alerts.yml`:

| Alert | Severity | Description |
|-------|----------|-------------|
| SSHMgrAPIDown | Critical | API unreachable for >1 minute |
| SSHMgrHighErrorRate | Warning | >5% error rate over 5 minutes |
| SSHMgrHighLatency | Warning | P95 latency >2 seconds |
| SSHMgrCertificateSpike | Warning | >100 certs issued in 1 hour |
| TraefikDown | Critical | Reverse proxy unreachable |

### Configuring Notifications

Edit `monitoring/alertmanager/alertmanager.yml` to configure notification channels:

**Slack:**
```yaml
global:
  slack_api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK'

receivers:
  - name: 'slack-notifications'
    slack_configs:
      - channel: '#sshmgr-alerts'
        send_resolved: true
```

**Email:**
```yaml
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@yourdomain.com'
  smtp_auth_username: 'alerts@yourdomain.com'
  smtp_auth_password: 'app-specific-password'

receivers:
  - name: 'email-notifications'
    email_configs:
      - to: 'oncall@yourdomain.com'
```

**PagerDuty:**
```yaml
receivers:
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'your-integration-key'
```

### Managing Monitoring

```bash
# Start with monitoring
make monitoring-up

# Stop monitoring services (keeps main stack running)
make monitoring-down

# View monitoring logs
make monitoring-logs

# Reload Prometheus config after changes
docker exec sshmgr-prometheus kill -HUP 1
```

### Resource Usage

Monitoring adds approximately:

| Service | CPU | Memory |
|---------|-----|--------|
| Prometheus | 0.5 cores | 512MB |
| Grafana | 0.5 cores | 256MB |
| AlertManager | 0.25 cores | 128MB |

## Troubleshooting

### Common Issues

**"ssh-keygen not found"**
```bash
# Verify OpenSSH is installed
which ssh-keygen

# Install if missing
# macOS: Usually pre-installed
# Ubuntu: sudo apt install openssh-client
# RHEL: sudo dnf install openssh-clients
```

**"Master key not configured"**
```bash
# Generate a new key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set in environment
export SSHMGR_MASTER_KEY=<generated-key>
```

**Database connection errors**
```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Check connection string
psql "postgresql://sshmgr:password@localhost:5432/sshmgr"
```

**Keycloak connection errors**
```bash
# Check Keycloak is running
curl http://localhost:8080/health/ready

# Verify realm exists
curl http://localhost:8080/realms/sshmgr/.well-known/openid-configuration
```

### Getting Help

- Check the [Testing Guide](testing.md) for debugging tests
- Review logs: `make docker-logs`
- Open an issue: https://github.com/yourorg/sshmgr/issues
