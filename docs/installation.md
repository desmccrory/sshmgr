# Installation Guide

This guide covers installing sshmgr for development and production environments.

## Prerequisites

- **Python 3.11+**
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

### 5. Verify Installation

```bash
# Run tests
make test           # Unit tests only
make test-all       # All tests (unit + integration)

# Start the API server
make run-api

# In another terminal, test the CLI
sshmgr --help
sshmgr login
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

### Create Realm and Clients

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

### Installation Steps

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
       listen 443 ssl;
       server_name sshmgr.example.com;

       ssl_certificate /etc/ssl/certs/sshmgr.crt;
       ssl_certificate_key /etc/ssl/private/sshmgr.key;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Environment Variables (Production)

```bash
# Required
SSHMGR_MASTER_KEY=<32-byte-fernet-key>
SSHMGR_DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/sshmgr
SSHMGR_KEYCLOAK_URL=https://keycloak.example.com
SSHMGR_KEYCLOAK_REALM=sshmgr
SSHMGR_KEYCLOAK_CLIENT_ID=sshmgr-api
SSHMGR_KEYCLOAK_CLIENT_SECRET=<client-secret>

# Optional
SSHMGR_API_HOST=0.0.0.0
SSHMGR_API_PORT=8000
SSHMGR_LOG_LEVEL=INFO
SSHMGR_LOG_FORMAT=json
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
   - Rate limiting via reverse proxy

4. **Keycloak Security**
   - Use production database (not H2)
   - Enable HTTPS
   - Configure password policies
   - Enable MFA for admin users

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
