# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sshmgr is a multi-tenant SSH certificate management system that handles key expiration and rotation using OpenSSH certificates. It provides CLI, REST API, and web frontend interfaces.

## Build & Development Commands

```bash
# Install in development mode
make install-dev

# Run tests
make test              # Unit tests only
make test-cov          # With coverage report

# Code quality
make lint              # Check with ruff
make format            # Format with ruff
make typecheck         # Check with mypy
make check             # All of the above + tests

# Start dev infrastructure (PostgreSQL + Keycloak)
make docker-up
make docker-down

# Set up Keycloak (realm, clients, roles) - run after docker-up
make keycloak-setup          # Creates realm, clients, roles, test user
make keycloak-setup-prod     # Production setup (outputs to .env)

# Generate a master encryption key
make generate-key

# Run API server (development)
make run-api

# Production with Traefik + TLS (uses docker-compose.prod.yml)
make prod-up           # Build and start production stack
make prod-down         # Stop production stack
make prod-logs         # View logs
make prod-status       # Show container health status
make prod-restart      # Restart all services
make prod-shell        # Shell into API container

# Frontend (Next.js)
make frontend-install  # Install npm dependencies
make frontend-dev      # Start dev server (http://localhost:3000)
make frontend-build    # Build for production
make frontend-lint     # Run ESLint
make frontend-typecheck # Run TypeScript checker
make frontend-check    # Run all frontend checks
```

### Keycloak Setup Script

The `scripts/keycloak_setup.py` script automates Keycloak configuration:

```bash
# Basic setup with test user
python scripts/keycloak_setup.py --create-test-user

# Custom Keycloak URL
KEYCLOAK_URL=http://keycloak:8080 python scripts/keycloak_setup.py

# Production setup (append secrets to .env)
python scripts/keycloak_setup.py --no-wait --output-env .env

# Custom environment groups
python scripts/keycloak_setup.py --create-environments prod staging dev
```

**What it creates:**
- Realm: `sshmgr`
- Roles: `admin`, `operator`, `viewer`
- Clients:
  - `sshmgr-api` (confidential) - for API JWT validation
  - `sshmgr-cli` (public) - for CLI device authorization flow
  - `sshmgr-web` (confidential) - for web frontend OAuth PKCE flow
- Groups: `/environments/{dev,staging,prod}`
- Test user: `testadmin` / `testadmin` (with `--create-test-user`)

## Architecture

### Backend (Python)
```
src/sshmgr/
├── core/           # Business logic
│   ├── ca.py       # CertificateAuthority - wraps ssh-keygen
│   └── exceptions.py
├── keys/           # Key storage abstraction
│   ├── base.py     # KeyStorage interface
│   └── encrypted.py # Fernet encryption for PostgreSQL
├── auth/           # Authentication (Keycloak OIDC)
│   ├── keycloak.py     # Keycloak client, token exchange
│   ├── device_flow.py  # OAuth 2.0 Device Authorization Flow
│   ├── jwt.py          # JWT validation, claims extraction
│   ├── rbac.py         # Role-based access control, FastAPI deps
│   └── credentials.py  # CLI credential storage
├── storage/        # Database layer (SQLAlchemy 2.0 async)
│   ├── database.py     # Engine and session management
│   ├── models.py       # Environment, Certificate, Policy
│   ├── repositories.py # Data access classes
│   └── migrations/     # Alembic migrations
├── cli/            # Click CLI commands
└── api/            # FastAPI REST API
```

### Frontend (Next.js)
```
frontend/
├── src/
│   ├── app/                      # Next.js App Router
│   │   ├── (auth)/               # Login, error pages
│   │   ├── (dashboard)/          # Protected routes
│   │   │   ├── user/             # User dashboard, certificates
│   │   │   ├── admin/            # Environment management
│   │   │   └── config/           # User management, settings
│   │   └── api/auth/             # Auth.js handler
│   ├── components/
│   │   ├── ui/                   # shadcn/ui components
│   │   ├── layout/               # Header, sidebar, breadcrumbs
│   │   └── certificates/         # Certificate table, forms
│   ├── hooks/                    # useAuth, useEnvironments, useCertificates
│   ├── lib/
│   │   ├── auth.ts               # Auth.js + Keycloak config
│   │   └── api-client.ts         # Type-safe API client
│   └── types/                    # API type definitions
```

## Configuration

Settings are managed via Pydantic with the `SSHMGR_` prefix:

```python
from sshmgr.config import get_settings

settings = get_settings()  # Cached singleton
print(settings.database_url)
print(settings.keycloak_url)
```

**Settings class** (`src/sshmgr/config.py`):
```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SSHMGR_",
        env_file=".env",
        case_sensitive=False,
    )

    # Database
    database_url: str = "postgresql+asyncpg://..."
    database_echo: bool = False

    # Encryption
    master_key: str  # Fernet key (44 characters, required)

    # Keycloak
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "sshmgr"
    keycloak_client_id: str = "sshmgr-api"
    keycloak_cli_client_id: str = "sshmgr-cli"  # Public client for CLI device flow
    keycloak_client_secret: str = ""

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False

    # Certificates
    default_user_cert_validity_hours: int = 8
    default_host_cert_validity_days: int = 90

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "text"] = "text"
```

**Test Settings**: Override with in-memory SQLite:
```python
class TestSettings(Settings):
    database_url: str = "sqlite+aiosqlite:///:memory:"
    master_key: str = "dGVzdC1tYXN0ZXIta2V5LWZvci10ZXN0aW5nLW9ubHk="
```

## Key Design Decisions

1. **OpenSSH for crypto**: All certificate operations use `ssh-keygen` subprocess calls, avoiding custom crypto implementation
2. **Fernet encryption**: CA private keys are encrypted with Fernet before storage in PostgreSQL
3. **Keycloak OIDC**: Authentication via Keycloak with Device Authorization Flow for CLI
4. **Multi-tenant**: Each environment has separate user/host CAs with RBAC access control

## Database Schema

### Entity Relationships

```
Environment (1) ──────< Certificate (many)
     │
     └──────< Policy (many)
```

### Environment Model
```python
class Environment(Base):
    id: UUID
    name: str  # unique, indexed

    # Current CAs
    user_ca_public_key: str
    user_ca_key_ref: str      # "encrypted:..." format
    host_ca_public_key: str
    host_ca_key_ref: str

    # Default validity
    default_user_cert_validity: timedelta  # default 8 hours
    default_host_cert_validity: timedelta  # default 90 days

    # CA Rotation (old CA kept during grace period)
    old_user_ca_public_key: str | None
    old_user_ca_key_ref: str | None
    old_user_ca_expires_at: datetime | None
    old_host_ca_public_key: str | None
    old_host_ca_key_ref: str | None
    old_host_ca_expires_at: datetime | None

    created_at: datetime
    updated_at: datetime

    # Relationships (cascade delete)
    certificates: List[Certificate]
    policies: List[Policy]
```

### Certificate Model
```python
class Certificate(Base):
    id: UUID
    environment_id: UUID  # FK -> Environment

    cert_type: CertType   # USER | HOST
    serial: int
    key_id: str           # indexed, identifier in certificate
    principals: List[str]

    valid_after: datetime
    valid_before: datetime  # indexed
    public_key_fingerprint: str  # SHA256

    # Audit
    issued_at: datetime
    issued_by: str        # username from JWT

    # Revocation
    revoked_at: datetime | None
    revoked_by: str | None
    revocation_reason: str | None

    # Unique constraint: (environment_id, serial)

    # Computed properties
    is_revoked: bool      # revoked_at is not None
    is_expired: bool      # now > valid_before
    is_valid: bool        # not revoked and within validity window
```

### Policy Model
```python
class Policy(Base):
    id: UUID
    environment_id: UUID  # FK -> Environment

    name: str
    cert_type: CertType   # USER | HOST

    # Constraints
    allowed_principals: List[str]  # patterns or exact matches
    max_validity: timedelta

    # Extensions
    extensions: List[str] | None      # ["permit-pty", "permit-port-forwarding"]
    force_command: str | None         # restricted command
    source_addresses: List[str] | None  # IP/CIDR restrictions

    is_active: bool
    created_at: datetime
    updated_at: datetime

    # Unique constraint: (environment_id, name)
```

## Error Handling

### Exception Hierarchy (`src/sshmgr/core/exceptions.py`)
```
SSHMgrError (base)
├── CAError (Certificate Authority operations)
│   ├── KeyGenerationError - ssh-keygen key generation failures
│   ├── SigningError - certificate signing failures
│   └── InvalidKeyError - invalid SSH key format
├── StorageError (key storage)
│   └── EncryptionError - Fernet encrypt/decrypt failures
├── EnvironmentError
│   └── EnvironmentNotFoundError
├── AuthenticationError - token validation failures
└── AuthorizationError - permission denied
```

### Error Handling Patterns

**In core modules** - wrap subprocess errors:
```python
try:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
except subprocess.CalledProcessError as e:
    raise KeyGenerationError(f"Failed to generate CA key: {e.stderr}") from e
except FileNotFoundError:
    raise KeyGenerationError("ssh-keygen not found in PATH")
```

**In API handlers** - convert to HTTP responses:
```python
@router.post("/environments")
async def create_environment(...):
    try:
        env = await env_repo.create(...)
    except EnvironmentExistsError:
        raise HTTPException(status_code=409, detail="Environment already exists")
```

**In CLI** - use `@handle_errors` decorator:
```python
@cli.command()
@handle_errors  # Catches SSHMgrError, prints user-friendly message
def sign_user(...):
    ...
```

## Important Patterns

### Certificate Authority Usage
```python
from sshmgr.core.ca import CertificateAuthority, KeyType
from datetime import timedelta

# Generate new CA
ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

# Sign user certificate
cert = ca.sign_user_key(
    public_key="ssh-ed25519 AAAA...",
    principals=["username"],
    key_id="user@example.com",
    validity=timedelta(hours=8),
)
```

### Encrypted Key Storage
```python
from sshmgr.keys.encrypted import EncryptedKeyStorage

storage = EncryptedKeyStorage(master_key)
key_ref = storage.store_key(env_id, "user_ca", private_key_bytes)
retrieved = storage.retrieve_key(key_ref)
```

### Repository Pattern (Database Access)
```python
from sshmgr.storage import Database, EnvironmentRepository, CertificateRepository

db = Database(settings)
async with db.session() as session:
    env_repo = EnvironmentRepository(session)

    # Create environment
    env = await env_repo.create(
        name="prod",
        user_ca_public_key=ca.public_key,
        user_ca_key_ref=key_storage.store_key(...),
        ...
    )

    # Issue certificate and record it
    cert_repo = CertificateRepository(session)
    await cert_repo.create(
        environment_id=env.id,
        cert_type=CertType.USER,
        serial=1,
        ...
    )
```

### Authentication (FastAPI)
```python
from fastapi import Depends
from sshmgr.auth import (
    AuthContext, Role, get_current_user,
    require_role, RequireEnvironmentAccess
)

@router.post("/environments/{env_name}/certs")
async def issue_cert(
    env_name: str,
    auth: AuthContext = Depends(get_current_user),      # JWT validation
    _: None = Depends(require_role(Role.OPERATOR)),     # Role check
    _: None = Depends(RequireEnvironmentAccess()),      # Env access check
):
    # auth.username, auth.roles, auth.can_access_environment(...)
    ...
```

### API Bearer Token Format

**Request format**:
```
Authorization: Bearer <access_token>
```

**Token validation** (`src/sshmgr/auth/rbac.py`):
```python
bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    validator: JWTValidator = Depends(get_jwt_validator),
) -> AuthContext:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = await validator.validate(credentials.credentials)
    return AuthContext(claims)
```

**JWT validation** (`src/sshmgr/auth/jwt.py`):
- Tokens are RS256-signed JWTs from Keycloak
- JWKS fetched from Keycloak's `/.well-known/openid-configuration`
- Validates: signature, expiration, audience, issuer

**Token claims structure**:
```python
@dataclass
class TokenClaims:
    sub: str                        # User ID
    exp: int                        # Expiration timestamp
    preferred_username: str | None
    email: str | None
    realm_roles: list[str]          # ["admin", "operator", "viewer"]
    groups: list[str]               # Environment access: ["/environments/prod"]
```

**Example API call**:
```bash
curl -X POST "http://localhost:8000/api/v1/environments/prod/certs/user" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{"public_key": "ssh-ed25519 AAAA...", "principals": ["username"]}'
```

### CLI Device Flow Login
```python
from sshmgr.auth import login_with_device_flow, get_credential_manager

# Login
def show_code(uri, code, _):
    print(f"Visit {uri} and enter: {code}")

tokens = await login_with_device_flow(on_code_received=show_code)

# Store credentials
manager = get_credential_manager()
manager.save_tokens(tokens, keycloak_url, realm)

# Later: get stored token
access_token = manager.get_access_token()
```

## Testing

- Tests require `ssh-keygen` in PATH
- Unit tests in `tests/unit/` - no external services needed
- Integration tests in `tests/integration/` - use SQLite in-memory, some use PostgreSQL

### Key Fixtures (`tests/conftest.py`)

```python
@pytest.fixture
def temp_dir():
    """Temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def sample_user_keypair(temp_dir):
    """Generate real SSH keypair using ssh-keygen."""
    key_path = temp_dir / "test_user_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""],
        capture_output=True, check=True,
    )
    return {
        "private_key": key_path.read_bytes(),
        "public_key": key_path.with_suffix(".pub").read_text().strip(),
        "path": key_path,
    }

@pytest.fixture
def ca_ed25519():
    """Fresh Ed25519 CA for each test."""
    return CertificateAuthority.generate(key_type=KeyType.ED25519)

@pytest.fixture
def master_key():
    """Test encryption master key."""
    return EncryptedKeyStorage.generate_master_key()

@pytest.fixture
def encrypted_storage(master_key):
    """Encrypted key storage instance."""
    return EncryptedKeyStorage(master_key)
```

### Testing Approach

- **No mocking of ssh-keygen**: Tests use the real `ssh-keygen` binary for cryptographic operations
- **Temporary directories**: Each test gets fresh temp dir that cleans up automatically
- **Fresh keypairs**: Sample keys generated per-test to avoid state leakage

### API Testing

```python
@pytest.fixture
def client():
    """Create test client with dependency overrides."""
    from sshmgr.api.main import create_app
    app = create_app()

    # Override dependencies
    async def mock_db_session():
        session = AsyncMock()
        yield session

    app.dependency_overrides[get_db_session] = mock_db_session
    app.dependency_overrides[get_app_settings] = lambda: TestSettings()

    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
```

## Database Migrations

```bash
# Run migrations
make db-migrate

# Create new migration
make db-revision

# Rollback one migration
make db-downgrade
```

## REST API Endpoints

Base URL: `/api/v1`

### Health
- `GET /health` - Basic health check
- `GET /ready` - Readiness check (database, Keycloak)
- `GET /version` - Version info

### Environments
- `GET /environments` - List environments (filtered by access)
- `POST /environments` - Create environment (admin only)
- `GET /environments/{name}` - Get environment details
- `DELETE /environments/{name}` - Delete environment (admin only)
- `GET /environments/{name}/ca/{type}` - Get CA public key
- `POST /environments/{name}/rotate` - Rotate CA (admin only)
- `GET /environments/{name}/rotation-status` - Get rotation status

### Certificates
- `GET /environments/{name}/certs` - List certificates
- `POST /environments/{name}/certs/user` - Sign user certificate (operator+)
- `POST /environments/{name}/certs/host` - Sign host certificate (operator+)
- `GET /environments/{name}/certs/{serial}` - Get certificate details
- `DELETE /environments/{name}/certs/{serial}` - Revoke certificate (operator+)
- `GET /environments/{name}/certs/by-key-id/{key_id}` - Find by key ID

API docs available at `/api/docs` (Swagger UI) and `/api/redoc` (ReDoc).

## CLI Commands

```bash
# Authentication
sshmgr login              # Browser-based login
sshmgr logout             # Clear credentials
sshmgr auth status        # Show login status
sshmgr auth whoami        # Show current user info

# Environments
sshmgr env init <name>    # Create environment
sshmgr env list           # List environments
sshmgr env show <name>    # Show environment details
sshmgr env delete <name>  # Delete environment
sshmgr env get-ca <name>  # Get CA public key

# Certificates
sshmgr cert sign-user     # Sign user certificate
sshmgr cert sign-host     # Sign host certificate
sshmgr cert list          # List issued certificates
sshmgr cert show          # Show certificate details
sshmgr cert revoke        # Revoke certificate

# CA Rotation
sshmgr rotate ca          # Rotate CA with grace period
sshmgr rotate status      # Show rotation status
sshmgr rotate cleanup     # Clean up expired old CAs
```

### CA Trust Relationships

Understanding where to deploy each CA type:

| CA Type | Signs | Trusted By | Deployment Location |
|---------|-------|------------|---------------------|
| **User CA** | User certificates | SSH **servers** | `/etc/ssh/trusted_user_ca.pub` |
| **Host CA** | Host certificates | SSH **clients** | `~/.ssh/known_hosts` |

**Key insight**: The names refer to *what gets signed*, not *where the CA goes*:
- "User CA" signs **user** keys → deployed to **servers** (which authenticate users)
- "Host CA" signs **host** keys → deployed to **clients** (which verify hosts)

**User CA deployment (on SSH servers):**
```bash
# Get User CA and configure sshd to trust it
sshmgr env get-ca prod --type user -o /etc/ssh/trusted_user_ca.pub

# sshd_config
TrustedUserCAKeys /etc/ssh/trusted_user_ca.pub
```

**Host CA deployment (on SSH clients):**
```bash
# Get Host CA and add to known_hosts
sshmgr env get-ca prod --type host
# Add to ~/.ssh/known_hosts:
@cert-authority *.example.com ssh-ed25519 AAAA...
```

**During CA rotation**, deploy both CAs:
```bash
sshmgr env get-ca prod --type user --include-old -o /etc/ssh/trusted_user_ca.pub
```

### CLI Audit Trail

All CLI certificate operations record `issued_by`/`revoked_by` for audit compliance.
User identification is resolved in order:

1. `SSHMGR_CLI_USER` env var (for CI/CD and service accounts)
2. Keycloak login username (if logged in via `sshmgr login`)
3. System username with `cli:` prefix (e.g., `cli:dmccrory`)

## Environment Variables

### Required (for encryption)
- `SSHMGR_MASTER_KEY` - Fernet key for encrypting CA private keys (44 characters). Required when creating environments or signing certificates. Generate with `make generate-key`.

### Database
- `SSHMGR_DATABASE_URL` - PostgreSQL connection string (default: `postgresql+asyncpg://...`)
- `SSHMGR_DATABASE_ECHO` - Echo SQL queries (default: false)

### Keycloak
- `SSHMGR_KEYCLOAK_URL` - Keycloak server URL (default: http://localhost:8080)
- `SSHMGR_KEYCLOAK_REALM` - Keycloak realm name (default: sshmgr)
- `SSHMGR_KEYCLOAK_CLIENT_ID` - OAuth client ID for API (default: sshmgr-api)
- `SSHMGR_KEYCLOAK_CLI_CLIENT_ID` - OAuth client ID for CLI device flow (default: sshmgr-cli)
- `SSHMGR_KEYCLOAK_CLIENT_SECRET` - OAuth client secret (for confidential API client)

### API Server
- `SSHMGR_API_HOST` - API server host (default: 0.0.0.0)
- `SSHMGR_API_PORT` - API server port (default: 8000)
- `SSHMGR_API_DEBUG` - Enable debug mode (default: false)

**Note**: The CLI constructs the API URL from `SSHMGR_API_HOST` and `SSHMGR_API_PORT` as `http://{host}:{port}`. There is no separate `SSHMGR_API_URL` variable.

### CORS (Cross-Origin Resource Sharing)
- `SSHMGR_CORS_ORIGINS` - Allowed origins, comma-separated (default: empty = no CORS)
- `SSHMGR_CORS_ALLOW_CREDENTIALS` - Allow credentials (default: false)
- `SSHMGR_CORS_ALLOW_METHODS` - Allowed methods (default: GET,POST,DELETE)
- `SSHMGR_CORS_ALLOW_HEADERS` - Allowed headers (default: Authorization,Content-Type)
- `SSHMGR_CORS_MAX_AGE` - Preflight cache max age in seconds (default: 600)

**Note**: CORS is disabled by default for security. Set `SSHMGR_CORS_ORIGINS` to enable.

Example for development:
```bash
SSHMGR_CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Rate Limiting
- `SSHMGR_RATE_LIMIT_ENABLED` - Enable rate limiting (default: true)
- `SSHMGR_RATE_LIMIT_REQUESTS` - Max requests per window (default: 100)
- `SSHMGR_RATE_LIMIT_WINDOW_SECONDS` - Rate limit window (default: 60)
- `SSHMGR_RATE_LIMIT_BURST` - Burst allowance for short spikes (default: 20)

**Note**: Rate limiting uses token bucket algorithm with per-client tracking (by user or IP).
Health endpoints (`/health`, `/ready`, `/metrics`) are excluded from rate limiting.

### Certificates
- `SSHMGR_DEFAULT_USER_CERT_VALIDITY_HOURS` - Default user cert validity (default: 8)
- `SSHMGR_DEFAULT_HOST_CERT_VALIDITY_DAYS` - Default host cert validity (default: 90)

### CLI
- `SSHMGR_CLI_USER` - Override CLI user for audit logs (for automation/service accounts)

### Logging
- `SSHMGR_LOG_LEVEL` - Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)
- `SSHMGR_LOG_FORMAT` - Log format: text, json (default: text)

### Frontend (Next.js)
- `AUTH_SECRET` - Auth.js session encryption key (generate with: `openssl rand -base64 32`)
- `AUTH_URL` - Frontend URL for Auth.js callbacks (e.g., `https://sshmgr.example.com`)
- `KEYCLOAK_URL` - Keycloak URL for browser redirects (e.g., `https://auth.sshmgr.example.com`)
- `KEYCLOAK_REALM` - Keycloak realm name (default: sshmgr)
- `KEYCLOAK_CLIENT_ID` - Web client ID (default: sshmgr-web)
- `KEYCLOAK_CLIENT_SECRET` - Web client secret (from Keycloak)
- `NEXT_PUBLIC_API_URL` - Backend API URL (e.g., `https://api.sshmgr.example.com`)

## Production Deployment

### Option 1: With Traefik + TLS (Recommended)

Uses `docker-compose.prod.yml` with Traefik reverse proxy and automatic Let's Encrypt certificates.

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env:
#   DOMAIN=sshmgr.example.com
#   ACME_EMAIL=admin@example.com
#   SSHMGR_MASTER_KEY=<from make generate-key>
#   POSTGRES_PASSWORD=<secure>
#   KEYCLOAK_ADMIN_PASSWORD=<secure>
#   AUTH_SECRET=<generate-with: openssl rand -base64 32>
#   KEYCLOAK_WEB_CLIENT_SECRET=<from keycloak-setup>

# 2. Ensure DNS is configured:
#   ${DOMAIN} → your server IP (frontend)
#   api.${DOMAIN} → your server IP
#   auth.${DOMAIN} → your server IP

# 3. Start production stack
make prod-up

# 4. Check status
make prod-status

# 5. View logs
make prod-logs

# 6. Stop production
make prod-down
```

Services available at:
- Frontend: `https://sshmgr.example.com`
- API: `https://api.sshmgr.example.com`
- Keycloak: `https://auth.sshmgr.example.com`
- API Docs: `https://api.sshmgr.example.com/api/docs`

### Option 2: Simple (No TLS)

Uses `docker-compose.yml` with production profile. Requires external TLS termination.

```bash
# Build Docker image
make docker-build

# Start production stack (requires .env file with SSHMGR_MASTER_KEY)
make docker-prod

# View logs
make docker-prod-logs

# Stop production stack
make docker-prod-down
```

## Monitoring

- **Metrics**: Prometheus metrics at `/api/v1/metrics`
- **Health**: `/api/v1/health` (liveness), `/api/v1/ready` (readiness)
- **Logging**: JSON structured logging with audit trail
- **Request Tracing**: Every request gets a unique `X-Request-ID` header for correlation

### Request ID Correlation

All API requests include an `X-Request-ID` header for distributed tracing:
- If client provides `X-Request-ID`, it's preserved through the request
- If not provided, a UUID is generated automatically
- The ID is returned in response headers for client-side correlation

```bash
# Request with custom ID
curl -H "X-Request-ID: my-trace-123" http://localhost:8000/api/v1/health

# Response includes the ID
# X-Request-ID: my-trace-123
```

### Key Metrics
- `sshmgr_certificates_issued_total` - Certificates issued (by env, type)
- `sshmgr_certificates_revoked_total` - Certificates revoked
- `sshmgr_http_requests_total` - HTTP requests (by method, endpoint, status)
- `sshmgr_http_request_duration_seconds` - Request latency histogram

## Frontend (Next.js Web UI)

### Tech Stack
- **Framework**: Next.js 14 (App Router)
- **Styling**: Tailwind CSS + shadcn/ui
- **Auth**: Auth.js v5 with Keycloak PKCE flow
- **Data Fetching**: TanStack Query (React Query)
- **Forms**: react-hook-form + zod validation

### Three Main Sections

| Section | Path | Description | Required Role |
|---------|------|-------------|---------------|
| **User** | `/user` | Personal dashboard, view/request certificates | viewer+ |
| **Admin** | `/admin` | Manage environments, certificates, CA rotation | viewer+ (filtered) |
| **Config** | `/config` | User management (Keycloak), system settings | admin |

### Frontend Setup

```bash
# 1. Install dependencies
make frontend-install

# 2. Create environment file
cp frontend/.env.example frontend/.env.local

# 3. Edit frontend/.env.local with:
NEXT_PUBLIC_API_URL=http://localhost:8000
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=sshmgr
KEYCLOAK_CLIENT_ID=sshmgr-web
KEYCLOAK_CLIENT_SECRET=<from-keycloak>
AUTH_SECRET=<generate-with: openssl rand -base64 32>

# 4. Start development server
make frontend-dev
# Frontend runs on http://localhost:3000
```

### Keycloak Web Client Setup

Create `sshmgr-web` client in Keycloak admin console:
- **Client type**: OpenID Connect
- **Client authentication**: ON (confidential)
- **Valid redirect URIs**: `http://localhost:3000/*` (dev), `https://your-domain.com/*` (prod)
- **Web origins**: `http://localhost:3000` (dev)

### Frontend Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NEXT_PUBLIC_API_URL` | Backend API URL | Yes |
| `KEYCLOAK_URL` | Keycloak server URL | Yes |
| `KEYCLOAK_REALM` | Keycloak realm (sshmgr) | Yes |
| `KEYCLOAK_CLIENT_ID` | Web client ID (sshmgr-web) | Yes |
| `KEYCLOAK_CLIENT_SECRET` | Web client secret | Yes |
| `AUTH_SECRET` | Session encryption key | Yes |
| `AUTH_URL` | Frontend URL for callbacks | Yes (prod) |

### Authentication Flow (Frontend)

1. User clicks "Sign in" → redirects to Keycloak
2. User authenticates with Keycloak
3. Keycloak redirects back with authorization code
4. Auth.js exchanges code for tokens (PKCE)
5. Session stored with access token, roles, groups
6. API calls include `Authorization: Bearer <token>`
7. Token refresh handled automatically

### Role-Based UI

```typescript
import { useAuth } from "@/hooks/use-auth";

function MyComponent() {
  const { isAdmin, isOperator, hasMinimumRole, canAccessEnvironment } = useAuth();

  // Check specific role
  if (isAdmin) { /* show admin features */ }

  // Check minimum role (includes higher roles)
  if (hasMinimumRole("operator")) { /* show operator+ features */ }

  // Check environment access
  if (canAccessEnvironment("prod")) { /* show prod environment */ }
}
```

### Key Frontend Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `Sidebar` | `components/layout/sidebar.tsx` | Navigation with role-based menu items |
| `Header` | `components/layout/header.tsx` | User menu, logout |
| `CertificateTable` | `components/certificates/certificate-table.tsx` | Cert list with status badges |
| `useEnvironments` | `hooks/use-environments.ts` | React Query hooks for env CRUD |
| `useCertificates` | `hooks/use-certificates.ts` | React Query hooks for cert operations |
| `apiClient` | `lib/api-client.ts` | Type-safe API client |

### Key Frontend Pages

| Page | Path | Features |
|------|------|----------|
| User Dashboard | `/user` | Overview, quick actions |
| My Certificates | `/user/certificates` | List certs by environment |
| Request Certificate | `/user/request` | Sign user cert form |
| Admin Dashboard | `/admin` | Metrics, recent environments |
| Environments | `/admin/environments` | List/create/delete |
| Environment Detail | `/admin/environments/[name]` | CA keys, certificates |
| Sign Certificate | `/admin/environments/[name]/certificates/sign` | User/host cert forms |
| CA Rotation | `/admin/environments/[name]/rotation` | Rotate with grace period |
| Audit Logs | `/admin/audit` | Certificate history |
| User Management | `/config/users` | Keycloak admin link |

### API Client Usage

```typescript
import apiClient from "@/lib/api-client";

// List environments (auto-includes auth header)
const { environments } = await apiClient.listEnvironments();

// Sign certificate
const cert = await apiClient.signUserCertificate("prod", {
  public_key: "ssh-ed25519 AAAA...",
  principals: ["username"],
  key_id: "user@example.com",
});
```

### React Query Hooks

```typescript
import { useEnvironments, useCreateEnvironment } from "@/hooks/use-environments";
import { useCertificates, useSignUserCertificate } from "@/hooks/use-certificates";

// Fetch with caching
const { data, isLoading } = useEnvironments();

// Mutations with auto-invalidation
const createMutation = useCreateEnvironment();
await createMutation.mutateAsync({ name: "prod", key_type: "ed25519" });
```

## Documentation

Full documentation in `docs/` directory:
- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [CLI Reference](docs/cli-reference.md)
- [API Reference](docs/api-reference.md)
- [Testing](docs/testing.md)
- [Security](docs/security.md)

Frontend documentation: [frontend/README.md](frontend/README.md)
