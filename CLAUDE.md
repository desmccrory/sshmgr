# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sshmgr is a multi-tenant SSH certificate management system that handles key expiration and rotation using OpenSSH certificates. It provides both CLI and REST API interfaces.

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

# Generate a master encryption key
make generate-key

# Run API server (development)
make run-api
```

## Architecture

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
    keycloak_client_secret: str = ""

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_debug: bool = False

    # Certificates
    default_user_cert_validity_hours: int = 8
    default_host_cert_validity_days: int = 90

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
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

## Environment Variables

### Required
- `SSHMGR_MASTER_KEY` - Fernet key for encrypting CA private keys (44 characters)

### Database
- `SSHMGR_DATABASE_URL` - PostgreSQL connection string (default: `postgresql+asyncpg://...`)
- `SSHMGR_DATABASE_ECHO` - Echo SQL queries (default: false)

### Keycloak
- `SSHMGR_KEYCLOAK_URL` - Keycloak server URL (default: http://localhost:8080)
- `SSHMGR_KEYCLOAK_REALM` - Keycloak realm name (default: sshmgr)
- `SSHMGR_KEYCLOAK_CLIENT_ID` - OAuth client ID (default: sshmgr-api)
- `SSHMGR_KEYCLOAK_CLIENT_SECRET` - OAuth client secret

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

### Certificates
- `SSHMGR_DEFAULT_USER_CERT_VALIDITY_HOURS` - Default user cert validity (default: 8)
- `SSHMGR_DEFAULT_HOST_CERT_VALIDITY_DAYS` - Default host cert validity (default: 90)

### Logging
- `SSHMGR_LOG_LEVEL` - Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
- `SSHMGR_LOG_FORMAT` - Log format: text, json (default: text)

## Production Deployment

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

## Documentation

Full documentation in `docs/` directory:
- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [CLI Reference](docs/cli-reference.md)
- [API Reference](docs/api-reference.md)
- [Testing](docs/testing.md)
- [Security](docs/security.md)
