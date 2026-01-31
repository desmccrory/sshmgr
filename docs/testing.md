# Testing Guide

This guide covers running tests, writing new tests, and testing best practices for sshmgr.

## Prerequisites

- Python 3.11+
- OpenSSH (`ssh-keygen` in PATH)
- Development dependencies installed

```bash
# Install development dependencies
pip install -e ".[dev]"
# or
make install-dev
```

## Running Tests

### Quick Start

```bash
# Run all tests
make test

# Run with coverage
make test-cov

# Run specific test file
pytest tests/unit/test_ca.py

# Run specific test
pytest tests/unit/test_ca.py::test_generate_ed25519_ca

# Run with verbose output
pytest -v

# Run and stop on first failure
pytest -x
```

### Test Categories

```bash
# Unit tests only (no external services)
pytest tests/unit/

# Integration tests (uses in-memory SQLite)
pytest tests/integration/

# Run all tests
make test-all

# Specific integration test categories
pytest tests/integration/test_api_integration.py     # API endpoints
pytest tests/integration/test_ca_integration.py      # CA/certificate signing
pytest tests/integration/test_cli_integration.py     # CLI commands
pytest tests/integration/test_auth_integration.py    # Authentication
pytest tests/integration/test_repositories.py        # Database repositories

# All tests with markers
pytest -m "not slow"  # Skip slow tests
pytest -m "database"  # Only database tests
```

## Test Structure

```
tests/
├── conftest.py                  # Shared fixtures
├── unit/                        # Unit tests (no external deps)
│   ├── test_api.py              # API endpoints and dependencies
│   ├── test_api_schemas.py      # Pydantic schema validation
│   ├── test_auth.py             # Authentication module
│   ├── test_ca.py               # Certificate Authority
│   ├── test_cli_main.py         # CLI commands and groups
│   ├── test_cli_output.py       # CLI output formatting
│   ├── test_encrypted_keys.py   # Key encryption/storage
│   ├── test_logging.py          # Structured logging and audit
│   ├── test_metrics.py          # Prometheus metrics
│   └── test_storage.py          # Database models
└── integration/                 # Integration tests
    ├── test_api_integration.py  # API endpoint E2E tests
    ├── test_auth_integration.py # Authentication flow tests
    ├── test_ca_integration.py   # CA signing workflow tests
    ├── test_cli_integration.py  # CLI command tests
    └── test_repositories.py     # Repository pattern tests
```

### Test Coverage by Module

| Module | Test File | Key Areas |
|--------|-----------|-----------|
| `core/ca.py` | `test_ca.py` | CA generation, certificate signing, key parsing |
| `keys/encrypted.py` | `test_encrypted_keys.py` | Fernet encryption, key storage |
| `auth/*` | `test_auth.py` | Keycloak config, JWT claims, RBAC, credentials |
| `storage/models.py` | `test_storage.py` | Environment, Certificate, Policy models |
| `storage/repositories.py` | `test_repositories.py` | CRUD operations, queries |
| `api/main.py` | `test_api.py` | App creation, health endpoints, dependencies |
| `api/schemas.py` | `test_api_schemas.py` | Request/response validation |
| `cli/main.py` | `test_cli_main.py` | Commands, groups, shortcuts |
| `cli/output.py` | `test_cli_output.py` | Formatters, print helpers |
| `logging.py` | `test_logging.py` | JSON/text formatting, audit logger |
| `metrics.py` | `test_metrics.py` | Counters, gauges, histograms |

## Key Fixtures

### conftest.py

The shared fixtures provide common test dependencies:

```python
import pytest
from sshmgr.core.ca import CertificateAuthority, KeyType
from sshmgr.keys.encrypted import EncryptedKeyStorage

@pytest.fixture
def temp_dir():
    """Provide a temporary directory that's cleaned up after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def ca_ed25519():
    """Provide a fresh Ed25519 CA for each test."""
    return CertificateAuthority.generate(key_type=KeyType.ED25519)

@pytest.fixture
def ca_rsa():
    """Provide a fresh RSA CA for each test."""
    return CertificateAuthority.generate(key_type=KeyType.RSA, bits=2048)

@pytest.fixture
def sample_user_keypair(temp_dir):
    """Generate a sample user SSH keypair for testing."""
    key_path = temp_dir / "test_user_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "test@example.com"],
        capture_output=True, check=True,
    )
    return {
        "private_key": key_path.read_bytes(),
        "public_key": key_path.with_suffix(".pub").read_text().strip(),
        "path": key_path,
    }

@pytest.fixture
def sample_host_keypair(temp_dir):
    """Generate a sample host SSH keypair for testing."""
    key_path = temp_dir / "test_host_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "host"],
        capture_output=True, check=True,
    )
    return {
        "private_key": key_path.read_bytes(),
        "public_key": key_path.with_suffix(".pub").read_text().strip(),
        "path": key_path,
    }

@pytest.fixture
def master_key():
    """Provide a test master encryption key."""
    return EncryptedKeyStorage.generate_master_key()

@pytest.fixture
def encrypted_storage(master_key):
    """Provide an encrypted key storage instance."""
    return EncryptedKeyStorage(master_key)

@pytest.fixture
def sample_environment_id():
    """Provide a sample environment UUID."""
    return uuid4()
```

### Database Fixtures

For integration tests, use SQLite in-memory or a test PostgreSQL database:

```python
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sshmgr.storage.database import Base

@pytest.fixture
async def db_session():
    """Create an in-memory SQLite database session."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSession(engine) as session:
        yield session

    await engine.dispose()
```

## Writing Tests

### Unit Test Example

```python
# tests/unit/test_ca.py

import pytest
from datetime import timedelta
from sshmgr.core.ca import CertificateAuthority, KeyType, CertificateType

class TestCertificateAuthority:
    """Tests for CertificateAuthority class."""

    def test_generate_ed25519_ca(self):
        """Test generating an Ed25519 CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        assert ca.public_key.startswith("ssh-ed25519")
        assert ca.private_key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        assert ca.key_type == KeyType.ED25519

    def test_generate_rsa_ca(self):
        """Test generating an RSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.RSA)

        assert ca.public_key.startswith("ssh-rsa")
        assert ca.key_type == KeyType.RSA

    def test_sign_user_key(self, ca, test_public_key):
        """Test signing a user public key."""
        cert = ca.sign_user_key(
            public_key=test_public_key,
            principals=["testuser"],
            key_id="test@example.com",
            validity=timedelta(hours=8),
        )

        assert cert.cert_type == CertificateType.USER
        assert cert.key_id == "test@example.com"
        assert cert.principals == ["testuser"]
        assert "ssh-ed25519-cert-v01@openssh.com" in cert.certificate

    def test_sign_host_key(self, ca, test_public_key):
        """Test signing a host public key."""
        cert = ca.sign_host_key(
            public_key=test_public_key,
            principals=["server.example.com", "10.0.0.1"],
            validity=timedelta(days=90),
        )

        assert cert.cert_type == CertificateType.HOST
        assert "server.example.com" in cert.principals

    def test_fingerprint(self, ca):
        """Test getting CA fingerprint."""
        fingerprint = ca.fingerprint

        assert fingerprint.startswith("SHA256:")
        assert len(fingerprint) > 10

    def test_from_private_key(self, ca):
        """Test loading CA from private key."""
        loaded = CertificateAuthority.from_private_key(ca.private_key)

        assert loaded.public_key == ca.public_key
        assert loaded.key_type == ca.key_type
```

### Async Test Example

```python
# tests/unit/test_repositories.py

import pytest
from datetime import timedelta
from sshmgr.storage.repositories import EnvironmentRepository

class TestEnvironmentRepository:
    """Tests for EnvironmentRepository."""

    @pytest.mark.asyncio
    async def test_create_environment(self, db_session, ca):
        """Test creating an environment."""
        repo = EnvironmentRepository(db_session)

        env = await repo.create(
            name="test-env",
            user_ca_public_key=ca.public_key,
            user_ca_key_ref="encrypted:test",
            host_ca_public_key=ca.public_key,
            host_ca_key_ref="encrypted:test",
            default_user_cert_validity=timedelta(hours=8),
            default_host_cert_validity=timedelta(days=90),
        )

        assert env.name == "test-env"
        assert env.id is not None

    @pytest.mark.asyncio
    async def test_get_by_name(self, db_session, ca):
        """Test getting environment by name."""
        repo = EnvironmentRepository(db_session)

        await repo.create(
            name="find-me",
            user_ca_public_key=ca.public_key,
            user_ca_key_ref="encrypted:test",
            host_ca_public_key=ca.public_key,
            host_ca_key_ref="encrypted:test",
        )

        found = await repo.get_by_name("find-me")
        assert found is not None
        assert found.name == "find-me"

        not_found = await repo.get_by_name("nonexistent")
        assert not_found is None
```

### API Test Example

```python
# tests/unit/test_api.py

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from sshmgr.api.main import create_app
from sshmgr.api.dependencies import get_db_session, get_app_settings

class TestHealthEndpoints:
    """Tests for health check endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client with mocked dependencies."""
        app = create_app()

        # Override database dependency
        async def mock_db_session():
            session = AsyncMock()
            session.execute = AsyncMock()
            yield session

        app.dependency_overrides[get_db_session] = mock_db_session
        app.dependency_overrides[get_app_settings] = lambda: MagicMock(
            keycloak_url="http://keycloak:8080",
            master_key=b"test-key",
        )

        with TestClient(app, raise_server_exceptions=False) as client:
            yield client

    def test_health_check(self, client):
        """Test /health endpoint."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_version_endpoint(self, client):
        """Test /version endpoint."""
        response = client.get("/api/v1/version")

        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert data["api_version"] == "v1"

    def test_readiness_check(self, client):
        """Test /ready endpoint."""
        response = client.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["database"] == "healthy"

    def test_metrics_endpoint(self, client):
        """Test /metrics endpoint returns Prometheus metrics."""
        response = client.get("/api/v1/metrics")

        assert response.status_code == 200
        assert "sshmgr" in response.text
```

### CLI Test Example

```python
# tests/unit/test_cli_main.py

import pytest
from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from sshmgr.cli.main import cli, Context, async_command, handle_errors
from sshmgr.cli.output import OutputFormat

class TestContext:
    """Tests for CLI Context class."""

    def test_context_initialization(self):
        """Test context initializes with defaults."""
        with patch("sshmgr.cli.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(api_host="localhost", api_port=8000)
            ctx = Context()

        assert ctx.output_format == OutputFormat.TEXT
        assert ctx.verbose is False

    def test_get_api_url(self):
        """Test get_api_url returns correct URL."""
        with patch("sshmgr.cli.main.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(api_host="localhost", api_port=8000)
            ctx = Context()

        assert ctx.get_api_url() == "http://localhost:8000"

class TestCLIGroup:
    """Tests for the main CLI group."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_cli_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "sshmgr" in result.output

    def test_cli_help(self, runner):
        """Test --help flag."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "SSH Certificate Management System" in result.output

    def test_auth_group_exists(self, runner):
        """Test auth command group exists."""
        result = runner.invoke(cli, ["auth", "--help"])
        assert result.exit_code == 0
        assert "login" in result.output

    def test_env_group_exists(self, runner):
        """Test env command group exists."""
        result = runner.invoke(cli, ["env", "--help"])
        assert result.exit_code == 0

    def test_cert_group_exists(self, runner):
        """Test cert command group exists."""
        result = runner.invoke(cli, ["cert", "--help"])
        assert result.exit_code == 0

    def test_rotate_group_exists(self, runner):
        """Test rotate command group exists."""
        result = runner.invoke(cli, ["rotate", "--help"])
        assert result.exit_code == 0
```

### Logging Test Example

```python
# tests/unit/test_logging.py

import pytest
import logging
from unittest.mock import patch
from uuid import uuid4
from sshmgr.logging import (
    AuditAction, AuditLogger, JSONFormatter, TextFormatter,
    StructuredLogger, setup_logging, get_logger
)

class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.fixture
    def audit_logger(self):
        test_logger = logging.getLogger("test.audit")
        test_logger.setLevel(logging.DEBUG)
        return AuditLogger(test_logger)

    def test_cert_signed(self, audit_logger):
        """Test certificate signing audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.cert_signed(
                actor="operator",
                environment="prod",
                cert_type="user",
                key_id="alice@example.com",
                serial=12345,
                principals=["alice", "admin"],
                validity_seconds=28800,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "certificate.sign_user"
            assert extra_data["details"]["key_id"] == "alice@example.com"

    def test_ca_rotated(self, audit_logger):
        """Test CA rotation audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.ca_rotated(
                actor="admin",
                environment="prod",
                ca_type="user",
                old_fingerprint="SHA256:old123",
                new_fingerprint="SHA256:new456",
                grace_period_seconds=86400,
            )

            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "ca.rotate"
```

### Metrics Test Example

```python
# tests/unit/test_metrics.py

import pytest
import time
from sshmgr.metrics import (
    CERTIFICATES_ISSUED, HTTP_REQUESTS,
    record_certificate_issued, record_http_request,
    track_request_duration, get_metrics,
)

class TestCertificateMetrics:
    """Tests for certificate-related metrics."""

    def test_record_certificate_issued(self):
        """Test recording certificate issuance."""
        initial = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="user"
        )._value.get()

        record_certificate_issued("test-env", "user")

        new_value = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="user"
        )._value.get()
        assert new_value == initial + 1

class TestHTTPMetrics:
    """Tests for HTTP-related metrics."""

    def test_track_request_duration(self):
        """Test tracking request duration."""
        with track_request_duration("GET", "/test"):
            time.sleep(0.01)

        metrics = get_metrics().decode("utf-8")
        assert "sshmgr_http_request_duration_seconds" in metrics
```

## Integration Tests

Integration tests verify end-to-end workflows across multiple components.

### API Integration Tests

```python
# tests/integration/test_api_integration.py

class TestEnvironmentEndpoints:
    """Integration tests for environment endpoints."""

    def test_create_environment(self, admin_client):
        """Test creating a new environment."""
        response = admin_client.post(
            "/api/v1/environments",
            json={
                "name": "test-env",
                "key_type": "ed25519",
                "default_user_cert_validity": "8h",
                "default_host_cert_validity": "90d",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "test-env"
        assert data["user_ca_fingerprint"].startswith("SHA256:")

class TestCertificateEndpoints:
    """Integration tests for certificate endpoints."""

    def test_sign_user_certificate(self, admin_client, env_with_certs, test_public_key):
        """Test signing a user certificate."""
        response = admin_client.post(
            "/api/v1/environments/cert-env/certs/user",
            json={
                "public_key": test_public_key,
                "principals": ["testuser", "admin"],
                "key_id": "test@example.com",
                "validity": "8h",
            },
        )

        assert response.status_code == 201
        assert "ssh-ed25519-cert" in response.json()["certificate"]
```

### CA Integration Tests

```python
# tests/integration/test_ca_integration.py

class TestFullCertificateWorkflow:
    """End-to-end tests for complete certificate workflows."""

    def test_user_certificate_workflow(self, tmp_path):
        """Test complete user certificate workflow."""
        # 1. Generate CA
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        # 2. Generate user keypair
        subprocess.run([
            "ssh-keygen", "-t", "ed25519", "-f", str(user_key_path),
            "-N", "", "-C", "user@example.com"
        ], check=True)
        user_public_key = user_key_path.with_suffix(".pub").read_text().strip()

        # 3. Sign certificate
        cert = ca.sign_user_key(
            public_key=user_public_key,
            principals=["deploy", "admin"],
            key_id="user@example.com",
            validity=timedelta(hours=8),
        )

        # 4. Verify with ssh-keygen -L
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            capture_output=True, text=True,
        )
        assert "user certificate" in result.stdout
```

### CLI Integration Tests

```python
# tests/integration/test_cli_integration.py

class TestCLICommands:
    """Integration tests for CLI commands."""

    def test_env_list_help(self, runner):
        """Test env list --help."""
        result = runner.invoke(cli, ["env", "list", "--help"])
        assert result.exit_code == 0

    def test_sign_user_cert_shortcut(self, runner):
        """Test sign-user-cert shortcut."""
        result = runner.invoke(cli, ["sign-user-cert", "--help"])
        assert result.exit_code == 0
        assert "--public-key" in result.output
```

### Auth Integration Tests

```python
# tests/integration/test_auth_integration.py

class TestRBACIntegration:
    """Integration tests for Role-Based Access Control."""

    def test_admin_can_create_environment(self):
        """Test admin role can create environments."""
        context = AuthContext(
            user_id="admin-123",
            username="admin",
            roles=[Role.ADMIN],
            environment_access=[],
        )
        assert context.has_minimum_role(Role.ADMIN)

    def test_environment_isolation(self):
        """Test environment access isolation."""
        prod_context = AuthContext(
            roles=[Role.OPERATOR],
            environment_access=["prod"],
        )
        assert prod_context.can_access_environment("prod")
        assert not prod_context.can_access_environment("staging")
```

## Mocking

### Mocking ssh-keygen

For faster tests without subprocess calls:

```python
import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture
def mock_ssh_keygen():
    """Mock ssh-keygen subprocess calls."""
    with patch("subprocess.run") as mock_run:
        # Mock key generation
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )
        yield mock_run
```

### Mocking Keycloak

```python
@pytest.fixture
def mock_keycloak():
    """Mock Keycloak client."""
    with patch("sshmgr.auth.keycloak.KeycloakClient") as mock:
        client = MagicMock()
        client.get_userinfo.return_value = UserInfo(
            sub="user-123",
            preferred_username="testuser",
            email="test@example.com",
            email_verified=True,
        )
        mock.return_value.__aenter__.return_value = client
        yield client
```

### Mocking JWT Validation

```python
@pytest.fixture
def mock_jwt_validator():
    """Mock JWT validator."""
    with patch("sshmgr.auth.jwt.JWTValidator") as mock:
        validator = MagicMock()
        validator.validate.return_value = TokenClaims(
            sub="user-123",
            preferred_username="testuser",
            realm_roles=["operator"],
            groups=["/environments/prod"],
        )
        mock.return_value = validator
        yield validator
```

## Test Configuration

### pytest.ini

```ini
[pytest]
testpaths = tests
asyncio_mode = auto
markers =
    slow: marks tests as slow
    database: marks tests requiring database
    integration: marks integration tests
filterwarnings =
    ignore::DeprecationWarning
```

### Coverage Configuration

```ini
# pyproject.toml
[tool.coverage.run]
source = ["src/sshmgr"]
branch = true

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
    "if TYPE_CHECKING:",
]
```

## Continuous Integration

### GitHub Actions Example

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -e ".[dev]"

    - name: Run tests
      run: |
        pytest --cov=sshmgr --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## Debugging Tests

### Verbose Output

```bash
# Show print statements
pytest -s

# Show local variables on failure
pytest -l

# Enter debugger on failure
pytest --pdb
```

### Test Selection

```bash
# Run tests matching pattern
pytest -k "test_sign"

# Run tests in specific class
pytest tests/unit/test_ca.py::TestCertificateAuthority

# Run failed tests from last run
pytest --lf
```

### Schema Validation Test Example

```python
# tests/unit/test_api_schemas.py

import pytest
from pydantic import ValidationError
from sshmgr.api.schemas import (
    EnvironmentCreate, UserCertificateRequest, CertTypeEnum
)

class TestEnvironmentCreate:
    """Tests for EnvironmentCreate schema."""

    def test_valid_environment(self):
        """Test creating valid environment."""
        env = EnvironmentCreate(name="production")
        assert env.name == "production"
        assert env.default_user_cert_validity == "8h"

    def test_name_with_uppercase(self):
        """Test uppercase name fails validation."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="Production")

    def test_name_starting_with_hyphen(self):
        """Test name starting with hyphen fails."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="-invalid")

class TestUserCertificateRequest:
    """Tests for UserCertificateRequest schema."""

    def test_valid_request(self):
        """Test valid user certificate request."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
            principals=["deploy", "admin"],
            key_id="user@example.com",
        )
        assert len(request.principals) == 2

    def test_invalid_public_key(self):
        """Test invalid public key format fails."""
        with pytest.raises(ValidationError) as exc_info:
            UserCertificateRequest(
                public_key="not-a-valid-key",
                principals=["user"],
                key_id="user@example.com",
            )
        assert "Invalid SSH public key format" in str(exc_info.value)
```

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Fixture Scope**: Use appropriate fixture scopes (`function`, `class`, `module`, `session`)
3. **Meaningful Names**: Test names should describe what's being tested
4. **Arrange-Act-Assert**: Structure tests clearly
5. **Test Edge Cases**: Include error conditions and boundary values
6. **Mock External Services**: Don't rely on Keycloak/PostgreSQL for unit tests
7. **Coverage Goals**: Aim for 80%+ coverage on core modules
8. **Schema Validation**: Test both valid inputs and validation error cases
9. **Async Tests**: Use `@pytest.mark.asyncio` for async tests (auto mode enabled)
10. **Dependency Overrides**: Use FastAPI's `dependency_overrides` for API tests
