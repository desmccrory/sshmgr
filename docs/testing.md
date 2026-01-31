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

# Integration tests (may need database)
pytest tests/integration/

# All tests with markers
pytest -m "not slow"  # Skip slow tests
pytest -m "database"  # Only database tests
```

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Unit tests (no external deps)
│   ├── test_ca.py           # Certificate Authority tests
│   ├── test_encrypted_keys.py
│   ├── test_jwt.py
│   └── test_repositories.py
└── integration/             # Integration tests
    ├── test_cli.py          # CLI end-to-end tests
    └── test_api.py          # API end-to-end tests
```

## Key Fixtures

### conftest.py

```python
import pytest
from sshmgr.core.ca import CertificateAuthority, KeyType

@pytest.fixture
def ca():
    """Generate a test CA."""
    return CertificateAuthority.generate(key_type=KeyType.ED25519)

@pytest.fixture
def test_public_key():
    """Generate a test user public key."""
    import subprocess
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "test_key"
        subprocess.run([
            "ssh-keygen", "-t", "ed25519",
            "-f", str(key_path),
            "-N", "",
            "-C", "test@example.com"
        ], check=True, capture_output=True)

        yield (key_path.with_suffix(".pub")).read_text().strip()
```

### Database Fixtures

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
# tests/integration/test_api.py

import pytest
from fastapi.testclient import TestClient
from sshmgr.api.main import app

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
def auth_headers(mock_jwt_token):
    """Headers with valid JWT."""
    return {"Authorization": f"Bearer {mock_jwt_token}"}

class TestHealthEndpoints:
    """Tests for health check endpoints."""

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

class TestEnvironmentEndpoints:
    """Tests for environment endpoints."""

    def test_list_environments_unauthorized(self, client):
        """Test that list requires authentication."""
        response = client.get("/api/v1/environments")

        assert response.status_code == 401

    def test_list_environments(self, client, auth_headers):
        """Test listing environments."""
        response = client.get(
            "/api/v1/environments",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "environments" in data
        assert "total" in data
```

### CLI Test Example

```python
# tests/integration/test_cli.py

import pytest
from click.testing import CliRunner
from sshmgr.cli.main import cli

@pytest.fixture
def runner():
    """Create CLI test runner."""
    return CliRunner()

class TestAuthCommands:
    """Tests for authentication commands."""

    def test_auth_status_not_logged_in(self, runner):
        """Test status when not logged in."""
        result = runner.invoke(cli, ["auth", "status"])

        assert result.exit_code == 0
        assert "Not logged in" in result.output

    def test_auth_help(self, runner):
        """Test auth help."""
        result = runner.invoke(cli, ["auth", "--help"])

        assert result.exit_code == 0
        assert "login" in result.output
        assert "logout" in result.output
        assert "status" in result.output

class TestEnvironmentCommands:
    """Tests for environment commands."""

    def test_env_list_json(self, runner, mock_db):
        """Test listing environments in JSON format."""
        result = runner.invoke(cli, ["env", "list", "-f", "json"])

        assert result.exit_code == 0
        # Should be valid JSON
        import json
        data = json.loads(result.output)
        assert isinstance(data, list)
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

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Fixture Scope**: Use appropriate fixture scopes (`function`, `class`, `module`, `session`)
3. **Meaningful Names**: Test names should describe what's being tested
4. **Arrange-Act-Assert**: Structure tests clearly
5. **Test Edge Cases**: Include error conditions and boundary values
6. **Mock External Services**: Don't rely on Keycloak/PostgreSQL for unit tests
7. **Coverage Goals**: Aim for 80%+ coverage on core modules
