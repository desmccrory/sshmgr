"""Integration tests for the REST API endpoints.

These tests use an in-memory SQLite database and mocked authentication
to test the full request/response cycle through the API.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sshmgr import __version__
from sshmgr.api.main import create_app
from sshmgr.api.dependencies import get_db_session, get_app_settings, get_key_storage
from sshmgr.auth.rbac import AuthContext, Role, get_current_user
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.database import Base


@pytest.fixture
def master_key():
    """Generate a master encryption key."""
    return EncryptedKeyStorage.generate_master_key()


@pytest.fixture
def key_storage(master_key):
    """Create an encrypted key storage instance."""
    return EncryptedKeyStorage(master_key)


@pytest.fixture
def mock_settings(master_key):
    """Create mock settings."""
    settings = MagicMock()
    settings.keycloak_url = "http://keycloak:8080"
    settings.master_key = master_key
    settings.api_host = "localhost"
    settings.api_port = 8000
    return settings


def create_auth_context(
    username: str = "testuser",
    roles: list[Role] = None,
    environments: list[str] = None,
) -> AuthContext:
    """Create a mock auth context using TokenClaims."""
    import time
    from sshmgr.auth.jwt import TokenClaims

    role_names = [r.value if isinstance(r, Role) else r for r in (roles or [Role.ADMIN])]
    env_groups = [f"/environments/{env}" for env in (environments or ["production", "staging"])]

    claims = TokenClaims.from_claims({
        "sub": str(uuid4()),
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "iss": "https://keycloak.example.com/realms/test",
        "aud": "test-client",
        "preferred_username": username,
        "email": f"{username}@example.com",
        "realm_access": {"roles": role_names},
        "groups": env_groups,
    })
    return AuthContext(claims)


@pytest_asyncio.fixture
async def async_engine():
    """Create an async SQLite engine for testing with shared cache."""
    from sqlalchemy.pool import StaticPool

    # Use shared cache mode and StaticPool to share a single connection
    # This allows data to be visible across requests in in-memory SQLite
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:?cache=shared",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(async_engine):
    """Create a session factory with auto-commit on close."""
    return async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=True,
    )


@pytest.fixture
def app(session_factory, mock_settings, key_storage):
    """Create a test application with overridden dependencies."""
    app = create_app()

    async def override_db_session():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def override_settings():
        return mock_settings

    def override_key_storage(settings=None):
        return key_storage

    def override_auth():
        return create_auth_context()

    app.dependency_overrides[get_db_session] = override_db_session
    app.dependency_overrides[get_app_settings] = override_settings
    app.dependency_overrides[get_key_storage] = override_key_storage
    app.dependency_overrides[get_current_user] = override_auth

    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def admin_app(session_factory, mock_settings, key_storage):
    """Create app with admin auth."""
    app = create_app()

    async def override_db_session():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = override_db_session
    app.dependency_overrides[get_app_settings] = lambda: mock_settings
    app.dependency_overrides[get_key_storage] = lambda s=None: key_storage
    app.dependency_overrides[get_current_user] = lambda: create_auth_context(
        username="admin", roles=[Role.ADMIN]
    )

    return app


@pytest.fixture
def admin_client(admin_app):
    """Create a test client with admin auth."""
    with TestClient(admin_app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def operator_app(session_factory, mock_settings, key_storage):
    """Create app with operator auth."""
    app = create_app()

    async def override_db_session():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db_session] = override_db_session
    app.dependency_overrides[get_app_settings] = lambda: mock_settings
    app.dependency_overrides[get_key_storage] = lambda s=None: key_storage
    app.dependency_overrides[get_current_user] = lambda: create_auth_context(
        username="operator",
        roles=[Role.OPERATOR],
        environments=["test-env"],
    )

    return app


@pytest.fixture
def operator_client(operator_app):
    """Create a test client with operator auth."""
    with TestClient(operator_app, raise_server_exceptions=False) as client:
        yield client


class TestHealthEndpoints:
    """Integration tests for health endpoints."""

    def test_health_check(self, client):
        """Test health check returns healthy status."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == __version__

    def test_version_info(self, client):
        """Test version endpoint."""
        response = client.get("/api/v1/version")

        assert response.status_code == 200
        data = response.json()
        assert data["version"] == __version__
        assert data["api_version"] == "v1"

    def test_readiness_check(self, client):
        """Test readiness check with database."""
        response = client.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["database"] == "healthy"

    def test_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get("/api/v1/metrics")

        assert response.status_code == 200
        assert b"sshmgr" in response.content


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
        assert "id" in data
        assert data["user_ca_fingerprint"].startswith("SHA256:")
        assert data["host_ca_fingerprint"].startswith("SHA256:")

    def test_create_environment_duplicate(self, admin_client):
        """Test creating duplicate environment fails."""
        # Create first
        admin_client.post(
            "/api/v1/environments",
            json={"name": "duplicate-env"},
        )

        # Try to create again
        response = admin_client.post(
            "/api/v1/environments",
            json={"name": "duplicate-env"},
        )

        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    def test_list_environments(self, admin_client):
        """Test listing environments."""
        # Create some environments
        admin_client.post("/api/v1/environments", json={"name": "env-a"})
        admin_client.post("/api/v1/environments", json={"name": "env-b"})

        response = admin_client.get("/api/v1/environments")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2
        names = [e["name"] for e in data["environments"]]
        assert "env-a" in names
        assert "env-b" in names

    def test_get_environment(self, admin_client):
        """Test getting environment details."""
        # Create environment
        create_resp = admin_client.post(
            "/api/v1/environments",
            json={"name": "get-test"},
        )
        assert create_resp.status_code == 201

        # Get environment
        response = admin_client.get("/api/v1/environments/get-test")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "get-test"

    def test_get_environment_not_found(self, admin_client):
        """Test getting non-existent environment."""
        response = admin_client.get("/api/v1/environments/nonexistent")

        assert response.status_code == 404

    def test_delete_environment(self, admin_client):
        """Test deleting an environment."""
        # Create environment
        admin_client.post("/api/v1/environments", json={"name": "to-delete"})

        # Delete it
        response = admin_client.delete("/api/v1/environments/to-delete")

        assert response.status_code == 204

        # Verify it's gone
        get_response = admin_client.get("/api/v1/environments/to-delete")
        assert get_response.status_code == 404

    def test_get_ca_public_key(self, admin_client):
        """Test getting CA public key."""
        # Create environment
        admin_client.post("/api/v1/environments", json={"name": "ca-test"})

        # Get user CA
        response = admin_client.get("/api/v1/environments/ca-test/ca/user")

        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "ca-test"
        assert data["ca_type"] == "user"
        assert data["public_key"].startswith("ssh-ed25519")
        assert data["fingerprint"].startswith("SHA256:")

    def test_get_ca_public_key_host(self, admin_client):
        """Test getting host CA public key."""
        admin_client.post("/api/v1/environments", json={"name": "host-ca-test"})

        response = admin_client.get("/api/v1/environments/host-ca-test/ca/host")

        assert response.status_code == 200
        data = response.json()
        assert data["ca_type"] == "host"

    def test_get_rotation_status(self, admin_client):
        """Test getting CA rotation status."""
        admin_client.post("/api/v1/environments", json={"name": "rotation-test"})

        response = admin_client.get(
            "/api/v1/environments/rotation-test/rotation-status"
        )

        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "rotation-test"
        assert data["user_ca"]["rotating"] is False
        assert data["host_ca"]["rotating"] is False

    def test_rotate_ca(self, admin_client):
        """Test rotating a CA."""
        admin_client.post("/api/v1/environments", json={"name": "rotate-env"})

        response = admin_client.post(
            "/api/v1/environments/rotate-env/rotate",
            json={
                "ca_type": "user",
                "grace_period": "24h",
                "key_type": "ed25519",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["user_ca"]["rotating"] is True
        assert data["user_ca"]["old_fingerprint"] is not None


class TestCertificateEndpoints:
    """Integration tests for certificate endpoints."""

    @pytest.fixture
    def env_with_certs(self, admin_client):
        """Create an environment for certificate tests."""
        response = admin_client.post(
            "/api/v1/environments",
            json={"name": "cert-env"},
        )
        return response.json()

    @pytest.fixture
    def test_public_key(self, tmp_path):
        """Generate a test SSH public key."""
        import subprocess

        key_path = tmp_path / "test_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(key_path),
                "-N",
                "",
                "-C",
                "test@example.com",
            ],
            check=True,
            capture_output=True,
        )
        return key_path.with_suffix(".pub").read_text().strip()

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
        data = response.json()
        assert data["cert_type"] == "user"
        assert data["key_id"] == "test@example.com"
        assert data["principals"] == ["testuser", "admin"]
        assert data["serial"] == 1
        assert data["certificate"] is not None
        assert "ssh-ed25519-cert" in data["certificate"]

    def test_sign_host_certificate(self, admin_client, env_with_certs, test_public_key):
        """Test signing a host certificate."""
        response = admin_client.post(
            "/api/v1/environments/cert-env/certs/host",
            json={
                "public_key": test_public_key,
                "principals": ["server.example.com", "10.0.0.5"],
                "validity": "90d",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["cert_type"] == "host"
        assert "server.example.com" in data["principals"]
        assert data["certificate"] is not None

    def test_sign_certificate_invalid_key(self, admin_client, env_with_certs):
        """Test signing with invalid public key."""
        response = admin_client.post(
            "/api/v1/environments/cert-env/certs/user",
            json={
                "public_key": "invalid-key-format",
                "principals": ["user"],
                "key_id": "test@example.com",
            },
        )

        assert response.status_code == 422  # Validation error

    def test_list_certificates(self, admin_client, env_with_certs, test_public_key):
        """Test listing certificates."""
        # Sign a few certs
        for i in range(3):
            admin_client.post(
                "/api/v1/environments/cert-env/certs/user",
                json={
                    "public_key": test_public_key,
                    "principals": [f"user{i}"],
                    "key_id": f"user{i}@example.com",
                },
            )

        response = admin_client.get("/api/v1/environments/cert-env/certs")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 3

    def test_get_certificate_by_serial(
        self, admin_client, env_with_certs, test_public_key
    ):
        """Test getting certificate by serial."""
        # Sign a cert
        sign_resp = admin_client.post(
            "/api/v1/environments/cert-env/certs/user",
            json={
                "public_key": test_public_key,
                "principals": ["testuser"],
                "key_id": "test@example.com",
            },
        )
        serial = sign_resp.json()["serial"]

        response = admin_client.get(f"/api/v1/environments/cert-env/certs/{serial}")

        assert response.status_code == 200
        data = response.json()
        assert data["serial"] == serial

    def test_get_certificate_not_found(self, admin_client, env_with_certs):
        """Test getting non-existent certificate."""
        response = admin_client.get("/api/v1/environments/cert-env/certs/99999")

        assert response.status_code == 404

    def test_revoke_certificate(self, admin_client, env_with_certs, test_public_key):
        """Test revoking a certificate."""
        # Sign a cert
        sign_resp = admin_client.post(
            "/api/v1/environments/cert-env/certs/user",
            json={
                "public_key": test_public_key,
                "principals": ["testuser"],
                "key_id": "revoke-test@example.com",
            },
        )
        serial = sign_resp.json()["serial"]

        # Revoke it (reason passed as query param)
        response = admin_client.delete(
            f"/api/v1/environments/cert-env/certs/{serial}",
            params={"reason": "Key compromised"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["revoked_at"] is not None

    def test_revoke_certificate_already_revoked(
        self, admin_client, env_with_certs, test_public_key
    ):
        """Test revoking already revoked certificate."""
        # Sign and revoke a cert
        sign_resp = admin_client.post(
            "/api/v1/environments/cert-env/certs/user",
            json={
                "public_key": test_public_key,
                "principals": ["testuser"],
                "key_id": "double-revoke@example.com",
            },
        )
        serial = sign_resp.json()["serial"]
        admin_client.delete(f"/api/v1/environments/cert-env/certs/{serial}")

        # Try to revoke again
        response = admin_client.delete(f"/api/v1/environments/cert-env/certs/{serial}")

        assert response.status_code == 409
        assert "already revoked" in response.json()["detail"]

    def test_find_certificates_by_key_id(
        self, admin_client, env_with_certs, test_public_key
    ):
        """Test finding certificates by key ID."""
        key_id = "findme@example.com"

        # Sign multiple certs with same key_id
        for _ in range(2):
            admin_client.post(
                "/api/v1/environments/cert-env/certs/user",
                json={
                    "public_key": test_public_key,
                    "principals": ["testuser"],
                    "key_id": key_id,
                },
            )

        response = admin_client.get(
            f"/api/v1/environments/cert-env/certs/by-key-id/{key_id}"
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2
        for cert in data["certificates"]:
            assert cert["key_id"] == key_id


class TestAuthorizationFlow:
    """Tests for authorization/access control."""

    def test_operator_can_sign_cert(self, session_factory, mock_settings, key_storage):
        """Test operator role can sign certificates."""
        app = create_app()

        async def override_db_session():
            async with session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

        app.dependency_overrides[get_db_session] = override_db_session
        app.dependency_overrides[get_app_settings] = lambda: mock_settings
        app.dependency_overrides[get_key_storage] = lambda s=None: key_storage

        # First create env as admin
        app.dependency_overrides[get_current_user] = lambda: create_auth_context(
            username="admin", roles=[Role.ADMIN]
        )

        with TestClient(app) as admin_client:
            admin_client.post("/api/v1/environments", json={"name": "auth-test"})

        # Now try to sign as operator with access to this env
        app.dependency_overrides[get_current_user] = lambda: create_auth_context(
            username="operator",
            roles=[Role.OPERATOR],
            environments=["auth-test"],
        )

        import subprocess
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""],
                check=True,
                capture_output=True,
            )
            public_key = key_path.with_suffix(".pub").read_text().strip()

            with TestClient(app) as operator_client:
                response = operator_client.post(
                    "/api/v1/environments/auth-test/certs/user",
                    json={
                        "public_key": public_key,
                        "principals": ["user"],
                        "key_id": "operator-test@example.com",
                    },
                )

                assert response.status_code == 201

    def test_viewer_cannot_sign_cert(self, session_factory, mock_settings, key_storage):
        """Test viewer role cannot sign certificates."""
        app = create_app()

        async def override_db_session():
            async with session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

        app.dependency_overrides[get_db_session] = override_db_session
        app.dependency_overrides[get_app_settings] = lambda: mock_settings
        app.dependency_overrides[get_key_storage] = lambda s=None: key_storage

        # Create env as admin
        app.dependency_overrides[get_current_user] = lambda: create_auth_context(
            username="admin", roles=[Role.ADMIN]
        )

        with TestClient(app) as admin_client:
            admin_client.post("/api/v1/environments", json={"name": "viewer-test"})

        # Try to sign as viewer
        app.dependency_overrides[get_current_user] = lambda: create_auth_context(
            username="viewer",
            roles=[Role.VIEWER],
            environments=["viewer-test"],
        )

        with TestClient(app) as viewer_client:
            response = viewer_client.post(
                "/api/v1/environments/viewer-test/certs/user",
                json={
                    "public_key": "ssh-ed25519 AAAA...",
                    "principals": ["user"],
                    "key_id": "viewer-test@example.com",
                },
            )

            assert response.status_code == 403
