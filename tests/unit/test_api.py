"""Tests for sshmgr.api module."""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from sshmgr import __version__


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client with mocked dependencies."""
        from sshmgr.api.main import create_app

        app = create_app()

        # Override database dependency
        async def mock_db_session():
            session = AsyncMock()
            session.execute = AsyncMock()
            yield session

        from sshmgr.api.dependencies import get_db_session, get_app_settings
        from sshmgr.config import Settings

        app.dependency_overrides[get_db_session] = mock_db_session
        app.dependency_overrides[get_app_settings] = lambda: MagicMock(
            keycloak_url="http://keycloak:8080",
            master_key=b"test-key",
        )

        with TestClient(app, raise_server_exceptions=False) as client:
            yield client

    def test_health_check(self, client):
        """Test /health endpoint returns healthy status."""
        response = client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == __version__
        assert "timestamp" in data

    def test_version_info(self, client):
        """Test /version endpoint returns version info."""
        response = client.get("/api/v1/version")

        assert response.status_code == 200
        data = response.json()
        assert data["version"] == __version__
        assert data["api_version"] == "v1"

    def test_readiness_check_healthy(self, client):
        """Test /ready endpoint when database is healthy."""
        response = client.get("/api/v1/ready")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database"] == "healthy"

    def test_metrics_endpoint(self, client):
        """Test /metrics endpoint returns Prometheus metrics."""
        response = client.get("/api/v1/metrics")

        assert response.status_code == 200
        assert "sshmgr" in response.text


class TestAPIApplication:
    """Tests for the FastAPI application."""

    def test_create_app(self):
        """Test application can be created."""
        from sshmgr.api.main import create_app

        app = create_app()

        assert app.title == "sshmgr API"
        assert app.version == __version__

    def test_app_has_routers(self):
        """Test application has expected routers."""
        from sshmgr.api.main import create_app

        app = create_app()

        # Check routes exist
        routes = [route.path for route in app.routes]
        assert "/api/v1/health" in routes
        assert "/api/v1/version" in routes

    def test_cors_middleware_added(self):
        """Test CORS middleware is configured."""
        from sshmgr.api.main import create_app

        app = create_app()

        # Check middleware stack includes CORS
        middleware_classes = [m.cls.__name__ for m in app.user_middleware]
        assert "CORSMiddleware" in middleware_classes or any(
            "cors" in str(m).lower() for m in app.user_middleware
        )


class TestDependencies:
    """Tests for API dependencies."""

    def test_get_app_settings(self):
        """Test get_app_settings returns settings."""
        from sshmgr.api.dependencies import get_app_settings

        with patch("sshmgr.api.dependencies.get_settings") as mock:
            mock.return_value = MagicMock()
            result = get_app_settings()

        assert result is not None

    def test_get_key_storage_no_master_key(self):
        """Test get_key_storage raises when no master key."""
        from sshmgr.api.dependencies import get_key_storage

        settings = MagicMock()
        settings.master_key = None

        with pytest.raises(HTTPException) as exc_info:
            get_key_storage(settings)

        assert exc_info.value.status_code == 503
        assert "Master key not configured" in exc_info.value.detail

    def test_get_key_storage_with_master_key(self):
        """Test get_key_storage returns storage when key configured."""
        from sshmgr.api.dependencies import get_key_storage
        from sshmgr.keys.encrypted import EncryptedKeyStorage

        settings = MagicMock()
        settings.master_key = EncryptedKeyStorage.generate_master_key()

        storage = get_key_storage(settings)

        assert isinstance(storage, EncryptedKeyStorage)


class TestParseValidity:
    """Tests for parse_validity function."""

    def test_parse_seconds(self):
        """Test parsing seconds."""
        from sshmgr.api.dependencies import parse_validity

        result = parse_validity("30s")
        assert result == timedelta(seconds=30)

    def test_parse_minutes(self):
        """Test parsing minutes."""
        from sshmgr.api.dependencies import parse_validity

        result = parse_validity("15m")
        assert result == timedelta(minutes=15)

    def test_parse_hours(self):
        """Test parsing hours."""
        from sshmgr.api.dependencies import parse_validity

        result = parse_validity("8h")
        assert result == timedelta(hours=8)

    def test_parse_days(self):
        """Test parsing days."""
        from sshmgr.api.dependencies import parse_validity

        result = parse_validity("90d")
        assert result == timedelta(days=90)

    def test_parse_weeks(self):
        """Test parsing weeks."""
        from sshmgr.api.dependencies import parse_validity

        result = parse_validity("2w")
        assert result == timedelta(weeks=2)

    def test_parse_case_insensitive(self):
        """Test parsing is case insensitive."""
        from sshmgr.api.dependencies import parse_validity

        assert parse_validity("8H") == timedelta(hours=8)
        assert parse_validity("90D") == timedelta(days=90)

    def test_parse_invalid_format(self):
        """Test parsing invalid format raises error."""
        from sshmgr.api.dependencies import parse_validity

        with pytest.raises(HTTPException) as exc_info:
            parse_validity("invalid")

        assert exc_info.value.status_code == 400
        assert "Invalid validity format" in exc_info.value.detail

    def test_parse_invalid_unit(self):
        """Test parsing with invalid unit raises error."""
        from sshmgr.api.dependencies import parse_validity

        with pytest.raises(HTTPException) as exc_info:
            parse_validity("10x")

        assert exc_info.value.status_code == 400


class TestFormatTimedelta:
    """Tests for format_timedelta function."""

    def test_format_seconds(self):
        """Test formatting seconds."""
        from sshmgr.api.dependencies import format_timedelta

        result = format_timedelta(timedelta(seconds=45))
        assert result == "45s"

    def test_format_minutes(self):
        """Test formatting minutes."""
        from sshmgr.api.dependencies import format_timedelta

        result = format_timedelta(timedelta(minutes=30))
        assert result == "30m"

    def test_format_hours(self):
        """Test formatting hours."""
        from sshmgr.api.dependencies import format_timedelta

        result = format_timedelta(timedelta(hours=8))
        assert result == "8h"

    def test_format_days(self):
        """Test formatting days."""
        from sshmgr.api.dependencies import format_timedelta

        # 90 days is >= 1 week, so it formats as weeks
        result = format_timedelta(timedelta(days=90))
        assert result == "12w"  # 90 days = 12 weeks (rounded)

    def test_format_days_less_than_week(self):
        """Test formatting days less than a week."""
        from sshmgr.api.dependencies import format_timedelta

        result = format_timedelta(timedelta(days=5))
        assert result == "5d"

    def test_format_weeks(self):
        """Test formatting weeks."""
        from sshmgr.api.dependencies import format_timedelta

        result = format_timedelta(timedelta(weeks=2))
        assert result == "2w"


class TestRequireEnvAccess:
    """Tests for RequireEnvAccess dependency."""

    @pytest.fixture
    def auth_context(self):
        """Create a mock auth context."""
        from sshmgr.auth.rbac import AuthContext
        from sshmgr.auth.jwt import TokenClaims
        import time

        claims = TokenClaims.from_claims({
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "https://keycloak.example.com/realms/test",
            "aud": "test-client",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["operator"]},
            "groups": ["/environments/production", "/environments/staging"],
        })
        return AuthContext(claims)

    @pytest.mark.asyncio
    async def test_require_env_access_allowed(self, auth_context):
        """Test access is allowed with correct role and environment."""
        from sshmgr.api.dependencies import RequireEnvAccess
        from sshmgr.auth.rbac import Role

        checker = RequireEnvAccess(Role.OPERATOR)

        # Mock the get_current_user dependency result
        result = await checker(
            env_name="production",
            auth=auth_context,
        )

        assert result == auth_context

    @pytest.mark.asyncio
    async def test_require_env_access_insufficient_role(self):
        """Test access denied with insufficient role."""
        from sshmgr.api.dependencies import RequireEnvAccess
        from sshmgr.auth.rbac import AuthContext, Role
        from sshmgr.auth.jwt import TokenClaims
        import time

        # Create context with only viewer role
        claims = TokenClaims.from_claims({
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "https://keycloak.example.com/realms/test",
            "aud": "test-client",
            "preferred_username": "viewer",
            "email": "viewer@example.com",
            "realm_access": {"roles": ["viewer"]},
            "groups": ["/environments/production"],
        })
        viewer_context = AuthContext(claims)

        checker = RequireEnvAccess(Role.ADMIN)

        with pytest.raises(HTTPException) as exc_info:
            await checker(
                env_name="production",
                auth=viewer_context,
            )

        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_require_env_access_no_env_access(self, auth_context):
        """Test access denied without environment access."""
        from sshmgr.api.dependencies import RequireEnvAccess
        from sshmgr.auth.rbac import Role

        checker = RequireEnvAccess(Role.VIEWER)

        with pytest.raises(HTTPException) as exc_info:
            await checker(
                env_name="unknown-env",
                auth=auth_context,
            )

        assert exc_info.value.status_code == 403
        assert "No access" in exc_info.value.detail


class TestAPISchemas:
    """Tests for API schemas."""

    def test_health_response_schema(self):
        """Test HealthResponse schema."""
        from sshmgr.api.schemas import HealthResponse

        response = HealthResponse(
            status="healthy",
            version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )

        assert response.status == "healthy"
        assert response.version == "1.0.0"

    def test_readiness_response_schema(self):
        """Test ReadinessResponse schema."""
        from sshmgr.api.schemas import ReadinessResponse

        response = ReadinessResponse(
            status="healthy",
            database="healthy",
            keycloak="configured",
        )

        assert response.status == "healthy"
        assert response.database == "healthy"
        assert response.keycloak == "configured"


class TestGetEnvironmentByName:
    """Tests for get_environment_by_name dependency."""

    @pytest.mark.asyncio
    async def test_get_environment_found(self):
        """Test getting environment by name when it exists."""
        from sshmgr.api.dependencies import get_environment_by_name
        from sshmgr.storage.models import Environment

        mock_repo = AsyncMock()
        mock_env = MagicMock(spec=Environment)
        mock_env.name = "production"
        mock_repo.get_by_name_or_raise.return_value = mock_env

        result = await get_environment_by_name(
            env_name="production",
            env_repo=mock_repo,
        )

        assert result == mock_env
        mock_repo.get_by_name_or_raise.assert_called_once_with("production")

    @pytest.mark.asyncio
    async def test_get_environment_not_found(self):
        """Test getting environment by name when it doesn't exist."""
        from sshmgr.api.dependencies import get_environment_by_name
        from sshmgr.core.exceptions import EnvironmentNotFoundError

        mock_repo = AsyncMock()
        mock_repo.get_by_name_or_raise.side_effect = EnvironmentNotFoundError("test")

        with pytest.raises(HTTPException) as exc_info:
            await get_environment_by_name(
                env_name="unknown",
                env_repo=mock_repo,
            )

        assert exc_info.value.status_code == 404
        assert "unknown" in exc_info.value.detail
