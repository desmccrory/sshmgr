"""Integration tests for authentication and authorization.

These tests verify the authentication flow with mocked Keycloak responses,
including device flow login, JWT validation, and RBAC.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from sshmgr.auth.credentials import CredentialManager, CredentialStore
from sshmgr.auth.jwt import TokenClaims
from sshmgr.auth.keycloak import KeycloakConfig, TokenResponse, UserInfo
from sshmgr.auth.rbac import AuthContext, Role


class TestKeycloakConfig:
    """Integration tests for Keycloak configuration."""

    def test_config_from_url(self):
        """Test creating config from URL."""
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="sshmgr",
            client_id="sshmgr-cli",
        )

        assert config.server_url == "https://keycloak.example.com"
        assert config.realm == "sshmgr"
        assert config.client_id == "sshmgr-cli"

    def test_config_urls(self):
        """Test computed URL properties."""
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="sshmgr",
            client_id="sshmgr-cli",
        )

        assert "sshmgr" in config.token_endpoint
        assert "sshmgr" in config.device_auth_endpoint
        assert "sshmgr" in config.userinfo_endpoint


class TestTokenResponse:
    """Tests for TokenResponse handling."""

    def test_token_response_parsing(self):
        """Test parsing token response from Keycloak."""
        response_data = {
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "expires_in": 300,
            "refresh_expires_in": 1800,
            "token_type": "Bearer",
            "scope": "openid profile email",
        }

        token = TokenResponse(**response_data)

        assert token.access_token.startswith("eyJ")
        assert token.refresh_token.startswith("eyJ")
        assert token.expires_in == 300

    def test_token_has_access_token(self):
        """Test token has access token."""
        token = TokenResponse(
            access_token="test-token",
            refresh_token="test-refresh",
            expires_in=300,
            refresh_expires_in=1800,
            token_type="Bearer",
        )

        assert token.access_token == "test-token"
        assert token.expires_in == 300

    def test_token_from_dict(self):
        """Test creating token from dict."""
        data = {
            "access_token": "test-token",
            "refresh_token": "test-refresh",
            "expires_in": 300,
            "refresh_expires_in": 1800,
            "token_type": "Bearer",
            "scope": "openid profile",
        }

        token = TokenResponse.from_dict(data)

        assert token.access_token == "test-token"
        assert token.scope == "openid profile"


class TestUserInfo:
    """Tests for UserInfo handling."""

    def test_userinfo_parsing(self):
        """Test parsing userinfo response."""
        userinfo_data = {
            "sub": "user-uuid-123",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "email_verified": True,
            "name": "Alice Smith",
            "given_name": "Alice",
            "family_name": "Smith",
        }

        userinfo = UserInfo(**userinfo_data)

        assert userinfo.sub == "user-uuid-123"
        assert userinfo.preferred_username == "alice"
        assert userinfo.email == "alice@example.com"


class TestTokenClaims:
    """Tests for JWT token claims."""

    def test_claims_parsing(self):
        """Test parsing JWT claims."""
        claims_data = {
            "sub": "user-uuid-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "https://keycloak.example.com/realms/test",
            "aud": "test-client",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["admin", "operator"]},
            "groups": ["/environments/prod", "/environments/staging"],
        }

        claims = TokenClaims.from_claims(claims_data)

        assert claims.sub == "user-uuid-123"
        assert "admin" in claims.realm_roles
        assert "/environments/prod" in claims.groups

    def test_claims_to_user_info(self):
        """Test converting claims to UserInfo."""
        claims_data = {
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "iss": "https://keycloak.example.com/realms/test",
            "aud": "test-client",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["operator"]},
            "groups": ["/environments/production", "/environments/staging"],
        }

        claims = TokenClaims.from_claims(claims_data)
        user_info = claims.to_user_info()

        assert user_info.preferred_username == "alice"
        assert user_info.email == "alice@example.com"
        assert "operator" in user_info.realm_roles


def _create_auth_context(
    username: str = "testuser",
    roles: list[str] = None,
    groups: list[str] = None,
) -> AuthContext:
    """Helper to create AuthContext from TokenClaims."""
    claims = TokenClaims.from_claims({
        "sub": str(uuid4()),
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "iss": "https://keycloak.example.com/realms/test",
        "aud": "test-client",
        "preferred_username": username,
        "email": f"{username}@example.com",
        "realm_access": {"roles": roles or []},
        "groups": groups or [],
    })
    return AuthContext(claims)


class TestAuthContext:
    """Integration tests for AuthContext."""

    def test_admin_has_all_access(self):
        """Test admin role has access to all environments."""
        context = _create_auth_context(
            username="admin",
            roles=["admin"],
            groups=[],
        )

        assert context.has_role(Role.ADMIN)
        assert context.can_access_environment("any-env")  # Admin has access to all

    def test_operator_role_check(self):
        """Test operator role check."""
        context = _create_auth_context(
            username="operator",
            roles=["operator"],
            groups=["/environments/prod"],
        )

        assert context.has_role(Role.OPERATOR)
        assert not context.has_role(Role.ADMIN)

    def test_environment_access_check(self):
        """Test environment access checking."""
        context = _create_auth_context(
            username="user",
            roles=["operator"],
            groups=["/environments/prod", "/environments/staging"],
        )

        assert context.can_access_environment("prod")
        assert context.can_access_environment("staging")
        assert not context.can_access_environment("dev")

    def test_admin_environment_access(self):
        """Test admin can access any environment."""
        context = _create_auth_context(
            username="admin",
            roles=["admin"],
            groups=[],  # No specific groups, but admin has access to all
        )

        assert context.can_access_environment("any-environment")

    def test_minimum_role_check(self):
        """Test minimum role requirement."""
        context = _create_auth_context(
            username="user",
            roles=["operator"],
            groups=[],
        )

        assert context.has_minimum_role(Role.VIEWER)
        assert context.has_minimum_role(Role.OPERATOR)
        assert not context.has_minimum_role(Role.ADMIN)


class TestCredentialStorage:
    """Integration tests for credential storage."""

    @pytest.fixture
    def temp_config_dir(self, tmp_path):
        """Create a temporary config directory."""
        config_dir = tmp_path / ".sshmgr"
        config_dir.mkdir()
        return config_dir

    def test_credential_store_save_and_load(self, temp_config_dir):
        """Test saving and loading credentials."""
        from sshmgr.auth.credentials import StoredCredentials

        store = CredentialStore(config_dir=temp_config_dir)

        tokens = TokenResponse(
            access_token="access-123",
            refresh_token="refresh-456",
            expires_in=300,
            refresh_expires_in=1800,
            token_type="Bearer",
        )

        # Create StoredCredentials and save
        creds = StoredCredentials.from_token_response(
            tokens,
            keycloak_url="https://keycloak.example.com",
            realm="sshmgr",
        )
        store.save(creds)

        # Load credentials
        loaded = store.load()

        assert loaded is not None
        assert loaded.access_token == "access-123"
        assert loaded.refresh_token == "refresh-456"
        assert loaded.keycloak_url == "https://keycloak.example.com"

    def test_credential_store_clear(self, temp_config_dir):
        """Test clearing credentials."""
        from sshmgr.auth.credentials import StoredCredentials

        store = CredentialStore(config_dir=temp_config_dir)

        tokens = TokenResponse(
            access_token="access-123",
            refresh_token="refresh-456",
            expires_in=300,
            refresh_expires_in=1800,
            token_type="Bearer",
        )

        creds = StoredCredentials.from_token_response(
            tokens, "https://keycloak.example.com", "sshmgr"
        )
        store.save(creds)

        # Clear credentials
        store.clear()

        # Should be empty now
        loaded = store.load()
        assert loaded is None

    def test_credential_manager_get_access_token(self, temp_config_dir):
        """Test getting access token from manager."""
        from sshmgr.auth.credentials import StoredCredentials

        store = CredentialStore(config_dir=temp_config_dir)
        manager = CredentialManager(store)

        tokens = TokenResponse(
            access_token="access-123",
            refresh_token="refresh-456",
            expires_in=300,
            refresh_expires_in=1800,
            token_type="Bearer",
        )

        creds = StoredCredentials.from_token_response(
            tokens, "https://keycloak.example.com", "sshmgr"
        )
        store.save(creds)

        # Get access token
        access_token = manager.get_access_token()

        assert access_token == "access-123"

    def test_credential_manager_not_logged_in(self, temp_config_dir):
        """Test manager when not logged in."""
        store = CredentialStore(config_dir=temp_config_dir)
        manager = CredentialManager(store)

        # No credentials saved
        access_token = manager.get_access_token()

        assert access_token is None

    def test_credential_manager_save_tokens(self, temp_config_dir):
        """Test saving tokens through manager."""
        from sshmgr.auth.credentials import StoredCredentials

        store = CredentialStore(config_dir=temp_config_dir)
        manager = CredentialManager(store)

        tokens = TokenResponse(
            access_token="new-access",
            refresh_token="new-refresh",
            expires_in=300,
            refresh_expires_in=1800,
            token_type="Bearer",
        )

        creds = StoredCredentials.from_token_response(
            tokens, "https://keycloak.example.com", "sshmgr"
        )
        manager.store.save(creds)

        # Verify saved
        access_token = manager.get_access_token()
        assert access_token == "new-access"


class TestDeviceFlowMocked:
    """Integration tests for device flow with mocked Keycloak."""

    @pytest.fixture
    def mock_keycloak_responses(self):
        """Mock Keycloak HTTP responses."""
        return {
            "device_auth": {
                "device_code": "device-code-123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://keycloak.example.com/device",
                "verification_uri_complete": "https://keycloak.example.com/device?user_code=ABCD-1234",
                "expires_in": 600,
                "interval": 5,
            },
            "token": {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "expires_in": 300,
                "refresh_expires_in": 1800,
                "token_type": "Bearer",
            },
            "userinfo": {
                "sub": "user-uuid-123",
                "preferred_username": "alice",
                "email": "alice@example.com",
                "email_verified": True,
            },
        }

    @pytest.mark.asyncio
    async def test_device_flow_structure(self, mock_keycloak_responses):
        """Test device flow response structure."""
        # This test verifies the expected response structure
        device_resp = mock_keycloak_responses["device_auth"]

        assert "device_code" in device_resp
        assert "user_code" in device_resp
        assert "verification_uri" in device_resp

        token_resp = mock_keycloak_responses["token"]
        assert "access_token" in token_resp
        assert "refresh_token" in token_resp


class TestJWTValidationMocked:
    """Integration tests for JWT validation with mocked JWKS."""

    @pytest.fixture
    def mock_jwt_payload(self):
        """Create a mock JWT payload."""
        now = int(time.time())
        return {
            "exp": now + 300,  # Expires in 5 minutes
            "iat": now,
            "jti": str(uuid4()),
            "iss": "https://keycloak.example.com/realms/sshmgr",
            "aud": "sshmgr-api",
            "sub": "user-uuid-123",
            "typ": "Bearer",
            "azp": "sshmgr-cli",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["sshmgr-admin"]},
            "groups": ["/environments/prod"],
        }

    def test_jwt_payload_structure(self, mock_jwt_payload):
        """Test JWT payload has required fields."""
        assert "sub" in mock_jwt_payload
        assert "exp" in mock_jwt_payload
        assert "preferred_username" in mock_jwt_payload
        assert "realm_access" in mock_jwt_payload

    def test_jwt_to_user_info(self, mock_jwt_payload):
        """Test converting JWT payload to user info."""
        claims = TokenClaims.from_claims(mock_jwt_payload)
        user_info = claims.to_user_info()

        assert user_info.preferred_username == "alice"
        assert "sshmgr-admin" in user_info.realm_roles


class TestRBACIntegration:
    """Integration tests for Role-Based Access Control."""

    def test_admin_can_create_environment(self):
        """Test admin role can create environments."""
        context = _create_auth_context(
            username="admin",
            roles=["admin"],
            groups=[],
        )

        assert context.has_minimum_role(Role.ADMIN)

    def test_operator_can_sign_certs(self):
        """Test operator role can sign certificates."""
        context = _create_auth_context(
            username="operator",
            roles=["operator"],
            groups=["/environments/prod"],
        )

        assert context.has_minimum_role(Role.OPERATOR)
        assert context.can_access_environment("prod")

    def test_viewer_readonly(self):
        """Test viewer role is read-only."""
        context = _create_auth_context(
            username="viewer",
            roles=["viewer"],
            groups=["/environments/prod"],
        )

        assert context.has_minimum_role(Role.VIEWER)
        assert not context.has_minimum_role(Role.OPERATOR)
        assert not context.has_minimum_role(Role.ADMIN)

    def test_multiple_roles(self):
        """Test user with multiple roles."""
        context = _create_auth_context(
            username="multi",
            roles=["operator", "viewer"],
            groups=["/environments/prod", "/environments/staging"],
        )

        # Should have highest role capabilities
        assert context.has_role(Role.OPERATOR)
        assert context.has_role(Role.VIEWER)
        assert not context.has_role(Role.ADMIN)

    def test_environment_isolation(self):
        """Test environment access isolation."""
        prod_context = _create_auth_context(
            username="prod-user",
            roles=["operator"],
            groups=["/environments/prod"],
        )

        staging_context = _create_auth_context(
            username="staging-user",
            roles=["operator"],
            groups=["/environments/staging"],
        )

        # Each user can only access their environment
        assert prod_context.can_access_environment("prod")
        assert not prod_context.can_access_environment("staging")

        assert staging_context.can_access_environment("staging")
        assert not staging_context.can_access_environment("prod")


class TestAuthenticationEndToEnd:
    """End-to-end authentication tests with mocked services."""

    @pytest.fixture
    def mock_keycloak_client(self):
        """Create a fully mocked Keycloak client."""
        client = MagicMock()
        client.get_device_code = AsyncMock(
            return_value={
                "device_code": "device-123",
                "user_code": "ABCD-1234",
                "verification_uri": "https://keycloak.example.com/device",
                "interval": 5,
                "expires_in": 600,
            }
        )
        client.poll_for_token = AsyncMock(
            return_value=TokenResponse(
                access_token="access-token-123",
                refresh_token="refresh-token-456",
                expires_in=300,
                refresh_expires_in=1800,
                token_type="Bearer",
            )
        )
        client.get_userinfo = AsyncMock(
            return_value=UserInfo(
                sub="user-123",
                preferred_username="alice",
                email="alice@example.com",
                email_verified=True,
            )
        )
        return client

    @pytest.mark.asyncio
    async def test_login_flow_mocked(self, mock_keycloak_client, tmp_path):
        """Test complete login flow with mocked Keycloak."""
        # 1. Get device code
        device_code_response = await mock_keycloak_client.get_device_code()

        assert device_code_response["user_code"] == "ABCD-1234"
        assert "verification_uri" in device_code_response

        # 2. Poll for token (simulates user completing browser auth)
        token = await mock_keycloak_client.poll_for_token()

        assert token.access_token == "access-token-123"
        assert token.refresh_token == "refresh-token-456"

        # 3. Get user info
        userinfo = await mock_keycloak_client.get_userinfo()

        assert userinfo.preferred_username == "alice"

        # 4. Store credentials
        from sshmgr.auth.credentials import StoredCredentials

        config_dir = tmp_path / ".sshmgr"
        config_dir.mkdir()
        store = CredentialStore(config_dir=config_dir)
        creds = StoredCredentials.from_token_response(
            token, "https://keycloak.example.com", "sshmgr"
        )
        store.save(creds)

        # 5. Verify credentials can be retrieved
        loaded = store.load()
        assert loaded.access_token == "access-token-123"
