"""Unit tests for authentication module."""

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sshmgr.auth.credentials import (
    CredentialManager,
    CredentialStore,
    StoredCredentials,
)
from sshmgr.auth.jwt import TokenClaims, decode_token_unverified, is_token_expired
from sshmgr.auth.keycloak import KeycloakConfig, TokenResponse, UserInfo
from sshmgr.auth.rbac import AuthContext, Role, ROLE_HIERARCHY


class TestKeycloakConfig:
    """Tests for KeycloakConfig."""

    def test_config_creation(self):
        """Create Keycloak config."""
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="sshmgr",
            client_id="sshmgr-cli",
        )

        assert config.server_url == "https://keycloak.example.com"
        assert config.realm == "sshmgr"
        assert config.client_id == "sshmgr-cli"

    def test_endpoint_urls(self):
        """Config generates correct endpoint URLs."""
        config = KeycloakConfig(
            server_url="https://keycloak.example.com",
            realm="test-realm",
            client_id="test-client",
        )

        assert "test-realm" in config.realm_url
        assert "token" in config.token_endpoint
        assert "auth" in config.auth_endpoint
        assert "userinfo" in config.userinfo_endpoint
        assert "device" in config.device_auth_endpoint
        assert "certs" in config.certs_endpoint


class TestTokenResponse:
    """Tests for TokenResponse."""

    def test_from_dict(self):
        """Create TokenResponse from dict."""
        data = {
            "access_token": "access123",
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": "refresh456",
            "refresh_expires_in": 1800,
            "scope": "openid profile email",
        }

        response = TokenResponse.from_dict(data)

        assert response.access_token == "access123"
        assert response.refresh_token == "refresh456"
        assert response.expires_in == 300

    def test_from_dict_minimal(self):
        """Create TokenResponse with minimal data."""
        data = {
            "access_token": "token",
        }

        response = TokenResponse.from_dict(data)

        assert response.access_token == "token"
        assert response.token_type == "Bearer"
        assert response.refresh_token is None


class TestUserInfo:
    """Tests for UserInfo."""

    def test_from_dict(self):
        """Create UserInfo from dict."""
        data = {
            "sub": "user-123",
            "preferred_username": "testuser",
            "email": "test@example.com",
            "email_verified": True,
            "name": "Test User",
            "groups": ["/environments/prod", "/environments/staging"],
            "realm_access": {"roles": ["admin", "operator"]},
        }

        user = UserInfo.from_dict(data)

        assert user.sub == "user-123"
        assert user.preferred_username == "testuser"
        assert user.email == "test@example.com"
        assert user.realm_roles == ["admin", "operator"]

    def test_has_role(self):
        """Check role membership."""
        user = UserInfo(
            sub="123",
            preferred_username="test",
            realm_roles=["admin", "viewer"],
        )

        assert user.has_role("admin") is True
        assert user.has_role("viewer") is True
        assert user.has_role("operator") is False

    def test_has_any_role(self):
        """Check any role membership."""
        user = UserInfo(
            sub="123",
            preferred_username="test",
            realm_roles=["viewer"],
        )

        assert user.has_any_role(["admin", "viewer"]) is True
        assert user.has_any_role(["admin", "operator"]) is False

    def test_get_environment_access(self):
        """Extract environment access from groups."""
        user = UserInfo(
            sub="123",
            preferred_username="test",
            groups=[
                "/environments/prod",
                "/environments/staging",
                "/other/group",
            ],
        )

        envs = user.get_environment_access()

        assert "prod" in envs
        assert "staging" in envs
        assert len(envs) == 2


class TestTokenClaims:
    """Tests for TokenClaims."""

    def test_from_claims(self):
        """Create TokenClaims from JWT claims."""
        claims = {
            "sub": "user-456",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "https://keycloak.example.com/realms/test",
            "aud": "sshmgr-api",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["operator"]},
            "groups": ["/environments/dev"],
        }

        token_claims = TokenClaims.from_claims(claims)

        assert token_claims.sub == "user-456"
        assert token_claims.preferred_username == "alice"
        assert "operator" in token_claims.realm_roles
        assert "/environments/dev" in token_claims.groups

    def test_is_expired(self):
        """Check token expiration."""
        # Not expired
        future_claims = TokenClaims.from_claims({
            "sub": "123",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
        })
        assert future_claims.is_expired is False

        # Expired
        past_claims = TokenClaims.from_claims({
            "sub": "123",
            "exp": int(time.time()) - 100,
            "iat": int(time.time()) - 400,
            "iss": "",
            "aud": "",
        })
        assert past_claims.is_expired is True

    def test_expires_in(self):
        """Get seconds until expiration."""
        claims = TokenClaims.from_claims({
            "sub": "123",
            "exp": int(time.time()) + 120,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
        })

        # Should be close to 120 seconds
        assert 115 <= claims.expires_in <= 120

    def test_to_user_info(self):
        """Convert to UserInfo."""
        claims = TokenClaims.from_claims({
            "sub": "user-789",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
            "preferred_username": "bob",
            "email": "bob@example.com",
            "realm_access": {"roles": ["viewer"]},
        })

        user_info = claims.to_user_info()

        assert user_info.sub == "user-789"
        assert user_info.preferred_username == "bob"
        assert "viewer" in user_info.realm_roles


class TestAuthContext:
    """Tests for AuthContext."""

    @pytest.fixture
    def admin_context(self):
        """Create admin auth context."""
        claims = TokenClaims.from_claims({
            "sub": "admin-user",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
            "preferred_username": "admin",
            "realm_access": {"roles": ["admin"]},
            "groups": [],
        })
        return AuthContext(claims)

    @pytest.fixture
    def operator_context(self):
        """Create operator auth context."""
        claims = TokenClaims.from_claims({
            "sub": "operator-user",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
            "preferred_username": "operator",
            "realm_access": {"roles": ["operator"]},
            "groups": ["/environments/prod", "/environments/staging"],
        })
        return AuthContext(claims)

    @pytest.fixture
    def viewer_context(self):
        """Create viewer auth context."""
        claims = TokenClaims.from_claims({
            "sub": "viewer-user",
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "iss": "",
            "aud": "",
            "preferred_username": "viewer",
            "realm_access": {"roles": ["viewer"]},
            "groups": ["/environments/dev"],
        })
        return AuthContext(claims)

    def test_has_role(self, admin_context):
        """Check role membership."""
        assert admin_context.has_role(Role.ADMIN) is True
        assert admin_context.has_role("admin") is True
        assert admin_context.has_role(Role.OPERATOR) is False

    def test_has_minimum_role_admin(self, admin_context):
        """Admin has all roles."""
        assert admin_context.has_minimum_role(Role.ADMIN) is True
        assert admin_context.has_minimum_role(Role.OPERATOR) is True
        assert admin_context.has_minimum_role(Role.VIEWER) is True

    def test_has_minimum_role_operator(self, operator_context):
        """Operator has operator and viewer."""
        assert operator_context.has_minimum_role(Role.ADMIN) is False
        assert operator_context.has_minimum_role(Role.OPERATOR) is True
        assert operator_context.has_minimum_role(Role.VIEWER) is True

    def test_has_minimum_role_viewer(self, viewer_context):
        """Viewer only has viewer."""
        assert viewer_context.has_minimum_role(Role.ADMIN) is False
        assert viewer_context.has_minimum_role(Role.OPERATOR) is False
        assert viewer_context.has_minimum_role(Role.VIEWER) is True

    def test_get_accessible_environments(self, operator_context):
        """Get environments from groups."""
        envs = operator_context.get_accessible_environments()

        assert "prod" in envs
        assert "staging" in envs
        assert len(envs) == 2

    def test_can_access_environment_admin(self, admin_context):
        """Admin can access any environment."""
        assert admin_context.can_access_environment("prod") is True
        assert admin_context.can_access_environment("any-env") is True

    def test_can_access_environment_operator(self, operator_context):
        """Operator can only access assigned environments."""
        assert operator_context.can_access_environment("prod") is True
        assert operator_context.can_access_environment("staging") is True
        assert operator_context.can_access_environment("dev") is False

    def test_can_access_environment_viewer(self, viewer_context):
        """Viewer can only access assigned environments."""
        assert viewer_context.can_access_environment("dev") is True
        assert viewer_context.can_access_environment("prod") is False


class TestRoleHierarchy:
    """Tests for role hierarchy."""

    def test_admin_implies_all(self):
        """Admin role implies all other roles."""
        implied = ROLE_HIERARCHY[Role.ADMIN]
        assert Role.ADMIN in implied
        assert Role.OPERATOR in implied
        assert Role.VIEWER in implied

    def test_operator_implies_viewer(self):
        """Operator role implies viewer."""
        implied = ROLE_HIERARCHY[Role.OPERATOR]
        assert Role.OPERATOR in implied
        assert Role.VIEWER in implied
        assert Role.ADMIN not in implied

    def test_viewer_only_viewer(self):
        """Viewer role only implies itself."""
        implied = ROLE_HIERARCHY[Role.VIEWER]
        assert Role.VIEWER in implied
        assert len(implied) == 1


class TestCredentialStore:
    """Tests for CredentialStore."""

    @pytest.fixture
    def temp_store(self, tmp_path):
        """Create store with temp directory."""
        return CredentialStore(config_dir=tmp_path)

    @pytest.fixture
    def sample_credentials(self):
        """Create sample credentials."""
        return StoredCredentials(
            access_token="access123",
            refresh_token="refresh456",
            token_type="Bearer",
            expires_at=time.time() + 300,
            refresh_expires_at=time.time() + 1800,
            scope="openid",
            id_token=None,
            keycloak_url="https://keycloak.example.com",
            realm="sshmgr",
        )

    def test_save_and_load(self, temp_store, sample_credentials):
        """Save and load credentials."""
        temp_store.save(sample_credentials)

        loaded = temp_store.load()

        assert loaded is not None
        assert loaded.access_token == sample_credentials.access_token
        assert loaded.refresh_token == sample_credentials.refresh_token

    def test_clear(self, temp_store, sample_credentials):
        """Clear credentials."""
        temp_store.save(sample_credentials)
        assert temp_store.exists() is True

        temp_store.clear()

        assert temp_store.exists() is False
        assert temp_store.load() is None

    def test_get_valid_credentials_not_expired(self, temp_store, sample_credentials):
        """Get valid non-expired credentials."""
        temp_store.save(sample_credentials)

        result = temp_store.get_valid_credentials()

        assert result is not None
        assert result.access_token == sample_credentials.access_token

    def test_get_valid_credentials_expired_but_refreshable(self, temp_store):
        """Get credentials when access expired but refresh available."""
        creds = StoredCredentials(
            access_token="expired",
            refresh_token="valid_refresh",
            token_type="Bearer",
            expires_at=time.time() - 100,  # Expired
            refresh_expires_at=time.time() + 1800,  # Still valid
            scope="openid",
            id_token=None,
            keycloak_url="https://keycloak.example.com",
            realm="sshmgr",
        )
        temp_store.save(creds)

        result = temp_store.get_valid_credentials()

        assert result is not None
        assert result.can_refresh is True

    def test_get_valid_credentials_all_expired(self, temp_store):
        """Returns None when all tokens expired."""
        creds = StoredCredentials(
            access_token="expired",
            refresh_token="also_expired",
            token_type="Bearer",
            expires_at=time.time() - 100,
            refresh_expires_at=time.time() - 50,
            scope="openid",
            id_token=None,
            keycloak_url="https://keycloak.example.com",
            realm="sshmgr",
        )
        temp_store.save(creds)

        result = temp_store.get_valid_credentials()

        assert result is None
        # Should have cleared the file
        assert temp_store.exists() is False


class TestStoredCredentials:
    """Tests for StoredCredentials."""

    def test_from_token_response(self):
        """Create from token response."""
        response = TokenResponse(
            access_token="access",
            token_type="Bearer",
            expires_in=300,
            refresh_token="refresh",
            refresh_expires_in=1800,
        )

        creds = StoredCredentials.from_token_response(
            response,
            keycloak_url="https://kc.example.com",
            realm="test",
        )

        assert creds.access_token == "access"
        assert creds.refresh_token == "refresh"
        assert creds.keycloak_url == "https://kc.example.com"
        assert creds.realm == "test"
        # expires_at should be in the future
        assert creds.expires_at > time.time()

    def test_is_access_token_expired(self):
        """Check access token expiration."""
        # Not expired
        valid = StoredCredentials(
            access_token="token",
            refresh_token=None,
            token_type="Bearer",
            expires_at=time.time() + 300,
            refresh_expires_at=None,
            scope=None,
            id_token=None,
            keycloak_url="",
            realm="",
        )
        assert valid.is_access_token_expired is False

        # Expired
        expired = StoredCredentials(
            access_token="token",
            refresh_token=None,
            token_type="Bearer",
            expires_at=time.time() - 100,
            refresh_expires_at=None,
            scope=None,
            id_token=None,
            keycloak_url="",
            realm="",
        )
        assert expired.is_access_token_expired is True

    def test_can_refresh(self):
        """Check if refresh is possible."""
        # Can refresh
        creds = StoredCredentials(
            access_token="token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_at=time.time() - 100,
            refresh_expires_at=time.time() + 1800,
            scope=None,
            id_token=None,
            keycloak_url="",
            realm="",
        )
        assert creds.can_refresh is True

        # No refresh token
        no_refresh = StoredCredentials(
            access_token="token",
            refresh_token=None,
            token_type="Bearer",
            expires_at=time.time() + 300,
            refresh_expires_at=None,
            scope=None,
            id_token=None,
            keycloak_url="",
            realm="",
        )
        assert no_refresh.can_refresh is False


class TestCredentialManager:
    """Tests for CredentialManager."""

    @pytest.fixture
    def manager(self, tmp_path):
        """Create manager with temp store."""
        store = CredentialStore(config_dir=tmp_path)
        return CredentialManager(store=store)

    @pytest.fixture
    def sample_response(self):
        """Create sample token response."""
        return TokenResponse(
            access_token="access_token_here",
            token_type="Bearer",
            expires_in=300,
            refresh_token="refresh_token_here",
            refresh_expires_in=1800,
        )

    def test_save_tokens(self, manager, sample_response):
        """Save tokens from response."""
        creds = manager.save_tokens(
            sample_response,
            keycloak_url="https://kc.example.com",
            realm="test",
        )

        assert creds.access_token == "access_token_here"
        assert manager.is_logged_in() is True

    def test_get_access_token(self, manager, sample_response):
        """Get access token."""
        manager.save_tokens(
            sample_response,
            keycloak_url="https://kc.example.com",
            realm="test",
        )

        token = manager.get_access_token()

        assert token == "access_token_here"

    def test_clear(self, manager, sample_response):
        """Clear credentials."""
        manager.save_tokens(
            sample_response,
            keycloak_url="https://kc.example.com",
            realm="test",
        )
        assert manager.is_logged_in() is True

        manager.clear()

        assert manager.is_logged_in() is False
        assert manager.get_access_token() is None

    def test_needs_refresh(self, manager):
        """Check if refresh is needed."""
        # Token expiring soon
        creds = StoredCredentials(
            access_token="token",
            refresh_token="refresh",
            token_type="Bearer",
            expires_at=time.time() + 30,  # 30 seconds, below threshold
            refresh_expires_at=time.time() + 1800,
            scope=None,
            id_token=None,
            keycloak_url="",
            realm="",
        )
        manager.store.save(creds)

        assert manager.needs_refresh() is True

    def test_get_login_info(self, manager, sample_response):
        """Get login information."""
        manager.save_tokens(
            sample_response,
            keycloak_url="https://kc.example.com",
            realm="test",
        )

        info = manager.get_login_info()

        assert info is not None
        assert info["keycloak_url"] == "https://kc.example.com"
        assert info["realm"] == "test"
        assert info["can_refresh"] is True
