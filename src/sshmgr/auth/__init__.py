"""Authentication module for sshmgr."""

from sshmgr.auth.keycloak import (
    KeycloakClient,
    KeycloakConfig,
    TokenResponse,
    UserInfo,
)
from sshmgr.auth.device_flow import (
    DeviceAuthFlow,
    DeviceAuthResponse,
    login_with_device_flow,
)
from sshmgr.auth.jwt import (
    JWTValidator,
    TokenClaims,
    decode_token_unverified,
    is_token_expired,
)
from sshmgr.auth.rbac import (
    AuthContext,
    Role,
    RequireRole,
    RequireEnvironmentAccess,
    get_current_user,
    get_optional_user,
    require_admin,
    require_operator,
    require_viewer,
    require_role,
    check_role,
    check_environment_access,
)
from sshmgr.auth.credentials import (
    CredentialManager,
    CredentialStore,
    StoredCredentials,
    get_credential_manager,
)

__all__ = [
    # Keycloak client
    "KeycloakClient",
    "KeycloakConfig",
    "TokenResponse",
    "UserInfo",
    # Device flow
    "DeviceAuthFlow",
    "DeviceAuthResponse",
    "login_with_device_flow",
    # JWT validation
    "JWTValidator",
    "TokenClaims",
    "decode_token_unverified",
    "is_token_expired",
    # RBAC
    "AuthContext",
    "Role",
    "RequireRole",
    "RequireEnvironmentAccess",
    "get_current_user",
    "get_optional_user",
    "require_admin",
    "require_operator",
    "require_viewer",
    "require_role",
    "check_role",
    "check_environment_access",
    # Credentials
    "CredentialManager",
    "CredentialStore",
    "StoredCredentials",
    "get_credential_manager",
]
