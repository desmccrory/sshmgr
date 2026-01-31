"""Role-Based Access Control (RBAC) for FastAPI."""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from sshmgr.auth.jwt import JWTValidator, TokenClaims
from sshmgr.auth.keycloak import KeycloakConfig, UserInfo
from sshmgr.config import Settings, get_settings
from sshmgr.core.exceptions import AuthenticationError, AuthorizationError


class Role(str, Enum):
    """Application roles."""

    ADMIN = "admin"  # Full access: create/delete environments, rotate CAs
    OPERATOR = "operator"  # Issue certificates, view audit logs
    VIEWER = "viewer"  # Read-only access


# Role hierarchy: admin > operator > viewer
ROLE_HIERARCHY = {
    Role.ADMIN: {Role.ADMIN, Role.OPERATOR, Role.VIEWER},
    Role.OPERATOR: {Role.OPERATOR, Role.VIEWER},
    Role.VIEWER: {Role.VIEWER},
}


# Security scheme for FastAPI
bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache
def get_jwt_validator() -> JWTValidator:
    """Get cached JWT validator instance."""
    return JWTValidator()


class AuthContext:
    """
    Authentication context for a request.

    Contains the validated token claims and provides helper methods
    for authorization checks.
    """

    def __init__(self, claims: TokenClaims):
        self.claims = claims
        self._user_info: UserInfo | None = None

    @property
    def user_id(self) -> str:
        """Get the user's subject ID."""
        return self.claims.sub

    @property
    def username(self) -> str:
        """Get the user's preferred username."""
        return self.claims.preferred_username or self.claims.sub

    @property
    def email(self) -> str | None:
        """Get the user's email."""
        return self.claims.email

    @property
    def roles(self) -> list[str]:
        """Get the user's realm roles."""
        return self.claims.realm_roles

    @property
    def groups(self) -> list[str]:
        """Get the user's groups."""
        return self.claims.groups

    @property
    def user_info(self) -> UserInfo:
        """Get UserInfo object from claims."""
        if self._user_info is None:
            self._user_info = self.claims.to_user_info()
        return self._user_info

    def has_role(self, role: Role | str) -> bool:
        """Check if user has a specific role."""
        role_str = role.value if isinstance(role, Role) else role
        return role_str in self.claims.realm_roles

    def has_any_role(self, roles: list[Role | str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(self.has_role(role) for role in roles)

    def has_minimum_role(self, minimum_role: Role) -> bool:
        """
        Check if user has at least the specified role level.

        Uses role hierarchy: admin > operator > viewer
        """
        user_roles = set(self.claims.realm_roles)
        for role, implied_roles in ROLE_HIERARCHY.items():
            if role.value in user_roles:
                return minimum_role in implied_roles
        return False

    def get_accessible_environments(self) -> list[str]:
        """
        Get list of environment names the user can access.

        Based on group membership: /environments/{env-name}
        """
        prefix = "/environments/"
        return [
            group[len(prefix):]
            for group in self.claims.groups
            if group.startswith(prefix)
        ]

    def can_access_environment(self, env_name: str) -> bool:
        """
        Check if user can access a specific environment.

        Admins can access all environments.
        Others need group membership.
        """
        if self.has_role(Role.ADMIN):
            return True
        return env_name in self.get_accessible_environments()

    def can_access_environment_id(self, env_id: UUID, env_name: str) -> bool:
        """
        Check if user can access environment by ID.

        Requires env_name to be passed since groups use names.
        """
        return self.can_access_environment(env_name)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    validator: Annotated[JWTValidator, Depends(get_jwt_validator)],
) -> AuthContext:
    """
    FastAPI dependency to get the current authenticated user.

    Usage:
        @router.get("/protected")
        async def protected_endpoint(
            auth: AuthContext = Depends(get_current_user),
        ):
            return {"user": auth.username}
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        claims = await validator.validate(credentials.credentials)
        return AuthContext(claims)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_optional_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    validator: Annotated[JWTValidator, Depends(get_jwt_validator)],
) -> AuthContext | None:
    """
    FastAPI dependency to optionally get the current user.

    Returns None if no valid token provided (useful for public endpoints
    that behave differently for authenticated users).
    """
    if credentials is None:
        return None

    try:
        claims = await validator.validate(credentials.credentials)
        return AuthContext(claims)
    except AuthenticationError:
        return None


class RequireRole:
    """
    FastAPI dependency to require a minimum role.

    Usage:
        @router.post("/admin-only")
        async def admin_endpoint(
            auth: AuthContext = Depends(get_current_user),
            _: None = Depends(RequireRole(Role.ADMIN)),
        ):
            ...
    """

    def __init__(self, minimum_role: Role):
        self.minimum_role = minimum_role

    async def __call__(
        self,
        auth: Annotated[AuthContext, Depends(get_current_user)],
    ) -> None:
        if not auth.has_minimum_role(self.minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {self.minimum_role.value} role or higher",
            )


class RequireEnvironmentAccess:
    """
    FastAPI dependency to require access to a specific environment.

    The environment name must be available in the path or provided.

    Usage:
        @router.get("/environments/{env_name}/certs")
        async def get_certs(
            env_name: str,
            auth: AuthContext = Depends(get_current_user),
            _: None = Depends(RequireEnvironmentAccess()),
        ):
            ...
    """

    def __init__(self, env_name_param: str = "env_name"):
        self.env_name_param = env_name_param

    async def __call__(
        self,
        auth: Annotated[AuthContext, Depends(get_current_user)],
        env_name: str | None = None,
    ) -> None:
        if env_name is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Environment name required",
            )

        if not auth.can_access_environment(env_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No access to environment: {env_name}",
            )


# Convenience dependency instances
require_admin = RequireRole(Role.ADMIN)
require_operator = RequireRole(Role.OPERATOR)
require_viewer = RequireRole(Role.VIEWER)


def require_role(role: Role | str) -> RequireRole:
    """Factory function to create RequireRole dependency."""
    if isinstance(role, str):
        role = Role(role)
    return RequireRole(role)


def check_role(auth: AuthContext, role: Role) -> None:
    """
    Check if user has required role, raise if not.

    For use outside of FastAPI dependency injection.
    """
    if not auth.has_minimum_role(role):
        raise AuthorizationError(
            f"User {auth.username} lacks required role: {role.value}"
        )


def check_environment_access(auth: AuthContext, env_name: str) -> None:
    """
    Check if user can access environment, raise if not.

    For use outside of FastAPI dependency injection.
    """
    if not auth.can_access_environment(env_name):
        raise AuthorizationError(
            f"User {auth.username} cannot access environment: {env_name}"
        )
