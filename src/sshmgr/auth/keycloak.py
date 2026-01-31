"""Keycloak OIDC client for sshmgr."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from sshmgr.config import Settings, get_settings
from sshmgr.core.exceptions import AuthenticationError


@dataclass
class KeycloakConfig:
    """Keycloak connection configuration."""

    server_url: str
    realm: str
    client_id: str
    client_secret: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "KeycloakConfig":
        """Create config from application settings."""
        settings = settings or get_settings()
        return cls(
            server_url=settings.keycloak_url,
            realm=settings.keycloak_realm,
            client_id=settings.keycloak_client_id,
            client_secret=settings.keycloak_client_secret or None,
        )

    @property
    def realm_url(self) -> str:
        """Get the realm URL."""
        return urljoin(self.server_url, f"/realms/{self.realm}/")

    @property
    def token_endpoint(self) -> str:
        """Get the token endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/token")

    @property
    def auth_endpoint(self) -> str:
        """Get the authorization endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/auth")

    @property
    def userinfo_endpoint(self) -> str:
        """Get the userinfo endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/userinfo")

    @property
    def introspect_endpoint(self) -> str:
        """Get the token introspection endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/token/introspect")

    @property
    def device_auth_endpoint(self) -> str:
        """Get the device authorization endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/auth/device")

    @property
    def certs_endpoint(self) -> str:
        """Get the JWKS (certs) endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/certs")

    @property
    def logout_endpoint(self) -> str:
        """Get the logout endpoint URL."""
        return urljoin(self.realm_url, "protocol/openid-connect/logout")


@dataclass
class TokenResponse:
    """OAuth2 token response."""

    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    refresh_expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenResponse":
        """Create from API response dict."""
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 300),
            refresh_token=data.get("refresh_token"),
            refresh_expires_in=data.get("refresh_expires_in"),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
        )


@dataclass
class UserInfo:
    """User information from Keycloak."""

    sub: str  # Subject (user ID)
    preferred_username: str
    email: str | None = None
    email_verified: bool = False
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    groups: list[str] | None = None
    realm_roles: list[str] | None = None
    client_roles: dict[str, list[str]] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserInfo":
        """Create from userinfo or token claims."""
        # Extract roles from realm_access and resource_access
        realm_roles = None
        client_roles = None

        if "realm_access" in data:
            realm_roles = data["realm_access"].get("roles", [])

        if "resource_access" in data:
            client_roles = {
                client: access.get("roles", [])
                for client, access in data["resource_access"].items()
            }

        return cls(
            sub=data.get("sub", ""),
            preferred_username=data.get("preferred_username", ""),
            email=data.get("email"),
            email_verified=data.get("email_verified", False),
            name=data.get("name"),
            given_name=data.get("given_name"),
            family_name=data.get("family_name"),
            groups=data.get("groups"),
            realm_roles=realm_roles,
            client_roles=client_roles,
        )

    def has_role(self, role: str) -> bool:
        """Check if user has a realm role."""
        if self.realm_roles is None:
            return False
        return role in self.realm_roles

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles."""
        return any(self.has_role(role) for role in roles)

    def get_environment_access(self) -> list[str]:
        """
        Get list of environments the user can access.

        Expects groups in format: /environments/{env-name}
        """
        if self.groups is None:
            return []

        prefix = "/environments/"
        return [
            group[len(prefix):]
            for group in self.groups
            if group.startswith(prefix)
        ]


class KeycloakClient:
    """
    Async HTTP client for Keycloak OIDC operations.

    Handles token exchange, refresh, introspection, and user info retrieval.
    """

    def __init__(self, config: KeycloakConfig | None = None):
        """
        Initialize Keycloak client.

        Args:
            config: Keycloak configuration. Uses settings if not provided.
        """
        self.config = config or KeycloakConfig.from_settings()
        self._http_client: httpx.AsyncClient | None = None
        self._jwks: dict | None = None

    async def __aenter__(self) -> "KeycloakClient":
        """Async context manager entry."""
        self._http_client = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Get the HTTP client, creating if needed."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def get_jwks(self) -> dict:
        """
        Fetch the JSON Web Key Set from Keycloak.

        Returns:
            JWKS dictionary containing public keys
        """
        if self._jwks is not None:
            return self._jwks

        response = await self.http_client.get(self.config.certs_endpoint)
        response.raise_for_status()
        self._jwks = response.json()
        return self._jwks

    async def exchange_code(
        self,
        code: str,
        redirect_uri: str,
    ) -> TokenResponse:
        """
        Exchange authorization code for tokens.

        Args:
            code: Authorization code from callback
            redirect_uri: Redirect URI used in authorization request

        Returns:
            TokenResponse with access and refresh tokens
        """
        data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        response = await self.http_client.post(
            self.config.token_endpoint,
            data=data,
        )

        if response.status_code != 200:
            raise AuthenticationError(f"Token exchange failed: {response.text}")

        return TokenResponse.from_dict(response.json())

    async def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh an access token.

        Args:
            refresh_token: Current refresh token

        Returns:
            New TokenResponse with fresh tokens
        """
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": refresh_token,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        response = await self.http_client.post(
            self.config.token_endpoint,
            data=data,
        )

        if response.status_code != 200:
            raise AuthenticationError(f"Token refresh failed: {response.text}")

        return TokenResponse.from_dict(response.json())

    async def get_userinfo(self, access_token: str) -> UserInfo:
        """
        Get user information from the userinfo endpoint.

        Args:
            access_token: Valid access token

        Returns:
            UserInfo with user details
        """
        response = await self.http_client.get(
            self.config.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if response.status_code != 200:
            raise AuthenticationError(f"Userinfo request failed: {response.text}")

        return UserInfo.from_dict(response.json())

    async def introspect_token(self, token: str) -> dict[str, Any]:
        """
        Introspect a token to check validity and get claims.

        Args:
            token: Access or refresh token to introspect

        Returns:
            Token introspection response
        """
        data = {
            "client_id": self.config.client_id,
            "token": token,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        response = await self.http_client.post(
            self.config.introspect_endpoint,
            data=data,
        )

        if response.status_code != 200:
            raise AuthenticationError(f"Token introspection failed: {response.text}")

        return response.json()

    async def logout(self, refresh_token: str) -> None:
        """
        Logout and invalidate tokens.

        Args:
            refresh_token: Refresh token to invalidate
        """
        data = {
            "client_id": self.config.client_id,
            "refresh_token": refresh_token,
        }

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        response = await self.http_client.post(
            self.config.logout_endpoint,
            data=data,
        )

        # Logout may return 204 No Content on success
        if response.status_code not in (200, 204):
            raise AuthenticationError(f"Logout failed: {response.text}")
