"""JWT token validation and user extraction."""

from __future__ import annotations

import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import httpx
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError

from sshmgr.auth.keycloak import KeycloakConfig, UserInfo
from sshmgr.config import Settings, get_settings
from sshmgr.core.exceptions import AuthenticationError


@dataclass
class TokenClaims:
    """Validated JWT token claims."""

    sub: str  # Subject (user ID)
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    iss: str  # Issuer
    aud: str | list[str]  # Audience
    azp: str | None  # Authorized party (client_id)
    preferred_username: str | None
    email: str | None
    email_verified: bool
    name: str | None
    given_name: str | None
    family_name: str | None
    realm_roles: list[str]
    client_roles: dict[str, list[str]]
    groups: list[str]
    raw_claims: dict[str, Any]

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "TokenClaims":
        """Create from decoded JWT claims."""
        # Extract roles
        realm_roles = []
        if "realm_access" in claims:
            realm_roles = claims["realm_access"].get("roles", [])

        client_roles = {}
        if "resource_access" in claims:
            for client, access in claims["resource_access"].items():
                client_roles[client] = access.get("roles", [])

        return cls(
            sub=claims.get("sub", ""),
            exp=claims.get("exp", 0),
            iat=claims.get("iat", 0),
            iss=claims.get("iss", ""),
            aud=claims.get("aud", ""),
            azp=claims.get("azp"),
            preferred_username=claims.get("preferred_username"),
            email=claims.get("email"),
            email_verified=claims.get("email_verified", False),
            name=claims.get("name"),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            realm_roles=realm_roles,
            client_roles=client_roles,
            groups=claims.get("groups", []),
            raw_claims=claims,
        )

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return time.time() >= self.exp

    @property
    def expires_in(self) -> int:
        """Seconds until token expires."""
        return max(0, self.exp - int(time.time()))

    def to_user_info(self) -> UserInfo:
        """Convert to UserInfo object."""
        return UserInfo(
            sub=self.sub,
            preferred_username=self.preferred_username or "",
            email=self.email,
            email_verified=self.email_verified,
            name=self.name,
            given_name=self.given_name,
            family_name=self.family_name,
            groups=self.groups,
            realm_roles=self.realm_roles,
            client_roles=self.client_roles,
        )


class JWTValidator:
    """
    JWT token validator using Keycloak's public keys.

    Fetches and caches the JWKS from Keycloak for token validation.
    """

    def __init__(
        self,
        config: KeycloakConfig | None = None,
        settings: Settings | None = None,
    ):
        """
        Initialize JWT validator.

        Args:
            config: Keycloak configuration
            settings: Application settings (used if config not provided)
        """
        self.config = config or KeycloakConfig.from_settings(settings)
        self._jwks: dict | None = None
        self._jwks_fetched_at: float = 0
        self._jwks_ttl: int = 3600  # Refresh JWKS every hour

    async def get_jwks(self, force_refresh: bool = False) -> dict:
        """
        Fetch the JSON Web Key Set from Keycloak.

        Args:
            force_refresh: Force refresh even if cached

        Returns:
            JWKS dictionary
        """
        now = time.time()

        if (
            not force_refresh
            and self._jwks is not None
            and (now - self._jwks_fetched_at) < self._jwks_ttl
        ):
            return self._jwks

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(self.config.certs_endpoint)
            response.raise_for_status()
            self._jwks = response.json()
            self._jwks_fetched_at = now
            return self._jwks

    def _get_signing_key(self, token: str, jwks: dict) -> dict:
        """
        Get the signing key for a token from JWKS.

        Args:
            token: JWT token string
            jwks: JWKS dictionary

        Returns:
            Key dictionary from JWKS

        Raises:
            AuthenticationError: If key not found
        """
        # Decode header without verification to get kid
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as e:
            raise AuthenticationError(f"Invalid token header: {e}")

        kid = unverified_header.get("kid")
        if not kid:
            raise AuthenticationError("Token missing key ID (kid)")

        # Find matching key in JWKS
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return key

        raise AuthenticationError(f"Key ID {kid} not found in JWKS")

    async def validate(
        self,
        token: str,
        audience: str | None = None,
        verify_exp: bool = True,
    ) -> TokenClaims:
        """
        Validate a JWT token and extract claims.

        Args:
            token: JWT access token string
            audience: Expected audience (defaults to client_id)
            verify_exp: Whether to verify expiration

        Returns:
            TokenClaims with validated claims

        Raises:
            AuthenticationError: If token is invalid
        """
        if audience is None:
            audience = self.config.client_id

        # Get JWKS
        try:
            jwks = await self.get_jwks()
        except Exception as e:
            raise AuthenticationError(f"Failed to fetch JWKS: {e}")

        # Get signing key
        signing_key = self._get_signing_key(token, jwks)

        # Validate token
        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=self.config.realm_url.rstrip("/"),
                options={
                    "verify_exp": verify_exp,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except JWTError as e:
            # Try refreshing JWKS in case keys were rotated
            try:
                jwks = await self.get_jwks(force_refresh=True)
                signing_key = self._get_signing_key(token, jwks)
                claims = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=audience,
                    issuer=self.config.realm_url.rstrip("/"),
                    options={
                        "verify_exp": verify_exp,
                        "verify_aud": True,
                        "verify_iss": True,
                    },
                )
            except JWTError:
                raise AuthenticationError(f"Invalid token: {e}")

        return TokenClaims.from_claims(claims)

    def validate_sync(
        self,
        token: str,
        jwks: dict,
        audience: str | None = None,
        verify_exp: bool = True,
    ) -> TokenClaims:
        """
        Synchronously validate a JWT token with pre-fetched JWKS.

        Useful for FastAPI dependency injection where JWKS is cached.

        Args:
            token: JWT access token string
            jwks: Pre-fetched JWKS dictionary
            audience: Expected audience
            verify_exp: Whether to verify expiration

        Returns:
            TokenClaims with validated claims
        """
        if audience is None:
            audience = self.config.client_id

        signing_key = self._get_signing_key(token, jwks)

        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=self.config.realm_url.rstrip("/"),
                options={
                    "verify_exp": verify_exp,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except JWTError as e:
            raise AuthenticationError(f"Invalid token: {e}")

        return TokenClaims.from_claims(claims)


def decode_token_unverified(token: str) -> dict[str, Any]:
    """
    Decode a JWT token without verification.

    Useful for debugging or getting claims before validation.

    Args:
        token: JWT token string

    Returns:
        Token claims dictionary

    Raises:
        AuthenticationError: If token cannot be decoded
    """
    try:
        claims = jwt.get_unverified_claims(token)
        return claims
    except JWTError as e:
        raise AuthenticationError(f"Cannot decode token: {e}")


def is_token_expired(token: str) -> bool:
    """
    Check if a token is expired without full validation.

    Args:
        token: JWT token string

    Returns:
        True if token is expired
    """
    try:
        claims = decode_token_unverified(token)
        exp = claims.get("exp", 0)
        return time.time() >= exp
    except AuthenticationError:
        return True
