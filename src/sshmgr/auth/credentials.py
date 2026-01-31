"""Credential storage for CLI authentication."""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sshmgr.auth.jwt import decode_token_unverified, is_token_expired
from sshmgr.auth.keycloak import TokenResponse
from sshmgr.core.exceptions import AuthenticationError


@dataclass
class StoredCredentials:
    """Credentials stored on disk."""

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_at: float  # Unix timestamp
    refresh_expires_at: float | None
    scope: str | None
    id_token: str | None
    keycloak_url: str
    realm: str

    @classmethod
    def from_token_response(
        cls,
        response: TokenResponse,
        keycloak_url: str,
        realm: str,
    ) -> "StoredCredentials":
        """Create from OAuth token response."""
        now = time.time()
        return cls(
            access_token=response.access_token,
            refresh_token=response.refresh_token,
            token_type=response.token_type,
            expires_at=now + response.expires_in,
            refresh_expires_at=(
                now + response.refresh_expires_in
                if response.refresh_expires_in
                else None
            ),
            scope=response.scope,
            id_token=response.id_token,
            keycloak_url=keycloak_url,
            realm=realm,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StoredCredentials":
        """Create from dictionary."""
        return cls(**data)

    @property
    def is_access_token_expired(self) -> bool:
        """Check if access token is expired."""
        return time.time() >= self.expires_at

    @property
    def is_refresh_token_expired(self) -> bool:
        """Check if refresh token is expired."""
        if self.refresh_expires_at is None:
            return True
        return time.time() >= self.refresh_expires_at

    @property
    def access_token_expires_in(self) -> int:
        """Seconds until access token expires."""
        return max(0, int(self.expires_at - time.time()))

    @property
    def can_refresh(self) -> bool:
        """Check if we can refresh the access token."""
        return (
            self.refresh_token is not None
            and not self.is_refresh_token_expired
        )

    def get_username(self) -> str | None:
        """Extract username from access token."""
        try:
            claims = decode_token_unverified(self.access_token)
            return claims.get("preferred_username")
        except Exception:
            return None


class CredentialStore:
    """
    Manages credential storage for the CLI.

    Stores credentials in ~/.sshmgr/credentials.json with restricted permissions.
    """

    DEFAULT_DIR = Path.home() / ".sshmgr"
    CREDENTIALS_FILE = "credentials.json"

    def __init__(self, config_dir: Path | None = None):
        """
        Initialize credential store.

        Args:
            config_dir: Directory for storing credentials.
                       Defaults to ~/.sshmgr
        """
        self.config_dir = config_dir or self.DEFAULT_DIR
        self._credentials_path = self.config_dir / self.CREDENTIALS_FILE

    def _ensure_config_dir(self) -> None:
        """Ensure config directory exists with proper permissions."""
        if not self.config_dir.exists():
            self.config_dir.mkdir(mode=0o700, parents=True)
        else:
            # Ensure directory has correct permissions
            current_mode = self.config_dir.stat().st_mode
            if current_mode & 0o077:  # Check if group/other have any access
                self.config_dir.chmod(0o700)

    def _secure_file(self, path: Path) -> None:
        """Set secure permissions on a file."""
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    def save(self, credentials: StoredCredentials) -> None:
        """
        Save credentials to disk.

        Args:
            credentials: Credentials to save
        """
        self._ensure_config_dir()

        # Write to temp file first, then rename (atomic on POSIX)
        temp_path = self._credentials_path.with_suffix(".tmp")

        try:
            with open(temp_path, "w") as f:
                json.dump(credentials.to_dict(), f, indent=2)
            self._secure_file(temp_path)
            temp_path.rename(self._credentials_path)
        except Exception:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

    def load(self) -> StoredCredentials | None:
        """
        Load credentials from disk.

        Returns:
            StoredCredentials if found and valid, None otherwise
        """
        if not self._credentials_path.exists():
            return None

        try:
            with open(self._credentials_path) as f:
                data = json.load(f)
            return StoredCredentials.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            # Corrupted file, remove it
            self.clear()
            return None

    def clear(self) -> None:
        """Remove stored credentials."""
        if self._credentials_path.exists():
            self._credentials_path.unlink()

    def exists(self) -> bool:
        """Check if credentials file exists."""
        return self._credentials_path.exists()

    def get_valid_credentials(self) -> StoredCredentials | None:
        """
        Get credentials if they exist and are usable.

        Returns credentials if:
        - Access token is not expired, OR
        - Refresh token is available and not expired

        Returns:
            StoredCredentials if usable, None otherwise
        """
        creds = self.load()
        if creds is None:
            return None

        if not creds.is_access_token_expired:
            return creds

        if creds.can_refresh:
            return creds

        # Both tokens expired, clear and return None
        self.clear()
        return None


class CredentialManager:
    """
    High-level credential management with automatic refresh.

    Handles loading, refreshing, and saving credentials.
    """

    def __init__(
        self,
        store: CredentialStore | None = None,
        refresh_threshold: int = 60,  # Refresh if <60s remaining
    ):
        """
        Initialize credential manager.

        Args:
            store: Credential store to use
            refresh_threshold: Refresh token if fewer seconds remaining
        """
        self.store = store or CredentialStore()
        self.refresh_threshold = refresh_threshold
        self._current: StoredCredentials | None = None

    def get_credentials(self) -> StoredCredentials | None:
        """
        Get current credentials, loading from disk if needed.

        Returns:
            Current credentials or None
        """
        if self._current is None:
            self._current = self.store.get_valid_credentials()
        return self._current

    def get_access_token(self) -> str | None:
        """
        Get access token if available and not expired.

        Returns:
            Access token string or None
        """
        creds = self.get_credentials()
        if creds is None:
            return None

        if creds.is_access_token_expired:
            return None

        return creds.access_token

    def needs_refresh(self) -> bool:
        """Check if access token needs refresh."""
        creds = self.get_credentials()
        if creds is None:
            return False

        return creds.access_token_expires_in < self.refresh_threshold

    def can_refresh(self) -> bool:
        """Check if refresh is possible."""
        creds = self.get_credentials()
        if creds is None:
            return False
        return creds.can_refresh

    def save_tokens(
        self,
        response: TokenResponse,
        keycloak_url: str,
        realm: str,
    ) -> StoredCredentials:
        """
        Save new tokens from OAuth response.

        Args:
            response: Token response from OAuth flow
            keycloak_url: Keycloak server URL
            realm: Keycloak realm

        Returns:
            Saved credentials
        """
        creds = StoredCredentials.from_token_response(
            response,
            keycloak_url=keycloak_url,
            realm=realm,
        )
        self.store.save(creds)
        self._current = creds
        return creds

    def update_tokens(self, response: TokenResponse) -> StoredCredentials:
        """
        Update tokens after refresh.

        Preserves original keycloak_url and realm.

        Args:
            response: Token response from refresh

        Returns:
            Updated credentials
        """
        current = self.get_credentials()
        if current is None:
            raise AuthenticationError("No existing credentials to update")

        creds = StoredCredentials.from_token_response(
            response,
            keycloak_url=current.keycloak_url,
            realm=current.realm,
        )
        self.store.save(creds)
        self._current = creds
        return creds

    def clear(self) -> None:
        """Clear all stored credentials."""
        self.store.clear()
        self._current = None

    def is_logged_in(self) -> bool:
        """Check if user is currently logged in."""
        creds = self.get_credentials()
        return creds is not None and (
            not creds.is_access_token_expired or creds.can_refresh
        )

    def get_login_info(self) -> dict[str, Any] | None:
        """
        Get information about current login.

        Returns:
            Dict with username, expires_in, etc. or None
        """
        creds = self.get_credentials()
        if creds is None:
            return None

        return {
            "username": creds.get_username(),
            "keycloak_url": creds.keycloak_url,
            "realm": creds.realm,
            "access_token_expires_in": creds.access_token_expires_in,
            "can_refresh": creds.can_refresh,
            "is_expired": creds.is_access_token_expired,
        }


# Global credential manager instance
_credential_manager: CredentialManager | None = None


def get_credential_manager() -> CredentialManager:
    """Get the global credential manager instance."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager
