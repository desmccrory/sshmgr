"""OAuth 2.0 Device Authorization Flow for CLI authentication."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum

import httpx

from sshmgr.auth.keycloak import KeycloakConfig, TokenResponse
from sshmgr.config import Settings, get_settings
from sshmgr.core.exceptions import AuthenticationError


class DeviceFlowError(Enum):
    """Device flow polling error types."""

    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    ACCESS_DENIED = "access_denied"
    EXPIRED_TOKEN = "expired_token"


@dataclass
class DeviceAuthResponse:
    """Response from device authorization request."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int  # Polling interval in seconds

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceAuthResponse":
        """Create from API response dict."""
        return cls(
            device_code=data["device_code"],
            user_code=data["user_code"],
            verification_uri=data["verification_uri"],
            verification_uri_complete=data.get("verification_uri_complete"),
            expires_in=data.get("expires_in", 600),
            interval=data.get("interval", 5),
        )


class DeviceAuthFlow:
    """
    OAuth 2.0 Device Authorization Flow handler.

    This flow is designed for devices without a browser or with limited
    input capabilities. The user authenticates in a browser on another
    device while the CLI polls for completion.

    Usage:
        async with DeviceAuthFlow() as flow:
            auth = await flow.start()
            print(f"Visit {auth.verification_uri} and enter code: {auth.user_code}")
            tokens = await flow.poll_for_token(auth)
    """

    def __init__(
        self,
        config: KeycloakConfig | None = None,
        settings: Settings | None = None,
    ):
        """
        Initialize device authorization flow.

        Args:
            config: Keycloak configuration
            settings: Application settings (used if config not provided)
        """
        self.config = config or KeycloakConfig.from_settings(settings)
        self._http_client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "DeviceAuthFlow":
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
        """Get the HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def start(self, scope: str = "openid profile email") -> DeviceAuthResponse:
        """
        Start the device authorization flow.

        Requests a device code and user code from the authorization server.

        Args:
            scope: OAuth scopes to request

        Returns:
            DeviceAuthResponse with codes and verification URI

        Raises:
            AuthenticationError: If the request fails
        """
        data = {
            "client_id": self.config.client_id,
            "scope": scope,
        }

        response = await self.http_client.post(
            self.config.device_auth_endpoint,
            data=data,
        )

        if response.status_code != 200:
            raise AuthenticationError(
                f"Device authorization request failed: {response.text}"
            )

        return DeviceAuthResponse.from_dict(response.json())

    async def poll_for_token(
        self,
        auth: DeviceAuthResponse,
        callback: callable | None = None,
    ) -> TokenResponse:
        """
        Poll the token endpoint until user completes authentication.

        Args:
            auth: DeviceAuthResponse from start()
            callback: Optional callback called on each poll attempt.
                      Signature: callback(attempt: int, elapsed: float)

        Returns:
            TokenResponse with access and refresh tokens

        Raises:
            AuthenticationError: If authentication fails or expires
        """
        interval = auth.interval
        start_time = time.time()
        attempt = 0

        while True:
            elapsed = time.time() - start_time

            # Check if device code has expired
            if elapsed >= auth.expires_in:
                raise AuthenticationError(
                    "Device code expired. Please restart the login process."
                )

            # Wait for the polling interval
            await asyncio.sleep(interval)
            attempt += 1

            # Call progress callback if provided
            if callback:
                callback(attempt, elapsed)

            # Try to get tokens
            try:
                return await self._request_token(auth.device_code)
            except DeviceFlowPendingError:
                # User hasn't completed auth yet, continue polling
                continue
            except DeviceFlowSlowDownError:
                # Server asked us to slow down
                interval += 5
                continue

    async def _request_token(self, device_code: str) -> TokenResponse:
        """
        Request tokens using the device code.

        Args:
            device_code: Device code from authorization response

        Returns:
            TokenResponse if successful

        Raises:
            DeviceFlowPendingError: If authorization is still pending
            DeviceFlowSlowDownError: If we need to slow down polling
            AuthenticationError: If authentication failed
        """
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self.config.client_id,
            "device_code": device_code,
        }

        response = await self.http_client.post(
            self.config.token_endpoint,
            data=data,
        )

        if response.status_code == 200:
            return TokenResponse.from_dict(response.json())

        # Handle error responses
        try:
            error_data = response.json()
            error = error_data.get("error", "")
        except Exception:
            raise AuthenticationError(f"Token request failed: {response.text}")

        if error == DeviceFlowError.AUTHORIZATION_PENDING.value:
            raise DeviceFlowPendingError("Authorization pending")
        elif error == DeviceFlowError.SLOW_DOWN.value:
            raise DeviceFlowSlowDownError("Slow down")
        elif error == DeviceFlowError.ACCESS_DENIED.value:
            raise AuthenticationError("Access denied by user")
        elif error == DeviceFlowError.EXPIRED_TOKEN.value:
            raise AuthenticationError("Device code expired")
        else:
            error_desc = error_data.get("error_description", error)
            raise AuthenticationError(f"Authentication failed: {error_desc}")


class DeviceFlowPendingError(Exception):
    """Authorization is still pending."""

    pass


class DeviceFlowSlowDownError(Exception):
    """Server requested slower polling."""

    pass


async def login_with_device_flow(
    settings: Settings | None = None,
    on_code_received: callable | None = None,
    on_poll_attempt: callable | None = None,
) -> TokenResponse:
    """
    Convenience function to perform device flow login.

    Args:
        settings: Application settings
        on_code_received: Callback when user code is received.
                         Signature: on_code_received(verification_uri, user_code, verification_uri_complete)
        on_poll_attempt: Callback during polling.
                        Signature: on_poll_attempt(attempt, elapsed)

    Returns:
        TokenResponse with tokens

    Example:
        def show_code(uri, code, uri_complete):
            print(f"Visit {uri} and enter code: {code}")

        tokens = await login_with_device_flow(on_code_received=show_code)
    """
    async with DeviceAuthFlow(settings=settings) as flow:
        # Start device authorization
        auth = await flow.start()

        # Notify about the user code
        if on_code_received:
            on_code_received(
                auth.verification_uri,
                auth.user_code,
                auth.verification_uri_complete,
            )

        # Poll for completion
        return await flow.poll_for_token(auth, callback=on_poll_attempt)
