"""Rate limiting middleware for the API."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from sshmgr.config import Settings


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""

    tokens: float
    last_update: float
    lock: Lock = field(default_factory=Lock)


class RateLimiter:
    """
    In-memory rate limiter using token bucket algorithm.

    Features:
    - Per-client rate limiting (by IP or user)
    - Configurable requests per window
    - Burst allowance for short spikes
    - Automatic cleanup of stale buckets
    """

    def __init__(
        self,
        requests_per_window: int = 100,
        window_seconds: int = 60,
        burst: int = 20,
    ):
        """
        Initialize rate limiter.

        Args:
            requests_per_window: Max requests allowed per window
            window_seconds: Time window in seconds
            burst: Extra tokens for burst handling
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.burst = burst

        # Token replenish rate (tokens per second)
        self.refill_rate = requests_per_window / window_seconds

        # Max tokens = requests + burst allowance
        self.max_tokens = requests_per_window + burst

        # Storage for client buckets
        self._buckets: dict[str, RateLimitBucket] = defaultdict(
            lambda: RateLimitBucket(
                tokens=self.max_tokens,
                last_update=time.monotonic(),
            )
        )
        self._global_lock = Lock()

        # Cleanup interval (clean stale buckets every N seconds)
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300  # 5 minutes

    def _get_client_key(self, request: Request) -> str:
        """
        Get unique client identifier for rate limiting.

        Priority:
        1. Authenticated user (from request state)
        2. X-Forwarded-For header (for proxied requests)
        3. Client IP address
        """
        # Try authenticated user first
        if hasattr(request.state, "user") and request.state.user:
            return f"user:{request.state.user}"

        # Try X-Forwarded-For for proxied requests
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take first IP (original client)
            client_ip = forwarded_for.split(",")[0].strip()
            return f"ip:{client_ip}"

        # Fall back to direct client IP
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    def _cleanup_stale_buckets(self) -> None:
        """Remove stale buckets to prevent memory growth."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        with self._global_lock:
            self._last_cleanup = now
            stale_threshold = now - (self.window_seconds * 2)

            # Find and remove stale buckets
            stale_keys = [
                key
                for key, bucket in self._buckets.items()
                if bucket.last_update < stale_threshold
            ]
            for key in stale_keys:
                del self._buckets[key]

    def is_allowed(self, request: Request) -> tuple[bool, dict[str, str]]:
        """
        Check if request is allowed under rate limit.

        Returns:
            Tuple of (is_allowed, headers_dict)
            Headers include rate limit info for client feedback
        """
        self._cleanup_stale_buckets()

        client_key = self._get_client_key(request)
        bucket = self._buckets[client_key]
        now = time.monotonic()

        with bucket.lock:
            # Refill tokens based on time passed
            elapsed = now - bucket.last_update
            bucket.tokens = min(
                self.max_tokens,
                bucket.tokens + (elapsed * self.refill_rate),
            )
            bucket.last_update = now

            # Check if we have tokens available
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                allowed = True
            else:
                allowed = False

            # Calculate headers
            remaining = max(0, int(bucket.tokens))
            reset_seconds = int((1 - bucket.tokens) / self.refill_rate) if not allowed else 0

        headers = {
            "X-RateLimit-Limit": str(self.requests_per_window),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_seconds),
        }

        if not allowed:
            headers["Retry-After"] = str(max(1, reset_seconds))

        return allowed, headers


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.

    Applies rate limiting to all requests except health checks.
    """

    # Paths excluded from rate limiting
    EXCLUDED_PATHS = {
        "/api/v1/health",
        "/api/v1/ready",
        "/api/v1/version",
        "/api/v1/metrics",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
    }

    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.enabled = settings.rate_limit_enabled
        self.limiter = RateLimiter(
            requests_per_window=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
            burst=settings.rate_limit_burst,
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Skip if disabled or excluded path
        if not self.enabled or request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        # Check rate limit
        allowed, headers = self.limiter.is_allowed(request)

        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please slow down.",
                    "code": "RATE_LIMIT_EXCEEDED",
                },
                headers=headers,
            )

        # Process request and add rate limit headers to response
        response = await call_next(request)
        for key, value in headers.items():
            response.headers[key] = value

        return response


def create_rate_limit_middleware(settings: Settings) -> type[RateLimitMiddleware]:
    """Create a configured rate limit middleware class."""

    class ConfiguredRateLimitMiddleware(RateLimitMiddleware):
        def __init__(self, app):
            super().__init__(app, settings)

    return ConfiguredRateLimitMiddleware
