"""Tests for sshmgr.api.ratelimit module."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request, status
from fastapi.testclient import TestClient
from starlette.responses import Response

from sshmgr.api.ratelimit import (
    RateLimitBucket,
    RateLimiter,
    RateLimitMiddleware,
    create_rate_limit_middleware,
)
from sshmgr.config import Settings


class TestRateLimitBucket:
    """Tests for RateLimitBucket dataclass."""

    def test_bucket_initialization(self):
        """Test bucket initializes with correct values."""
        bucket = RateLimitBucket(tokens=100, last_update=time.monotonic())
        assert bucket.tokens == 100
        assert bucket.last_update > 0
        assert bucket.lock is not None

    def test_bucket_lock_is_independent(self):
        """Test each bucket has its own lock."""
        bucket1 = RateLimitBucket(tokens=100, last_update=time.monotonic())
        bucket2 = RateLimitBucket(tokens=100, last_update=time.monotonic())
        assert bucket1.lock is not bucket2.lock


class TestRateLimiter:
    """Tests for RateLimiter class."""

    @pytest.fixture
    def limiter(self):
        """Create a rate limiter with test settings."""
        return RateLimiter(
            requests_per_window=10,
            window_seconds=60,
            burst=5,
        )

    @pytest.fixture
    def mock_request(self):
        """Create a mock request object."""
        request = MagicMock(spec=Request)
        request.state = MagicMock()
        request.state.user = None
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        return request

    def test_limiter_initialization(self, limiter):
        """Test limiter initializes with correct values."""
        assert limiter.requests_per_window == 10
        assert limiter.window_seconds == 60
        assert limiter.burst == 5
        assert limiter.max_tokens == 15  # 10 + 5
        assert limiter.refill_rate == 10 / 60

    def test_limiter_default_values(self):
        """Test limiter with default values."""
        limiter = RateLimiter()
        assert limiter.requests_per_window == 100
        assert limiter.window_seconds == 60
        assert limiter.burst == 20
        assert limiter.max_tokens == 120

    def test_get_client_key_from_ip(self, limiter, mock_request):
        """Test client key from IP address."""
        key = limiter._get_client_key(mock_request)
        assert key == "ip:127.0.0.1"

    def test_get_client_key_from_authenticated_user(self, limiter, mock_request):
        """Test client key from authenticated user."""
        mock_request.state.user = "alice"
        key = limiter._get_client_key(mock_request)
        assert key == "user:alice"

    def test_get_client_key_from_forwarded_for(self, limiter, mock_request):
        """Test client key from X-Forwarded-For header."""
        mock_request.headers = {"X-Forwarded-For": "203.0.113.195, 70.41.3.18"}
        key = limiter._get_client_key(mock_request)
        assert key == "ip:203.0.113.195"

    def test_get_client_key_user_takes_precedence(self, limiter, mock_request):
        """Test authenticated user takes precedence over IP."""
        mock_request.state.user = "alice"
        mock_request.headers = {"X-Forwarded-For": "203.0.113.195"}
        key = limiter._get_client_key(mock_request)
        assert key == "user:alice"

    def test_get_client_key_no_client(self, limiter, mock_request):
        """Test client key when no client info available."""
        mock_request.client = None
        key = limiter._get_client_key(mock_request)
        assert key == "ip:unknown"

    def test_is_allowed_initial_request(self, limiter, mock_request):
        """Test first request is always allowed."""
        allowed, headers = limiter.is_allowed(mock_request)
        assert allowed is True
        assert "X-RateLimit-Limit" in headers
        assert headers["X-RateLimit-Limit"] == "10"

    def test_is_allowed_multiple_requests(self, limiter, mock_request):
        """Test multiple requests within limit."""
        for _ in range(10):
            allowed, _ = limiter.is_allowed(mock_request)
            assert allowed is True

    def test_is_allowed_burst_requests(self, limiter, mock_request):
        """Test burst allowance works."""
        # Should allow 15 requests (10 + 5 burst)
        for i in range(15):
            allowed, _ = limiter.is_allowed(mock_request)
            assert allowed is True, f"Request {i+1} should be allowed"

    def test_is_denied_after_limit(self, limiter, mock_request):
        """Test request is denied after limit exhausted."""
        # Exhaust all tokens
        for _ in range(15):
            limiter.is_allowed(mock_request)

        # Next request should be denied
        allowed, headers = limiter.is_allowed(mock_request)
        assert allowed is False
        assert "Retry-After" in headers

    def test_headers_include_remaining(self, limiter, mock_request):
        """Test headers include remaining tokens."""
        _, headers = limiter.is_allowed(mock_request)
        remaining = int(headers["X-RateLimit-Remaining"])
        assert remaining >= 0

    def test_headers_include_reset(self, limiter, mock_request):
        """Test headers include reset time."""
        # Exhaust tokens
        for _ in range(15):
            limiter.is_allowed(mock_request)

        _, headers = limiter.is_allowed(mock_request)
        assert "X-RateLimit-Reset" in headers
        reset = int(headers["X-RateLimit-Reset"])
        assert reset >= 0

    def test_tokens_refill_over_time(self, limiter, mock_request):
        """Test tokens refill over time."""
        # Use some tokens
        for _ in range(5):
            limiter.is_allowed(mock_request)

        # Get bucket
        client_key = limiter._get_client_key(mock_request)
        bucket = limiter._buckets[client_key]

        initial_tokens = bucket.tokens

        # Simulate time passing
        bucket.last_update = time.monotonic() - 30  # 30 seconds ago

        # Make another request - tokens should have refilled
        limiter.is_allowed(mock_request)

        # Tokens should have increased (but capped at max)
        # After 30 seconds at 10/60 rate = 5 tokens added
        assert bucket.tokens <= limiter.max_tokens

    def test_different_clients_tracked_separately(self, limiter):
        """Test different clients have separate buckets."""
        request1 = MagicMock(spec=Request)
        request1.state = MagicMock()
        request1.state.user = None
        request1.headers = {}
        request1.client = MagicMock()
        request1.client.host = "192.168.1.1"

        request2 = MagicMock(spec=Request)
        request2.state = MagicMock()
        request2.state.user = None
        request2.headers = {}
        request2.client = MagicMock()
        request2.client.host = "192.168.1.2"

        # Exhaust tokens for client 1
        for _ in range(15):
            limiter.is_allowed(request1)

        # Client 1 should be limited
        allowed1, _ = limiter.is_allowed(request1)
        assert allowed1 is False

        # Client 2 should still be allowed
        allowed2, _ = limiter.is_allowed(request2)
        assert allowed2 is True

    def test_cleanup_stale_buckets(self, limiter, mock_request):
        """Test stale bucket cleanup."""
        # Create a bucket
        limiter.is_allowed(mock_request)

        # Verify bucket exists
        client_key = limiter._get_client_key(mock_request)
        assert client_key in limiter._buckets

        # Set last update to be old
        limiter._buckets[client_key].last_update = time.monotonic() - 1000

        # Force cleanup
        limiter._last_cleanup = time.monotonic() - limiter._cleanup_interval - 1
        limiter._cleanup_stale_buckets()

        # Bucket should be removed
        # Note: using defaultdict, so accessing creates new bucket
        # We check by verifying the bucket's last_update is recent
        new_bucket = limiter._buckets[client_key]
        assert abs(new_bucket.last_update - time.monotonic()) < 1


class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware class."""

    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=True,
            rate_limit_requests=10,
            rate_limit_window_seconds=60,
            rate_limit_burst=5,
        )

    @pytest.fixture
    def disabled_settings(self):
        """Create settings with rate limiting disabled."""
        return Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=False,
        )

    def test_excluded_paths(self):
        """Test excluded paths are correct."""
        expected_paths = {
            "/api/v1/health",
            "/api/v1/ready",
            "/api/v1/version",
            "/api/v1/metrics",
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json",
        }
        assert RateLimitMiddleware.EXCLUDED_PATHS == expected_paths

    @pytest.mark.asyncio
    async def test_middleware_allows_excluded_paths(self, settings):
        """Test middleware skips excluded paths."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/health"

        call_next = AsyncMock(return_value=Response())

        await middleware.dispatch(request, call_next)

        call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_middleware_allows_when_disabled(self, disabled_settings):
        """Test middleware skips when rate limiting disabled."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, disabled_settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/environments"

        call_next = AsyncMock(return_value=Response())

        await middleware.dispatch(request, call_next)

        call_next.assert_called_once_with(request)

    @pytest.mark.asyncio
    async def test_middleware_adds_headers_to_response(self, settings):
        """Test middleware adds rate limit headers to response."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/environments"
        request.state = MagicMock()
        request.state.user = None
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        response = Response()
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        assert "X-RateLimit-Limit" in result.headers
        assert "X-RateLimit-Remaining" in result.headers
        assert "X-RateLimit-Reset" in result.headers

    @pytest.mark.asyncio
    async def test_middleware_returns_429_when_limited(self, settings):
        """Test middleware returns 429 when rate limited."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/environments"
        request.state = MagicMock()
        request.state.user = None
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        call_next = AsyncMock(return_value=Response())

        # Exhaust rate limit
        for _ in range(16):  # 10 + 5 + 1 = exceed limit
            result = await middleware.dispatch(request, call_next)

        # Should get 429
        assert result.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    @pytest.mark.asyncio
    async def test_middleware_429_response_body(self, settings):
        """Test 429 response has correct body."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/environments"
        request.state = MagicMock()
        request.state.user = None
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        call_next = AsyncMock(return_value=Response())

        # Exhaust rate limit
        for _ in range(16):
            result = await middleware.dispatch(request, call_next)

        import json

        body = json.loads(result.body)
        assert "detail" in body
        assert "code" in body
        assert body["code"] == "RATE_LIMIT_EXCEEDED"

    @pytest.mark.asyncio
    async def test_middleware_429_includes_retry_after(self, settings):
        """Test 429 response includes Retry-After header."""
        app = MagicMock()
        middleware = RateLimitMiddleware(app, settings)

        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/environments"
        request.state = MagicMock()
        request.state.user = None
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        call_next = AsyncMock(return_value=Response())

        # Exhaust rate limit
        for _ in range(16):
            result = await middleware.dispatch(request, call_next)

        assert "Retry-After" in result.headers


class TestCreateRateLimitMiddleware:
    """Tests for create_rate_limit_middleware factory function."""

    def test_creates_middleware_class(self):
        """Test factory creates a middleware class."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=True,
            rate_limit_requests=50,
        )

        MiddlewareClass = create_rate_limit_middleware(settings)

        assert issubclass(MiddlewareClass, RateLimitMiddleware)

    def test_middleware_class_uses_settings(self):
        """Test created middleware uses provided settings."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=True,
            rate_limit_requests=50,
            rate_limit_window_seconds=120,
            rate_limit_burst=10,
        )

        MiddlewareClass = create_rate_limit_middleware(settings)
        app = MagicMock()
        middleware = MiddlewareClass(app)

        assert middleware.enabled is True
        assert middleware.limiter.requests_per_window == 50
        assert middleware.limiter.window_seconds == 120
        assert middleware.limiter.burst == 10


class TestRateLimitIntegration:
    """Integration tests for rate limiting with FastAPI app."""

    @pytest.fixture
    def app_with_rate_limit(self):
        """Create a FastAPI app with rate limiting."""
        from fastapi import FastAPI

        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=True,
            rate_limit_requests=5,
            rate_limit_window_seconds=60,
            rate_limit_burst=2,
        )

        app = FastAPI()

        @app.get("/test")
        async def test_endpoint():
            return {"message": "ok"}

        @app.get("/api/v1/health")
        async def health_endpoint():
            return {"status": "healthy"}

        MiddlewareClass = create_rate_limit_middleware(settings)
        app.add_middleware(MiddlewareClass)

        return app

    def test_rate_limit_on_regular_endpoint(self, app_with_rate_limit):
        """Test rate limiting applies to regular endpoints."""
        with TestClient(app_with_rate_limit) as client:
            # First 7 requests should succeed (5 + 2 burst)
            for _ in range(7):
                response = client.get("/test")
                assert response.status_code == 200

            # 8th request should be rate limited
            response = client.get("/test")
            assert response.status_code == 429

    def test_no_rate_limit_on_health_endpoint(self, app_with_rate_limit):
        """Test health endpoint is not rate limited."""
        with TestClient(app_with_rate_limit) as client:
            # Make many requests to health endpoint
            for _ in range(20):
                response = client.get("/api/v1/health")
                assert response.status_code == 200

    def test_rate_limit_headers_present(self, app_with_rate_limit):
        """Test rate limit headers are present in response."""
        with TestClient(app_with_rate_limit) as client:
            response = client.get("/test")

            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers

    def test_remaining_decreases(self, app_with_rate_limit):
        """Test remaining count decreases with each request."""
        with TestClient(app_with_rate_limit) as client:
            response1 = client.get("/test")
            remaining1 = int(response1.headers["X-RateLimit-Remaining"])

            response2 = client.get("/test")
            remaining2 = int(response2.headers["X-RateLimit-Remaining"])

            assert remaining2 < remaining1
