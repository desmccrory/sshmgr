"""Prometheus metrics for sshmgr."""

from __future__ import annotations

import time
from contextlib import contextmanager
from functools import wraps
from typing import Callable, Generator

from prometheus_client import Counter, Gauge, Histogram, Info, generate_latest, CONTENT_TYPE_LATEST

from sshmgr import __version__

# -----------------------------------------------------------------------------
# Application Info
# -----------------------------------------------------------------------------

APP_INFO = Info(
    "sshmgr",
    "SSH Certificate Manager information",
)
APP_INFO.info({
    "version": __version__,
})

# -----------------------------------------------------------------------------
# Certificate Metrics
# -----------------------------------------------------------------------------

CERTIFICATES_ISSUED = Counter(
    "sshmgr_certificates_issued_total",
    "Total number of certificates issued",
    ["environment", "cert_type"],
)

CERTIFICATES_REVOKED = Counter(
    "sshmgr_certificates_revoked_total",
    "Total number of certificates revoked",
    ["environment", "cert_type"],
)

CERTIFICATES_ACTIVE = Gauge(
    "sshmgr_certificates_active",
    "Number of currently active (non-expired, non-revoked) certificates",
    ["environment", "cert_type"],
)

CERTIFICATE_SIGNING_DURATION = Histogram(
    "sshmgr_certificate_signing_duration_seconds",
    "Time spent signing certificates",
    ["environment", "cert_type"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# -----------------------------------------------------------------------------
# Environment Metrics
# -----------------------------------------------------------------------------

ENVIRONMENTS_TOTAL = Gauge(
    "sshmgr_environments_total",
    "Total number of environments",
)

ENVIRONMENTS_WITH_ROTATION = Gauge(
    "sshmgr_environments_rotating_total",
    "Number of environments with CA rotation in progress",
    ["ca_type"],
)

CA_ROTATIONS = Counter(
    "sshmgr_ca_rotations_total",
    "Total number of CA rotations performed",
    ["environment", "ca_type"],
)

# -----------------------------------------------------------------------------
# API Metrics
# -----------------------------------------------------------------------------

HTTP_REQUESTS = Counter(
    "sshmgr_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "sshmgr_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "sshmgr_http_requests_in_progress",
    "Number of HTTP requests currently in progress",
    ["method", "endpoint"],
)

# -----------------------------------------------------------------------------
# Authentication Metrics
# -----------------------------------------------------------------------------

AUTH_ATTEMPTS = Counter(
    "sshmgr_auth_attempts_total",
    "Total authentication attempts",
    ["method", "status"],
)

AUTH_FAILURES = Counter(
    "sshmgr_auth_failures_total",
    "Total authentication failures",
    ["reason"],
)

# -----------------------------------------------------------------------------
# Database Metrics
# -----------------------------------------------------------------------------

DB_CONNECTIONS_ACTIVE = Gauge(
    "sshmgr_db_connections_active",
    "Number of active database connections",
)

DB_QUERY_DURATION = Histogram(
    "sshmgr_db_query_duration_seconds",
    "Database query duration",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)

# -----------------------------------------------------------------------------
# Error Metrics
# -----------------------------------------------------------------------------

ERRORS = Counter(
    "sshmgr_errors_total",
    "Total errors",
    ["type", "operation"],
)

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------


def get_metrics() -> bytes:
    """Generate Prometheus metrics output."""
    return generate_latest()


def get_metrics_content_type() -> str:
    """Get the content type for metrics response."""
    return CONTENT_TYPE_LATEST


@contextmanager
def track_request_duration(method: str, endpoint: str) -> Generator[None, None, None]:
    """Context manager to track request duration."""
    HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
    start_time = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start_time
        HTTP_REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)
        HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()


@contextmanager
def track_signing_duration(
    environment: str, cert_type: str
) -> Generator[None, None, None]:
    """Context manager to track certificate signing duration."""
    start_time = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start_time
        CERTIFICATE_SIGNING_DURATION.labels(
            environment=environment, cert_type=cert_type
        ).observe(duration)


def record_certificate_issued(environment: str, cert_type: str) -> None:
    """Record that a certificate was issued."""
    CERTIFICATES_ISSUED.labels(environment=environment, cert_type=cert_type).inc()


def record_certificate_revoked(environment: str, cert_type: str) -> None:
    """Record that a certificate was revoked."""
    CERTIFICATES_REVOKED.labels(environment=environment, cert_type=cert_type).inc()


def record_ca_rotation(environment: str, ca_type: str) -> None:
    """Record that a CA was rotated."""
    CA_ROTATIONS.labels(environment=environment, ca_type=ca_type).inc()


def record_http_request(method: str, endpoint: str, status: int) -> None:
    """Record an HTTP request."""
    HTTP_REQUESTS.labels(method=method, endpoint=endpoint, status=str(status)).inc()


def record_auth_attempt(method: str, success: bool) -> None:
    """Record an authentication attempt."""
    status = "success" if success else "failure"
    AUTH_ATTEMPTS.labels(method=method, status=status).inc()


def record_auth_failure(reason: str) -> None:
    """Record an authentication failure reason."""
    AUTH_FAILURES.labels(reason=reason).inc()


def record_error(error_type: str, operation: str) -> None:
    """Record an error."""
    ERRORS.labels(type=error_type, operation=operation).inc()


def set_environments_count(count: int) -> None:
    """Set the total number of environments."""
    ENVIRONMENTS_TOTAL.set(count)


def set_active_certificates(environment: str, cert_type: str, count: int) -> None:
    """Set the number of active certificates."""
    CERTIFICATES_ACTIVE.labels(environment=environment, cert_type=cert_type).set(count)


def set_rotating_environments(ca_type: str, count: int) -> None:
    """Set the number of environments with rotation in progress."""
    ENVIRONMENTS_WITH_ROTATION.labels(ca_type=ca_type).set(count)


# -----------------------------------------------------------------------------
# Middleware for FastAPI
# -----------------------------------------------------------------------------


def create_metrics_middleware():
    """Create FastAPI middleware for request metrics."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response

    class MetricsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next) -> Response:
            # Normalize endpoint for metrics (remove path params)
            path = request.url.path
            method = request.method

            # Skip metrics endpoint itself
            if path == "/metrics":
                return await call_next(request)

            # Track request
            with track_request_duration(method, path):
                response = await call_next(request)

            # Record request
            record_http_request(method, path, response.status_code)

            return response

    return MetricsMiddleware
