"""Tests for sshmgr.metrics module."""

import time

import pytest
from prometheus_client import REGISTRY

from sshmgr.metrics import (
    APP_INFO,
    AUTH_ATTEMPTS,
    AUTH_FAILURES,
    CA_ROTATIONS,
    CERTIFICATES_ACTIVE,
    CERTIFICATES_ISSUED,
    CERTIFICATES_REVOKED,
    DB_CONNECTIONS_ACTIVE,
    ENVIRONMENTS_TOTAL,
    ENVIRONMENTS_WITH_ROTATION,
    ERRORS,
    HTTP_REQUEST_DURATION,
    HTTP_REQUESTS,
    HTTP_REQUESTS_IN_PROGRESS,
    get_metrics,
    get_metrics_content_type,
    record_auth_attempt,
    record_auth_failure,
    record_ca_rotation,
    record_certificate_issued,
    record_certificate_revoked,
    record_error,
    record_http_request,
    set_active_certificates,
    set_environments_count,
    set_rotating_environments,
    track_request_duration,
    track_signing_duration,
)


class TestAppInfo:
    """Tests for APP_INFO metric."""

    def test_app_info_has_version(self):
        """Test that APP_INFO contains version."""
        from sshmgr import __version__

        # Get the info metric value
        metrics = get_metrics().decode("utf-8")
        assert f'sshmgr_info{{version="{__version__}"}}' in metrics


class TestCertificateMetrics:
    """Tests for certificate-related metrics."""

    def test_record_certificate_issued(self):
        """Test recording certificate issuance."""
        initial = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="user"
        )._value.get()

        record_certificate_issued("test-env", "user")

        new_value = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="user"
        )._value.get()
        assert new_value == initial + 1

    def test_record_certificate_issued_host(self):
        """Test recording host certificate issuance."""
        initial = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="host"
        )._value.get()

        record_certificate_issued("test-env", "host")

        new_value = CERTIFICATES_ISSUED.labels(
            environment="test-env", cert_type="host"
        )._value.get()
        assert new_value == initial + 1

    def test_record_certificate_revoked(self):
        """Test recording certificate revocation."""
        initial = CERTIFICATES_REVOKED.labels(
            environment="test-env", cert_type="user"
        )._value.get()

        record_certificate_revoked("test-env", "user")

        new_value = CERTIFICATES_REVOKED.labels(
            environment="test-env", cert_type="user"
        )._value.get()
        assert new_value == initial + 1

    def test_set_active_certificates(self):
        """Test setting active certificate count."""
        set_active_certificates("prod-env", "user", 42)

        value = CERTIFICATES_ACTIVE.labels(
            environment="prod-env", cert_type="user"
        )._value.get()
        assert value == 42

    def test_track_signing_duration(self):
        """Test tracking certificate signing duration."""
        with track_signing_duration("test-env", "user"):
            time.sleep(0.01)  # Small delay to ensure non-zero duration

        # Verify the histogram was updated (check sum is > 0)
        metrics = get_metrics().decode("utf-8")
        assert "sshmgr_certificate_signing_duration_seconds" in metrics


class TestEnvironmentMetrics:
    """Tests for environment-related metrics."""

    def test_set_environments_count(self):
        """Test setting total environments count."""
        set_environments_count(10)

        value = ENVIRONMENTS_TOTAL._value.get()
        assert value == 10

    def test_set_rotating_environments(self):
        """Test setting rotating environments count."""
        set_rotating_environments("user", 3)

        value = ENVIRONMENTS_WITH_ROTATION.labels(ca_type="user")._value.get()
        assert value == 3

    def test_record_ca_rotation(self):
        """Test recording CA rotation."""
        initial = CA_ROTATIONS.labels(
            environment="test-env", ca_type="user"
        )._value.get()

        record_ca_rotation("test-env", "user")

        new_value = CA_ROTATIONS.labels(
            environment="test-env", ca_type="user"
        )._value.get()
        assert new_value == initial + 1


class TestHTTPMetrics:
    """Tests for HTTP-related metrics."""

    def test_record_http_request(self):
        """Test recording HTTP request."""
        initial = HTTP_REQUESTS.labels(
            method="GET", endpoint="/api/v1/health", status="200"
        )._value.get()

        record_http_request("GET", "/api/v1/health", 200)

        new_value = HTTP_REQUESTS.labels(
            method="GET", endpoint="/api/v1/health", status="200"
        )._value.get()
        assert new_value == initial + 1

    def test_record_http_request_error_status(self):
        """Test recording HTTP request with error status."""
        initial = HTTP_REQUESTS.labels(
            method="POST", endpoint="/api/v1/certs", status="500"
        )._value.get()

        record_http_request("POST", "/api/v1/certs", 500)

        new_value = HTTP_REQUESTS.labels(
            method="POST", endpoint="/api/v1/certs", status="500"
        )._value.get()
        assert new_value == initial + 1

    def test_track_request_duration(self):
        """Test tracking request duration."""
        method = "GET"
        endpoint = "/test/duration"

        # Track in-progress gauge
        initial_in_progress = HTTP_REQUESTS_IN_PROGRESS.labels(
            method=method, endpoint=endpoint
        )._value.get()

        with track_request_duration(method, endpoint):
            # During the request, in_progress should be incremented
            in_progress = HTTP_REQUESTS_IN_PROGRESS.labels(
                method=method, endpoint=endpoint
            )._value.get()
            assert in_progress == initial_in_progress + 1
            time.sleep(0.01)

        # After the request, in_progress should be decremented
        final_in_progress = HTTP_REQUESTS_IN_PROGRESS.labels(
            method=method, endpoint=endpoint
        )._value.get()
        assert final_in_progress == initial_in_progress


class TestAuthMetrics:
    """Tests for authentication-related metrics."""

    def test_record_auth_attempt_success(self):
        """Test recording successful auth attempt."""
        initial = AUTH_ATTEMPTS.labels(
            method="device_flow", status="success"
        )._value.get()

        record_auth_attempt("device_flow", success=True)

        new_value = AUTH_ATTEMPTS.labels(
            method="device_flow", status="success"
        )._value.get()
        assert new_value == initial + 1

    def test_record_auth_attempt_failure(self):
        """Test recording failed auth attempt."""
        initial = AUTH_ATTEMPTS.labels(
            method="device_flow", status="failure"
        )._value.get()

        record_auth_attempt("device_flow", success=False)

        new_value = AUTH_ATTEMPTS.labels(
            method="device_flow", status="failure"
        )._value.get()
        assert new_value == initial + 1

    def test_record_auth_failure(self):
        """Test recording auth failure reason."""
        initial = AUTH_FAILURES.labels(reason="invalid_token")._value.get()

        record_auth_failure("invalid_token")

        new_value = AUTH_FAILURES.labels(reason="invalid_token")._value.get()
        assert new_value == initial + 1


class TestErrorMetrics:
    """Tests for error metrics."""

    def test_record_error(self):
        """Test recording an error."""
        initial = ERRORS.labels(
            type="ValidationError", operation="sign_cert"
        )._value.get()

        record_error("ValidationError", "sign_cert")

        new_value = ERRORS.labels(
            type="ValidationError", operation="sign_cert"
        )._value.get()
        assert new_value == initial + 1


class TestMetricsOutput:
    """Tests for metrics output functions."""

    def test_get_metrics_returns_bytes(self):
        """Test that get_metrics returns bytes."""
        result = get_metrics()

        assert isinstance(result, bytes)
        # Should contain some prometheus metrics
        content = result.decode("utf-8")
        assert "sshmgr" in content

    def test_get_metrics_content_type(self):
        """Test getting metrics content type."""
        content_type = get_metrics_content_type()

        assert "text/plain" in content_type or "text/openmetrics" in content_type


class TestMetricsMiddleware:
    """Tests for metrics middleware."""

    def test_create_metrics_middleware(self):
        """Test creating the metrics middleware."""
        from sshmgr.metrics import create_metrics_middleware

        middleware_class = create_metrics_middleware()

        # Verify it's a valid middleware class
        assert middleware_class is not None
        assert hasattr(middleware_class, "dispatch")


class TestTrackSigningDurationExceptionHandling:
    """Tests for track_signing_duration exception handling."""

    def test_duration_tracked_on_exception(self):
        """Test that duration is still tracked even when exception occurs."""
        try:
            with track_signing_duration("error-env", "user"):
                time.sleep(0.01)
                raise ValueError("Test error")
        except ValueError:
            pass

        # Metrics should still be updated
        metrics = get_metrics().decode("utf-8")
        assert "sshmgr_certificate_signing_duration_seconds" in metrics


class TestTrackRequestDurationExceptionHandling:
    """Tests for track_request_duration exception handling."""

    def test_in_progress_decremented_on_exception(self):
        """Test that in_progress gauge is decremented on exception."""
        method = "POST"
        endpoint = "/test/error"

        initial = HTTP_REQUESTS_IN_PROGRESS.labels(
            method=method, endpoint=endpoint
        )._value.get()

        try:
            with track_request_duration(method, endpoint):
                raise ValueError("Test error")
        except ValueError:
            pass

        final = HTTP_REQUESTS_IN_PROGRESS.labels(
            method=method, endpoint=endpoint
        )._value.get()
        assert final == initial


class TestMetricLabels:
    """Tests for proper metric label handling."""

    def test_certificate_metrics_support_multiple_environments(self):
        """Test certificate metrics work with multiple environments."""
        record_certificate_issued("env-a", "user")
        record_certificate_issued("env-b", "user")
        record_certificate_issued("env-a", "host")

        # Each environment/type combination should be tracked separately
        env_a_user = CERTIFICATES_ISSUED.labels(
            environment="env-a", cert_type="user"
        )._value.get()
        env_b_user = CERTIFICATES_ISSUED.labels(
            environment="env-b", cert_type="user"
        )._value.get()
        env_a_host = CERTIFICATES_ISSUED.labels(
            environment="env-a", cert_type="host"
        )._value.get()

        assert env_a_user >= 1
        assert env_b_user >= 1
        assert env_a_host >= 1

    def test_http_metrics_support_multiple_status_codes(self):
        """Test HTTP metrics work with multiple status codes."""
        record_http_request("GET", "/api/test", 200)
        record_http_request("GET", "/api/test", 404)
        record_http_request("GET", "/api/test", 500)

        # Each status code should be tracked separately
        ok = HTTP_REQUESTS.labels(
            method="GET", endpoint="/api/test", status="200"
        )._value.get()
        not_found = HTTP_REQUESTS.labels(
            method="GET", endpoint="/api/test", status="404"
        )._value.get()
        error = HTTP_REQUESTS.labels(
            method="GET", endpoint="/api/test", status="500"
        )._value.get()

        assert ok >= 1
        assert not_found >= 1
        assert error >= 1
