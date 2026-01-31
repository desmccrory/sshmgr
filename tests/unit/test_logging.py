"""Tests for sshmgr.logging module."""

import json
import logging
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

import pytest

from sshmgr.logging import (
    AuditAction,
    AuditLogger,
    JSONFormatter,
    StructuredLogger,
    TextFormatter,
    get_audit_logger,
    get_logger,
    setup_logging,
)


class TestAuditAction:
    """Tests for AuditAction enum."""

    def test_auth_actions(self):
        """Test authentication action values."""
        assert AuditAction.LOGIN.value == "auth.login"
        assert AuditAction.LOGOUT.value == "auth.logout"
        assert AuditAction.TOKEN_REFRESH.value == "auth.token_refresh"

    def test_env_actions(self):
        """Test environment action values."""
        assert AuditAction.ENV_CREATE.value == "environment.create"
        assert AuditAction.ENV_DELETE.value == "environment.delete"
        assert AuditAction.ENV_UPDATE.value == "environment.update"

    def test_cert_actions(self):
        """Test certificate action values."""
        assert AuditAction.CERT_SIGN_USER.value == "certificate.sign_user"
        assert AuditAction.CERT_SIGN_HOST.value == "certificate.sign_host"
        assert AuditAction.CERT_REVOKE.value == "certificate.revoke"

    def test_ca_actions(self):
        """Test CA action values."""
        assert AuditAction.CA_ROTATE.value == "ca.rotate"
        assert AuditAction.CA_CLEANUP.value == "ca.cleanup"


class TestJSONFormatter:
    """Tests for JSONFormatter."""

    def test_basic_format(self):
        """Test basic JSON formatting."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "Test message"
        assert "timestamp" in data

    def test_format_with_extra(self):
        """Test JSON formatting with extra fields."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.extra = {"user": "alice", "action": "login"}

        result = formatter.format(record)
        data = json.loads(result)

        assert data["user"] == "alice"
        assert data["action"] == "login"

    def test_format_with_exception(self):
        """Test JSON formatting with exception info."""
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)
        data = json.loads(result)

        assert "exception" in data
        assert "ValueError" in data["exception"]
        assert "test error" in data["exception"]

    def test_debug_level_includes_location(self):
        """Test that debug level includes file location."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="myfile.py",
            lineno=42,
            msg="Debug message",
            args=(),
            exc_info=None,
        )
        record.filename = "myfile.py"
        record.funcName = "test_function"

        result = formatter.format(record)
        data = json.loads(result)

        assert "location" in data
        assert data["location"]["file"] == "myfile.py"
        assert data["location"]["line"] == 42
        assert data["location"]["function"] == "test_function"


class TestTextFormatter:
    """Tests for TextFormatter."""

    def test_basic_format(self):
        """Test basic text formatting."""
        formatter = TextFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        assert "INFO" in result
        assert "[test.logger]" in result
        assert "Test message" in result

    def test_format_with_extra(self):
        """Test text formatting with extra fields."""
        formatter = TextFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.extra = {"user": "alice", "action": "login"}

        result = formatter.format(record)

        assert "user=alice" in result
        assert "action=login" in result
        assert "|" in result

    def test_format_with_exception(self):
        """Test text formatting with exception info."""
        formatter = TextFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)

        assert "ValueError" in result
        assert "test error" in result


class TestStructuredLogger:
    """Tests for StructuredLogger."""

    def test_basic_logging(self):
        """Test basic structured logging."""
        base_logger = logging.getLogger("test.structured")
        base_logger.setLevel(logging.DEBUG)
        logger = StructuredLogger(base_logger, {})

        # StructuredLogger uses LoggerAdapter which calls logger._log
        # Just verify it doesn't raise and processes correctly
        msg, kwargs = logger.process("Test message", {})
        assert msg == "Test message"
        assert "extra" in kwargs

    def test_with_context(self):
        """Test creating logger with additional context."""
        base_logger = logging.getLogger("test.context")
        logger = StructuredLogger(base_logger, {"request_id": "123"})

        new_logger = logger.with_context(user="alice")

        assert new_logger.extra["request_id"] == "123"
        assert new_logger.extra["user"] == "alice"

    def test_context_override(self):
        """Test that with_context can override existing context."""
        base_logger = logging.getLogger("test.override")
        logger = StructuredLogger(base_logger, {"user": "bob"})

        new_logger = logger.with_context(user="alice")

        assert new_logger.extra["user"] == "alice"


class TestAuditLogger:
    """Tests for AuditLogger."""

    @pytest.fixture
    def audit_logger(self):
        """Create an audit logger with a test logger."""
        test_logger = logging.getLogger("test.audit")
        test_logger.setLevel(logging.DEBUG)
        return AuditLogger(test_logger)

    def test_log_success(self, audit_logger):
        """Test logging a successful action."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.log(
                action=AuditAction.LOGIN,
                actor="alice",
                success=True,
            )

            mock_log.assert_called_once()
            call_args = mock_log.call_args
            assert call_args[0][0] == logging.INFO
            assert "auth.login" in call_args[0][1]
            assert "succeeded" in call_args[0][1]

    def test_log_failure(self, audit_logger):
        """Test logging a failed action."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.log(
                action=AuditAction.LOGIN,
                actor="alice",
                success=False,
                error="Invalid credentials",
            )

            mock_log.assert_called_once()
            call_args = mock_log.call_args
            assert call_args[0][0] == logging.WARNING
            assert "failed" in call_args[0][1]

    def test_log_with_resource(self, audit_logger):
        """Test logging with resource information."""
        env_id = uuid4()

        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.log(
                action=AuditAction.ENV_CREATE,
                actor="admin",
                resource_type="environment",
                resource_id=env_id,
                environment="production",
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["resource_type"] == "environment"
            assert extra_data["resource_id"] == str(env_id)
            assert extra_data["environment"] == "production"

    def test_cert_signed(self, audit_logger):
        """Test certificate signing audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.cert_signed(
                actor="operator",
                environment="prod",
                cert_type="user",
                key_id="alice@example.com",
                serial=12345,
                principals=["alice", "admin"],
                validity_seconds=28800,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "certificate.sign_user"
            assert extra_data["details"]["key_id"] == "alice@example.com"
            assert extra_data["details"]["principals"] == ["alice", "admin"]
            assert extra_data["details"]["validity_seconds"] == 28800
            # Serial is stored as resource_id, not in details
            assert extra_data["resource_id"] == "12345"

    def test_cert_signed_host(self, audit_logger):
        """Test host certificate signing audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.cert_signed(
                actor="operator",
                environment="prod",
                cert_type="host",
                key_id="server1.example.com",
                serial=12346,
                principals=["server1.example.com", "10.0.0.5"],
                validity_seconds=7776000,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "certificate.sign_host"

    def test_cert_revoked(self, audit_logger):
        """Test certificate revocation audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.cert_revoked(
                actor="admin",
                environment="prod",
                serial=12345,
                key_id="alice@example.com",
                reason="Key compromised",
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "certificate.revoke"
            assert extra_data["details"]["reason"] == "Key compromised"

    def test_env_created(self, audit_logger):
        """Test environment creation audit log."""
        env_id = uuid4()

        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.env_created(
                actor="admin",
                environment="new-env",
                env_id=env_id,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "environment.create"
            assert extra_data["resource_id"] == str(env_id)

    def test_env_deleted(self, audit_logger):
        """Test environment deletion audit log."""
        env_id = uuid4()

        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.env_deleted(
                actor="admin",
                environment="old-env",
                env_id=env_id,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "environment.delete"

    def test_ca_rotated(self, audit_logger):
        """Test CA rotation audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.ca_rotated(
                actor="admin",
                environment="prod",
                ca_type="user",
                old_fingerprint="SHA256:old123",
                new_fingerprint="SHA256:new456",
                grace_period_seconds=86400,
            )

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "ca.rotate"
            assert extra_data["details"]["ca_type"] == "user"
            assert extra_data["details"]["old_fingerprint"] == "SHA256:old123"
            assert extra_data["details"]["new_fingerprint"] == "SHA256:new456"

    def test_login(self, audit_logger):
        """Test login audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.login(actor="alice", method="device_flow")

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "auth.login"
            assert extra_data["details"]["method"] == "device_flow"

    def test_logout(self, audit_logger):
        """Test logout audit log."""
        with patch.object(audit_logger.logger, "log") as mock_log:
            audit_logger.logout(actor="alice")

            mock_log.assert_called_once()
            extra_data = mock_log.call_args[1]["extra"]["extra"]
            assert extra_data["action"] == "auth.logout"


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_json_logging(self):
        """Test setting up JSON logging."""
        logger = setup_logging(level="DEBUG", format="json", logger_name="test.json")

        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, JSONFormatter)

    def test_setup_text_logging(self):
        """Test setting up text logging."""
        logger = setup_logging(level="INFO", format="text", logger_name="test.text")

        assert logger.level == logging.INFO
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, TextFormatter)

    def test_setup_removes_existing_handlers(self):
        """Test that setup removes existing handlers."""
        logger_name = "test.handlers"
        logger = logging.getLogger(logger_name)
        logger.addHandler(logging.NullHandler())
        logger.addHandler(logging.NullHandler())

        result = setup_logging(level="INFO", format="text", logger_name=logger_name)

        assert len(result.handlers) == 1


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_with_prefix(self):
        """Test get_logger adds sshmgr prefix."""
        logger = get_logger("test")

        assert isinstance(logger, StructuredLogger)
        assert logger.logger.name == "sshmgr.test"

    def test_get_logger_without_prefix(self):
        """Test get_logger doesn't double-prefix."""
        logger = get_logger("sshmgr.api")

        assert logger.logger.name == "sshmgr.api"

    def test_get_logger_default(self):
        """Test get_logger with default name."""
        logger = get_logger()

        assert logger.logger.name == "sshmgr"


class TestGetAuditLogger:
    """Tests for get_audit_logger function."""

    def test_get_audit_logger(self):
        """Test getting the audit logger."""
        logger = get_audit_logger()

        assert isinstance(logger, AuditLogger)
        assert logger.logger.name == "sshmgr.audit"
