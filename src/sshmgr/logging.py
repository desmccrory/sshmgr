"""Structured logging with audit trail support."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from sshmgr.config import get_settings


class AuditAction(str, Enum):
    """Audit log action types."""

    # Authentication
    LOGIN = "auth.login"
    LOGOUT = "auth.logout"
    TOKEN_REFRESH = "auth.token_refresh"

    # Environment operations
    ENV_CREATE = "environment.create"
    ENV_DELETE = "environment.delete"
    ENV_UPDATE = "environment.update"

    # Certificate operations
    CERT_SIGN_USER = "certificate.sign_user"
    CERT_SIGN_HOST = "certificate.sign_host"
    CERT_REVOKE = "certificate.revoke"

    # CA operations
    CA_ROTATE = "ca.rotate"
    CA_CLEANUP = "ca.cleanup"


class JSONFormatter(logging.Formatter):
    """Format log records as JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add location info for debug
        if record.levelno <= logging.DEBUG:
            log_data["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """Format log records as human-readable text."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as text."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        level = record.levelname.ljust(8)
        message = record.getMessage()

        base = f"{timestamp} {level} [{record.name}] {message}"

        # Add extra fields
        if hasattr(record, "extra") and record.extra:
            extras = " ".join(f"{k}={v}" for k, v in record.extra.items())
            base = f"{base} | {extras}"

        # Add exception info if present
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"

        return base


class StructuredLogger(logging.LoggerAdapter):
    """Logger adapter that adds structured context."""

    def process(self, msg: str, kwargs: dict) -> tuple[str, dict]:
        """Add extra context to log records."""
        extra = kwargs.get("extra", {})
        extra.update(self.extra)
        kwargs["extra"] = extra

        # Store extra in record for formatters
        if "extra" not in kwargs:
            kwargs["extra"] = {}

        return msg, kwargs

    def with_context(self, **context) -> "StructuredLogger":
        """Create a new logger with additional context."""
        new_extra = {**self.extra, **context}
        return StructuredLogger(self.logger, new_extra)


class AuditLogger:
    """
    Audit logger for security-relevant operations.

    All audit logs are written at INFO level with structured data.
    """

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger("sshmgr.audit")

    def log(
        self,
        action: AuditAction,
        actor: str,
        resource_type: str | None = None,
        resource_id: str | UUID | None = None,
        environment: str | None = None,
        details: dict[str, Any] | None = None,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        """
        Log an audit event.

        Args:
            action: The action being performed
            actor: Who performed the action (username or system)
            resource_type: Type of resource (environment, certificate, etc.)
            resource_id: ID of the resource
            environment: Environment name if applicable
            details: Additional details about the action
            success: Whether the action succeeded
            error: Error message if action failed
        """
        audit_data = {
            "audit": True,
            "action": action.value,
            "actor": actor,
            "success": success,
        }

        if resource_type:
            audit_data["resource_type"] = resource_type
        if resource_id:
            audit_data["resource_id"] = str(resource_id)
        if environment:
            audit_data["environment"] = environment
        if details:
            audit_data["details"] = details
        if error:
            audit_data["error"] = error

        level = logging.INFO if success else logging.WARNING
        self.logger.log(
            level,
            f"{action.value}: {actor} {'succeeded' if success else 'failed'}",
            extra={"extra": audit_data},
        )

    def cert_signed(
        self,
        actor: str,
        environment: str,
        cert_type: str,
        key_id: str,
        serial: int,
        principals: list[str],
        validity_seconds: int,
    ) -> None:
        """Log certificate signing."""
        action = (
            AuditAction.CERT_SIGN_USER
            if cert_type == "user"
            else AuditAction.CERT_SIGN_HOST
        )
        self.log(
            action=action,
            actor=actor,
            resource_type="certificate",
            resource_id=str(serial),
            environment=environment,
            details={
                "cert_type": cert_type,
                "key_id": key_id,
                "principals": principals,
                "validity_seconds": validity_seconds,
            },
        )

    def cert_revoked(
        self,
        actor: str,
        environment: str,
        serial: int,
        key_id: str,
        reason: str | None = None,
    ) -> None:
        """Log certificate revocation."""
        self.log(
            action=AuditAction.CERT_REVOKE,
            actor=actor,
            resource_type="certificate",
            resource_id=str(serial),
            environment=environment,
            details={
                "key_id": key_id,
                "reason": reason,
            },
        )

    def env_created(
        self,
        actor: str,
        environment: str,
        env_id: UUID,
    ) -> None:
        """Log environment creation."""
        self.log(
            action=AuditAction.ENV_CREATE,
            actor=actor,
            resource_type="environment",
            resource_id=env_id,
            environment=environment,
        )

    def env_deleted(
        self,
        actor: str,
        environment: str,
        env_id: UUID,
    ) -> None:
        """Log environment deletion."""
        self.log(
            action=AuditAction.ENV_DELETE,
            actor=actor,
            resource_type="environment",
            resource_id=env_id,
            environment=environment,
        )

    def ca_rotated(
        self,
        actor: str,
        environment: str,
        ca_type: str,
        old_fingerprint: str,
        new_fingerprint: str,
        grace_period_seconds: int,
    ) -> None:
        """Log CA rotation."""
        self.log(
            action=AuditAction.CA_ROTATE,
            actor=actor,
            resource_type="ca",
            environment=environment,
            details={
                "ca_type": ca_type,
                "old_fingerprint": old_fingerprint,
                "new_fingerprint": new_fingerprint,
                "grace_period_seconds": grace_period_seconds,
            },
        )

    def login(self, actor: str, method: str = "device_flow") -> None:
        """Log user login."""
        self.log(
            action=AuditAction.LOGIN,
            actor=actor,
            details={"method": method},
        )

    def logout(self, actor: str) -> None:
        """Log user logout."""
        self.log(
            action=AuditAction.LOGOUT,
            actor=actor,
        )


def setup_logging(
    level: str = "INFO",
    format: str = "text",
    logger_name: str = "sshmgr",
) -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format ("text" or "json")
        logger_name: Name of the root logger

    Returns:
        Configured logger
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))

    # Set formatter based on format
    if format.lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(TextFormatter())

    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str = "sshmgr") -> StructuredLogger:
    """
    Get a structured logger.

    Args:
        name: Logger name (will be prefixed with "sshmgr.")

    Returns:
        StructuredLogger instance
    """
    if not name.startswith("sshmgr"):
        name = f"sshmgr.{name}"

    logger = logging.getLogger(name)
    return StructuredLogger(logger, {})


def get_audit_logger() -> AuditLogger:
    """Get the audit logger."""
    return AuditLogger()


# Initialize logging on module load
_initialized = False


def init_logging() -> None:
    """Initialize logging from settings."""
    global _initialized
    if _initialized:
        return

    settings = get_settings()
    setup_logging(
        level=settings.log_level,
        format=settings.log_format,
    )
    _initialized = True
