"""Pydantic schemas for API request/response models."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


# -----------------------------------------------------------------------------
# Common Types
# -----------------------------------------------------------------------------


class CertTypeEnum(str, Enum):
    """Certificate type."""

    USER = "user"
    HOST = "host"


class KeyTypeEnum(str, Enum):
    """SSH key type."""

    ED25519 = "ed25519"
    RSA = "rsa"
    ECDSA = "ecdsa"


# -----------------------------------------------------------------------------
# Environment Schemas
# -----------------------------------------------------------------------------


class EnvironmentCreate(BaseModel):
    """Request to create a new environment."""

    name: Annotated[
        str,
        Field(
            min_length=1,
            max_length=64,
            pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$",
            description="Environment name (lowercase alphanumeric with hyphens)",
            examples=["prod", "staging", "customer-prod"],
        ),
    ]
    key_type: KeyTypeEnum = Field(
        default=KeyTypeEnum.ED25519,
        description="Key type for CA keypairs",
    )
    default_user_cert_validity: str = Field(
        default="8h",
        description="Default validity for user certificates (e.g., 8h, 1d)",
        examples=["8h", "12h", "1d"],
    )
    default_host_cert_validity: str = Field(
        default="90d",
        description="Default validity for host certificates (e.g., 90d, 1y)",
        examples=["90d", "180d", "365d"],
    )


class EnvironmentResponse(BaseModel):
    """Environment details response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    user_ca_fingerprint: str
    host_ca_fingerprint: str
    default_user_cert_validity: str
    default_host_cert_validity: str
    created_at: datetime
    updated_at: datetime | None = None
    has_old_user_ca: bool = False
    has_old_host_ca: bool = False


class EnvironmentListResponse(BaseModel):
    """List of environments response."""

    environments: list[EnvironmentResponse]
    total: int


class CAPublicKeyResponse(BaseModel):
    """CA public key response."""

    environment: str
    ca_type: CertTypeEnum
    public_key: str
    fingerprint: str
    old_public_key: str | None = None
    old_fingerprint: str | None = None
    old_expires_at: datetime | None = None


# -----------------------------------------------------------------------------
# Certificate Schemas
# -----------------------------------------------------------------------------


class UserCertificateRequest(BaseModel):
    """Request to sign a user certificate."""

    public_key: Annotated[
        str,
        Field(
            description="User's SSH public key (OpenSSH format)",
            examples=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"],
        ),
    ]
    principals: Annotated[
        list[str],
        Field(
            min_length=1,
            description="List of usernames the certificate is valid for",
            examples=[["deploy", "admin"]],
        ),
    ]
    key_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=256,
            description="Key identifier (e.g., email address)",
            examples=["user@example.com"],
        ),
    ]
    validity: str | None = Field(
        default=None,
        description="Certificate validity (e.g., 8h, 1d). Uses environment default if not specified.",
        examples=["8h", "12h", "1d"],
    )
    force_command: str | None = Field(
        default=None,
        description="Force a specific command when certificate is used",
    )

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        """Validate SSH public key format."""
        v = v.strip()
        valid_prefixes = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-")
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(
                "Invalid SSH public key format. Must start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-"
            )
        return v


class HostCertificateRequest(BaseModel):
    """Request to sign a host certificate."""

    public_key: Annotated[
        str,
        Field(
            description="Host's SSH public key (OpenSSH format)",
            examples=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... root@server"],
        ),
    ]
    principals: Annotated[
        list[str],
        Field(
            min_length=1,
            description="List of hostnames/IPs the certificate is valid for",
            examples=[["server1.example.com", "10.0.0.5"]],
        ),
    ]
    validity: str | None = Field(
        default=None,
        description="Certificate validity (e.g., 90d, 1y). Uses environment default if not specified.",
        examples=["90d", "180d"],
    )

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        """Validate SSH public key format."""
        v = v.strip()
        valid_prefixes = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-")
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(
                "Invalid SSH public key format. Must start with ssh-ed25519, ssh-rsa, or ecdsa-sha2-"
            )
        return v


class CertificateResponse(BaseModel):
    """Signed certificate response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    serial: int
    cert_type: CertTypeEnum
    key_id: str
    principals: list[str]
    valid_after: datetime
    valid_before: datetime
    public_key_fingerprint: str
    certificate: str | None = None  # Only included when signing
    issued_at: datetime
    issued_by: str
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None


class CertificateListResponse(BaseModel):
    """List of certificates response."""

    certificates: list[CertificateResponse]
    total: int


class RevokeRequest(BaseModel):
    """Request to revoke a certificate."""

    reason: str | None = Field(
        default=None,
        max_length=500,
        description="Reason for revocation",
    )


# -----------------------------------------------------------------------------
# CA Rotation Schemas
# -----------------------------------------------------------------------------


class RotateCARequest(BaseModel):
    """Request to rotate a CA."""

    ca_type: CertTypeEnum = Field(description="Which CA to rotate (user or host)")
    grace_period: str = Field(
        default="24h",
        description="How long to keep the old CA valid",
        examples=["24h", "7d", "30d"],
    )
    key_type: KeyTypeEnum = Field(
        default=KeyTypeEnum.ED25519,
        description="Key type for the new CA",
    )


class RotationStatusResponse(BaseModel):
    """CA rotation status response."""

    environment: str
    user_ca: CARotationInfo
    host_ca: CARotationInfo


class CARotationInfo(BaseModel):
    """Rotation info for a single CA."""

    rotating: bool
    fingerprint: str
    old_fingerprint: str | None = None
    old_expires_at: datetime | None = None


# -----------------------------------------------------------------------------
# Health Check Schemas
# -----------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    """Readiness check response."""

    status: str
    database: str
    keycloak: str


# -----------------------------------------------------------------------------
# Error Schemas
# -----------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    code: str | None = None


class ValidationErrorResponse(BaseModel):
    """Validation error response."""

    detail: list[ValidationErrorItem]


class ValidationErrorItem(BaseModel):
    """Single validation error."""

    loc: list[str | int]
    msg: str
    type: str
