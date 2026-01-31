"""SQLAlchemy ORM models for sshmgr."""

import json
from datetime import datetime, timedelta
from enum import Enum as PyEnum
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Interval,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sshmgr.storage.database import Base


class StringArray(TypeDecorator):
    """
    A portable array type that uses PostgreSQL ARRAY for PostgreSQL
    and JSON text for other databases (like SQLite).
    """

    impl = Text
    cache_ok = True

    def __init__(self, item_length: int = 255):
        super().__init__()
        self.item_length = item_length

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(ARRAY(String(self.item_length)))
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value
        return json.loads(value)


class CertType(str, PyEnum):
    """Certificate type enumeration."""

    USER = "user"
    HOST = "host"


class Environment(Base):
    """
    Represents a customer environment with its own CA keypairs.

    Each environment has separate user and host CAs for multi-tenant isolation.
    """

    __tablename__ = "environments"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # User CA
    user_ca_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    user_ca_key_ref: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Reference to encrypted private key (encrypted:... or vault:...)",
    )

    # Host CA
    host_ca_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    host_ca_key_ref: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Reference to encrypted private key",
    )

    # Default validity periods
    default_user_cert_validity: Mapped[timedelta] = mapped_column(
        Interval,
        nullable=False,
        default=timedelta(hours=8),
    )
    default_host_cert_validity: Mapped[timedelta] = mapped_column(
        Interval,
        nullable=False,
        default=timedelta(days=90),
    )

    # Rotation support - old CA kept during grace period
    old_user_ca_public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_user_ca_key_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_user_ca_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    old_host_ca_public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_host_ca_key_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    old_host_ca_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    certificates: Mapped[List["Certificate"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
    )
    policies: Mapped[List["Policy"]] = relationship(
        back_populates="environment",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Environment(name={self.name!r}, id={self.id})>"


class Certificate(Base):
    """
    Audit log entry for an issued certificate.

    Stores metadata about certificates, not the certificates themselves.
    Used for tracking, auditing, and revocation.
    """

    __tablename__ = "certificates"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    environment_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("environments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    cert_type: Mapped[CertType] = mapped_column(
        Enum(CertType, name="cert_type"),
        nullable=False,
    )
    serial: Mapped[int] = mapped_column(Integer, nullable=False)
    key_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Identifier embedded in the certificate (e.g., email)",
    )

    # Principals stored as array (PostgreSQL) or JSON (SQLite)
    principals: Mapped[List[str]] = mapped_column(
        StringArray(255),
        nullable=False,
    )

    # Validity period
    valid_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    valid_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Public key fingerprint for identification
    public_key_fingerprint: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="SHA256 fingerprint of the signed public key",
    )

    # Audit fields
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    issued_by: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Identity of the requester (from JWT)",
    )

    # Revocation
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    revocation_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationship
    environment: Mapped["Environment"] = relationship(back_populates="certificates")

    __table_args__ = (
        UniqueConstraint("environment_id", "serial", name="uq_environment_serial"),
    )

    def __repr__(self) -> str:
        return f"<Certificate(key_id={self.key_id!r}, serial={self.serial}, type={self.cert_type.value})>"

    @property
    def is_revoked(self) -> bool:
        """Check if the certificate has been revoked."""
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        return datetime.now(self.valid_before.tzinfo) > self.valid_before

    @property
    def is_valid(self) -> bool:
        """Check if the certificate is currently valid (not revoked or expired)."""
        now = datetime.now(self.valid_before.tzinfo)
        return (
            not self.is_revoked
            and self.valid_after <= now <= self.valid_before
        )


class Policy(Base):
    """
    Certificate issuance policy for an environment.

    Policies control what certificates can be issued, including
    allowed principals, maximum validity, and required extensions.
    """

    __tablename__ = "policies"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    environment_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("environments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    cert_type: Mapped[CertType] = mapped_column(
        Enum(CertType, name="cert_type", create_constraint=False),
        nullable=False,
    )

    # Allowed principals (patterns or exact matches)
    allowed_principals: Mapped[List[str]] = mapped_column(
        StringArray(255),
        nullable=False,
        comment="List of allowed principal patterns (supports wildcards)",
    )

    # Maximum validity period
    max_validity: Mapped[timedelta] = mapped_column(
        Interval,
        nullable=False,
    )

    # Extensions (stored as key=value pairs)
    # For user certs: permit-pty, permit-port-forwarding, etc.
    extensions: Mapped[Optional[List[str]]] = mapped_column(
        StringArray(255),
        nullable=True,
        comment="Certificate extensions in key=value format",
    )

    # Force command (for restricted access)
    force_command: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Command to force when certificate is used",
    )

    # Source IP restrictions
    source_addresses: Mapped[Optional[List[str]]] = mapped_column(
        StringArray(50),
        nullable=True,
        comment="Allowed source IP addresses/CIDRs",
    )

    # Status
    is_active: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationship
    environment: Mapped["Environment"] = relationship(back_populates="policies")

    __table_args__ = (
        UniqueConstraint("environment_id", "name", name="uq_environment_policy_name"),
    )

    def __repr__(self) -> str:
        return f"<Policy(name={self.name!r}, type={self.cert_type.value})>"
