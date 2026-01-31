"""Unit tests for storage layer."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from sshmgr.storage.models import CertType, Certificate, Environment, Policy


class TestEnvironmentModel:
    """Tests for Environment model."""

    def test_create_environment(self):
        """Create an environment instance."""
        env = Environment(
            name="test-env",
            user_ca_public_key="ssh-ed25519 AAAA... user-ca",
            user_ca_key_ref="encrypted:abc123",
            host_ca_public_key="ssh-ed25519 AAAA... host-ca",
            host_ca_key_ref="encrypted:def456",
        )

        assert env.name == "test-env"
        assert env.user_ca_public_key.startswith("ssh-ed25519")
        assert env.user_ca_key_ref.startswith("encrypted:")

    def test_environment_default_validity(self):
        """Environment can have validity periods set."""
        # Note: SQLAlchemy defaults are applied at insert time, not at object creation
        # So we test with explicit values
        env = Environment(
            name="test",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
            default_user_cert_validity=timedelta(hours=8),
            default_host_cert_validity=timedelta(days=90),
        )

        assert env.default_user_cert_validity == timedelta(hours=8)
        assert env.default_host_cert_validity == timedelta(days=90)

    def test_environment_repr(self):
        """Environment has readable repr."""
        env = Environment(name="prod", user_ca_public_key="", user_ca_key_ref="",
                         host_ca_public_key="", host_ca_key_ref="")
        env.id = uuid4()

        assert "prod" in repr(env)


class TestCertificateModel:
    """Tests for Certificate model."""

    def test_create_certificate(self):
        """Create a certificate instance."""
        now = datetime.now(timezone.utc)
        cert = Certificate(
            environment_id=uuid4(),
            cert_type=CertType.USER,
            serial=1,
            key_id="user@example.com",
            principals=["user", "admin"],
            valid_after=now - timedelta(minutes=5),
            valid_before=now + timedelta(hours=8),
            public_key_fingerprint="SHA256:abc123",
            issued_by="admin@example.com",
        )

        assert cert.cert_type == CertType.USER
        assert cert.serial == 1
        assert len(cert.principals) == 2

    def test_certificate_is_valid(self):
        """Certificate validity check."""
        now = datetime.now(timezone.utc)
        cert = Certificate(
            environment_id=uuid4(),
            cert_type=CertType.USER,
            serial=1,
            key_id="test",
            principals=["user"],
            valid_after=now - timedelta(hours=1),
            valid_before=now + timedelta(hours=7),
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
        )

        assert cert.is_valid is True
        assert cert.is_expired is False
        assert cert.is_revoked is False

    def test_certificate_is_expired(self):
        """Expired certificate check."""
        now = datetime.now(timezone.utc)
        cert = Certificate(
            environment_id=uuid4(),
            cert_type=CertType.USER,
            serial=1,
            key_id="test",
            principals=["user"],
            valid_after=now - timedelta(hours=10),
            valid_before=now - timedelta(hours=2),  # Expired 2 hours ago
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
        )

        assert cert.is_expired is True
        assert cert.is_valid is False

    def test_certificate_is_revoked(self):
        """Revoked certificate check."""
        now = datetime.now(timezone.utc)
        cert = Certificate(
            environment_id=uuid4(),
            cert_type=CertType.HOST,
            serial=1,
            key_id="test",
            principals=["host"],
            valid_after=now - timedelta(hours=1),
            valid_before=now + timedelta(days=89),
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
            revoked_at=now,
            revoked_by="security@example.com",
            revocation_reason="Key compromised",
        )

        assert cert.is_revoked is True
        assert cert.is_valid is False

    def test_certificate_repr(self):
        """Certificate has readable repr."""
        cert = Certificate(
            environment_id=uuid4(),
            cert_type=CertType.USER,
            serial=42,
            key_id="test@example.com",
            principals=["user"],
            valid_after=datetime.now(timezone.utc),
            valid_before=datetime.now(timezone.utc),
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
        )

        repr_str = repr(cert)
        assert "test@example.com" in repr_str
        assert "42" in repr_str


class TestPolicyModel:
    """Tests for Policy model."""

    def test_create_policy(self):
        """Create a policy instance."""
        # Note: SQLAlchemy defaults are applied at insert time, not at object creation
        policy = Policy(
            environment_id=uuid4(),
            name="default-user-policy",
            cert_type=CertType.USER,
            allowed_principals=["deploy-*", "admin"],
            max_validity=timedelta(hours=12),
            extensions=["permit-pty", "permit-port-forwarding"],
            is_active=True,  # Explicitly set since we're not using DB
        )

        assert policy.name == "default-user-policy"
        assert policy.cert_type == CertType.USER
        assert len(policy.allowed_principals) == 2
        assert policy.is_active is True

    def test_policy_with_force_command(self):
        """Policy with force command."""
        policy = Policy(
            environment_id=uuid4(),
            name="restricted-policy",
            cert_type=CertType.USER,
            allowed_principals=["backup"],
            max_validity=timedelta(hours=1),
            force_command="/usr/local/bin/backup-only.sh",
        )

        assert policy.force_command is not None
        assert "backup" in policy.force_command

    def test_policy_with_source_addresses(self):
        """Policy with source IP restrictions."""
        policy = Policy(
            environment_id=uuid4(),
            name="office-only",
            cert_type=CertType.USER,
            allowed_principals=["*"],
            max_validity=timedelta(hours=8),
            source_addresses=["10.0.0.0/8", "192.168.1.0/24"],
        )

        assert len(policy.source_addresses) == 2

    def test_policy_repr(self):
        """Policy has readable repr."""
        policy = Policy(
            environment_id=uuid4(),
            name="my-policy",
            cert_type=CertType.HOST,
            allowed_principals=["*"],
            max_validity=timedelta(days=90),
        )

        repr_str = repr(policy)
        assert "my-policy" in repr_str
        assert "host" in repr_str


class TestCertTypeEnum:
    """Tests for CertType enum."""

    def test_user_cert_type(self):
        """User certificate type."""
        assert CertType.USER.value == "user"

    def test_host_cert_type(self):
        """Host certificate type."""
        assert CertType.HOST.value == "host"

    def test_cert_type_comparison(self):
        """CertType can be compared as string."""
        assert CertType.USER == "user"
        assert CertType.HOST == "host"
