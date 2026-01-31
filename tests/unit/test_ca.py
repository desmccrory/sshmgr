"""Unit tests for the Certificate Authority module."""

from datetime import timedelta

import pytest

from sshmgr.core.ca import (
    CertificateAuthority,
    CertificateType,
    KeyType,
    SignedCertificate,
)
from sshmgr.core.exceptions import InvalidKeyError, SigningError


class TestCertificateAuthorityGeneration:
    """Tests for CA key generation."""

    def test_generate_ed25519_ca(self):
        """Generate an Ed25519 CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        assert ca.private_key is not None
        assert ca.public_key.startswith("ssh-ed25519")
        assert ca.key_type == KeyType.ED25519

    def test_generate_rsa_ca(self):
        """Generate an RSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.RSA, bits=2048)

        assert ca.private_key is not None
        assert ca.public_key.startswith("ssh-rsa")
        assert ca.key_type == KeyType.RSA

    def test_generate_ecdsa_ca(self):
        """Generate an ECDSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.ECDSA)

        assert ca.private_key is not None
        assert ca.public_key.startswith("ecdsa-")
        assert ca.key_type == KeyType.ECDSA

    def test_ca_fingerprint(self, ca_ed25519):
        """CA should have a valid fingerprint."""
        fingerprint = ca_ed25519.fingerprint

        assert fingerprint.startswith("SHA256:")
        assert len(fingerprint) > 10


class TestCertificateAuthorityFromKey:
    """Tests for loading CA from existing key."""

    def test_load_from_private_key(self, ca_ed25519):
        """Load CA from existing private key."""
        loaded_ca = CertificateAuthority.from_private_key(ca_ed25519.private_key)

        assert loaded_ca.public_key == ca_ed25519.public_key
        assert loaded_ca.key_type == KeyType.ED25519

    def test_load_invalid_key(self):
        """Loading invalid key should raise error."""
        with pytest.raises(InvalidKeyError):
            CertificateAuthority.from_private_key(b"not a valid key")


class TestUserCertificateSigning:
    """Tests for signing user certificates."""

    def test_sign_user_certificate(self, ca_ed25519, sample_user_keypair):
        """Sign a user's public key."""
        cert = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser", "admin"],
            key_id="test@example.com",
            validity=timedelta(hours=8),
        )

        assert isinstance(cert, SignedCertificate)
        assert cert.cert_type == CertificateType.USER
        assert cert.key_id == "test@example.com"
        assert cert.principals == ["testuser", "admin"]
        assert "ssh-ed25519-cert-v01@openssh.com" in cert.certificate

    def test_sign_user_certificate_custom_validity(self, ca_ed25519, sample_user_keypair):
        """Sign with custom validity period."""
        cert = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser"],
            key_id="test@example.com",
            validity=timedelta(days=1),
        )

        # Certificate should be valid for ~24 hours
        duration = cert.valid_before - cert.valid_after
        assert timedelta(hours=23) < duration < timedelta(hours=25)

    def test_sign_user_certificate_serial(self, ca_ed25519, sample_user_keypair):
        """Serial numbers should increment."""
        cert1 = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser"],
            key_id="test1",
        )
        cert2 = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser"],
            key_id="test2",
        )

        assert cert2.serial == cert1.serial + 1

    def test_sign_user_certificate_explicit_serial(self, ca_ed25519, sample_user_keypair):
        """Use explicit serial number."""
        cert = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser"],
            key_id="test",
            serial=12345,
        )

        assert cert.serial == 12345

    def test_sign_invalid_public_key(self, ca_ed25519):
        """Signing invalid public key should raise error."""
        with pytest.raises((InvalidKeyError, SigningError)):
            ca_ed25519.sign_user_key(
                public_key="not a valid public key",
                principals=["testuser"],
                key_id="test",
            )


class TestHostCertificateSigning:
    """Tests for signing host certificates."""

    def test_sign_host_certificate(self, ca_ed25519, sample_host_keypair):
        """Sign a host's public key."""
        cert = ca_ed25519.sign_host_key(
            public_key=sample_host_keypair["public_key"],
            principals=["server1.example.com", "10.0.0.1"],
            validity=timedelta(days=90),
        )

        assert isinstance(cert, SignedCertificate)
        assert cert.cert_type == CertificateType.HOST
        assert cert.principals == ["server1.example.com", "10.0.0.1"]
        assert "ssh-ed25519-cert-v01@openssh.com" in cert.certificate

    def test_sign_host_certificate_default_key_id(self, ca_ed25519, sample_host_keypair):
        """Host cert key_id defaults to first principal."""
        cert = ca_ed25519.sign_host_key(
            public_key=sample_host_keypair["public_key"],
            principals=["server1.example.com"],
        )

        assert cert.key_id == "server1.example.com"


class TestCertificateParsing:
    """Tests for parsing certificates."""

    def test_parse_user_certificate(self, ca_ed25519, sample_user_keypair):
        """Parse a user certificate."""
        cert = ca_ed25519.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser", "admin"],
            key_id="test@example.com",
            serial=100,
        )

        parsed = CertificateAuthority.parse_certificate(cert.certificate)

        assert parsed["type"] == CertificateType.USER
        assert parsed["key_id"] == "test@example.com"
        assert parsed["serial"] == 100
        assert "testuser" in parsed["principals"]
        assert "admin" in parsed["principals"]

    def test_parse_host_certificate(self, ca_ed25519, sample_host_keypair):
        """Parse a host certificate."""
        cert = ca_ed25519.sign_host_key(
            public_key=sample_host_keypair["public_key"],
            principals=["server1.example.com"],
            key_id="server1",
        )

        parsed = CertificateAuthority.parse_certificate(cert.certificate)

        assert parsed["type"] == CertificateType.HOST
        assert parsed["key_id"] == "server1"

    def test_parse_invalid_certificate(self):
        """Parsing invalid certificate should raise error."""
        with pytest.raises(InvalidKeyError):
            CertificateAuthority.parse_certificate("not a certificate")


class TestPublicKeyFingerprint:
    """Tests for public key fingerprinting."""

    def test_get_fingerprint(self, sample_user_keypair):
        """Get fingerprint of a public key."""
        fingerprint = CertificateAuthority.get_public_key_fingerprint(
            sample_user_keypair["public_key"]
        )

        assert fingerprint.startswith("SHA256:")

    def test_fingerprint_invalid_key(self):
        """Invalid key should raise error."""
        with pytest.raises(InvalidKeyError):
            CertificateAuthority.get_public_key_fingerprint("invalid key")


class TestValidityFormatting:
    """Tests for validity period formatting."""

    def test_format_hours(self):
        """Format hours validity."""
        result = CertificateAuthority._format_validity(timedelta(hours=8))
        assert "+8h" in result

    def test_format_days(self):
        """Format days validity."""
        result = CertificateAuthority._format_validity(timedelta(days=30))
        assert "+30d" in result

    def test_format_weeks(self):
        """Format weeks validity."""
        result = CertificateAuthority._format_validity(timedelta(weeks=12))
        assert "+12w" in result


class TestMultipleKeyTypes:
    """Test signing with different key types."""

    def test_rsa_ca_signs_ed25519_key(self, ca_rsa, sample_user_keypair):
        """RSA CA can sign Ed25519 user key."""
        cert = ca_rsa.sign_user_key(
            public_key=sample_user_keypair["public_key"],
            principals=["testuser"],
            key_id="test",
        )

        assert cert.certificate is not None
        # RSA-signed Ed25519 cert has specific format
        assert "-cert-" in cert.certificate
