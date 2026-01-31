"""Integration tests for Certificate Authority operations.

These tests verify the full certificate signing workflow, including
key generation, certificate signing, and certificate validation.
"""

import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from sshmgr.core.ca import CertificateAuthority, CertificateType, KeyType
from sshmgr.core.exceptions import InvalidKeyError, SigningError
from sshmgr.keys.encrypted import EncryptedKeyStorage


class TestCAGeneration:
    """Integration tests for CA key generation."""

    def test_generate_ed25519_ca(self):
        """Test generating an Ed25519 CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        assert ca.public_key.startswith("ssh-ed25519")
        assert ca.private_key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        assert ca.key_type == KeyType.ED25519
        assert ca.fingerprint.startswith("SHA256:")

    def test_generate_rsa_ca(self):
        """Test generating an RSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.RSA, bits=2048)

        assert ca.public_key.startswith("ssh-rsa")
        assert ca.key_type == KeyType.RSA

    def test_generate_rsa_4096_ca(self):
        """Test generating a 4096-bit RSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.RSA, bits=4096)

        assert ca.public_key.startswith("ssh-rsa")

    def test_generate_ecdsa_ca(self):
        """Test generating an ECDSA CA."""
        ca = CertificateAuthority.generate(key_type=KeyType.ECDSA)

        assert ca.public_key.startswith("ecdsa-sha2-")

    def test_ca_from_private_key(self):
        """Test loading CA from private key."""
        original = CertificateAuthority.generate(key_type=KeyType.ED25519)
        loaded = CertificateAuthority.from_private_key(original.private_key)

        assert loaded.public_key == original.public_key
        assert loaded.fingerprint == original.fingerprint

    def test_fingerprint_consistency(self):
        """Test fingerprint is consistent across loads."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        fingerprint1 = ca.fingerprint

        loaded = CertificateAuthority.from_private_key(ca.private_key)
        fingerprint2 = loaded.fingerprint

        assert fingerprint1 == fingerprint2


class TestUserCertificateSigning:
    """Integration tests for user certificate signing."""

    @pytest.fixture
    def ca(self):
        """Generate a test CA."""
        return CertificateAuthority.generate(key_type=KeyType.ED25519)

    @pytest.fixture
    def user_keypair(self, tmp_path):
        """Generate a test user keypair."""
        key_path = tmp_path / "user_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(key_path),
                "-N",
                "",
                "-C",
                "testuser@example.com",
            ],
            check=True,
            capture_output=True,
        )
        return {
            "private_key_path": key_path,
            "public_key": key_path.with_suffix(".pub").read_text().strip(),
        }

    def test_sign_user_certificate(self, ca, user_keypair):
        """Test signing a user certificate."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["testuser"],
            key_id="testuser@example.com",
            validity=timedelta(hours=8),
        )

        assert cert.cert_type == CertificateType.USER
        assert cert.key_id == "testuser@example.com"
        assert cert.principals == ["testuser"]
        assert "ssh-ed25519-cert-v01@openssh.com" in cert.certificate
        assert cert.serial is not None

    def test_sign_user_certificate_multiple_principals(self, ca, user_keypair):
        """Test signing with multiple principals."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["deploy", "admin", "operator"],
            key_id="multi@example.com",
            validity=timedelta(hours=8),
        )

        assert cert.principals == ["deploy", "admin", "operator"]

    def test_sign_user_certificate_custom_serial(self, ca, user_keypair):
        """Test signing with custom serial number."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["testuser"],
            key_id="serial@example.com",
            validity=timedelta(hours=8),
            serial=12345,
        )

        assert cert.serial == 12345

    def test_sign_user_certificate_with_force_command(self, ca, user_keypair):
        """Test signing with force command."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["testuser"],
            key_id="forced@example.com",
            validity=timedelta(hours=8),
            force_command="/usr/bin/git-shell",
        )

        assert cert.certificate is not None

    def test_verify_signed_certificate(self, ca, user_keypair, tmp_path):
        """Test verifying a signed certificate with ssh-keygen."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["testuser"],
            key_id="verify@example.com",
            validity=timedelta(hours=8),
        )

        # Write certificate to file
        cert_path = tmp_path / "user_key-cert.pub"
        cert_path.write_text(cert.certificate)

        # Verify with ssh-keygen -L
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Type: ssh-ed25519-cert-v01@openssh.com user certificate" in result.stdout
        assert "verify@example.com" in result.stdout
        assert "testuser" in result.stdout

    def test_certificate_validity_period(self, ca, user_keypair, tmp_path):
        """Test certificate validity period is set correctly."""
        cert = ca.sign_user_key(
            public_key=user_keypair["public_key"],
            principals=["testuser"],
            key_id="validity@example.com",
            validity=timedelta(hours=8),
        )

        # Check validity times
        assert cert.valid_after is not None
        assert cert.valid_before is not None

        # Valid before should be ~8 hours after valid_after
        diff = cert.valid_before - cert.valid_after
        assert 7 * 3600 < diff.total_seconds() < 9 * 3600


class TestHostCertificateSigning:
    """Integration tests for host certificate signing."""

    @pytest.fixture
    def ca(self):
        """Generate a test CA."""
        return CertificateAuthority.generate(key_type=KeyType.ED25519)

    @pytest.fixture
    def host_keypair(self, tmp_path):
        """Generate a test host keypair."""
        key_path = tmp_path / "host_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(key_path),
                "-N",
                "",
                "-C",
                "host",
            ],
            check=True,
            capture_output=True,
        )
        return {
            "private_key_path": key_path,
            "public_key": key_path.with_suffix(".pub").read_text().strip(),
        }

    def test_sign_host_certificate(self, ca, host_keypair):
        """Test signing a host certificate."""
        cert = ca.sign_host_key(
            public_key=host_keypair["public_key"],
            principals=["server.example.com"],
            validity=timedelta(days=90),
        )

        assert cert.cert_type == CertificateType.HOST
        assert "server.example.com" in cert.principals
        assert "ssh-ed25519-cert-v01@openssh.com" in cert.certificate

    def test_sign_host_certificate_multiple_hostnames(self, ca, host_keypair):
        """Test signing with multiple hostnames and IPs."""
        cert = ca.sign_host_key(
            public_key=host_keypair["public_key"],
            principals=["server.example.com", "server", "10.0.0.5", "192.168.1.100"],
            validity=timedelta(days=90),
        )

        assert "server.example.com" in cert.principals
        assert "10.0.0.5" in cert.principals

    def test_verify_host_certificate(self, ca, host_keypair, tmp_path):
        """Test verifying a signed host certificate."""
        cert = ca.sign_host_key(
            public_key=host_keypair["public_key"],
            principals=["server.example.com"],
            validity=timedelta(days=90),
        )

        # Write certificate to file
        cert_path = tmp_path / "host_key-cert.pub"
        cert_path.write_text(cert.certificate)

        # Verify with ssh-keygen -L
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "host certificate" in result.stdout
        assert "server.example.com" in result.stdout


class TestEncryptedKeyStorage:
    """Integration tests for encrypted key storage."""

    @pytest.fixture
    def master_key(self):
        """Generate a master key."""
        return EncryptedKeyStorage.generate_master_key()

    @pytest.fixture
    def storage(self, master_key):
        """Create encrypted storage."""
        return EncryptedKeyStorage(master_key)

    def test_store_and_retrieve_key(self, storage):
        """Test storing and retrieving a CA private key."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        env_id = uuid4()

        # Store key
        key_ref = storage.store_key(env_id, "user_ca", ca.private_key)

        # Retrieve key
        retrieved = storage.retrieve_key(key_ref)

        assert retrieved == ca.private_key

    def test_store_multiple_keys(self, storage):
        """Test storing multiple keys for same environment."""
        user_ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        host_ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        env_id = uuid4()

        user_ref = storage.store_key(env_id, "user_ca", user_ca.private_key)
        host_ref = storage.store_key(env_id, "host_ca", host_ca.private_key)

        retrieved_user = storage.retrieve_key(user_ref)
        retrieved_host = storage.retrieve_key(host_ref)

        assert retrieved_user == user_ca.private_key
        assert retrieved_host == host_ca.private_key

    def test_different_master_key_fails(self, storage, master_key):
        """Test that different master key cannot decrypt."""
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        env_id = uuid4()

        key_ref = storage.store_key(env_id, "user_ca", ca.private_key)

        # Create storage with different master key
        different_key = EncryptedKeyStorage.generate_master_key()
        different_storage = EncryptedKeyStorage(different_key)

        with pytest.raises(Exception):  # Fernet raises InvalidToken
            different_storage.retrieve_key(key_ref)


class TestFullCertificateWorkflow:
    """End-to-end tests for complete certificate workflows."""

    def test_user_certificate_workflow(self, tmp_path):
        """Test complete user certificate workflow."""
        # 1. Generate CA
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        # 2. Generate user keypair
        user_key_path = tmp_path / "user_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(user_key_path),
                "-N",
                "",
                "-C",
                "user@example.com",
            ],
            check=True,
            capture_output=True,
        )
        user_public_key = user_key_path.with_suffix(".pub").read_text().strip()

        # 3. Sign certificate
        cert = ca.sign_user_key(
            public_key=user_public_key,
            principals=["deploy", "admin"],
            key_id="user@example.com",
            validity=timedelta(hours=8),
            serial=1,
        )

        # 4. Write certificate
        cert_path = user_key_path.parent / "user_key-cert.pub"
        cert_path.write_text(cert.certificate)

        # 5. Verify certificate is valid
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "user certificate" in result.stdout
        assert "user@example.com" in result.stdout
        assert "deploy" in result.stdout
        assert "admin" in result.stdout

    def test_host_certificate_workflow(self, tmp_path):
        """Test complete host certificate workflow."""
        # 1. Generate CA
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)

        # 2. Generate host keypair
        host_key_path = tmp_path / "ssh_host_ed25519_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(host_key_path),
                "-N",
                "",
                "-C",
                "",
            ],
            check=True,
            capture_output=True,
        )
        host_public_key = host_key_path.with_suffix(".pub").read_text().strip()

        # 3. Sign certificate
        cert = ca.sign_host_key(
            public_key=host_public_key,
            principals=["server.example.com", "10.0.0.5"],
            validity=timedelta(days=90),
            serial=1,
        )

        # 4. Write certificate
        cert_path = host_key_path.parent / "ssh_host_ed25519_key-cert.pub"
        cert_path.write_text(cert.certificate)

        # 5. Verify certificate is valid
        result = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "host certificate" in result.stdout
        assert "server.example.com" in result.stdout

    def test_ca_rotation_workflow(self, tmp_path):
        """Test CA rotation workflow."""
        # 1. Generate original CA
        old_ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        old_fingerprint = old_ca.fingerprint

        # 2. Generate user keypair
        user_key_path = tmp_path / "user_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(user_key_path),
                "-N",
                "",
            ],
            check=True,
            capture_output=True,
        )
        user_public_key = user_key_path.with_suffix(".pub").read_text().strip()

        # 3. Sign cert with old CA
        old_cert = old_ca.sign_user_key(
            public_key=user_public_key,
            principals=["user"],
            key_id="user@example.com",
            validity=timedelta(hours=8),
        )

        # 4. Generate new CA (rotation)
        new_ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        new_fingerprint = new_ca.fingerprint

        # 5. Fingerprints should be different
        assert old_fingerprint != new_fingerprint

        # 6. Sign cert with new CA
        new_cert = new_ca.sign_user_key(
            public_key=user_public_key,
            principals=["user"],
            key_id="user@example.com",
            validity=timedelta(hours=8),
        )

        # 7. Both certs should be valid (different signing authorities)
        assert old_cert.certificate != new_cert.certificate

    def test_encrypted_ca_workflow(self, tmp_path):
        """Test workflow with encrypted CA storage."""
        # 1. Generate master key and storage
        master_key = EncryptedKeyStorage.generate_master_key()
        storage = EncryptedKeyStorage(master_key)

        # 2. Generate and store CA
        ca = CertificateAuthority.generate(key_type=KeyType.ED25519)
        env_id = uuid4()
        key_ref = storage.store_key(env_id, "user_ca", ca.private_key)

        # 3. Retrieve CA from storage
        retrieved_key = storage.retrieve_key(key_ref)
        loaded_ca = CertificateAuthority.from_private_key(retrieved_key)

        # 4. Verify loaded CA matches original
        assert loaded_ca.fingerprint == ca.fingerprint

        # 5. Generate user keypair
        user_key_path = tmp_path / "user_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(user_key_path),
                "-N",
                "",
            ],
            check=True,
            capture_output=True,
        )
        user_public_key = user_key_path.with_suffix(".pub").read_text().strip()

        # 6. Sign certificate with loaded CA
        cert = loaded_ca.sign_user_key(
            public_key=user_public_key,
            principals=["user"],
            key_id="encrypted@example.com",
            validity=timedelta(hours=8),
        )

        # 7. Verify certificate
        assert cert.certificate is not None
        assert "ssh-ed25519-cert" in cert.certificate


class TestCertificateErrorHandling:
    """Tests for certificate error handling."""

    @pytest.fixture
    def ca(self):
        """Generate a test CA."""
        return CertificateAuthority.generate(key_type=KeyType.ED25519)

    def test_invalid_public_key_format(self, ca):
        """Test signing with invalid public key format."""
        with pytest.raises((InvalidKeyError, SigningError)):
            ca.sign_user_key(
                public_key="not-a-valid-key",
                principals=["user"],
                key_id="invalid@example.com",
                validity=timedelta(hours=8),
            )

    def test_empty_principals(self, ca, tmp_path):
        """Test signing with empty principals."""
        # Generate valid key
        key_path = tmp_path / "test_key"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""],
            check=True,
            capture_output=True,
        )
        public_key = key_path.with_suffix(".pub").read_text().strip()

        # Empty principals should raise error or be handled
        with pytest.raises((ValueError, SigningError)):
            ca.sign_user_key(
                public_key=public_key,
                principals=[],
                key_id="empty@example.com",
                validity=timedelta(hours=8),
            )

    def test_zero_validity(self, ca, tmp_path):
        """Test signing with zero validity."""
        key_path = tmp_path / "test_key"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""],
            check=True,
            capture_output=True,
        )
        public_key = key_path.with_suffix(".pub").read_text().strip()

        # Zero validity might be handled differently
        # Just ensure it doesn't crash unexpectedly
        try:
            cert = ca.sign_user_key(
                public_key=public_key,
                principals=["user"],
                key_id="zero@example.com",
                validity=timedelta(seconds=0),
            )
            # If it succeeds, cert should still be returned
            assert cert is not None
        except (ValueError, SigningError):
            # Expected for zero validity
            pass
