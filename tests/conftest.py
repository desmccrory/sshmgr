"""Pytest configuration and fixtures for sshmgr tests."""

import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from sshmgr.core.ca import CertificateAuthority, KeyType
from sshmgr.keys.encrypted import EncryptedKeyStorage


@pytest.fixture
def temp_dir():
    """Provide a temporary directory that's cleaned up after the test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_user_keypair(temp_dir):
    """Generate a sample user SSH keypair for testing."""
    key_path = temp_dir / "test_user_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "test@example.com"],
        capture_output=True,
        check=True,
    )
    return {
        "private_key": key_path.read_bytes(),
        "public_key": key_path.with_suffix(".pub").read_text().strip(),
        "path": key_path,
    }


@pytest.fixture
def sample_host_keypair(temp_dir):
    """Generate a sample host SSH keypair for testing."""
    key_path = temp_dir / "test_host_key"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", "host"],
        capture_output=True,
        check=True,
    )
    return {
        "private_key": key_path.read_bytes(),
        "public_key": key_path.with_suffix(".pub").read_text().strip(),
        "path": key_path,
    }


@pytest.fixture
def ca_ed25519():
    """Provide a fresh Ed25519 CA for each test."""
    return CertificateAuthority.generate(key_type=KeyType.ED25519)


@pytest.fixture
def ca_rsa():
    """Provide a fresh RSA CA for each test."""
    return CertificateAuthority.generate(key_type=KeyType.RSA, bits=2048)


@pytest.fixture
def master_key():
    """Provide a test master encryption key."""
    return EncryptedKeyStorage.generate_master_key()


@pytest.fixture
def encrypted_storage(master_key):
    """Provide an encrypted key storage instance."""
    return EncryptedKeyStorage(master_key)


@pytest.fixture
def sample_environment_id():
    """Provide a sample environment UUID."""
    return uuid4()
