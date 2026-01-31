"""Unit tests for encrypted key storage."""

import base64
import os
from uuid import uuid4

import pytest

from sshmgr.core.exceptions import EncryptionError, StorageError
from sshmgr.keys.encrypted import EncryptedKeyStorage, get_master_key_from_env


class TestEncryptedKeyStorageInit:
    """Tests for EncryptedKeyStorage initialization."""

    def test_init_with_fernet_key(self):
        """Initialize with a valid Fernet key."""
        key = EncryptedKeyStorage.generate_master_key()
        storage = EncryptedKeyStorage(key)

        assert storage is not None

    def test_init_with_32_byte_key(self):
        """Initialize with a 32-byte raw key."""
        key = os.urandom(32)
        storage = EncryptedKeyStorage(key)

        assert storage is not None

    def test_init_with_string_key(self):
        """Initialize with a string Fernet key."""
        key = EncryptedKeyStorage.generate_master_key()
        storage = EncryptedKeyStorage(key)  # String key

        assert storage is not None

    def test_init_with_invalid_key(self):
        """Invalid key should raise ValueError."""
        with pytest.raises(ValueError):
            EncryptedKeyStorage(b"too short")

    def test_generate_master_key(self):
        """Generated master key should be valid."""
        key = EncryptedKeyStorage.generate_master_key()

        assert isinstance(key, str)
        assert len(key) == 44  # Fernet key length

    def test_from_passphrase(self):
        """Create storage from passphrase."""
        storage = EncryptedKeyStorage.from_passphrase("my-secure-passphrase")

        assert storage is not None

    def test_from_passphrase_with_salt(self):
        """Create storage from passphrase with explicit salt."""
        salt = os.urandom(16)
        storage1 = EncryptedKeyStorage.from_passphrase("passphrase", salt=salt)
        storage2 = EncryptedKeyStorage.from_passphrase("passphrase", salt=salt)

        # Same passphrase + salt should produce same encryption
        data = b"test data"
        encrypted1 = storage1.encrypt(data)
        decrypted = storage2.decrypt(encrypted1)

        assert decrypted == data


class TestEncryption:
    """Tests for encrypt/decrypt operations."""

    def test_encrypt_decrypt_roundtrip(self, encrypted_storage):
        """Data should survive encrypt/decrypt cycle."""
        original = b"This is sensitive CA private key data"

        encrypted = encrypted_storage.encrypt(original)
        decrypted = encrypted_storage.decrypt(encrypted)

        assert decrypted == original
        assert encrypted != original

    def test_encrypt_produces_different_ciphertext(self, encrypted_storage):
        """Same plaintext should produce different ciphertext (random IV)."""
        data = b"test data"

        encrypted1 = encrypted_storage.encrypt(data)
        encrypted2 = encrypted_storage.encrypt(data)

        assert encrypted1 != encrypted2

    def test_decrypt_with_wrong_key(self, master_key):
        """Decrypting with wrong key should fail."""
        storage1 = EncryptedKeyStorage(master_key)
        storage2 = EncryptedKeyStorage(EncryptedKeyStorage.generate_master_key())

        encrypted = storage1.encrypt(b"secret")

        with pytest.raises(EncryptionError):
            storage2.decrypt(encrypted)

    def test_decrypt_corrupted_data(self, encrypted_storage):
        """Decrypting corrupted data should fail."""
        with pytest.raises(EncryptionError):
            encrypted_storage.decrypt(b"corrupted data")


class TestKeyStorage:
    """Tests for KeyStorage interface methods."""

    def test_store_key(self, encrypted_storage, sample_environment_id):
        """Store a CA private key."""
        private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"

        key_ref = encrypted_storage.store_key(
            environment_id=sample_environment_id,
            key_type="user_ca",
            private_key=private_key,
        )

        assert key_ref.startswith("encrypted:")
        assert len(key_ref) > 20

    def test_store_key_invalid_type(self, encrypted_storage, sample_environment_id):
        """Invalid key_type should raise ValueError."""
        with pytest.raises(ValueError):
            encrypted_storage.store_key(
                environment_id=sample_environment_id,
                key_type="invalid",
                private_key=b"key",
            )

    def test_retrieve_key(self, encrypted_storage, sample_environment_id):
        """Retrieve a stored key."""
        original_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\ntest key content\n-----END OPENSSH PRIVATE KEY-----"

        key_ref = encrypted_storage.store_key(
            environment_id=sample_environment_id,
            key_type="host_ca",
            private_key=original_key,
        )
        retrieved = encrypted_storage.retrieve_key(key_ref)

        assert retrieved == original_key

    def test_retrieve_key_invalid_ref(self, encrypted_storage):
        """Invalid key reference should raise StorageError."""
        with pytest.raises(StorageError):
            encrypted_storage.retrieve_key("invalid:reference")

    def test_retrieve_key_corrupted_ref(self, encrypted_storage):
        """Corrupted key reference should raise error."""
        with pytest.raises((StorageError, EncryptionError)):
            encrypted_storage.retrieve_key("encrypted:not-valid-base64!!!")

    def test_delete_key(self, encrypted_storage, sample_environment_id):
        """Delete should validate reference format."""
        private_key = b"test key"
        key_ref = encrypted_storage.store_key(
            environment_id=sample_environment_id,
            key_type="user_ca",
            private_key=private_key,
        )

        # Should not raise
        encrypted_storage.delete_key(key_ref)

    def test_delete_key_invalid_ref(self, encrypted_storage):
        """Delete with invalid reference should raise StorageError."""
        with pytest.raises(StorageError):
            encrypted_storage.delete_key("invalid:reference")

    def test_rotate_key(self, encrypted_storage, sample_environment_id):
        """Rotate a key."""
        new_key = b"new private key content"

        new_ref, old_ref = encrypted_storage.rotate_key(
            environment_id=sample_environment_id,
            key_type="user_ca",
            new_private_key=new_key,
        )

        assert new_ref.startswith("encrypted:")
        assert old_ref is None  # Old key managed by caller

        # Verify new key can be retrieved
        retrieved = encrypted_storage.retrieve_key(new_ref)
        assert retrieved == new_key


class TestRealCAKey:
    """Tests with real CA keys generated by ssh-keygen."""

    def test_store_retrieve_real_ca_key(self, encrypted_storage, ca_ed25519, sample_environment_id):
        """Store and retrieve a real CA private key."""
        key_ref = encrypted_storage.store_key(
            environment_id=sample_environment_id,
            key_type="user_ca",
            private_key=ca_ed25519.private_key,
        )

        retrieved = encrypted_storage.retrieve_key(key_ref)

        assert retrieved == ca_ed25519.private_key
        assert b"OPENSSH PRIVATE KEY" in retrieved


class TestGetMasterKeyFromEnv:
    """Tests for get_master_key_from_env function."""

    def test_get_key_from_env(self, master_key, monkeypatch):
        """Get master key from environment variable."""
        monkeypatch.setenv("SSHMGR_MASTER_KEY", master_key)

        result = get_master_key_from_env()

        assert result == master_key

    def test_get_key_custom_var(self, master_key, monkeypatch):
        """Get master key from custom environment variable."""
        monkeypatch.setenv("CUSTOM_KEY_VAR", master_key)

        result = get_master_key_from_env("CUSTOM_KEY_VAR")

        assert result == master_key

    def test_get_key_not_set(self, monkeypatch):
        """Missing environment variable should raise ValueError."""
        monkeypatch.delenv("SSHMGR_MASTER_KEY", raising=False)

        with pytest.raises(ValueError) as exc_info:
            get_master_key_from_env()

        assert "SSHMGR_MASTER_KEY" in str(exc_info.value)
