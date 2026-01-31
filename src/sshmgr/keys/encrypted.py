"""Encrypted key storage using Fernet symmetric encryption."""

from __future__ import annotations

import base64
import os
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from sshmgr.core.exceptions import EncryptionError, StorageError
from sshmgr.keys.base import KeyStorage


class EncryptedKeyStorage(KeyStorage):
    """
    Key storage using Fernet symmetric encryption.

    Keys are encrypted before storage and decrypted on retrieval.
    The encrypted data is returned as a base64-encoded string that can
    be stored in a database column.

    The master key should be provided via environment variable or
    loaded from a secrets manager at application startup.
    """

    def __init__(self, master_key: bytes | str):
        """
        Initialize with a master encryption key.

        Args:
            master_key: 32-byte key or Fernet key string (base64 url-safe encoded).
                        Can also be a passphrase if derive_from_passphrase is used.

        Raises:
            ValueError: If master_key is invalid
        """
        if isinstance(master_key, str):
            master_key = master_key.encode()

        # If it's a valid Fernet key (44 bytes base64), use directly
        if len(master_key) == 44:
            try:
                self._fernet = Fernet(master_key)
                return
            except Exception:
                pass

        # If it's a 32-byte raw key, encode it for Fernet
        if len(master_key) == 32:
            fernet_key = base64.urlsafe_b64encode(master_key)
            self._fernet = Fernet(fernet_key)
            return

        raise ValueError(
            "master_key must be a 32-byte key or a valid Fernet key string (44 chars)"
        )

    @classmethod
    def from_passphrase(cls, passphrase: str, salt: bytes | None = None) -> "EncryptedKeyStorage":
        """
        Create storage with a key derived from a passphrase.

        Args:
            passphrase: Human-readable passphrase
            salt: Salt for key derivation (generated if not provided)

        Returns:
            EncryptedKeyStorage instance

        Note:
            The salt must be stored and reused to decrypt data later.
            Consider storing it alongside the encrypted data or in config.
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # OWASP recommended minimum
        )
        key = kdf.derive(passphrase.encode())
        return cls(key)

    @classmethod
    def generate_master_key(cls) -> str:
        """
        Generate a new random master key.

        Returns:
            Base64 url-safe encoded Fernet key string
        """
        return Fernet.generate_key().decode()

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data.

        Args:
            data: Plaintext bytes to encrypt

        Returns:
            Encrypted bytes (Fernet token)
        """
        return self._fernet.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data.

        Args:
            encrypted_data: Fernet token bytes

        Returns:
            Decrypted plaintext bytes

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            return self._fernet.decrypt(encrypted_data)
        except InvalidToken as e:
            raise EncryptionError("Failed to decrypt data: invalid key or corrupted data") from e

    def store_key(self, environment_id: UUID, key_type: str, private_key: bytes) -> str:
        """
        Encrypt and store a CA private key.

        The encrypted key is returned as a base64 string prefixed with "encrypted:"
        for identification. This string can be stored in a database column.

        Args:
            environment_id: UUID of the environment
            key_type: Either "user_ca" or "host_ca"
            private_key: PEM-encoded private key bytes

        Returns:
            Reference string containing the encrypted key
        """
        if key_type not in ("user_ca", "host_ca"):
            raise ValueError(f"Invalid key_type: {key_type}")

        encrypted = self.encrypt(private_key)
        # Return as prefixed base64 string
        return f"encrypted:{base64.urlsafe_b64encode(encrypted).decode()}"

    def retrieve_key(self, key_ref: str) -> bytes:
        """
        Decrypt and retrieve a CA private key.

        Args:
            key_ref: Reference returned from store_key()

        Returns:
            PEM-encoded private key bytes

        Raises:
            StorageError: If key reference is invalid
            EncryptionError: If decryption fails
        """
        if not key_ref.startswith("encrypted:"):
            raise StorageError(f"Invalid key reference format: {key_ref[:20]}...")

        try:
            encrypted = base64.urlsafe_b64decode(key_ref[10:])  # Skip "encrypted:" prefix
            return self.decrypt(encrypted)
        except Exception as e:
            if isinstance(e, EncryptionError):
                raise
            raise StorageError(f"Failed to decode key reference: {e}") from e

    def delete_key(self, key_ref: str) -> None:
        """
        Delete a key reference.

        For encrypted storage, the key is stored inline, so "deletion" is
        handled by removing the reference from the database. This method
        is a no-op but validates the reference format.

        Args:
            key_ref: Reference returned from store_key()
        """
        if not key_ref.startswith("encrypted:"):
            raise StorageError(f"Invalid key reference format: {key_ref[:20]}...")
        # No-op: actual deletion happens in database layer

    def rotate_key(
        self, environment_id: UUID, key_type: str, new_private_key: bytes
    ) -> tuple[str, str | None]:
        """
        Create a new encrypted key reference.

        For encrypted storage, rotation just means encrypting the new key.
        The old key reference should be kept in the database for the grace period.

        Args:
            environment_id: UUID of the environment
            key_type: Either "user_ca" or "host_ca"
            new_private_key: New PEM-encoded private key bytes

        Returns:
            Tuple of (new_key_ref, None) - old key is managed by caller
        """
        new_ref = self.store_key(environment_id, key_type, new_private_key)
        return (new_ref, None)


def get_master_key_from_env(env_var: str = "SSHMGR_MASTER_KEY") -> str:
    """
    Load master key from environment variable.

    Args:
        env_var: Name of environment variable containing the key

    Returns:
        Master key string

    Raises:
        ValueError: If environment variable is not set
    """
    key = os.environ.get(env_var)
    if not key:
        raise ValueError(
            f"Environment variable {env_var} not set. "
            f"Generate a key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        )
    return key
