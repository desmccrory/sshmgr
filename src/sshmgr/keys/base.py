"""Abstract base class for key storage implementations."""

from abc import ABC, abstractmethod
from typing import Protocol
from uuid import UUID


class KeyStorage(ABC):
    """
    Abstract base class for CA private key storage.

    Implementations handle secure storage and retrieval of CA private keys.
    Keys are identified by environment ID and key type (user_ca or host_ca).
    """

    @abstractmethod
    def store_key(self, environment_id: UUID, key_type: str, private_key: bytes) -> str:
        """
        Store a CA private key.

        Args:
            environment_id: UUID of the environment
            key_type: Either "user_ca" or "host_ca"
            private_key: PEM-encoded private key bytes

        Returns:
            Reference string for retrieving the key (e.g., path or vault ref)
        """
        pass

    @abstractmethod
    def retrieve_key(self, key_ref: str) -> bytes:
        """
        Retrieve a CA private key.

        Args:
            key_ref: Reference returned from store_key()

        Returns:
            PEM-encoded private key bytes

        Raises:
            StorageError: If key cannot be retrieved
        """
        pass

    @abstractmethod
    def delete_key(self, key_ref: str) -> None:
        """
        Delete a CA private key.

        Args:
            key_ref: Reference returned from store_key()

        Raises:
            StorageError: If key cannot be deleted
        """
        pass

    @abstractmethod
    def rotate_key(
        self, environment_id: UUID, key_type: str, new_private_key: bytes
    ) -> tuple[str, str | None]:
        """
        Rotate a CA private key, keeping the old key temporarily.

        Args:
            environment_id: UUID of the environment
            key_type: Either "user_ca" or "host_ca"
            new_private_key: New PEM-encoded private key bytes

        Returns:
            Tuple of (new_key_ref, old_key_ref or None)
        """
        pass
