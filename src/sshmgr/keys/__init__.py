"""Key storage implementations for sshmgr."""

from sshmgr.keys.base import KeyStorage
from sshmgr.keys.encrypted import EncryptedKeyStorage

__all__ = ["KeyStorage", "EncryptedKeyStorage"]
