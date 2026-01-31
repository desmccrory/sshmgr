"""Custom exceptions for sshmgr."""


class SSHMgrError(Exception):
    """Base exception for all sshmgr errors."""

    pass


class CAError(SSHMgrError):
    """Base exception for Certificate Authority errors."""

    pass


class KeyGenerationError(CAError):
    """Error generating SSH keys."""

    pass


class SigningError(CAError):
    """Error signing a certificate."""

    pass


class InvalidKeyError(CAError):
    """Invalid SSH key format or type."""

    pass


class StorageError(SSHMgrError):
    """Error with key storage operations."""

    pass


class EncryptionError(StorageError):
    """Error encrypting or decrypting data."""

    pass


class EnvironmentError(SSHMgrError):
    """Error with environment operations."""

    pass


class EnvironmentNotFoundError(EnvironmentError):
    """Environment not found."""

    pass


class AuthenticationError(SSHMgrError):
    """Authentication failed."""

    pass


class AuthorizationError(SSHMgrError):
    """User not authorized for this action."""

    pass
