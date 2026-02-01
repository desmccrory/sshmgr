"""Certificate Authority implementation using OpenSSH ssh-keygen."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Self

from sshmgr.core.exceptions import (
    InvalidKeyError,
    KeyGenerationError,
    SigningError,
)


class KeyType(str, Enum):
    """Supported SSH key types."""

    ED25519 = "ed25519"
    RSA = "rsa"
    ECDSA = "ecdsa"


class CertificateType(str, Enum):
    """Type of SSH certificate."""

    USER = "user"
    HOST = "host"


@dataclass
class SignedCertificate:
    """Result of signing a public key."""

    certificate: str  # The certificate content
    serial: int
    key_id: str
    principals: list[str]
    valid_after: datetime
    valid_before: datetime
    cert_type: CertificateType


@dataclass
class CertificateAuthority:
    """
    SSH Certificate Authority that wraps OpenSSH ssh-keygen.

    Uses subprocess calls to ssh-keygen for all cryptographic operations,
    ensuring we use battle-tested OpenSSH code rather than implementing
    crypto ourselves.
    """

    private_key: bytes  # PEM-encoded private key
    public_key: str  # OpenSSH public key format
    key_type: KeyType
    _serial_counter: int = 0

    @classmethod
    def generate(cls, key_type: KeyType = KeyType.ED25519, bits: int = 4096) -> Self:
        """
        Generate a new CA keypair.

        Args:
            key_type: Type of key to generate (ed25519, rsa, ecdsa)
            bits: Key size for RSA keys (ignored for ed25519)

        Returns:
            New CertificateAuthority instance

        Raises:
            KeyGenerationError: If key generation fails
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "ca_key"

            cmd = [
                "ssh-keygen",
                "-t",
                key_type.value,
                "-f",
                str(key_path),
                "-N",
                "",  # No passphrase
                "-C",
                "sshmgr-ca",
            ]

            if key_type == KeyType.RSA:
                cmd.extend(["-b", str(bits)])

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise KeyGenerationError(f"Failed to generate CA key: {e.stderr}") from e
            except FileNotFoundError as e:
                raise KeyGenerationError("ssh-keygen not found in PATH") from e

            # Read the generated keys
            private_key = key_path.read_bytes()
            public_key = (key_path.with_suffix(".pub")).read_text().strip()

            return cls(
                private_key=private_key,
                public_key=public_key,
                key_type=key_type,
            )

    @classmethod
    def from_private_key(cls, private_key: bytes, key_type: KeyType | None = None) -> Self:
        """
        Load a CA from an existing private key.

        Args:
            private_key: PEM-encoded private key bytes
            key_type: Key type (auto-detected if not provided)

        Returns:
            CertificateAuthority instance

        Raises:
            InvalidKeyError: If the key is invalid
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "ca_key"
            key_path.write_bytes(private_key)
            os.chmod(key_path, 0o600)

            # Extract public key
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-y", "-f", str(key_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                public_key = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                raise InvalidKeyError(f"Invalid private key: {e.stderr}") from e

            # Auto-detect key type from public key
            if key_type is None:
                key_type = cls._detect_key_type(public_key)

            return cls(
                private_key=private_key,
                public_key=public_key,
                key_type=key_type,
            )

    @staticmethod
    def _detect_key_type(public_key: str) -> KeyType:
        """Detect key type from public key string."""
        if public_key.startswith("ssh-ed25519"):
            return KeyType.ED25519
        elif public_key.startswith("ssh-rsa"):
            return KeyType.RSA
        elif public_key.startswith("ecdsa-"):
            return KeyType.ECDSA
        else:
            raise InvalidKeyError(f"Unknown key type in: {public_key[:50]}...")

    @property
    def fingerprint(self) -> str:
        """Get the SHA256 fingerprint of the CA public key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=False) as f:
            f.write(self.public_key)
            f.flush()
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-l", "-f", f.name],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                # Output format: "256 SHA256:xxx comment (ED25519)"
                parts = result.stdout.strip().split()
                return parts[1] if len(parts) >= 2 else result.stdout.strip()
            finally:
                os.unlink(f.name)

    def _next_serial(self) -> int:
        """Get next certificate serial number."""
        self._serial_counter += 1
        return self._serial_counter

    def sign_user_key(
        self,
        public_key: str,
        principals: list[str],
        key_id: str,
        validity: timedelta = timedelta(hours=8),
        serial: int | None = None,
        extensions: dict[str, str] | None = None,
        force_command: str | None = None,
    ) -> SignedCertificate:
        """
        Sign a user's public key to create a user certificate.

        Args:
            public_key: User's SSH public key (OpenSSH format)
            principals: List of usernames the cert is valid for
            key_id: Identifier embedded in the certificate (e.g., email)
            validity: How long the certificate is valid
            serial: Certificate serial number (auto-generated if not provided)
            extensions: Additional certificate extensions
            force_command: Force a specific command when used

        Returns:
            SignedCertificate with the certificate and metadata

        Raises:
            SigningError: If signing fails
            InvalidKeyError: If the public key is invalid
        """
        return self._sign_key(
            public_key=public_key,
            principals=principals,
            key_id=key_id,
            validity=validity,
            serial=serial,
            cert_type=CertificateType.USER,
            extensions=extensions,
            force_command=force_command,
        )

    def sign_host_key(
        self,
        public_key: str,
        principals: list[str],
        key_id: str | None = None,
        validity: timedelta = timedelta(days=90),
        serial: int | None = None,
    ) -> SignedCertificate:
        """
        Sign a host's public key to create a host certificate.

        Args:
            public_key: Host's SSH public key (OpenSSH format)
            principals: List of hostnames/IPs the cert is valid for
            key_id: Identifier embedded in the certificate (defaults to first principal)
            validity: How long the certificate is valid
            serial: Certificate serial number (auto-generated if not provided)

        Returns:
            SignedCertificate with the certificate and metadata

        Raises:
            SigningError: If signing fails
            InvalidKeyError: If the public key is invalid
        """
        if key_id is None:
            key_id = principals[0] if principals else "host"

        return self._sign_key(
            public_key=public_key,
            principals=principals,
            key_id=key_id,
            validity=validity,
            serial=serial,
            cert_type=CertificateType.HOST,
        )

    def _sign_key(
        self,
        public_key: str,
        principals: list[str],
        key_id: str,
        validity: timedelta,
        serial: int | None,
        cert_type: CertificateType,
        extensions: dict[str, str] | None = None,
        force_command: str | None = None,
    ) -> SignedCertificate:
        """Internal method to sign a key."""
        if serial is None:
            serial = self._next_serial()

        # Calculate validity timestamps (timezone-aware)
        now = datetime.now(UTC)
        valid_after = now - timedelta(minutes=5)  # 5 min clock skew tolerance
        valid_before = now + validity

        # Format validity for ssh-keygen
        validity_str = self._format_validity(validity)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            # Write CA private key
            ca_key_path = tmpdir_path / "ca_key"
            ca_key_path.write_bytes(self.private_key)
            os.chmod(ca_key_path, 0o600)

            # Write user/host public key
            user_key_path = tmpdir_path / "user_key.pub"
            user_key_path.write_text(public_key.strip() + "\n")

            # Build ssh-keygen command
            cmd = [
                "ssh-keygen",
                "-s",
                str(ca_key_path),
                "-I",
                key_id,
                "-n",
                ",".join(principals),
                "-V",
                validity_str,
                "-z",
                str(serial),
            ]

            # Add -h flag for host certificates
            if cert_type == CertificateType.HOST:
                cmd.append("-h")

            # Add extensions for user certificates
            if cert_type == CertificateType.USER:
                # Default extensions for user certs
                if extensions is None:
                    extensions = {}

                # Add force-command if specified
                if force_command:
                    cmd.extend(["-O", f"force-command={force_command}"])

                # Standard user certificate options
                for opt in ["permit-pty", "permit-user-rc"]:
                    if opt not in extensions or extensions[opt] != "no":
                        cmd.extend(["-O", opt])

            # Add the key to sign
            cmd.append(str(user_key_path))

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    cwd=tmpdir,
                )
            except subprocess.CalledProcessError as e:
                if "invalid format" in e.stderr.lower():
                    raise InvalidKeyError(f"Invalid public key format: {e.stderr}") from e
                raise SigningError(f"Failed to sign key: {e.stderr}") from e

            # Read the generated certificate
            cert_path = tmpdir_path / "user_key-cert.pub"
            if not cert_path.exists():
                raise SigningError("Certificate file was not created")

            certificate = cert_path.read_text().strip()

            return SignedCertificate(
                certificate=certificate,
                serial=serial,
                key_id=key_id,
                principals=principals,
                valid_after=valid_after,
                valid_before=valid_before,
                cert_type=cert_type,
            )

    @staticmethod
    def _format_validity(validity: timedelta) -> str:
        """Format validity period for ssh-keygen -V option."""
        # ssh-keygen uses relative format like "+52w" or "+8h"
        total_seconds = int(validity.total_seconds())

        if total_seconds < 0:
            raise ValueError("Validity period must be positive")

        # Choose appropriate unit
        if total_seconds >= 86400 * 7:  # weeks
            weeks = total_seconds // (86400 * 7)
            return f"-5m:+{weeks}w"
        elif total_seconds >= 86400:  # days
            days = total_seconds // 86400
            return f"-5m:+{days}d"
        elif total_seconds >= 3600:  # hours
            hours = total_seconds // 3600
            return f"-5m:+{hours}h"
        else:  # minutes
            minutes = max(1, total_seconds // 60)
            return f"-5m:+{minutes}m"

    @staticmethod
    def get_public_key_fingerprint(public_key: str) -> str:
        """Get the SHA256 fingerprint of a public key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=False) as f:
            f.write(public_key)
            f.flush()
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-l", "-f", f.name],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                parts = result.stdout.strip().split()
                return parts[1] if len(parts) >= 2 else result.stdout.strip()
            except subprocess.CalledProcessError as e:
                raise InvalidKeyError(f"Invalid public key: {e.stderr}") from e
            finally:
                os.unlink(f.name)

    @staticmethod
    def parse_certificate(certificate: str) -> dict:
        """
        Parse a certificate and return its details.

        Returns dict with: type, public_key, serial, key_id, principals, valid_after, valid_before
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix="-cert.pub", delete=False) as f:
            f.write(certificate)
            f.flush()
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-L", "-f", f.name],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                return CertificateAuthority._parse_cert_output(result.stdout)
            except subprocess.CalledProcessError as e:
                raise InvalidKeyError(f"Invalid certificate: {e.stderr}") from e
            finally:
                os.unlink(f.name)

    @staticmethod
    def _parse_cert_output(output: str) -> dict:
        """Parse ssh-keygen -L output into a dictionary."""
        info: dict = {}

        # Parse type
        if "user certificate" in output.lower():
            info["type"] = CertificateType.USER
        elif "host certificate" in output.lower():
            info["type"] = CertificateType.HOST

        # Parse serial
        serial_match = re.search(r"Serial:\s*(\d+)", output)
        if serial_match:
            info["serial"] = int(serial_match.group(1))

        # Parse key ID
        key_id_match = re.search(r'Key ID:\s*"([^"]*)"', output)
        if key_id_match:
            info["key_id"] = key_id_match.group(1)

        # Parse principals
        principals = []
        in_principals = False
        for line in output.split("\n"):
            if "Principals:" in line:
                in_principals = True
                continue
            if in_principals:
                line = line.strip()
                if line and not line.startswith(("Critical", "Extensions", "Valid")):
                    principals.append(line)
                else:
                    in_principals = False
        info["principals"] = principals

        # Parse validity
        valid_match = re.search(
            r"Valid:\s*from\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+to\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
            output,
        )
        if valid_match:
            info["valid_after"] = datetime.fromisoformat(valid_match.group(1))
            info["valid_before"] = datetime.fromisoformat(valid_match.group(2))

        return info
