"""Tests for sshmgr.api.schemas module."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from sshmgr.api.schemas import (
    CAPublicKeyResponse,
    CARotationInfo,
    CertificateListResponse,
    CertificateResponse,
    CertTypeEnum,
    EnvironmentCreate,
    EnvironmentListResponse,
    EnvironmentResponse,
    ErrorResponse,
    HealthResponse,
    HostCertificateRequest,
    KeyTypeEnum,
    ReadinessResponse,
    RevokeRequest,
    RotateCARequest,
    RotationStatusResponse,
    UserCertificateRequest,
    ValidationErrorItem,
    ValidationErrorResponse,
)


class TestCertTypeEnum:
    """Tests for CertTypeEnum."""

    def test_user_type(self):
        """Test USER cert type."""
        assert CertTypeEnum.USER.value == "user"

    def test_host_type(self):
        """Test HOST cert type."""
        assert CertTypeEnum.HOST.value == "host"


class TestKeyTypeEnum:
    """Tests for KeyTypeEnum."""

    def test_ed25519_type(self):
        """Test ED25519 key type."""
        assert KeyTypeEnum.ED25519.value == "ed25519"

    def test_rsa_type(self):
        """Test RSA key type."""
        assert KeyTypeEnum.RSA.value == "rsa"

    def test_ecdsa_type(self):
        """Test ECDSA key type."""
        assert KeyTypeEnum.ECDSA.value == "ecdsa"


class TestEnvironmentCreate:
    """Tests for EnvironmentCreate schema."""

    def test_valid_environment(self):
        """Test creating valid environment."""
        env = EnvironmentCreate(name="production")

        assert env.name == "production"
        assert env.key_type == KeyTypeEnum.ED25519
        assert env.default_user_cert_validity == "8h"
        assert env.default_host_cert_validity == "90d"

    def test_valid_environment_with_options(self):
        """Test creating environment with all options."""
        env = EnvironmentCreate(
            name="staging",
            key_type=KeyTypeEnum.RSA,
            default_user_cert_validity="12h",
            default_host_cert_validity="180d",
        )

        assert env.name == "staging"
        assert env.key_type == KeyTypeEnum.RSA
        assert env.default_user_cert_validity == "12h"
        assert env.default_host_cert_validity == "180d"

    def test_single_char_name(self):
        """Test single character name is valid."""
        env = EnvironmentCreate(name="a")
        assert env.name == "a"

    def test_name_with_hyphen(self):
        """Test name with hyphens is valid."""
        env = EnvironmentCreate(name="customer-prod")
        assert env.name == "customer-prod"

    def test_name_too_long(self):
        """Test name exceeding max length fails."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="a" * 65)

    def test_name_with_uppercase(self):
        """Test uppercase name fails validation."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="Production")

    def test_name_starting_with_hyphen(self):
        """Test name starting with hyphen fails."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="-invalid")

    def test_name_ending_with_hyphen(self):
        """Test name ending with hyphen fails."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="invalid-")

    def test_name_with_special_chars(self):
        """Test name with special characters fails."""
        with pytest.raises(ValidationError):
            EnvironmentCreate(name="invalid_name")


class TestEnvironmentResponse:
    """Tests for EnvironmentResponse schema."""

    def test_valid_response(self):
        """Test creating valid response."""
        response = EnvironmentResponse(
            id=uuid4(),
            name="production",
            user_ca_fingerprint="SHA256:abc123",
            host_ca_fingerprint="SHA256:def456",
            default_user_cert_validity="8h",
            default_host_cert_validity="90d",
            created_at=datetime.now(timezone.utc),
        )

        assert response.name == "production"
        assert response.has_old_user_ca is False
        assert response.has_old_host_ca is False

    def test_response_with_rotation(self):
        """Test response with CA rotation in progress."""
        response = EnvironmentResponse(
            id=uuid4(),
            name="production",
            user_ca_fingerprint="SHA256:abc123",
            host_ca_fingerprint="SHA256:def456",
            default_user_cert_validity="8h",
            default_host_cert_validity="90d",
            created_at=datetime.now(timezone.utc),
            has_old_user_ca=True,
        )

        assert response.has_old_user_ca is True


class TestEnvironmentListResponse:
    """Tests for EnvironmentListResponse schema."""

    def test_empty_list(self):
        """Test empty environment list."""
        response = EnvironmentListResponse(environments=[], total=0)

        assert len(response.environments) == 0
        assert response.total == 0

    def test_list_with_environments(self):
        """Test list with environments."""
        env1 = EnvironmentResponse(
            id=uuid4(),
            name="prod",
            user_ca_fingerprint="SHA256:abc",
            host_ca_fingerprint="SHA256:def",
            default_user_cert_validity="8h",
            default_host_cert_validity="90d",
            created_at=datetime.now(timezone.utc),
        )

        response = EnvironmentListResponse(environments=[env1], total=1)

        assert len(response.environments) == 1
        assert response.total == 1


class TestCAPublicKeyResponse:
    """Tests for CAPublicKeyResponse schema."""

    def test_current_key_only(self):
        """Test response with only current key."""
        response = CAPublicKeyResponse(
            environment="production",
            ca_type=CertTypeEnum.USER,
            public_key="ssh-ed25519 AAAA...",
            fingerprint="SHA256:abc123",
        )

        assert response.old_public_key is None
        assert response.old_fingerprint is None
        assert response.old_expires_at is None

    def test_with_old_key(self):
        """Test response with old key during rotation."""
        response = CAPublicKeyResponse(
            environment="production",
            ca_type=CertTypeEnum.USER,
            public_key="ssh-ed25519 AAAA...",
            fingerprint="SHA256:abc123",
            old_public_key="ssh-ed25519 BBBB...",
            old_fingerprint="SHA256:old456",
            old_expires_at=datetime.now(timezone.utc),
        )

        assert response.old_public_key is not None
        assert response.old_fingerprint is not None


class TestUserCertificateRequest:
    """Tests for UserCertificateRequest schema."""

    def test_valid_request(self):
        """Test valid user certificate request."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["deploy", "admin"],
            key_id="user@example.com",
        )

        assert len(request.principals) == 2
        assert request.validity is None

    def test_request_with_all_options(self):
        """Test request with all options."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["deploy"],
            key_id="user@example.com",
            validity="12h",
            force_command="/usr/bin/deploy.sh",
        )

        assert request.validity == "12h"
        assert request.force_command == "/usr/bin/deploy.sh"

    def test_invalid_public_key(self):
        """Test invalid public key format fails."""
        with pytest.raises(ValidationError) as exc_info:
            UserCertificateRequest(
                public_key="not-a-valid-key",
                principals=["user"],
                key_id="user@example.com",
            )

        assert "Invalid SSH public key format" in str(exc_info.value)

    def test_empty_principals(self):
        """Test empty principals list fails."""
        with pytest.raises(ValidationError):
            UserCertificateRequest(
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
                principals=[],
                key_id="user@example.com",
            )

    def test_rsa_key_accepted(self):
        """Test RSA key is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB... user@host",
            principals=["user"],
            key_id="user@example.com",
        )

        assert request.public_key.startswith("ssh-rsa")

    def test_ecdsa_key_accepted(self):
        """Test ECDSA key is accepted."""
        request = UserCertificateRequest(
            public_key="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHA... user@host",
            principals=["user"],
            key_id="user@example.com",
        )

        assert request.public_key.startswith("ecdsa-sha2-")

    def test_key_whitespace_stripped(self):
        """Test whitespace is stripped from key."""
        request = UserCertificateRequest(
            public_key="  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host  ",
            principals=["user"],
            key_id="user@example.com",
        )

        assert not request.public_key.startswith(" ")
        assert not request.public_key.endswith(" ")


class TestKeyIdValidation:
    """Tests for key_id field validation in certificate requests."""

    def test_valid_email_key_id(self):
        """Test email format key_id is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="user@example.com",
        )
        assert request.key_id == "user@example.com"

    def test_valid_alphanumeric_key_id(self):
        """Test alphanumeric key_id is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="user123",
        )
        assert request.key_id == "user123"

    def test_valid_key_id_with_dots(self):
        """Test key_id with dots is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="user.name.test",
        )
        assert request.key_id == "user.name.test"

    def test_valid_key_id_with_underscore(self):
        """Test key_id with underscore is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="service_account",
        )
        assert request.key_id == "service_account"

    def test_valid_key_id_with_hyphen(self):
        """Test key_id with hyphen is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="my-key-id",
        )
        assert request.key_id == "my-key-id"

    def test_valid_key_id_with_plus(self):
        """Test key_id with plus sign is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="user+tag@example.com",
        )
        assert request.key_id == "user+tag@example.com"

    def test_valid_complex_key_id(self):
        """Test key_id with multiple allowed characters."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="user.name-123+tag@sub.example.com",
        )
        assert request.key_id == "user.name-123+tag@sub.example.com"

    def test_invalid_key_id_with_space(self):
        """Test key_id with space is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            UserCertificateRequest(
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
                principals=["user"],
                key_id="user name",
            )
        assert "pattern" in str(exc_info.value).lower() or "string" in str(exc_info.value).lower()

    def test_invalid_key_id_with_special_chars(self):
        """Test key_id with disallowed special characters is rejected."""
        invalid_chars = ["!", "#", "$", "%", "^", "&", "*", "(", ")", "=", "[", "]", "{", "}", "|", "\\", ";", ":", "'", '"', "<", ">", ",", "/", "?"]
        for char in invalid_chars:
            with pytest.raises(ValidationError):
                UserCertificateRequest(
                    public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
                    principals=["user"],
                    key_id=f"user{char}test",
                )

    def test_key_id_empty_rejected(self):
        """Test empty key_id is rejected."""
        with pytest.raises(ValidationError):
            UserCertificateRequest(
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
                principals=["user"],
                key_id="",
            )

    def test_key_id_too_long_rejected(self):
        """Test key_id exceeding max length is rejected."""
        with pytest.raises(ValidationError):
            UserCertificateRequest(
                public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
                principals=["user"],
                key_id="a" * 257,  # Max is 256
            )

    def test_key_id_max_length_accepted(self):
        """Test key_id at max length is accepted."""
        max_key_id = "a" * 256
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id=max_key_id,
        )
        assert len(request.key_id) == 256

    def test_key_id_single_char_accepted(self):
        """Test single character key_id is accepted."""
        request = UserCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
            principals=["user"],
            key_id="a",
        )
        assert request.key_id == "a"


class TestHostCertificateRequest:
    """Tests for HostCertificateRequest schema."""

    def test_valid_request(self):
        """Test valid host certificate request."""
        request = HostCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... root@server",
            principals=["server1.example.com", "10.0.0.5"],
        )

        assert len(request.principals) == 2
        assert request.validity is None

    def test_request_with_validity(self):
        """Test request with custom validity."""
        request = HostCertificateRequest(
            public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... root@server",
            principals=["server1.example.com"],
            validity="180d",
        )

        assert request.validity == "180d"

    def test_invalid_public_key(self):
        """Test invalid public key format fails."""
        with pytest.raises(ValidationError):
            HostCertificateRequest(
                public_key="invalid-key",
                principals=["server.example.com"],
            )


class TestCertificateResponse:
    """Tests for CertificateResponse schema."""

    def test_active_certificate(self):
        """Test active certificate response."""
        now = datetime.now(timezone.utc)
        response = CertificateResponse(
            id=uuid4(),
            serial=12345,
            cert_type=CertTypeEnum.USER,
            key_id="user@example.com",
            principals=["deploy", "admin"],
            valid_after=now,
            valid_before=now,
            public_key_fingerprint="SHA256:abc123",
            issued_at=now,
            issued_by="operator",
        )

        assert response.revoked_at is None
        assert response.certificate is None

    def test_revoked_certificate(self):
        """Test revoked certificate response."""
        now = datetime.now(timezone.utc)
        response = CertificateResponse(
            id=uuid4(),
            serial=12345,
            cert_type=CertTypeEnum.USER,
            key_id="user@example.com",
            principals=["deploy"],
            valid_after=now,
            valid_before=now,
            public_key_fingerprint="SHA256:abc123",
            issued_at=now,
            issued_by="operator",
            revoked_at=now,
            revoked_by="admin",
            revocation_reason="Key compromised",
        )

        assert response.revoked_at is not None
        assert response.revoked_by == "admin"

    def test_certificate_with_cert_data(self):
        """Test certificate response includes cert data when signing."""
        now = datetime.now(timezone.utc)
        response = CertificateResponse(
            id=uuid4(),
            serial=12345,
            cert_type=CertTypeEnum.USER,
            key_id="user@example.com",
            principals=["deploy"],
            valid_after=now,
            valid_before=now,
            public_key_fingerprint="SHA256:abc123",
            issued_at=now,
            issued_by="operator",
            certificate="ssh-ed25519-cert-v01@openssh.com AAAA...",
        )

        assert response.certificate is not None


class TestCertificateListResponse:
    """Tests for CertificateListResponse schema."""

    def test_empty_list(self):
        """Test empty certificate list."""
        response = CertificateListResponse(certificates=[], total=0)

        assert len(response.certificates) == 0


class TestRevokeRequest:
    """Tests for RevokeRequest schema."""

    def test_without_reason(self):
        """Test revoke request without reason."""
        request = RevokeRequest()

        assert request.reason is None

    def test_with_reason(self):
        """Test revoke request with reason."""
        request = RevokeRequest(reason="Key compromised")

        assert request.reason == "Key compromised"

    def test_reason_max_length(self):
        """Test reason max length enforcement."""
        with pytest.raises(ValidationError):
            RevokeRequest(reason="x" * 501)


class TestRotateCARequest:
    """Tests for RotateCARequest schema."""

    def test_default_values(self):
        """Test default values for rotation request."""
        request = RotateCARequest(ca_type=CertTypeEnum.USER)

        assert request.grace_period == "24h"
        assert request.key_type == KeyTypeEnum.ED25519

    def test_custom_values(self):
        """Test custom values for rotation request."""
        request = RotateCARequest(
            ca_type=CertTypeEnum.HOST,
            grace_period="7d",
            key_type=KeyTypeEnum.RSA,
        )

        assert request.ca_type == CertTypeEnum.HOST
        assert request.grace_period == "7d"
        assert request.key_type == KeyTypeEnum.RSA


class TestCARotationInfo:
    """Tests for CARotationInfo schema."""

    def test_not_rotating(self):
        """Test CA not in rotation."""
        info = CARotationInfo(
            rotating=False,
            fingerprint="SHA256:abc123",
        )

        assert info.rotating is False
        assert info.old_fingerprint is None

    def test_rotating(self):
        """Test CA in rotation."""
        info = CARotationInfo(
            rotating=True,
            fingerprint="SHA256:new123",
            old_fingerprint="SHA256:old456",
            old_expires_at=datetime.now(timezone.utc),
        )

        assert info.rotating is True
        assert info.old_fingerprint is not None


class TestRotationStatusResponse:
    """Tests for RotationStatusResponse schema."""

    def test_status_response(self):
        """Test rotation status response."""
        response = RotationStatusResponse(
            environment="production",
            user_ca=CARotationInfo(rotating=False, fingerprint="SHA256:user"),
            host_ca=CARotationInfo(rotating=True, fingerprint="SHA256:host"),
        )

        assert response.environment == "production"
        assert response.user_ca.rotating is False
        assert response.host_ca.rotating is True


class TestHealthResponse:
    """Tests for HealthResponse schema."""

    def test_healthy_response(self):
        """Test healthy response."""
        response = HealthResponse(
            status="healthy",
            version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )

        assert response.status == "healthy"

    def test_default_status(self):
        """Test default status is healthy."""
        response = HealthResponse(
            version="1.0.0",
            timestamp=datetime.now(timezone.utc),
        )

        assert response.status == "healthy"


class TestReadinessResponse:
    """Tests for ReadinessResponse schema."""

    def test_healthy_response(self):
        """Test healthy readiness response."""
        response = ReadinessResponse(
            status="healthy",
            database="healthy",
            keycloak="configured",
        )

        assert response.status == "healthy"

    def test_unhealthy_response(self):
        """Test unhealthy readiness response."""
        response = ReadinessResponse(
            status="unhealthy",
            database="unavailable",
            keycloak="not configured",
        )

        assert response.status == "unhealthy"


class TestErrorResponse:
    """Tests for ErrorResponse schema."""

    def test_error_with_detail_only(self):
        """Test error with detail only."""
        response = ErrorResponse(detail="Something went wrong")

        assert response.detail == "Something went wrong"
        assert response.code is None

    def test_error_with_code(self):
        """Test error with code."""
        response = ErrorResponse(
            detail="Environment not found",
            code="ENV_NOT_FOUND",
        )

        assert response.code == "ENV_NOT_FOUND"


class TestValidationErrorResponse:
    """Tests for ValidationErrorResponse schema."""

    def test_validation_error_response(self):
        """Test validation error response."""
        item = ValidationErrorItem(
            loc=["body", "name"],
            msg="field required",
            type="value_error.missing",
        )
        response = ValidationErrorResponse(detail=[item])

        assert len(response.detail) == 1
        assert response.detail[0].loc == ["body", "name"]


class TestValidationErrorItem:
    """Tests for ValidationErrorItem schema."""

    def test_error_item(self):
        """Test error item."""
        item = ValidationErrorItem(
            loc=["body", "principals", 0],
            msg="ensure this value has at least 1 characters",
            type="value_error.any_str.min_length",
        )

        assert item.loc[0] == "body"
        assert item.loc[2] == 0
