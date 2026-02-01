"""Tests for sshmgr.config module."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from sshmgr.config import Settings, TestSettings, get_settings, get_test_settings
from sshmgr.keys.encrypted import EncryptedKeyStorage


class TestMasterKeyValidation:
    """Tests for master_key field validation."""

    def test_empty_master_key_allowed(self):
        """Test empty master key is allowed (unconfigured state)."""
        with patch.dict(os.environ, {"SSHMGR_MASTER_KEY": ""}, clear=False):
            settings = Settings(
                master_key="",
                database_url="postgresql+asyncpg://test:test@localhost/test",
            )
        assert settings.master_key == ""

    def test_valid_fernet_key_accepted(self):
        """Test valid Fernet key is accepted."""
        valid_key = EncryptedKeyStorage.generate_master_key()
        settings = Settings(
            master_key=valid_key,
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.master_key == valid_key

    def test_invalid_base64_rejected(self):
        """Test invalid base64 is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                master_key="not-valid-base64!!!",
                database_url="postgresql+asyncpg://test:test@localhost/test",
            )
        assert "valid Fernet key" in str(exc_info.value)

    def test_wrong_length_key_rejected(self):
        """Test key with wrong length is rejected."""
        # Too short - valid base64 but not 32 bytes
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                master_key="dG9vLXNob3J0",  # "too-short" in base64
                database_url="postgresql+asyncpg://test:test@localhost/test",
            )
        assert "valid Fernet key" in str(exc_info.value)

    def test_fernet_key_exactly_44_chars(self):
        """Test Fernet keys are exactly 44 characters."""
        valid_key = EncryptedKeyStorage.generate_master_key()
        assert len(valid_key) == 44

        settings = Settings(
            master_key=valid_key,
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert len(settings.master_key) == 44


class TestCORSSettings:
    """Tests for CORS configuration settings."""

    def test_cors_origins_default_empty(self):
        """Test CORS origins default to empty list."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_origins == []

    def test_cors_origins_from_string(self):
        """Test CORS origins parsed from comma-separated string."""
        # Pass string directly to test the validator
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            cors_origins="http://localhost:3000,http://localhost:5173",
        )
        assert settings.cors_origins == ["http://localhost:3000", "http://localhost:5173"]

    def test_cors_origins_empty_string(self):
        """Test empty string results in empty list."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            cors_origins="",
        )
        assert settings.cors_origins == []

    def test_cors_origins_whitespace_stripped(self):
        """Test whitespace is stripped from origins."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            cors_origins=" http://localhost:3000 , http://localhost:5173 ",
        )
        assert settings.cors_origins == ["http://localhost:3000", "http://localhost:5173"]

    def test_cors_origins_as_list(self):
        """Test CORS origins can be passed as list."""
        settings = Settings(
            cors_origins=["http://localhost:3000"],
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_origins == ["http://localhost:3000"]

    def test_cors_allow_credentials_default_false(self):
        """Test CORS allow credentials defaults to false."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_allow_credentials is False

    def test_cors_allow_methods_default(self):
        """Test CORS allow methods defaults."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_allow_methods == ["GET", "POST", "DELETE"]

    def test_cors_allow_methods_from_string(self):
        """Test CORS allow methods parsed from string."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            cors_allow_methods="GET,POST,PUT,DELETE",
        )
        assert settings.cors_allow_methods == ["GET", "POST", "PUT", "DELETE"]

    def test_cors_allow_headers_default(self):
        """Test CORS allow headers defaults."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_allow_headers == ["Authorization", "Content-Type"]

    def test_cors_max_age_default(self):
        """Test CORS max age default value."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.cors_max_age == 600


class TestRateLimitSettings:
    """Tests for rate limiting configuration."""

    def test_rate_limit_enabled_default_true(self):
        """Test rate limiting is enabled by default."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.rate_limit_enabled is True

    def test_rate_limit_requests_default(self):
        """Test rate limit requests default value."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.rate_limit_requests == 100

    def test_rate_limit_window_seconds_default(self):
        """Test rate limit window seconds default value."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.rate_limit_window_seconds == 60

    def test_rate_limit_burst_default(self):
        """Test rate limit burst default value."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.rate_limit_burst == 20

    def test_rate_limit_custom_values(self):
        """Test custom rate limit values."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
            rate_limit_enabled=False,
            rate_limit_requests=50,
            rate_limit_window_seconds=120,
            rate_limit_burst=10,
        )
        assert settings.rate_limit_enabled is False
        assert settings.rate_limit_requests == 50
        assert settings.rate_limit_window_seconds == 120
        assert settings.rate_limit_burst == 10


class TestCertificateDefaults:
    """Tests for certificate default settings."""

    def test_default_user_cert_validity_hours(self):
        """Test default user cert validity hours."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.default_user_cert_validity_hours == 8

    def test_default_host_cert_validity_days(self):
        """Test default host cert validity days."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.default_host_cert_validity_days == 90


class TestDatabaseSettings:
    """Tests for database configuration."""

    def test_sync_database_url_conversion(self):
        """Test sync database URL removes asyncpg driver."""
        settings = Settings(
            database_url="postgresql+asyncpg://user:pass@localhost/db",
        )
        assert settings.sync_database_url == "postgresql://user:pass@localhost/db"

    def test_database_echo_default_false(self):
        """Test database echo defaults to false."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.database_echo is False


class TestLoggingSettings:
    """Tests for logging configuration."""

    def test_log_level_default(self):
        """Test log level defaults to INFO."""
        settings = Settings(
            database_url="postgresql+asyncpg://test:test@localhost/test",
        )
        assert settings.log_level == "INFO"

    def test_log_format_field_default(self):
        """Test log format field has 'text' as default in the schema."""
        # Check the field info directly to verify the default value
        field = Settings.model_fields["log_format"]
        assert field.default == "text"

    def test_log_level_valid_values(self):
        """Test valid log level values."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            settings = Settings(
                database_url="postgresql+asyncpg://test:test@localhost/test",
                log_level=level,
            )
            assert settings.log_level == level

    def test_log_format_valid_values(self):
        """Test valid log format values."""
        for fmt in ["text", "json"]:
            settings = Settings(
                database_url="postgresql+asyncpg://test:test@localhost/test",
                log_format=fmt,
            )
            assert settings.log_format == fmt


class TestTestSettings:
    """Tests for TestSettings class."""

    def test_test_settings_uses_sqlite(self):
        """Test TestSettings uses SQLite by default."""
        settings = TestSettings()
        assert "sqlite" in settings.database_url

    def test_test_settings_has_master_key(self):
        """Test TestSettings has a test master key."""
        settings = TestSettings()
        assert settings.master_key != ""

    def test_test_settings_different_env_prefix(self):
        """Test TestSettings uses different env prefix."""
        assert TestSettings.model_config["env_prefix"] == "SSHMGR_TEST_"


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_returns_settings(self):
        """Test get_settings returns a Settings instance."""
        # Clear cache to get fresh settings
        get_settings.cache_clear()
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_get_settings_cached(self):
        """Test get_settings returns cached instance."""
        get_settings.cache_clear()
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2


class TestGetTestSettings:
    """Tests for get_test_settings function."""

    def test_get_test_settings_returns_test_settings(self):
        """Test get_test_settings returns TestSettings instance."""
        settings = get_test_settings()
        assert isinstance(settings, TestSettings)

    def test_get_test_settings_not_cached(self):
        """Test get_test_settings returns new instance each time."""
        settings1 = get_test_settings()
        settings2 = get_test_settings()
        # Objects should be equal but not the same instance
        assert settings1 is not settings2
