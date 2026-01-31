"""Configuration management for sshmgr using pydantic-settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Environment variables are prefixed with SSHMGR_ (e.g., SSHMGR_DATABASE_URL).
    """

    model_config = SettingsConfigDict(
        env_prefix="SSHMGR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://sshmgr:sshmgr_dev_password@localhost:5432/sshmgr",
        description="PostgreSQL connection URL (async)",
    )
    database_echo: bool = Field(
        default=False,
        description="Echo SQL statements for debugging",
    )

    # Encryption
    master_key: str = Field(
        default="",
        description="Fernet key for encrypting CA private keys",
    )

    # Keycloak
    keycloak_url: str = Field(
        default="http://localhost:8080",
        description="Keycloak server URL",
    )
    keycloak_realm: str = Field(
        default="sshmgr",
        description="Keycloak realm name",
    )
    keycloak_client_id: str = Field(
        default="sshmgr-api",
        description="Keycloak client ID for API",
    )
    keycloak_client_secret: str = Field(
        default="",
        description="Keycloak client secret (for confidential client)",
    )

    # API
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    api_debug: bool = Field(default=False, description="Enable debug mode")

    # Certificate defaults
    default_user_cert_validity_hours: int = Field(
        default=8,
        description="Default validity for user certificates in hours",
    )
    default_host_cert_validity_days: int = Field(
        default=90,
        description="Default validity for host certificates in days",
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Log level",
    )
    log_format: Literal["json", "text"] = Field(
        default="text",
        description="Log output format",
    )

    @field_validator("master_key")
    @classmethod
    def validate_master_key(cls, v: str) -> str:
        """Validate master key if provided."""
        if v and len(v) != 44:
            raise ValueError(
                "master_key must be a valid Fernet key (44 characters). "
                "Generate one with: make generate-key"
            )
        return v

    @property
    def sync_database_url(self) -> str:
        """Get synchronous database URL for Alembic."""
        return self.database_url.replace("+asyncpg", "")


class TestSettings(Settings):
    """Settings for testing with SQLite."""

    model_config = SettingsConfigDict(
        env_prefix="SSHMGR_TEST_",
        extra="ignore",
    )

    database_url: str = "sqlite+aiosqlite:///:memory:"
    master_key: str = "dGVzdC1tYXN0ZXIta2V5LWZvci10ZXN0aW5nLW9ubHk="  # Test key


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def get_test_settings() -> TestSettings:
    """Get test settings instance (not cached)."""
    return TestSettings()
