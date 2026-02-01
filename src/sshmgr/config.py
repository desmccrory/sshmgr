"""Configuration management for sshmgr using pydantic-settings."""

from functools import lru_cache
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken
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

    # CORS
    cors_origins: list[str] = Field(
        default_factory=list,
        description="Allowed CORS origins (empty = allow none, ['*'] = allow all)",
    )
    cors_allow_credentials: bool = Field(
        default=False,
        description="Allow credentials in CORS requests",
    )
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "DELETE"],
        description="Allowed HTTP methods for CORS",
    )
    cors_allow_headers: list[str] = Field(
        default=["Authorization", "Content-Type"],
        description="Allowed headers for CORS",
    )
    cors_max_age: int = Field(
        default=600,
        description="CORS preflight cache max age in seconds",
    )

    # Rate Limiting
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting",
    )
    rate_limit_requests: int = Field(
        default=100,
        description="Maximum requests per window",
    )
    rate_limit_window_seconds: int = Field(
        default=60,
        description="Rate limit window in seconds",
    )
    rate_limit_burst: int = Field(
        default=20,
        description="Burst limit (extra requests allowed in short bursts)",
    )

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
        """Validate master key is a valid Fernet key."""
        if not v:
            return v
        # Validate by actually instantiating Fernet - catches invalid base64 and wrong length
        try:
            Fernet(v.encode())
        except (ValueError, InvalidToken) as e:
            raise ValueError(
                "master_key must be a valid Fernet key (base64-encoded 32-byte key). "
                "Generate one with: make generate-key"
            ) from e
        return v

    @field_validator("cors_origins", "cors_allow_methods", "cors_allow_headers", mode="before")
    @classmethod
    def parse_list_from_string(cls, v: str | list[str]) -> list[str]:
        """Parse comma-separated string into list."""
        if isinstance(v, str):
            if not v.strip():
                return []
            return [item.strip() for item in v.split(",")]
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
