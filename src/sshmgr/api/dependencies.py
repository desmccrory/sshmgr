"""FastAPI dependencies for the API."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Annotated, AsyncGenerator

from fastapi import Depends, HTTPException, Path, status
from sqlalchemy.ext.asyncio import AsyncSession

from sshmgr.auth.rbac import AuthContext, get_current_user, RequireEnvironmentAccess, RequireRole, Role
from sshmgr.config import Settings, get_settings
from sshmgr.core.exceptions import EnvironmentNotFoundError
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.database import Database, get_database
from sshmgr.storage.models import Environment
from sshmgr.storage.repositories import CertificateRepository, EnvironmentRepository


# -----------------------------------------------------------------------------
# Settings and Database Dependencies
# -----------------------------------------------------------------------------


def get_app_settings() -> Settings:
    """Get application settings."""
    return get_settings()


async def get_db_session(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> AsyncGenerator[AsyncSession, None]:
    """Get a database session."""
    db = get_database(settings)
    async with db.session() as session:
        yield session


def get_key_storage(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> EncryptedKeyStorage:
    """Get encrypted key storage."""
    if not settings.master_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Master key not configured",
        )
    return EncryptedKeyStorage(settings.master_key)


# -----------------------------------------------------------------------------
# Repository Dependencies
# -----------------------------------------------------------------------------


async def get_env_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> EnvironmentRepository:
    """Get environment repository."""
    return EnvironmentRepository(session)


async def get_cert_repository(
    session: Annotated[AsyncSession, Depends(get_db_session)],
) -> CertificateRepository:
    """Get certificate repository."""
    return CertificateRepository(session)


# -----------------------------------------------------------------------------
# Environment Resolution Dependencies
# -----------------------------------------------------------------------------


async def get_environment_by_name(
    env_name: Annotated[str, Path(description="Environment name")],
    env_repo: Annotated[EnvironmentRepository, Depends(get_env_repository)],
) -> Environment:
    """
    Resolve environment by name from path parameter.

    Raises 404 if not found.
    """
    try:
        return await env_repo.get_by_name_or_raise(env_name)
    except EnvironmentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Environment '{env_name}' not found",
        )


# -----------------------------------------------------------------------------
# Authorization Dependencies
# -----------------------------------------------------------------------------


class RequireEnvAccess:
    """
    Dependency that checks both authentication and environment access.

    Combines get_current_user and RequireEnvironmentAccess into a single dependency.
    """

    def __init__(self, minimum_role: Role | None = None):
        self.minimum_role = minimum_role

    async def __call__(
        self,
        env_name: Annotated[str, Path(description="Environment name")],
        auth: Annotated[AuthContext, Depends(get_current_user)],
    ) -> AuthContext:
        # Check role if required
        if self.minimum_role and not auth.has_minimum_role(self.minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {self.minimum_role.value} role or higher",
            )

        # Check environment access
        if not auth.can_access_environment(env_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"No access to environment: {env_name}",
            )

        return auth


# Convenience instances
require_env_viewer = RequireEnvAccess(Role.VIEWER)
require_env_operator = RequireEnvAccess(Role.OPERATOR)
require_env_admin = RequireEnvAccess(Role.ADMIN)


# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------


def parse_validity(validity_str: str) -> timedelta:
    """
    Parse a validity string like '8h', '90d', '1w' into a timedelta.

    Supported units: s (seconds), m (minutes), h (hours), d (days), w (weeks)
    """
    match = re.match(r"^(\d+)([smhdw])$", validity_str.lower())
    if not match:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid validity format: {validity_str}. Use format like '8h', '90d', '1w'",
        )

    value = int(match.group(1))
    unit = match.group(2)

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
    }

    return timedelta(seconds=value * multipliers[unit])


def format_timedelta(td: timedelta) -> str:
    """Format a timedelta to a human-readable string."""
    total_seconds = int(td.total_seconds())

    if total_seconds >= 604800:  # weeks
        weeks = total_seconds // 604800
        return f"{weeks}w"
    elif total_seconds >= 86400:  # days
        days = total_seconds // 86400
        return f"{days}d"
    elif total_seconds >= 3600:  # hours
        hours = total_seconds // 3600
        return f"{hours}h"
    elif total_seconds >= 60:  # minutes
        minutes = total_seconds // 60
        return f"{minutes}m"
    else:
        return f"{total_seconds}s"
