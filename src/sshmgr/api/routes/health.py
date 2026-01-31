"""Health check endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sshmgr import __version__
from sshmgr.api.dependencies import get_db_session, get_app_settings
from sshmgr.api.schemas import HealthResponse, ReadinessResponse
from sshmgr.config import Settings
from sshmgr.metrics import get_metrics, get_metrics_content_type

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Basic health check endpoint. Returns 200 if the service is running.",
)
async def health_check() -> HealthResponse:
    """Basic health check."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check",
    description="Checks if the service is ready to handle requests by verifying database connectivity.",
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "description": "Service not ready",
            "content": {
                "application/json": {
                    "example": {
                        "status": "unhealthy",
                        "database": "unavailable",
                        "keycloak": "unknown",
                    }
                }
            },
        }
    },
)
async def readiness_check(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> ReadinessResponse:
    """
    Readiness check.

    Verifies:
    - Database connectivity
    - Keycloak configuration (basic check)
    """
    db_status = "healthy"
    keycloak_status = "configured" if settings.keycloak_url else "not configured"

    # Check database
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    overall_status = "healthy" if db_status == "healthy" else "unhealthy"

    return ReadinessResponse(
        status=overall_status,
        database=db_status,
        keycloak=keycloak_status,
    )


@router.get(
    "/version",
    summary="Version info",
    description="Returns the API version.",
)
async def version_info() -> dict:
    """Get version information."""
    return {
        "version": __version__,
        "api_version": "v1",
    }


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    description="Returns Prometheus-formatted metrics.",
    include_in_schema=False,
)
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(
        content=get_metrics(),
        media_type=get_metrics_content_type(),
    )
