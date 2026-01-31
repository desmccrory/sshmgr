"""FastAPI application for sshmgr REST API."""

from __future__ import annotations

import signal
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from sshmgr import __version__
from sshmgr.api.routes import certificates, environments, health
from sshmgr.config import get_settings
from sshmgr.logging import get_logger, init_logging
from sshmgr.metrics import create_metrics_middleware, set_environments_count
from sshmgr.storage.database import close_database, get_database

# Initialize logging
init_logging()
logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    logger.info("Starting sshmgr API", extra={"extra": {"version": __version__}})

    settings = get_settings()
    db = get_database(settings)

    # Verify database connection
    try:
        async with db.session() as session:
            await session.execute(text("SELECT 1"))
        logger.info("Database connection verified")
    except Exception as e:
        logger.warning(f"Database connection failed: {e}")

    # Update initial metrics
    try:
        from sshmgr.storage.repositories import EnvironmentRepository

        async with db.session() as session:
            env_repo = EnvironmentRepository(session)
            envs = await env_repo.list_all()
            set_environments_count(len(envs))
    except Exception:
        pass

    yield

    # Shutdown
    logger.info("Shutting down sshmgr API")
    await close_database()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="sshmgr API",
        description="SSH Certificate Management System API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Metrics middleware (must be added before CORS)
    MetricsMiddleware = create_metrics_middleware()
    app.add_middleware(MetricsMiddleware)

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Exception handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation errors with consistent format."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": [
                    {
                        "loc": list(error["loc"]),
                        "msg": error["msg"],
                        "type": error["type"],
                    }
                    for error in exc.errors()
                ]
            },
        )

    # Include routers
    app.include_router(
        health.router,
        prefix="/api/v1",
        tags=["Health"],
    )
    app.include_router(
        environments.router,
        prefix="/api/v1/environments",
        tags=["Environments"],
    )
    app.include_router(
        certificates.router,
        prefix="/api/v1/environments/{env_name}/certs",
        tags=["Certificates"],
    )

    return app


# Create the app instance
app = create_app()


def main() -> None:
    """Run the API server."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "sshmgr.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_debug,
    )


if __name__ == "__main__":
    main()
