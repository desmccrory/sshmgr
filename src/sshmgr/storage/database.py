"""Database configuration and session management."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from sshmgr.config import Settings, get_settings

# Naming conventions for constraints (helps with migrations)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    metadata = MetaData(naming_convention=convention)


class Database:
    """
    Database connection manager.

    Handles async engine and session creation for SQLAlchemy 2.0.
    """

    def __init__(self, settings: Settings | None = None):
        """
        Initialize database with settings.

        Args:
            settings: Application settings. Uses default if not provided.
        """
        self.settings = settings or get_settings()
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    @property
    def engine(self) -> AsyncEngine:
        """Get or create the async engine."""
        if self._engine is None:
            self._engine = create_async_engine(
                self.settings.database_url,
                echo=self.settings.database_echo,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
            )
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = async_sessionmaker(
                bind=self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )
        return self._session_factory

    async def create_all(self) -> None:
        """Create all tables. Use only for testing."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        """Drop all tables. Use only for testing."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def close(self) -> None:
        """Close the database engine."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get an async database session.

        Usage:
            async with db.session() as session:
                result = await session.execute(...)
        """
        session = self.session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Dependency injection helper for FastAPI.

        Usage:
            @app.get("/")
            async def endpoint(session: AsyncSession = Depends(db.get_session)):
                ...
        """
        async with self.session() as session:
            yield session


# Global database instance (initialized on first use)
_db: Database | None = None


def get_database(settings: Settings | None = None) -> Database:
    """Get or create the global database instance."""
    global _db
    if _db is None:
        _db = Database(settings)
    return _db


async def init_database(settings: Settings | None = None) -> Database:
    """Initialize and return the database."""
    return get_database(settings)


async def close_database() -> None:
    """Close the global database connection."""
    global _db
    if _db is not None:
        await _db.close()
        _db = None
