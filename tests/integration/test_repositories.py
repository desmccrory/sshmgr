"""Integration tests for repository classes using SQLite."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from sshmgr.storage.database import Base
from sshmgr.storage.models import CertType, Environment
from sshmgr.storage.repositories import (
    CertificateRepository,
    EnvironmentRepository,
    PolicyRepository,
)


# Use SQLite for testing (avoids PostgreSQL-specific features in tests)
# Note: Some PostgreSQL features (ARRAY) won't work with SQLite
# These tests focus on basic CRUD operations


@pytest_asyncio.fixture
async def async_engine():
    """Create an async SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )

    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def session(async_engine):
    """Create an async session for testing."""
    session_factory = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session


@pytest.fixture
def env_repo(session):
    """Create an environment repository."""
    return EnvironmentRepository(session)


@pytest.fixture
def cert_repo(session):
    """Create a certificate repository."""
    return CertificateRepository(session)


@pytest.fixture
def policy_repo(session):
    """Create a policy repository."""
    return PolicyRepository(session)


class TestEnvironmentRepository:
    """Tests for EnvironmentRepository."""

    @pytest.mark.asyncio
    async def test_create_environment(self, env_repo, session):
        """Create an environment."""
        env = await env_repo.create(
            name="test-prod",
            user_ca_public_key="ssh-ed25519 AAAA... user",
            user_ca_key_ref="encrypted:user123",
            host_ca_public_key="ssh-ed25519 AAAA... host",
            host_ca_key_ref="encrypted:host456",
        )

        assert env.id is not None
        assert env.name == "test-prod"

    @pytest.mark.asyncio
    async def test_get_by_id(self, env_repo, session):
        """Get environment by ID."""
        created = await env_repo.create(
            name="env1",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()

        found = await env_repo.get_by_id(created.id)
        assert found is not None
        assert found.name == "env1"

    @pytest.mark.asyncio
    async def test_get_by_id_not_found(self, env_repo):
        """Get non-existent environment returns None."""
        result = await env_repo.get_by_id(uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_get_by_name(self, env_repo, session):
        """Get environment by name."""
        await env_repo.create(
            name="production",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()

        found = await env_repo.get_by_name("production")
        assert found is not None
        assert found.name == "production"

    @pytest.mark.asyncio
    async def test_list_all(self, env_repo, session):
        """List all environments."""
        await env_repo.create(
            name="env-a",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await env_repo.create(
            name="env-b",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()

        envs = await env_repo.list_all()
        assert len(envs) == 2
        # Should be sorted by name
        assert envs[0].name == "env-a"
        assert envs[1].name == "env-b"

    @pytest.mark.asyncio
    async def test_delete(self, env_repo, session):
        """Delete an environment."""
        env = await env_repo.create(
            name="to-delete",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()
        env_id = env.id

        deleted = await env_repo.delete(env_id)
        await session.commit()

        assert deleted is True
        assert await env_repo.get_by_id(env_id) is None

    @pytest.mark.asyncio
    async def test_update(self, env_repo, session):
        """Update an environment."""
        env = await env_repo.create(
            name="update-test",
            user_ca_public_key="old-key",
            user_ca_key_ref="old-ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
            default_user_cert_validity=timedelta(hours=8),
        )
        await session.commit()

        updated = await env_repo.update(
            env.id,
            default_user_cert_validity=timedelta(hours=12),
        )
        await session.commit()

        assert updated.default_user_cert_validity == timedelta(hours=12)


class TestCertificateRepository:
    """Tests for CertificateRepository."""

    @pytest_asyncio.fixture
    async def test_env(self, env_repo, session):
        """Create a test environment."""
        env = await env_repo.create(
            name="cert-test-env",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()
        return env

    @pytest.mark.asyncio
    async def test_create_certificate(self, cert_repo, test_env, session):
        """Create a certificate record."""
        now = datetime.now(timezone.utc)
        cert = await cert_repo.create(
            environment_id=test_env.id,
            cert_type=CertType.USER,
            serial=1,
            key_id="test@example.com",
            principals=["user", "admin"],
            valid_after=now,
            valid_before=now + timedelta(hours=8),
            public_key_fingerprint="SHA256:abc123",
            issued_by="admin@example.com",
        )
        await session.commit()

        assert cert.id is not None
        assert cert.serial == 1

    @pytest.mark.asyncio
    async def test_get_by_serial(self, cert_repo, test_env, session):
        """Get certificate by serial number."""
        now = datetime.now(timezone.utc)
        await cert_repo.create(
            environment_id=test_env.id,
            cert_type=CertType.USER,
            serial=42,
            key_id="test",
            principals=["user"],
            valid_after=now,
            valid_before=now + timedelta(hours=8),
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
        )
        await session.commit()

        found = await cert_repo.get_by_serial(test_env.id, 42)
        assert found is not None
        assert found.serial == 42

    @pytest.mark.asyncio
    async def test_list_by_environment(self, cert_repo, test_env, session):
        """List certificates for an environment."""
        now = datetime.now(timezone.utc)

        # Create multiple certs
        for i in range(3):
            await cert_repo.create(
                environment_id=test_env.id,
                cert_type=CertType.USER,
                serial=i + 1,
                key_id=f"user{i}@example.com",
                principals=["user"],
                valid_after=now,
                valid_before=now + timedelta(hours=8),
                public_key_fingerprint=f"SHA256:xxx{i}",
                issued_by="admin",
            )
        await session.commit()

        certs = await cert_repo.list_by_environment(test_env.id)
        assert len(certs) == 3

    @pytest.mark.asyncio
    async def test_revoke_certificate(self, cert_repo, test_env, session):
        """Revoke a certificate."""
        now = datetime.now(timezone.utc)
        cert = await cert_repo.create(
            environment_id=test_env.id,
            cert_type=CertType.USER,
            serial=100,
            key_id="revoke-test",
            principals=["user"],
            valid_after=now,
            valid_before=now + timedelta(hours=8),
            public_key_fingerprint="SHA256:xxx",
            issued_by="admin",
        )
        await session.commit()

        revoked = await cert_repo.revoke(
            cert.id,
            revoked_by="security@example.com",
            reason="Key compromised",
        )
        await session.commit()

        assert revoked.is_revoked is True
        assert revoked.revoked_by == "security@example.com"

    @pytest.mark.asyncio
    async def test_get_max_serial(self, cert_repo, test_env, session):
        """Get maximum serial number."""
        now = datetime.now(timezone.utc)

        # Create certs with various serials
        for serial in [5, 10, 3, 8]:
            await cert_repo.create(
                environment_id=test_env.id,
                cert_type=CertType.USER,
                serial=serial,
                key_id=f"test{serial}",
                principals=["user"],
                valid_after=now,
                valid_before=now + timedelta(hours=8),
                public_key_fingerprint=f"SHA256:{serial}",
                issued_by="admin",
            )
        await session.commit()

        max_serial = await cert_repo.get_max_serial(test_env.id)
        assert max_serial == 10


class TestPolicyRepository:
    """Tests for PolicyRepository."""

    @pytest_asyncio.fixture
    async def test_env(self, env_repo, session):
        """Create a test environment."""
        env = await env_repo.create(
            name="policy-test-env",
            user_ca_public_key="key",
            user_ca_key_ref="ref",
            host_ca_public_key="key",
            host_ca_key_ref="ref",
        )
        await session.commit()
        return env

    @pytest.mark.asyncio
    async def test_create_policy(self, policy_repo, test_env, session):
        """Create a policy."""
        policy = await policy_repo.create(
            environment_id=test_env.id,
            name="default-user",
            cert_type=CertType.USER,
            allowed_principals=["*"],
            max_validity=timedelta(hours=8),
        )
        await session.commit()

        assert policy.id is not None
        assert policy.name == "default-user"
        assert policy.is_active is True

    @pytest.mark.asyncio
    async def test_get_by_name(self, policy_repo, test_env, session):
        """Get policy by name."""
        await policy_repo.create(
            environment_id=test_env.id,
            name="find-me",
            cert_type=CertType.USER,
            allowed_principals=["user"],
            max_validity=timedelta(hours=4),
        )
        await session.commit()

        found = await policy_repo.get_by_name(test_env.id, "find-me")
        assert found is not None
        assert found.name == "find-me"

    @pytest.mark.asyncio
    async def test_list_by_environment(self, policy_repo, test_env, session):
        """List policies for environment."""
        await policy_repo.create(
            environment_id=test_env.id,
            name="policy-a",
            cert_type=CertType.USER,
            allowed_principals=["*"],
            max_validity=timedelta(hours=8),
        )
        await policy_repo.create(
            environment_id=test_env.id,
            name="policy-b",
            cert_type=CertType.HOST,
            allowed_principals=["*"],
            max_validity=timedelta(days=90),
        )
        await session.commit()

        # All policies
        all_policies = await policy_repo.list_by_environment(test_env.id)
        assert len(all_policies) == 2

        # Filter by type
        user_policies = await policy_repo.list_by_environment(
            test_env.id, cert_type=CertType.USER
        )
        assert len(user_policies) == 1
        assert user_policies[0].name == "policy-a"

    @pytest.mark.asyncio
    async def test_deactivate_policy(self, policy_repo, test_env, session):
        """Deactivate a policy."""
        policy = await policy_repo.create(
            environment_id=test_env.id,
            name="to-deactivate",
            cert_type=CertType.USER,
            allowed_principals=["*"],
            max_validity=timedelta(hours=8),
        )
        await session.commit()

        deactivated = await policy_repo.deactivate(policy.id)
        await session.commit()

        assert deactivated.is_active is False

        # Should not appear in active-only listing
        active = await policy_repo.list_by_environment(test_env.id, active_only=True)
        assert len(active) == 0
