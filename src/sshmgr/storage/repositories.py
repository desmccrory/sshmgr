"""Repository classes for data access."""

from datetime import datetime, timedelta, timezone
from typing import Sequence
from uuid import UUID

from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sshmgr.core.exceptions import EnvironmentNotFoundError
from sshmgr.storage.models import Certificate, CertType, Environment, Policy


class EnvironmentRepository:
    """Repository for Environment CRUD operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        name: str,
        user_ca_public_key: str,
        user_ca_key_ref: str,
        host_ca_public_key: str,
        host_ca_key_ref: str,
        default_user_cert_validity: timedelta = timedelta(hours=8),
        default_host_cert_validity: timedelta = timedelta(days=90),
    ) -> Environment:
        """Create a new environment."""
        env = Environment(
            name=name,
            user_ca_public_key=user_ca_public_key,
            user_ca_key_ref=user_ca_key_ref,
            host_ca_public_key=host_ca_public_key,
            host_ca_key_ref=host_ca_key_ref,
            default_user_cert_validity=default_user_cert_validity,
            default_host_cert_validity=default_host_cert_validity,
        )
        self.session.add(env)
        await self.session.flush()
        return env

    async def get_by_id(self, env_id: UUID) -> Environment | None:
        """Get environment by ID."""
        result = await self.session.execute(
            select(Environment).where(Environment.id == env_id)
        )
        return result.scalar_one_or_none()

    async def get_by_id_or_raise(self, env_id: UUID) -> Environment:
        """Get environment by ID, raise if not found."""
        env = await self.get_by_id(env_id)
        if env is None:
            raise EnvironmentNotFoundError(f"Environment {env_id} not found")
        return env

    async def get_by_name(self, name: str) -> Environment | None:
        """Get environment by name."""
        result = await self.session.execute(
            select(Environment).where(Environment.name == name)
        )
        return result.scalar_one_or_none()

    async def get_by_name_or_raise(self, name: str) -> Environment:
        """Get environment by name, raise if not found."""
        env = await self.get_by_name(name)
        if env is None:
            raise EnvironmentNotFoundError(f"Environment '{name}' not found")
        return env

    async def list_all(self) -> Sequence[Environment]:
        """List all environments."""
        result = await self.session.execute(
            select(Environment).order_by(Environment.name)
        )
        return result.scalars().all()

    async def delete(self, env_id: UUID) -> bool:
        """Delete an environment by ID."""
        result = await self.session.execute(
            delete(Environment).where(Environment.id == env_id)
        )
        return result.rowcount > 0

    async def update(
        self,
        env_id: UUID,
        **kwargs,
    ) -> Environment | None:
        """Update an environment."""
        env = await self.get_by_id(env_id)
        if env is None:
            return None

        for key, value in kwargs.items():
            if hasattr(env, key):
                setattr(env, key, value)

        await self.session.flush()
        return env

    async def rotate_user_ca(
        self,
        env_id: UUID,
        new_public_key: str,
        new_key_ref: str,
        grace_period: timedelta = timedelta(hours=24),
    ) -> Environment:
        """
        Rotate the user CA, keeping the old one for the grace period.
        """
        env = await self.get_by_id_or_raise(env_id)

        # Move current to old
        env.old_user_ca_public_key = env.user_ca_public_key
        env.old_user_ca_key_ref = env.user_ca_key_ref
        env.old_user_ca_expires_at = datetime.now(timezone.utc) + grace_period

        # Set new
        env.user_ca_public_key = new_public_key
        env.user_ca_key_ref = new_key_ref

        await self.session.flush()
        return env

    async def rotate_host_ca(
        self,
        env_id: UUID,
        new_public_key: str,
        new_key_ref: str,
        grace_period: timedelta = timedelta(hours=24),
    ) -> Environment:
        """
        Rotate the host CA, keeping the old one for the grace period.
        """
        env = await self.get_by_id_or_raise(env_id)

        # Move current to old
        env.old_host_ca_public_key = env.host_ca_public_key
        env.old_host_ca_key_ref = env.host_ca_key_ref
        env.old_host_ca_expires_at = datetime.now(timezone.utc) + grace_period

        # Set new
        env.host_ca_public_key = new_public_key
        env.host_ca_key_ref = new_key_ref

        await self.session.flush()
        return env

    async def cleanup_expired_old_cas(self) -> int:
        """Remove expired old CA references."""
        now = datetime.now(timezone.utc)
        count = 0

        # Clean up expired user CAs
        result = await self.session.execute(
            update(Environment)
            .where(
                and_(
                    Environment.old_user_ca_expires_at.isnot(None),
                    Environment.old_user_ca_expires_at < now,
                )
            )
            .values(
                old_user_ca_public_key=None,
                old_user_ca_key_ref=None,
                old_user_ca_expires_at=None,
            )
        )
        count += result.rowcount

        # Clean up expired host CAs
        result = await self.session.execute(
            update(Environment)
            .where(
                and_(
                    Environment.old_host_ca_expires_at.isnot(None),
                    Environment.old_host_ca_expires_at < now,
                )
            )
            .values(
                old_host_ca_public_key=None,
                old_host_ca_key_ref=None,
                old_host_ca_expires_at=None,
            )
        )
        count += result.rowcount

        return count


class CertificateRepository:
    """Repository for Certificate audit log operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        environment_id: UUID,
        cert_type: CertType,
        serial: int,
        key_id: str,
        principals: list[str],
        valid_after: datetime,
        valid_before: datetime,
        public_key_fingerprint: str,
        issued_by: str,
    ) -> Certificate:
        """Record a newly issued certificate."""
        cert = Certificate(
            environment_id=environment_id,
            cert_type=cert_type,
            serial=serial,
            key_id=key_id,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            public_key_fingerprint=public_key_fingerprint,
            issued_by=issued_by,
        )
        self.session.add(cert)
        await self.session.flush()
        return cert

    async def get_by_id(self, cert_id: UUID) -> Certificate | None:
        """Get certificate by ID."""
        result = await self.session.execute(
            select(Certificate).where(Certificate.id == cert_id)
        )
        return result.scalar_one_or_none()

    async def get_by_serial(
        self, environment_id: UUID, serial: int
    ) -> Certificate | None:
        """Get certificate by environment and serial number."""
        result = await self.session.execute(
            select(Certificate).where(
                and_(
                    Certificate.environment_id == environment_id,
                    Certificate.serial == serial,
                )
            )
        )
        return result.scalar_one_or_none()

    async def list_by_environment(
        self,
        environment_id: UUID,
        cert_type: CertType | None = None,
        include_expired: bool = False,
        include_revoked: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[Certificate]:
        """List certificates for an environment."""
        query = select(Certificate).where(
            Certificate.environment_id == environment_id
        )

        if cert_type is not None:
            query = query.where(Certificate.cert_type == cert_type)

        if not include_expired:
            query = query.where(
                Certificate.valid_before > datetime.now(timezone.utc)
            )

        if not include_revoked:
            query = query.where(Certificate.revoked_at.is_(None))

        query = query.order_by(Certificate.issued_at.desc())
        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return result.scalars().all()

    async def list_by_key_id(
        self,
        key_id: str,
        environment_id: UUID | None = None,
    ) -> Sequence[Certificate]:
        """Find certificates by key ID (e.g., email)."""
        query = select(Certificate).where(Certificate.key_id == key_id)

        if environment_id is not None:
            query = query.where(Certificate.environment_id == environment_id)

        query = query.order_by(Certificate.issued_at.desc())
        result = await self.session.execute(query)
        return result.scalars().all()

    async def revoke(
        self,
        cert_id: UUID,
        revoked_by: str,
        reason: str | None = None,
    ) -> Certificate | None:
        """Revoke a certificate."""
        cert = await self.get_by_id(cert_id)
        if cert is None:
            return None

        cert.revoked_at = datetime.now(timezone.utc)
        cert.revoked_by = revoked_by
        cert.revocation_reason = reason

        await self.session.flush()
        return cert

    async def count_by_environment(
        self,
        environment_id: UUID,
        cert_type: CertType | None = None,
    ) -> int:
        """Count certificates for an environment."""
        from sqlalchemy import func

        query = select(func.count(Certificate.id)).where(
            Certificate.environment_id == environment_id
        )

        if cert_type is not None:
            query = query.where(Certificate.cert_type == cert_type)

        result = await self.session.execute(query)
        return result.scalar_one()

    async def get_max_serial(self, environment_id: UUID) -> int:
        """Get the highest serial number for an environment."""
        from sqlalchemy import func

        result = await self.session.execute(
            select(func.max(Certificate.serial)).where(
                Certificate.environment_id == environment_id
            )
        )
        return result.scalar_one() or 0


class PolicyRepository:
    """Repository for Policy operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        environment_id: UUID,
        name: str,
        cert_type: CertType,
        allowed_principals: list[str],
        max_validity: timedelta,
        extensions: list[str] | None = None,
        force_command: str | None = None,
        source_addresses: list[str] | None = None,
    ) -> Policy:
        """Create a new policy."""
        policy = Policy(
            environment_id=environment_id,
            name=name,
            cert_type=cert_type,
            allowed_principals=allowed_principals,
            max_validity=max_validity,
            extensions=extensions,
            force_command=force_command,
            source_addresses=source_addresses,
        )
        self.session.add(policy)
        await self.session.flush()
        return policy

    async def get_by_id(self, policy_id: UUID) -> Policy | None:
        """Get policy by ID."""
        result = await self.session.execute(
            select(Policy).where(Policy.id == policy_id)
        )
        return result.scalar_one_or_none()

    async def get_by_name(
        self, environment_id: UUID, name: str
    ) -> Policy | None:
        """Get policy by environment and name."""
        result = await self.session.execute(
            select(Policy).where(
                and_(
                    Policy.environment_id == environment_id,
                    Policy.name == name,
                )
            )
        )
        return result.scalar_one_or_none()

    async def list_by_environment(
        self,
        environment_id: UUID,
        cert_type: CertType | None = None,
        active_only: bool = True,
    ) -> Sequence[Policy]:
        """List policies for an environment."""
        query = select(Policy).where(Policy.environment_id == environment_id)

        if cert_type is not None:
            query = query.where(Policy.cert_type == cert_type)

        if active_only:
            query = query.where(Policy.is_active == True)

        query = query.order_by(Policy.name)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def update(self, policy_id: UUID, **kwargs) -> Policy | None:
        """Update a policy."""
        policy = await self.get_by_id(policy_id)
        if policy is None:
            return None

        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)

        await self.session.flush()
        return policy

    async def delete(self, policy_id: UUID) -> bool:
        """Delete a policy."""
        result = await self.session.execute(
            delete(Policy).where(Policy.id == policy_id)
        )
        return result.rowcount > 0

    async def deactivate(self, policy_id: UUID) -> Policy | None:
        """Deactivate a policy without deleting it."""
        return await self.update(policy_id, is_active=False)
