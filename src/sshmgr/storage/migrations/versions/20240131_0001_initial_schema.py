"""Initial schema - environments, certificates, policies.

Revision ID: 0001
Revises:
Create Date: 2024-01-31 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create cert_type enum
    cert_type_enum = postgresql.ENUM("user", "host", name="cert_type", create_type=False)
    cert_type_enum.create(op.get_bind(), checkfirst=True)

    # Create environments table
    op.create_table(
        "environments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True, index=True),
        # User CA
        sa.Column("user_ca_public_key", sa.Text(), nullable=False),
        sa.Column("user_ca_key_ref", sa.Text(), nullable=False),
        # Host CA
        sa.Column("host_ca_public_key", sa.Text(), nullable=False),
        sa.Column("host_ca_key_ref", sa.Text(), nullable=False),
        # Default validity
        sa.Column(
            "default_user_cert_validity",
            sa.Interval(),
            nullable=False,
            server_default=sa.text("'8 hours'"),
        ),
        sa.Column(
            "default_host_cert_validity",
            sa.Interval(),
            nullable=False,
            server_default=sa.text("'90 days'"),
        ),
        # Old CA for rotation
        sa.Column("old_user_ca_public_key", sa.Text(), nullable=True),
        sa.Column("old_user_ca_key_ref", sa.Text(), nullable=True),
        sa.Column("old_user_ca_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("old_host_ca_public_key", sa.Text(), nullable=True),
        sa.Column("old_host_ca_key_ref", sa.Text(), nullable=True),
        sa.Column("old_host_ca_expires_at", sa.DateTime(timezone=True), nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Create certificates table
    op.create_table(
        "certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "environment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "cert_type",
            postgresql.ENUM("user", "host", name="cert_type", create_type=False),
            nullable=False,
        ),
        sa.Column("serial", sa.Integer(), nullable=False),
        sa.Column("key_id", sa.String(255), nullable=False, index=True),
        sa.Column("principals", postgresql.ARRAY(sa.String(255)), nullable=False),
        sa.Column("valid_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_before", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("public_key_fingerprint", sa.String(100), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("issued_by", sa.String(255), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        # Unique constraint on environment + serial
        sa.UniqueConstraint("environment_id", "serial", name="uq_environment_serial"),
    )

    # Create policies table
    op.create_table(
        "policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "environment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("environments.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "cert_type",
            postgresql.ENUM("user", "host", name="cert_type", create_type=False),
            nullable=False,
        ),
        sa.Column("allowed_principals", postgresql.ARRAY(sa.String(255)), nullable=False),
        sa.Column("max_validity", sa.Interval(), nullable=False),
        sa.Column("extensions", postgresql.ARRAY(sa.String(255)), nullable=True),
        sa.Column("force_command", sa.Text(), nullable=True),
        sa.Column("source_addresses", postgresql.ARRAY(sa.String(50)), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # Unique constraint on environment + name
        sa.UniqueConstraint("environment_id", "name", name="uq_environment_policy_name"),
    )


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("certificates")
    op.drop_table("environments")

    # Drop enum type
    postgresql.ENUM(name="cert_type").drop(op.get_bind(), checkfirst=True)
