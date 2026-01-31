"""Environment management commands for CLI."""

from __future__ import annotations

import re
from datetime import timedelta

import click

from sshmgr.cli.main import Context, async_command, handle_errors, pass_context
from sshmgr.cli.output import (
    console,
    create_table,
    format_timedelta,
    print_environment_details,
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
    spinner_context,
    OutputFormat,
)
from sshmgr.config import get_settings
from sshmgr.core.ca import CertificateAuthority, KeyType
from sshmgr.core.exceptions import EnvironmentNotFoundError
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.database import get_database
from sshmgr.storage.repositories import EnvironmentRepository


def parse_validity(validity_str: str) -> timedelta:
    """
    Parse a validity string like '8h', '90d', '1w' into a timedelta.

    Supported units: s (seconds), m (minutes), h (hours), d (days), w (weeks)
    """
    match = re.match(r"^(\d+)([smhdw])$", validity_str.lower())
    if not match:
        raise click.BadParameter(
            f"Invalid validity format: {validity_str}. Use format like '8h', '90d', '1w'"
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


@click.group("env")
def env_group():
    """Environment management commands."""
    pass


@env_group.command("init")
@click.argument("name")
@click.option(
    "--user-validity",
    default="8h",
    help="Default user certificate validity (e.g., 8h, 1d)",
)
@click.option(
    "--host-validity",
    default="90d",
    help="Default host certificate validity (e.g., 90d, 1y)",
)
@click.option(
    "--key-type",
    type=click.Choice(["ed25519", "rsa", "ecdsa"]),
    default="ed25519",
    help="Key type for CA keypairs",
)
@pass_context
@handle_errors
@async_command
async def init_env(
    ctx: Context,
    name: str,
    user_validity: str,
    host_validity: str,
    key_type: str,
):
    """
    Initialize a new environment with CA keypairs.

    Creates a new environment with separate user and host Certificate
    Authorities. The CA private keys are encrypted and stored in the database.

    Example:
        sshmgr env init customer-prod --user-validity 12h --host-validity 90d
    """
    settings = get_settings()

    # Validate master key is configured
    if not settings.master_key:
        print_error("SSHMGR_MASTER_KEY environment variable not set")
        print_info("Generate a key with: make generate-key")
        raise click.Abort()

    # Parse validity periods
    try:
        user_cert_validity = parse_validity(user_validity)
        host_cert_validity = parse_validity(host_validity)
    except click.BadParameter as e:
        print_error(str(e))
        raise click.Abort()

    # Validate name
    if not re.match(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$", name):
        print_error(
            "Environment name must be lowercase alphanumeric with hyphens, "
            "starting and ending with alphanumeric"
        )
        raise click.Abort()

    key_type_enum = KeyType(key_type)
    key_storage = EncryptedKeyStorage(settings.master_key)
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        # Check if environment already exists
        existing = await env_repo.get_by_name(name)
        if existing:
            print_error(f"Environment '{name}' already exists")
            raise click.Abort()

        # Generate CA keypairs
        with spinner_context("Generating User CA keypair..."):
            user_ca = CertificateAuthority.generate(key_type=key_type_enum)

        with spinner_context("Generating Host CA keypair..."):
            host_ca = CertificateAuthority.generate(key_type=key_type_enum)

        # Encrypt and store private keys
        # We'll use a placeholder UUID for now, then update after creation
        from uuid import uuid4

        temp_id = uuid4()
        user_ca_key_ref = key_storage.store_key(temp_id, "user_ca", user_ca.private_key)
        host_ca_key_ref = key_storage.store_key(temp_id, "host_ca", host_ca.private_key)

        # Create environment in database
        with spinner_context("Creating environment..."):
            env = await env_repo.create(
                name=name,
                user_ca_public_key=user_ca.public_key,
                user_ca_key_ref=user_ca_key_ref,
                host_ca_public_key=host_ca.public_key,
                host_ca_key_ref=host_ca_key_ref,
                default_user_cert_validity=user_cert_validity,
                default_host_cert_validity=host_cert_validity,
            )

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "id": str(env.id),
            "name": env.name,
            "user_ca_fingerprint": user_ca.fingerprint,
            "host_ca_fingerprint": host_ca.fingerprint,
            "default_user_cert_validity": str(user_cert_validity),
            "default_host_cert_validity": str(host_cert_validity),
        })
        return

    print_success(f"Environment '{name}' created successfully")
    console.print()
    console.print(f"[cyan]Environment ID:[/cyan]    {env.id}")
    console.print(f"[cyan]User CA fingerprint:[/cyan] {user_ca.fingerprint}")
    console.print(f"[cyan]Host CA fingerprint:[/cyan] {host_ca.fingerprint}")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Get User CA public key:  sshmgr env get-ca {name} --type user")
    console.print(f"  2. Get Host CA public key:  sshmgr env get-ca {name} --type host")
    console.print("  3. Distribute CA public keys to your infrastructure")


@env_group.command("list")
@pass_context
@handle_errors
@async_command
async def list_envs(ctx: Context):
    """List all environments."""
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        envs = await env_repo.list_all()

    if not envs:
        print_info("No environments found")
        console.print("\nRun [bold]sshmgr env init <name>[/bold] to create one")
        return

    if ctx.output_format == OutputFormat.JSON:
        print_json([
            {
                "id": str(env.id),
                "name": env.name,
                "created_at": env.created_at.isoformat() if env.created_at else None,
                "default_user_cert_validity": str(env.default_user_cert_validity),
                "default_host_cert_validity": str(env.default_host_cert_validity),
            }
            for env in envs
        ])
        return

    table = create_table(
        title="Environments",
        columns=[
            ("Name", "cyan"),
            ("User Cert Validity", ""),
            ("Host Cert Validity", ""),
            ("Created", "dim"),
        ],
    )

    for env in envs:
        created = env.created_at.strftime("%Y-%m-%d") if env.created_at else "—"
        table.add_row(
            env.name,
            format_timedelta(env.default_user_cert_validity),
            format_timedelta(env.default_host_cert_validity),
            created,
        )

    console.print(table)


@env_group.command("show")
@click.argument("name")
@pass_context
@handle_errors
@async_command
async def show_env(ctx: Context, name: str):
    """Show details of an environment."""
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        try:
            env = await env_repo.get_by_name_or_raise(name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{name}' not found")
            raise click.Abort()

    # Get fingerprints from public keys
    user_ca_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.user_ca_public_key)
    host_ca_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.host_ca_public_key)

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "id": str(env.id),
            "name": env.name,
            "created_at": env.created_at.isoformat() if env.created_at else None,
            "updated_at": env.updated_at.isoformat() if env.updated_at else None,
            "user_ca_fingerprint": user_ca_fingerprint,
            "host_ca_fingerprint": host_ca_fingerprint,
            "default_user_cert_validity": str(env.default_user_cert_validity),
            "default_host_cert_validity": str(env.default_host_cert_validity),
            "has_old_user_ca": env.old_user_ca_public_key is not None,
            "has_old_host_ca": env.old_host_ca_public_key is not None,
        })
        return

    print_environment_details({
        "id": str(env.id),
        "name": env.name,
        "created_at": env.created_at,
        "user_ca_fingerprint": user_ca_fingerprint,
        "host_ca_fingerprint": host_ca_fingerprint,
        "default_user_cert_validity": env.default_user_cert_validity,
        "default_host_cert_validity": env.default_host_cert_validity,
    })

    # Show rotation info if applicable
    if env.old_user_ca_public_key:
        console.print()
        print_warning(
            f"User CA rotation in progress (old CA expires: {env.old_user_ca_expires_at})"
        )
    if env.old_host_ca_public_key:
        console.print()
        print_warning(
            f"Host CA rotation in progress (old CA expires: {env.old_host_ca_expires_at})"
        )


@env_group.command("delete")
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
@pass_context
@handle_errors
@async_command
async def delete_env(ctx: Context, name: str, force: bool):
    """
    Delete an environment.

    This will permanently delete the environment and its CA keys.
    All certificates issued by this environment will become invalid.
    """
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        try:
            env = await env_repo.get_by_name_or_raise(name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{name}' not found")
            raise click.Abort()

        if not force:
            print_warning(f"You are about to delete environment '{name}'")
            console.print("This will:")
            console.print("  - Permanently delete the CA keypairs")
            console.print("  - Invalidate all certificates issued by this environment")
            console.print()
            if not click.confirm("Are you sure you want to continue?", default=False):
                print_info("Deletion cancelled")
                return

        with spinner_context(f"Deleting environment '{name}'..."):
            deleted = await env_repo.delete(env.id)

        if deleted:
            print_success(f"Environment '{name}' deleted")
        else:
            print_error("Failed to delete environment")
            raise click.Abort()


@env_group.command("get-ca")
@click.argument("name")
@click.option(
    "--type",
    "ca_type",
    type=click.Choice(["user", "host"]),
    required=True,
    help="CA type to retrieve",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (defaults to stdout)",
)
@click.option(
    "--include-old",
    is_flag=True,
    help="Also include the old CA if rotation is in progress",
)
@pass_context
@handle_errors
@async_command
async def get_ca(ctx: Context, name: str, ca_type: str, output: str | None, include_old: bool):
    """
    Get the CA public key for an environment.

    The public key can be used to:
    - Configure SSH servers to trust user certificates (user CA)
    - Configure SSH clients to trust host certificates (host CA)

    Example:
        sshmgr env get-ca customer-prod --type user > /etc/ssh/user_ca.pub
        sshmgr env get-ca customer-prod --type host >> ~/.ssh/known_hosts
    """
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        try:
            env = await env_repo.get_by_name_or_raise(name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{name}' not found")
            raise click.Abort()

    if ca_type == "user":
        public_key = env.user_ca_public_key
        old_public_key = env.old_user_ca_public_key if include_old else None
        old_expires = env.old_user_ca_expires_at
    else:
        public_key = env.host_ca_public_key
        old_public_key = env.old_host_ca_public_key if include_old else None
        old_expires = env.old_host_ca_expires_at

    if ctx.output_format == OutputFormat.JSON:
        result = {
            "environment": name,
            "ca_type": ca_type,
            "public_key": public_key,
            "fingerprint": CertificateAuthority.get_public_key_fingerprint(public_key),
        }
        if include_old and old_public_key:
            result["old_public_key"] = old_public_key
            result["old_fingerprint"] = CertificateAuthority.get_public_key_fingerprint(old_public_key)
            result["old_expires_at"] = old_expires.isoformat() if old_expires else None
        print_json(result)
        return

    content = public_key
    if include_old and old_public_key:
        content += f"\n# Old CA (expires: {old_expires})\n{old_public_key}"

    if output:
        with open(output, "w") as f:
            f.write(content + "\n")
        print_success(f"CA public key written to {output}")
        fingerprint = CertificateAuthority.get_public_key_fingerprint(public_key)
        console.print(f"[cyan]Fingerprint:[/cyan] {fingerprint}")
    else:
        console.print(content)
