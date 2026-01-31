"""CA rotation commands for CLI."""

from __future__ import annotations

from datetime import timedelta

import click

from sshmgr.cli.commands.environment import parse_validity
from sshmgr.cli.main import Context, async_command, handle_errors, pass_context
from sshmgr.cli.output import (
    console,
    format_datetime,
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


@click.group("rotate")
def rotate_group():
    """CA key rotation commands."""
    pass


@rotate_group.command("ca")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--type",
    "ca_type",
    type=click.Choice(["user", "host"]),
    required=True,
    help="Which CA to rotate",
)
@click.option(
    "--grace-period",
    "-g",
    default="24h",
    help="How long to keep the old CA valid (e.g., 24h, 7d)",
)
@click.option(
    "--key-type",
    type=click.Choice(["ed25519", "rsa", "ecdsa"]),
    default="ed25519",
    help="Key type for the new CA",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Skip confirmation prompt",
)
@pass_context
@handle_errors
@async_command
async def rotate_ca(
    ctx: Context,
    env_name: str,
    ca_type: str,
    grace_period: str,
    key_type: str,
    force: bool,
):
    """
    Rotate a CA key with a grace period.

    During rotation:
    - A new CA keypair is generated
    - The old CA is retained for the grace period
    - New certificates should be signed with the new CA
    - Infrastructure should be updated to trust both CAs

    After the grace period expires:
    - The old CA public key is removed
    - Certificates signed by the old CA become untrusted

    Example:
        sshmgr rotate ca -e prod --type user --grace-period 7d
    """
    settings = get_settings()

    if not settings.master_key:
        print_error("SSHMGR_MASTER_KEY environment variable not set")
        raise click.Abort()

    # Parse grace period
    try:
        grace_td = parse_validity(grace_period)
    except click.BadParameter as e:
        print_error(str(e))
        raise click.Abort()

    key_type_enum = KeyType(key_type)
    key_storage = EncryptedKeyStorage(settings.master_key)
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Check if rotation is already in progress
        if ca_type == "user" and env.old_user_ca_public_key:
            print_warning(
                f"User CA rotation already in progress "
                f"(old CA expires: {env.old_user_ca_expires_at})"
            )
            if not force and not click.confirm("Start a new rotation anyway?", default=False):
                return

        if ca_type == "host" and env.old_host_ca_public_key:
            print_warning(
                f"Host CA rotation already in progress "
                f"(old CA expires: {env.old_host_ca_expires_at})"
            )
            if not force and not click.confirm("Start a new rotation anyway?", default=False):
                return

        # Get current CA fingerprint
        if ca_type == "user":
            old_fingerprint = CertificateAuthority.get_public_key_fingerprint(
                env.user_ca_public_key
            )
        else:
            old_fingerprint = CertificateAuthority.get_public_key_fingerprint(
                env.host_ca_public_key
            )

        if not force:
            console.print(f"[bold]CA Rotation for {env_name}[/bold]")
            console.print(f"  CA Type:          {ca_type}")
            console.print(f"  Current CA:       {old_fingerprint}")
            console.print(f"  Grace Period:     {grace_period}")
            console.print(f"  New Key Type:     {key_type}")
            console.print()
            print_warning("After rotation, you must update your infrastructure to trust the new CA")
            console.print()
            if not click.confirm("Proceed with rotation?", default=False):
                print_info("Rotation cancelled")
                return

        # Generate new CA
        with spinner_context(f"Generating new {ca_type} CA..."):
            new_ca = CertificateAuthority.generate(key_type=key_type_enum)
            new_key_ref = key_storage.store_key(env.id, f"{ca_type}_ca", new_ca.private_key)

        # Perform rotation in database
        with spinner_context("Updating environment..."):
            if ca_type == "user":
                env = await env_repo.rotate_user_ca(
                    env_id=env.id,
                    new_public_key=new_ca.public_key,
                    new_key_ref=new_key_ref,
                    grace_period=grace_td,
                )
            else:
                env = await env_repo.rotate_host_ca(
                    env_id=env.id,
                    new_public_key=new_ca.public_key,
                    new_key_ref=new_key_ref,
                    grace_period=grace_td,
                )

    new_fingerprint = new_ca.fingerprint

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "environment": env_name,
            "ca_type": ca_type,
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
            "grace_period": str(grace_td),
            "old_ca_expires_at": (
                env.old_user_ca_expires_at.isoformat()
                if ca_type == "user" else
                env.old_host_ca_expires_at.isoformat()
            ),
        })
        return

    print_success(f"{ca_type.capitalize()} CA rotated successfully")
    console.print()
    console.print(f"[cyan]Old CA fingerprint:[/cyan] {old_fingerprint}")
    console.print(f"[cyan]New CA fingerprint:[/cyan] {new_fingerprint}")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  1. Get new CA public key:  sshmgr env get-ca {env_name} --type {ca_type}")
    console.print(f"  2. Get both CAs:           sshmgr env get-ca {env_name} --type {ca_type} --include-old")
    console.print("  3. Update your infrastructure to trust both CAs")
    console.print(f"  4. Wait for grace period ({grace_period}) before removing old CA from config")


@rotate_group.command("status")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@pass_context
@handle_errors
@async_command
async def rotation_status(ctx: Context, env_name: str):
    """Show CA rotation status for an environment."""
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

    user_ca_rotating = env.old_user_ca_public_key is not None
    host_ca_rotating = env.old_host_ca_public_key is not None

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "environment": env_name,
            "user_ca": {
                "rotating": user_ca_rotating,
                "fingerprint": CertificateAuthority.get_public_key_fingerprint(env.user_ca_public_key),
                "old_fingerprint": (
                    CertificateAuthority.get_public_key_fingerprint(env.old_user_ca_public_key)
                    if user_ca_rotating else None
                ),
                "old_expires_at": (
                    env.old_user_ca_expires_at.isoformat()
                    if user_ca_rotating else None
                ),
            },
            "host_ca": {
                "rotating": host_ca_rotating,
                "fingerprint": CertificateAuthority.get_public_key_fingerprint(env.host_ca_public_key),
                "old_fingerprint": (
                    CertificateAuthority.get_public_key_fingerprint(env.old_host_ca_public_key)
                    if host_ca_rotating else None
                ),
                "old_expires_at": (
                    env.old_host_ca_expires_at.isoformat()
                    if host_ca_rotating else None
                ),
            },
        })
        return

    console.print(f"[bold]Rotation Status: {env_name}[/bold]\n")

    # User CA
    console.print("[bold]User CA[/bold]")
    user_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.user_ca_public_key)
    console.print(f"  [cyan]Current:[/cyan] {user_fingerprint}")
    if user_ca_rotating:
        old_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.old_user_ca_public_key)
        console.print(f"  [yellow]Old:[/yellow]     {old_fingerprint}")
        console.print(f"  [yellow]Expires:[/yellow] {format_datetime(env.old_user_ca_expires_at)}")
    else:
        console.print(f"  [dim]Status:  No rotation in progress[/dim]")

    console.print()

    # Host CA
    console.print("[bold]Host CA[/bold]")
    host_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.host_ca_public_key)
    console.print(f"  [cyan]Current:[/cyan] {host_fingerprint}")
    if host_ca_rotating:
        old_fingerprint = CertificateAuthority.get_public_key_fingerprint(env.old_host_ca_public_key)
        console.print(f"  [yellow]Old:[/yellow]     {old_fingerprint}")
        console.print(f"  [yellow]Expires:[/yellow] {format_datetime(env.old_host_ca_expires_at)}")
    else:
        console.print(f"  [dim]Status:  No rotation in progress[/dim]")


@rotate_group.command("cleanup")
@click.option(
    "--env",
    "-e",
    "env_name",
    help="Environment name (optional, cleans all if not specified)",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Force cleanup even if grace period hasn't expired",
)
@pass_context
@handle_errors
@async_command
async def cleanup_old_cas(ctx: Context, env_name: str | None, force: bool):
    """
    Clean up expired old CA keys from rotation.

    By default, only removes old CAs whose grace period has expired.
    Use --force to remove all old CAs regardless of expiration.
    """
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)

        if env_name:
            # Clean up specific environment
            try:
                env = await env_repo.get_by_name_or_raise(env_name)
            except EnvironmentNotFoundError:
                print_error(f"Environment '{env_name}' not found")
                raise click.Abort()

            cleaned = False

            if env.old_user_ca_public_key:
                if force or (env.old_user_ca_expires_at and
                           env.old_user_ca_expires_at < env.old_user_ca_expires_at.now(env.old_user_ca_expires_at.tzinfo)):
                    await env_repo.update(
                        env.id,
                        old_user_ca_public_key=None,
                        old_user_ca_key_ref=None,
                        old_user_ca_expires_at=None,
                    )
                    print_success(f"Cleaned up old User CA for {env_name}")
                    cleaned = True

            if env.old_host_ca_public_key:
                if force or (env.old_host_ca_expires_at and
                           env.old_host_ca_expires_at < env.old_host_ca_expires_at.now(env.old_host_ca_expires_at.tzinfo)):
                    await env_repo.update(
                        env.id,
                        old_host_ca_public_key=None,
                        old_host_ca_key_ref=None,
                        old_host_ca_expires_at=None,
                    )
                    print_success(f"Cleaned up old Host CA for {env_name}")
                    cleaned = True

            if not cleaned:
                print_info(f"No expired old CAs to clean up for {env_name}")

        else:
            # Clean up all environments
            with spinner_context("Cleaning up expired old CAs..."):
                count = await env_repo.cleanup_expired_old_cas()

            if count > 0:
                print_success(f"Cleaned up {count} expired old CA(s)")
            else:
                print_info("No expired old CAs to clean up")
