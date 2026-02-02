"""Certificate signing commands for CLI."""

from __future__ import annotations

from pathlib import Path

import click

from sshmgr.cli.commands.environment import parse_validity
from sshmgr.cli.main import Context, async_command, get_cli_user, handle_errors, pass_context
from sshmgr.cli.output import (
    OutputFormat,
    console,
    create_table,
    format_datetime,
    format_validity,
    print_certificate_details,
    print_error,
    print_info,
    print_json,
    print_success,
    print_warning,
    spinner_context,
)
from sshmgr.config import get_settings
from sshmgr.core.ca import CertificateAuthority
from sshmgr.core.exceptions import EnvironmentNotFoundError, InvalidKeyError, SigningError
from sshmgr.keys.encrypted import EncryptedKeyStorage
from sshmgr.storage.database import get_database
from sshmgr.storage.models import CertType
from sshmgr.storage.repositories import CertificateRepository, EnvironmentRepository


@click.group("cert")
def cert_group():
    """Certificate signing and management commands."""
    pass


@cert_group.command("sign-user")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--public-key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to user's public key file",
)
@click.option(
    "--principals",
    "-n",
    required=True,
    help="Comma-separated list of principals (usernames)",
)
@click.option(
    "--key-id",
    "-I",
    required=True,
    help="Key identifier (e.g., email address)",
)
@click.option(
    "--validity",
    "-V",
    default=None,
    help="Validity period (e.g., 8h, 1d). Defaults to environment setting.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output path for certificate (defaults to <key>-cert.pub)",
)
@click.option(
    "--force-command",
    help="Force a specific command to be run",
)
@pass_context
@handle_errors
@async_command
async def sign_user(
    ctx: Context,
    env_name: str,
    public_key: str,
    principals: str,
    key_id: str,
    validity: str | None,
    output: str | None,
    force_command: str | None,
):
    """
    Sign a user's public key to create an SSH certificate.

    The certificate allows the user to authenticate to SSH servers that
    trust the environment's User CA.

    Example:
        sshmgr cert sign-user -e prod -k ~/.ssh/id_ed25519.pub \\
            -n "deploy,admin" -I "user@example.com"
    """
    settings = get_settings()

    if not settings.master_key:
        print_error("SSHMGR_MASTER_KEY environment variable not set")
        raise click.Abort()

    # Read public key
    pub_key_path = Path(public_key)
    pub_key_content = pub_key_path.read_text().strip()

    # Parse principals
    principal_list = [p.strip() for p in principals.split(",") if p.strip()]
    if not principal_list:
        print_error("At least one principal is required")
        raise click.Abort()

    # Determine output path
    if output is None:
        # Can't use with_suffix("-cert.pub") as it contains a dot
        base = str(pub_key_path.with_suffix(""))
        output = f"{base}-cert.pub"

    key_storage = EncryptedKeyStorage(settings.master_key)
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        cert_repo = CertificateRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Parse validity or use default
        if validity:
            try:
                cert_validity = parse_validity(validity)
            except click.BadParameter as e:
                print_error(str(e))
                raise click.Abort()
        else:
            cert_validity = env.default_user_cert_validity

        # Load CA private key
        with spinner_context("Loading CA..."):
            ca_private_key = key_storage.retrieve_key(env.user_ca_key_ref)
            ca = CertificateAuthority.from_private_key(ca_private_key)

        # Get next serial number
        serial = await cert_repo.get_max_serial(env.id) + 1

        # Sign the certificate
        try:
            with spinner_context("Signing certificate..."):
                signed_cert = ca.sign_user_key(
                    public_key=pub_key_content,
                    principals=principal_list,
                    key_id=key_id,
                    validity=cert_validity,
                    serial=serial,
                    force_command=force_command,
                )
        except InvalidKeyError as e:
            print_error(f"Invalid public key: {e}")
            raise click.Abort()
        except SigningError as e:
            print_error(f"Signing failed: {e}")
            raise click.Abort()

        # Record in database
        pub_key_fingerprint = CertificateAuthority.get_public_key_fingerprint(pub_key_content)
        await cert_repo.create(
            environment_id=env.id,
            cert_type=CertType.USER,
            serial=signed_cert.serial,
            key_id=key_id,
            principals=principal_list,
            valid_after=signed_cert.valid_after,
            valid_before=signed_cert.valid_before,
            public_key_fingerprint=pub_key_fingerprint,
            issued_by=get_cli_user(),
        )

    # Write certificate
    Path(output).write_text(signed_cert.certificate + "\n")

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "certificate_path": output,
            "serial": signed_cert.serial,
            "key_id": signed_cert.key_id,
            "principals": signed_cert.principals,
            "valid_after": signed_cert.valid_after.isoformat(),
            "valid_before": signed_cert.valid_before.isoformat(),
            "fingerprint": pub_key_fingerprint,
        })
        return

    print_success(f"Certificate written to {output}")
    console.print()
    console.print(f"[cyan]Serial:[/cyan]      {signed_cert.serial}")
    console.print(f"[cyan]Key ID:[/cyan]      {signed_cert.key_id}")
    console.print(f"[cyan]Principals:[/cyan]  {', '.join(signed_cert.principals)}")
    console.print(f"[cyan]Valid until:[/cyan] {format_datetime(signed_cert.valid_before)}")
    console.print()
    console.print("[dim]Verify with: ssh-keygen -L -f " + output + "[/dim]")


@cert_group.command("sign-host")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--public-key",
    "-k",
    required=True,
    type=click.Path(exists=True),
    help="Path to host's public key file",
)
@click.option(
    "--principals",
    "-n",
    required=True,
    help="Comma-separated list of hostnames/IPs",
)
@click.option(
    "--validity",
    "-V",
    default=None,
    help="Validity period (e.g., 90d, 1y). Defaults to environment setting.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output path for certificate (defaults to <key>-cert.pub)",
)
@pass_context
@handle_errors
@async_command
async def sign_host(
    ctx: Context,
    env_name: str,
    public_key: str,
    principals: str,
    validity: str | None,
    output: str | None,
):
    """
    Sign a host's public key to create an SSH host certificate.

    The certificate allows SSH clients to verify the host's identity
    without needing to trust individual host keys.

    Example:
        sshmgr cert sign-host -e prod -k /etc/ssh/ssh_host_ed25519_key.pub \\
            -n "server1.example.com,10.0.0.5"
    """
    settings = get_settings()

    if not settings.master_key:
        print_error("SSHMGR_MASTER_KEY environment variable not set")
        raise click.Abort()

    # Read public key
    pub_key_path = Path(public_key)
    pub_key_content = pub_key_path.read_text().strip()

    # Parse principals
    principal_list = [p.strip() for p in principals.split(",") if p.strip()]
    if not principal_list:
        print_error("At least one hostname/IP is required")
        raise click.Abort()

    # Determine output path
    if output is None:
        # Can't use with_suffix("-cert.pub") as it contains a dot
        base = str(pub_key_path.with_suffix(""))
        output = f"{base}-cert.pub"

    key_storage = EncryptedKeyStorage(settings.master_key)
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        cert_repo = CertificateRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Parse validity or use default
        if validity:
            try:
                cert_validity = parse_validity(validity)
            except click.BadParameter as e:
                print_error(str(e))
                raise click.Abort()
        else:
            cert_validity = env.default_host_cert_validity

        # Load CA private key
        with spinner_context("Loading CA..."):
            ca_private_key = key_storage.retrieve_key(env.host_ca_key_ref)
            ca = CertificateAuthority.from_private_key(ca_private_key)

        # Get next serial number
        serial = await cert_repo.get_max_serial(env.id) + 1

        # Sign the certificate
        try:
            with spinner_context("Signing certificate..."):
                signed_cert = ca.sign_host_key(
                    public_key=pub_key_content,
                    principals=principal_list,
                    validity=cert_validity,
                    serial=serial,
                )
        except InvalidKeyError as e:
            print_error(f"Invalid public key: {e}")
            raise click.Abort()
        except SigningError as e:
            print_error(f"Signing failed: {e}")
            raise click.Abort()

        # Record in database
        pub_key_fingerprint = CertificateAuthority.get_public_key_fingerprint(pub_key_content)
        await cert_repo.create(
            environment_id=env.id,
            cert_type=CertType.HOST,
            serial=signed_cert.serial,
            key_id=signed_cert.key_id,
            principals=principal_list,
            valid_after=signed_cert.valid_after,
            valid_before=signed_cert.valid_before,
            public_key_fingerprint=pub_key_fingerprint,
            issued_by=get_cli_user(),
        )

    # Write certificate
    Path(output).write_text(signed_cert.certificate + "\n")

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "certificate_path": output,
            "serial": signed_cert.serial,
            "key_id": signed_cert.key_id,
            "principals": signed_cert.principals,
            "valid_after": signed_cert.valid_after.isoformat(),
            "valid_before": signed_cert.valid_before.isoformat(),
            "fingerprint": pub_key_fingerprint,
        })
        return

    print_success(f"Certificate written to {output}")
    console.print()
    console.print(f"[cyan]Serial:[/cyan]      {signed_cert.serial}")
    console.print(f"[cyan]Key ID:[/cyan]      {signed_cert.key_id}")
    console.print(f"[cyan]Principals:[/cyan]  {', '.join(signed_cert.principals)}")
    console.print(f"[cyan]Valid until:[/cyan] {format_datetime(signed_cert.valid_before)}")


@cert_group.command("list")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--type",
    "cert_type",
    type=click.Choice(["user", "host"]),
    help="Filter by certificate type",
)
@click.option(
    "--include-expired",
    is_flag=True,
    help="Include expired certificates",
)
@click.option(
    "--include-revoked",
    is_flag=True,
    help="Include revoked certificates",
)
@click.option(
    "--limit",
    default=50,
    help="Maximum number of certificates to show",
)
@pass_context
@handle_errors
@async_command
async def list_certs(
    ctx: Context,
    env_name: str,
    cert_type: str | None,
    include_expired: bool,
    include_revoked: bool,
    limit: int,
):
    """
    List certificates issued for an environment.

    Shows certificate audit log with status information.
    """
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        cert_repo = CertificateRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Get certificates
        type_filter = CertType(cert_type) if cert_type else None
        certs = await cert_repo.list_by_environment(
            environment_id=env.id,
            cert_type=type_filter,
            include_expired=include_expired,
            include_revoked=include_revoked,
            limit=limit,
        )

    if not certs:
        print_info("No certificates found")
        return

    if ctx.output_format == OutputFormat.JSON:
        print_json([
            {
                "id": str(cert.id),
                "serial": cert.serial,
                "cert_type": cert.cert_type.value,
                "key_id": cert.key_id,
                "principals": cert.principals,
                "valid_after": cert.valid_after.isoformat() if cert.valid_after else None,
                "valid_before": cert.valid_before.isoformat() if cert.valid_before else None,
                "issued_at": cert.issued_at.isoformat() if cert.issued_at else None,
                "issued_by": cert.issued_by,
                "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
            }
            for cert in certs
        ])
        return

    table = create_table(
        title=f"Certificates for {env_name}",
        columns=[
            ("Serial", "cyan"),
            ("Type", ""),
            ("Key ID", ""),
            ("Principals", ""),
            ("Status", ""),
        ],
    )

    for cert in certs:
        # Determine status
        if cert.revoked_at:
            status = "[red]Revoked[/red]"
        elif cert.valid_before:
            status = format_validity(cert.valid_before)
        else:
            status = "[dim]Unknown[/dim]"

        principals_str = ", ".join(cert.principals[:2])
        if len(cert.principals) > 2:
            principals_str += f" (+{len(cert.principals) - 2})"

        table.add_row(
            str(cert.serial),
            cert.cert_type.value.upper(),
            cert.key_id[:30] + "..." if len(cert.key_id) > 30 else cert.key_id,
            principals_str,
            status,
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(certs)} certificate(s)[/dim]")


@cert_group.command("show")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--serial",
    "-s",
    type=int,
    required=True,
    help="Certificate serial number",
)
@pass_context
@handle_errors
@async_command
async def show_cert(ctx: Context, env_name: str, serial: int):
    """Show details of a specific certificate."""
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        cert_repo = CertificateRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Get certificate
        cert = await cert_repo.get_by_serial(env.id, serial)
        if not cert:
            print_error(f"Certificate with serial {serial} not found")
            raise click.Abort()

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "id": str(cert.id),
            "serial": cert.serial,
            "cert_type": cert.cert_type.value,
            "key_id": cert.key_id,
            "principals": cert.principals,
            "valid_after": cert.valid_after.isoformat() if cert.valid_after else None,
            "valid_before": cert.valid_before.isoformat() if cert.valid_before else None,
            "public_key_fingerprint": cert.public_key_fingerprint,
            "issued_at": cert.issued_at.isoformat() if cert.issued_at else None,
            "issued_by": cert.issued_by,
            "revoked_at": cert.revoked_at.isoformat() if cert.revoked_at else None,
            "revoked_by": cert.revoked_by,
            "revocation_reason": cert.revocation_reason,
        })
        return

    print_certificate_details({
        "cert_type": cert.cert_type.value.upper(),
        "key_id": cert.key_id,
        "serial": cert.serial,
        "principals": cert.principals,
        "valid_after": cert.valid_after,
        "valid_before": cert.valid_before,
        "revoked_at": cert.revoked_at,
        "revoked_by": cert.revoked_by,
    })

    console.print()
    console.print(f"[cyan]Fingerprint:[/cyan]  {cert.public_key_fingerprint}")
    console.print(f"[cyan]Issued by:[/cyan]    {cert.issued_by}")
    console.print(f"[cyan]Issued at:[/cyan]    {format_datetime(cert.issued_at)}")


@cert_group.command("revoke")
@click.option(
    "--env",
    "-e",
    "env_name",
    required=True,
    help="Environment name",
)
@click.option(
    "--serial",
    "-s",
    type=int,
    required=True,
    help="Certificate serial number to revoke",
)
@click.option(
    "--reason",
    "-r",
    help="Reason for revocation",
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
async def revoke_cert(
    ctx: Context,
    env_name: str,
    serial: int,
    reason: str | None,
    force: bool,
):
    """
    Revoke a certificate.

    Note: SSH certificate revocation requires distributing a revocation list
    (KRL) to all SSH servers. This command marks the certificate as revoked
    in the database but does not automatically update KRLs.
    """
    settings = get_settings()
    db = get_database(settings)

    async with db.session() as session:
        env_repo = EnvironmentRepository(session)
        cert_repo = CertificateRepository(session)

        # Get environment
        try:
            env = await env_repo.get_by_name_or_raise(env_name)
        except EnvironmentNotFoundError:
            print_error(f"Environment '{env_name}' not found")
            raise click.Abort()

        # Get certificate
        cert = await cert_repo.get_by_serial(env.id, serial)
        if not cert:
            print_error(f"Certificate with serial {serial} not found")
            raise click.Abort()

        if cert.revoked_at:
            print_warning(f"Certificate {serial} is already revoked")
            return

        if not force:
            console.print("[bold]Certificate to revoke:[/bold]")
            console.print(f"  Serial:     {cert.serial}")
            console.print(f"  Key ID:     {cert.key_id}")
            console.print(f"  Principals: {', '.join(cert.principals)}")
            console.print()
            if not click.confirm("Revoke this certificate?", default=False):
                print_info("Revocation cancelled")
                return

        # Revoke
        with spinner_context("Revoking certificate..."):
            await cert_repo.revoke(
                cert_id=cert.id,
                revoked_by=get_cli_user(),
                reason=reason,
            )

    print_success(f"Certificate {serial} revoked")
    print_warning(
        "Remember to generate and distribute updated KRL files to enforce revocation"
    )
