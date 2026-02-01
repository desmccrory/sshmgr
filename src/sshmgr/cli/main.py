"""CLI main entry point and command groups."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable
from functools import wraps

import click

from sshmgr import __version__
from sshmgr.cli.output import OutputFormat, error_console, print_error
from sshmgr.config import Settings, get_settings


def get_cli_user() -> str:
    """
    Get the current CLI user for audit logging.

    Resolution order:
    1. SSHMGR_CLI_USER environment variable (for automation/service accounts)
    2. Authenticated user from stored credentials (Keycloak login)
    3. Local system username as fallback

    Returns:
        Username string for audit trail
    """
    # 1. Explicit override via environment variable
    env_user = os.environ.get("SSHMGR_CLI_USER")
    if env_user:
        return env_user

    # 2. Try to get from stored Keycloak credentials
    try:
        from sshmgr.auth.credentials import get_credential_manager

        manager = get_credential_manager()
        creds = manager.get_credentials()
        if creds and not creds.is_access_token_expired:
            username = creds.get_username()
            if username:
                return username
    except Exception:
        pass  # Credentials not available or invalid

    # 3. Fall back to system username
    import getpass

    return f"cli:{getpass.getuser()}"


class Context:
    """CLI context object passed to all commands."""

    def __init__(self):
        self.settings: Settings = get_settings()
        self.output_format: OutputFormat = OutputFormat.TEXT
        self.verbose: bool = False
        self.environment: str | None = None

    def get_api_url(self) -> str:
        """Get the API base URL."""
        return f"http://{self.settings.api_host}:{self.settings.api_port}"


pass_context = click.make_pass_decorator(Context, ensure=True)


def async_command(f: Callable) -> Callable:
    """Decorator to run async functions in Click commands."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


def handle_errors(f: Callable) -> Callable:
    """Decorator to handle common errors gracefully."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except KeyboardInterrupt:
            print_error("Operation cancelled")
            sys.exit(130)
        except click.ClickException:
            raise
        except Exception as e:
            print_error(str(e))
            if kwargs.get("verbose") or (args and hasattr(args[0], "verbose") and args[0].verbose):
                error_console.print_exception()
            sys.exit(1)

    return wrapper


@click.group()
@click.version_option(version=__version__, prog_name="sshmgr")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "table"]),
    default="text",
    help="Output format",
)
@click.option(
    "-e",
    "--env",
    "environment",
    envvar="SSHMGR_ENVIRONMENT",
    help="Target environment name",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
@pass_context
def cli(ctx: Context, output_format: str, environment: str | None, verbose: bool):
    """
    sshmgr - SSH Certificate Management System

    Manage SSH certificates for multiple customer environments with
    automatic key rotation and expiration.
    """
    ctx.output_format = OutputFormat(output_format)
    ctx.environment = environment
    ctx.verbose = verbose


# Import and register command groups
from sshmgr.cli.commands.auth import auth_group
from sshmgr.cli.commands.cert import cert_group
from sshmgr.cli.commands.environment import env_group
from sshmgr.cli.commands.rotate import rotate_group

cli.add_command(auth_group)
cli.add_command(env_group)
cli.add_command(cert_group)
cli.add_command(rotate_group)


# Add shortcuts for common commands
@cli.command("login")
@click.pass_context
@handle_errors
def login_shortcut(ctx):
    """Login to sshmgr (shortcut for 'auth login')."""
    ctx.invoke(auth_group.commands["login"])


@cli.command("logout")
@click.pass_context
@handle_errors
def logout_shortcut(ctx):
    """Logout from sshmgr (shortcut for 'auth logout')."""
    ctx.invoke(auth_group.commands["logout"])


@cli.command("init-env")
@click.argument("name")
@click.option("--user-validity", default="8h", help="Default user cert validity (e.g., 8h, 1d)")
@click.option("--host-validity", default="90d", help="Default host cert validity (e.g., 90d)")
@click.pass_context
@handle_errors
def init_env_shortcut(ctx, name: str, user_validity: str, host_validity: str):
    """Initialize a new environment (shortcut for 'env init')."""
    ctx.invoke(
        env_group.commands["init"],
        name=name,
        user_validity=user_validity,
        host_validity=host_validity,
    )


@cli.command("sign-user-cert")
@click.option("--env", "-e", "env_name", required=True, help="Environment name")
@click.option("--public-key", "-k", required=True, type=click.Path(exists=True), help="Path to public key")
@click.option("--principals", "-n", required=True, help="Comma-separated principals")
@click.option("--key-id", "-I", required=True, help="Key identifier (e.g., email)")
@click.option("--validity", "-V", default=None, help="Validity period (e.g., 8h)")
@click.option("--output", "-o", type=click.Path(), help="Output path for certificate")
@click.pass_context
@handle_errors
def sign_user_shortcut(ctx, env_name, public_key, principals, key_id, validity, output):
    """Sign a user certificate (shortcut for 'cert sign-user')."""
    ctx.invoke(
        cert_group.commands["sign-user"],
        env_name=env_name,
        public_key=public_key,
        principals=principals,
        key_id=key_id,
        validity=validity,
        output=output,
    )


@cli.command("sign-host-cert")
@click.option("--env", "-e", "env_name", required=True, help="Environment name")
@click.option("--public-key", "-k", required=True, type=click.Path(exists=True), help="Path to public key")
@click.option("--principals", "-n", required=True, help="Comma-separated hostnames/IPs")
@click.option("--validity", "-V", default=None, help="Validity period (e.g., 90d)")
@click.option("--output", "-o", type=click.Path(), help="Output path for certificate")
@click.pass_context
@handle_errors
def sign_host_shortcut(ctx, env_name, public_key, principals, validity, output):
    """Sign a host certificate (shortcut for 'cert sign-host')."""
    ctx.invoke(
        cert_group.commands["sign-host"],
        env_name=env_name,
        public_key=public_key,
        principals=principals,
        validity=validity,
        output=output,
    )


def main():
    """Main entry point."""
    cli(auto_envvar_prefix="SSHMGR")


if __name__ == "__main__":
    main()
