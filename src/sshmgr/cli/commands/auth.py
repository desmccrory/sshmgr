"""Authentication commands for CLI."""

from __future__ import annotations

import asyncio

import click

from sshmgr.auth.credentials import get_credential_manager
from sshmgr.auth.device_flow import DeviceAuthFlow
from sshmgr.auth.keycloak import KeycloakClient, KeycloakConfig
from sshmgr.cli.main import Context, async_command, handle_errors, pass_context
from sshmgr.cli.output import (
    console,
    print_error,
    print_info,
    print_json,
    print_key_value,
    print_login_instructions,
    print_login_success,
    print_success,
    print_warning,
    spinner_context,
    OutputFormat,
)
from sshmgr.config import get_settings


@click.group("auth", invoke_without_command=True)
@click.pass_context
def auth_group(ctx):
    """Authentication commands."""
    if ctx.invoked_subcommand is None:
        # Default to showing status
        ctx.invoke(status)


@auth_group.command("login")
@pass_context
@handle_errors
@async_command
async def login(ctx: Context):
    """
    Login to sshmgr using browser authentication.

    Uses OAuth 2.0 Device Authorization Flow:
    1. Displays a code and URL
    2. You authenticate in your browser
    3. CLI receives tokens automatically
    """
    settings = get_settings()
    manager = get_credential_manager()

    # Check if already logged in
    if manager.is_logged_in():
        info = manager.get_login_info()
        if info:
            print_warning(f"Already logged in as {info.get('username', 'unknown')}")
            if not click.confirm("Login again?", default=False):
                return

    # Use CLI client (public) for device flow, not API client (confidential)
    config = KeycloakConfig(
        server_url=settings.keycloak_url,
        realm=settings.keycloak_realm,
        client_id=settings.keycloak_cli_client_id,
        client_secret=None,  # CLI client is public, no secret
    )

    async with DeviceAuthFlow(config=config) as flow:
        # Start device authorization
        with spinner_context("Requesting device authorization..."):
            auth = await flow.start(scope="openid profile email")

        # Show login instructions
        print_login_instructions(
            auth.verification_uri,
            auth.user_code,
            auth.verification_uri_complete,
        )

        console.print("\n[dim]Waiting for authentication...[/dim]")

        # Poll for completion
        attempt = 0

        def on_poll(n: int, elapsed: float):
            nonlocal attempt
            attempt = n
            if n % 6 == 0:  # Every ~30 seconds
                console.print(f"[dim]Still waiting... ({int(elapsed)}s)[/dim]")

        try:
            tokens = await flow.poll_for_token(auth, callback=on_poll)
        except Exception as e:
            print_error(f"Authentication failed: {e}")
            raise click.Abort()

    # Save credentials
    creds = manager.save_tokens(
        tokens,
        keycloak_url=settings.keycloak_url,
        realm=settings.keycloak_realm,
    )

    # Show success
    username = creds.get_username() or "user"
    print_login_success(username)


@auth_group.command("logout")
@pass_context
@handle_errors
@async_command
async def logout(ctx: Context):
    """
    Logout and clear stored credentials.

    This will:
    1. Invalidate the refresh token with Keycloak
    2. Remove local credentials from ~/.sshmgr/
    """
    settings = get_settings()
    manager = get_credential_manager()

    if not manager.is_logged_in():
        print_info("Not currently logged in")
        return

    creds = manager.get_credentials()

    # Try to logout from Keycloak
    if creds and creds.refresh_token:
        config = KeycloakConfig.from_settings(settings)

        try:
            async with KeycloakClient(config=config) as client:
                with spinner_context("Logging out from Keycloak..."):
                    await client.logout(creds.refresh_token)
        except Exception as e:
            print_warning(f"Could not notify Keycloak: {e}")

    # Clear local credentials
    manager.clear()
    print_success("Logged out successfully")


@auth_group.command("status")
@pass_context
@handle_errors
def status(ctx: Context):
    """Show current authentication status."""
    manager = get_credential_manager()

    if ctx.output_format == OutputFormat.JSON:
        info = manager.get_login_info()
        if info:
            print_json(info)
        else:
            print_json({"logged_in": False})
        return

    if not manager.is_logged_in():
        print_info("Not logged in")
        console.print("\nRun [bold]sshmgr login[/bold] to authenticate")
        return

    info = manager.get_login_info()
    if not info:
        print_warning("Credentials corrupted, please login again")
        return

    console.print("[bold]Authentication Status[/bold]\n")
    print_key_value("Logged in as", info.get("username") or "unknown")
    print_key_value("Keycloak URL", info.get("keycloak_url", ""))
    print_key_value("Realm", info.get("realm", ""))

    if info.get("is_expired"):
        if info.get("can_refresh"):
            print_key_value("Token Status", "[yellow]Expired (can refresh)[/yellow]")
        else:
            print_key_value("Token Status", "[red]Expired[/red]")
    else:
        expires_in = info.get("access_token_expires_in", 0)
        if expires_in < 300:
            print_key_value("Token Status", f"[yellow]Expires in {expires_in}s[/yellow]")
        else:
            print_key_value("Token Status", f"[green]Valid ({expires_in}s remaining)[/green]")


@auth_group.command("whoami")
@pass_context
@handle_errors
@async_command
async def whoami(ctx: Context):
    """Show information about the current user."""
    settings = get_settings()
    manager = get_credential_manager()

    if not manager.is_logged_in():
        print_error("Not logged in. Run 'sshmgr login' first.")
        raise click.Abort()

    creds = manager.get_credentials()
    if not creds:
        print_error("Could not load credentials")
        raise click.Abort()

    # Refresh if needed
    if creds.is_access_token_expired and creds.can_refresh:
        config = KeycloakConfig.from_settings(settings)
        async with KeycloakClient(config=config) as client:
            with spinner_context("Refreshing token..."):
                tokens = await client.refresh_token(creds.refresh_token)
            creds = manager.update_tokens(tokens)

    # Get user info from Keycloak
    config = KeycloakConfig.from_settings(settings)
    async with KeycloakClient(config=config) as client:
        with spinner_context("Fetching user info..."):
            user_info = await client.get_userinfo(creds.access_token)

    if ctx.output_format == OutputFormat.JSON:
        print_json({
            "sub": user_info.sub,
            "username": user_info.preferred_username,
            "email": user_info.email,
            "email_verified": user_info.email_verified,
            "name": user_info.name,
            "roles": user_info.realm_roles or [],
            "groups": user_info.groups or [],
            "environments": user_info.get_environment_access(),
        })
        return

    console.print("[bold]Current User[/bold]\n")
    print_key_value("Username", user_info.preferred_username)
    print_key_value("User ID", user_info.sub)

    if user_info.email:
        verified = "[green]✓[/green]" if user_info.email_verified else "[yellow]✗[/yellow]"
        print_key_value("Email", f"{user_info.email} {verified}")

    if user_info.name:
        print_key_value("Name", user_info.name)

    if user_info.realm_roles:
        print_key_value("Roles", ", ".join(user_info.realm_roles))

    envs = user_info.get_environment_access()
    if envs:
        print_key_value("Environments", ", ".join(envs))
    elif "admin" in (user_info.realm_roles or []):
        print_key_value("Environments", "[dim]All (admin)[/dim]")
    else:
        print_key_value("Environments", "[dim]None[/dim]")


@auth_group.command("refresh")
@pass_context
@handle_errors
@async_command
async def refresh(ctx: Context):
    """Refresh the access token."""
    settings = get_settings()
    manager = get_credential_manager()

    if not manager.is_logged_in():
        print_error("Not logged in. Run 'sshmgr login' first.")
        raise click.Abort()

    creds = manager.get_credentials()
    if not creds:
        print_error("Could not load credentials")
        raise click.Abort()

    if not creds.can_refresh:
        print_error("Cannot refresh: no valid refresh token")
        print_info("Please run 'sshmgr login' to re-authenticate")
        raise click.Abort()

    config = KeycloakConfig.from_settings(settings)
    async with KeycloakClient(config=config) as client:
        with spinner_context("Refreshing token..."):
            tokens = await client.refresh_token(creds.refresh_token)
        creds = manager.update_tokens(tokens)

    print_success(f"Token refreshed, valid for {creds.access_token_expires_in}s")
