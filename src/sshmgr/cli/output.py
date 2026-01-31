"""Output formatting helpers for CLI."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Global console instances
console = Console()
error_console = Console(stderr=True)


class OutputFormat(str, Enum):
    """Output format options."""

    TEXT = "text"
    JSON = "json"
    TABLE = "table"


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str) -> None:
    """Print an error message to stderr."""
    error_console.print(f"[red]✗[/red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[yellow]![/yellow] {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[blue]ℹ[/blue] {message}")


def print_json(data: Any) -> None:
    """Print data as formatted JSON."""
    if hasattr(data, "to_dict"):
        data = data.to_dict()
    elif hasattr(data, "__dict__"):
        data = data.__dict__

    # Handle non-serializable types
    def serialize(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, timedelta):
            return str(obj)
        elif hasattr(obj, "value"):  # Enum
            return obj.value
        elif hasattr(obj, "__dict__"):
            return obj.__dict__
        return str(obj)

    console.print_json(json.dumps(data, default=serialize, indent=2))


def print_key_value(key: str, value: str, key_width: int = 20) -> None:
    """Print a key-value pair."""
    console.print(f"[cyan]{key:<{key_width}}[/cyan] {value}")


def print_section(title: str) -> None:
    """Print a section header."""
    console.print(f"\n[bold]{title}[/bold]")
    console.print("─" * len(title))


def create_table(
    title: str | None = None,
    columns: list[tuple[str, str]] | None = None,
) -> Table:
    """
    Create a rich table.

    Args:
        title: Optional table title
        columns: List of (header, style) tuples

    Returns:
        Rich Table instance
    """
    table = Table(title=title, show_header=True, header_style="bold cyan")

    if columns:
        for header, style in columns:
            table.add_column(header, style=style)

    return table


def format_datetime(dt: datetime | None) -> str:
    """Format a datetime for display."""
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def format_timedelta(td: timedelta | None) -> str:
    """Format a timedelta for display."""
    if td is None:
        return "—"

    total_seconds = int(td.total_seconds())

    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes}m"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return f"{days}d {hours}h" if hours else f"{days}d"


def format_validity(valid_before: datetime) -> Text:
    """Format certificate validity with color coding."""
    now = datetime.now(valid_before.tzinfo)
    remaining = valid_before - now

    if remaining.total_seconds() < 0:
        return Text("Expired", style="red")
    elif remaining.total_seconds() < 3600:  # < 1 hour
        return Text(f"{format_timedelta(remaining)} remaining", style="yellow")
    else:
        return Text(f"{format_timedelta(remaining)} remaining", style="green")


def format_fingerprint(fingerprint: str, truncate: bool = True) -> str:
    """Format a key fingerprint."""
    if truncate and len(fingerprint) > 20:
        return fingerprint[:20] + "..."
    return fingerprint


def print_environment_details(env: dict[str, Any]) -> None:
    """Print environment details in a formatted panel."""
    content = []
    content.append(f"[cyan]ID:[/cyan]           {env.get('id', 'N/A')}")
    content.append(f"[cyan]Name:[/cyan]         {env.get('name', 'N/A')}")
    content.append(f"[cyan]Created:[/cyan]      {format_datetime(env.get('created_at'))}")

    content.append("")
    content.append("[bold]User CA[/bold]")
    content.append(f"  Fingerprint:  {env.get('user_ca_fingerprint', 'N/A')}")
    content.append(f"  Validity:     {format_timedelta(env.get('default_user_cert_validity'))}")

    content.append("")
    content.append("[bold]Host CA[/bold]")
    content.append(f"  Fingerprint:  {env.get('host_ca_fingerprint', 'N/A')}")
    content.append(f"  Validity:     {format_timedelta(env.get('default_host_cert_validity'))}")

    panel = Panel(
        "\n".join(content),
        title=f"[bold]Environment: {env.get('name', 'Unknown')}[/bold]",
        border_style="blue",
    )
    console.print(panel)


def print_certificate_details(cert: dict[str, Any]) -> None:
    """Print certificate details in a formatted panel."""
    content = []
    content.append(f"[cyan]Type:[/cyan]         {cert.get('cert_type', 'N/A')}")
    content.append(f"[cyan]Key ID:[/cyan]       {cert.get('key_id', 'N/A')}")
    content.append(f"[cyan]Serial:[/cyan]       {cert.get('serial', 'N/A')}")
    content.append(f"[cyan]Principals:[/cyan]   {', '.join(cert.get('principals', []))}")

    content.append("")
    valid_before = cert.get('valid_before')
    if valid_before:
        content.append(f"[cyan]Valid From:[/cyan]   {format_datetime(cert.get('valid_after'))}")
        content.append(f"[cyan]Valid Until:[/cyan]  {format_datetime(valid_before)}")

    if cert.get('revoked_at'):
        content.append("")
        content.append(f"[red]Revoked:[/red]      {format_datetime(cert.get('revoked_at'))}")
        content.append(f"[red]Revoked By:[/red]   {cert.get('revoked_by', 'N/A')}")

    panel = Panel(
        "\n".join(content),
        title=f"[bold]Certificate: {cert.get('key_id', 'Unknown')}[/bold]",
        border_style="green" if not cert.get('revoked_at') else "red",
    )
    console.print(panel)


def print_login_instructions(
    verification_uri: str,
    user_code: str,
    verification_uri_complete: str | None = None,
) -> None:
    """Print device flow login instructions."""
    content = []
    content.append("To sign in, open a browser and visit:")
    content.append("")
    content.append(f"  [bold blue]{verification_uri}[/bold blue]")
    content.append("")
    content.append("Then enter the code:")
    content.append("")
    content.append(f"  [bold green]{user_code}[/bold green]")

    if verification_uri_complete:
        content.append("")
        content.append("Or visit this URL directly:")
        content.append(f"  [dim]{verification_uri_complete}[/dim]")

    panel = Panel(
        "\n".join(content),
        title="[bold]Login Required[/bold]",
        border_style="yellow",
    )
    console.print(panel)


def print_login_success(username: str) -> None:
    """Print successful login message."""
    console.print(
        Panel(
            f"Successfully logged in as [bold green]{username}[/bold green]",
            title="[bold]Login Successful[/bold]",
            border_style="green",
        )
    )


def confirm(message: str, default: bool = False) -> bool:
    """
    Ask for confirmation.

    Args:
        message: Confirmation message
        default: Default value if user just presses Enter

    Returns:
        True if confirmed, False otherwise
    """
    suffix = " [Y/n]" if default else " [y/N]"
    response = console.input(f"{message}{suffix} ").strip().lower()

    if not response:
        return default

    return response in ("y", "yes")


def spinner_context(message: str):
    """
    Create a spinner context manager.

    Usage:
        with spinner_context("Loading..."):
            do_something()
    """
    return console.status(message, spinner="dots")
