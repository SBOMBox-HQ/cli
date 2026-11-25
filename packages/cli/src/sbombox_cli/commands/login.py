"""Authentication commands: login, logout, whoami."""
from __future__ import annotations
import typer
from rich.console import Console

app = typer.Typer(help="Authentication commands.")
console = Console()

@app.command()
def login() -> None:
    """Log in via OAuth device flow."""
    from sbombox_cli.auth import device_flow
    from sbombox_cli.config import load_config
    config = load_config()
    try:
        token = device_flow(config.api_url)
        console.print("[green]Login successful.[/green]")
    except Exception as exc:
        console.print(f"[red]Login failed:[/red] {exc}")
        raise typer.Exit(code=5)

@app.command()
def logout() -> None:
    """Clear stored credentials."""
    from sbombox_cli.auth import clear_token
    clear_token()
    console.print("[green]Logged out.[/green]")

@app.command()
def whoami() -> None:
    """Show current user info."""
    from sbombox_cli.config import load_config
    from sbombox_cli.api_client import ApiClient
    config = load_config()
    client = ApiClient(config)
    try:
        info = client.whoami()
        console.print(f"Logged in as: [bold]{info.get('email', 'unknown')}[/bold]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=getattr(exc, "exit_code", 3))
