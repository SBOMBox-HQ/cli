"""Configuration management commands."""
from __future__ import annotations
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

app = typer.Typer(help="Configuration management.")
console = Console()

TEMPLATE = """\
# SBOMBox CLI configuration
api_url: https://api.sbombox.com
project_id: ""
default_format: cyclonedx
# Anonymous usage data for runs in this repository (see `sbombox config --telemetry status`).
telemetry: true
scoring:
  weights:
    completeness: 0.2
    provenance: 0.2
    licenses: 0.15
    vulnerabilities: 0.15
    hashes: 0.1
    suppliers: 0.1
    versions: 0.05
    dependencies: 0.05
"""

@app.command(name="config")
def config_cmd(
    init: bool = typer.Option(False, "--init", help="Write .sbombox.yml to the current directory instead of printing it."),
    telemetry: Optional[str] = typer.Option(
        None, "--telemetry", metavar="on|off|status",
        help="Turn anonymous usage data on or off for this user, or show the current setting.",
    ),
) -> None:
    """Emit or initialize scoring config, or change the usage-data setting."""
    if telemetry is not None:
        _telemetry_setting(telemetry.strip().lower())
        return
    if init:
        path = Path(".sbombox.yml")
        if path.exists():
            console.print("[yellow].sbombox.yml already exists.[/yellow]")
            return
        path.write_text(TEMPLATE)
        console.print("[green]Created .sbombox.yml[/green]")
    else:
        console.print(TEMPLATE)


def _telemetry_setting(choice: str) -> None:
    from sbombox_cli import telemetry
    from sbombox_cli.config import load_config

    if choice in ("on", "off"):
        telemetry.set_enabled(choice == "on")
        console.print(f"Anonymous usage data is now [bold]{choice}[/bold] for this user.")
    elif choice != "status":
        console.print("[red]Use --telemetry on, off or status.[/red]")
        raise typer.Exit(2)
    try:
        repo_config = dict(load_config()._raw)
    except Exception:  # noqa: BLE001
        repo_config = {}
    reason = telemetry.disabled_reason(repo_config)
    if reason:
        console.print(f"Usage data: [bold]off[/bold] ({reason}).")
    else:
        console.print("Usage data: [bold]on[/bold]. Turn it off with `sbombox config --telemetry off`.")
