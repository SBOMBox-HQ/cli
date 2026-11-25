"""Configuration management commands."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console

app = typer.Typer(help="Configuration management.")
console = Console()

TEMPLATE = """\
# SBOMBox CLI configuration
api_url: https://api.sbombox.com
project_id: ""
default_format: cyclonedx
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
) -> None:
    """Emit or initialize scoring config."""
    if init:
        path = Path(".sbombox.yml")
        if path.exists():
            console.print("[yellow].sbombox.yml already exists.[/yellow]")
            return
        path.write_text(TEMPLATE)
        console.print("[green]Created .sbombox.yml[/green]")
    else:
        console.print(TEMPLATE)
