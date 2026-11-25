"""Check SBOM compliance against profiles."""
from __future__ import annotations
import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Check SBOM compliance.")
console = Console()

@app.command()
def compliance(
    sbom_path: Path = typer.Argument(..., help="Path to the SBOM file."),
    profile: str = typer.Option("ntia-2021", "--profile", "-p", help="Ruleset ID, e.g. ntia-2021, cisa-2026, cra-readiness, bsi-tr-03183-2@2.1.0, or a short alias (ntia, cisa, bsi, cra)."),
    format: str = typer.Option("table", "--format", "-f", help="Output: table or json."),
) -> None:
    """Check SBOM compliance against a profile."""
    from sbombox_core.compliance import list_profiles, resolve_profile

    profile = resolve_profile(profile)
    known = list_profiles()
    if profile not in known:
        # The core library falls back to NTIA for unknown names; reporting that
        # under the requested name would be a misleading compliance record.
        console.print(f"[red]Unknown profile '{profile}'.[/red] Available: {', '.join(known)}")
        raise typer.Exit(code=2)
    try:
        from sbombox_core import load, check_compliance
        sbom = load(sbom_path.read_bytes())
        result = check_compliance(sbom, profile=profile)
    except Exception as exc:
        console.print(f"[red]Compliance check failed:[/red] {exc}")
        raise typer.Exit(code=4)
    if format == "json":
        console.print_json(json.dumps(result.model_dump(), default=str))
    else:
        table = Table(title=f"Compliance: {profile}")
        table.add_column("Requirement", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Message")
        for req in result.requirements:
            status_style = {"pass": "green", "partial": "yellow"}.get(req.status, "red")
            table.add_row(req.id, f"[{status_style}]{req.status}[/{status_style}]", req.message or "")
        console.print(table)
        console.print(f"\n[bold]Overall: {result.status.replace('_', ' ').upper()}[/bold]"
                      f" - required {result.required_score:.2f}/10, overall {result.overall:.2f}/10")
