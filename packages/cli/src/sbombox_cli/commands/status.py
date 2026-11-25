"""Show project status."""
from __future__ import annotations
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Show project status.")
console = Console()

@app.command()
def status() -> None:
    """Show latest score and vulnerabilities for the linked project."""
    from sbombox_cli.config import load_config
    from sbombox_cli.api_client import ApiClient
    config = load_config()
    if not config.project_id:
        console.print("[red]No project configured. Run 'sbombox init' or 'sbombox projects use'.[/red]")
        raise typer.Exit(code=2)
    client = ApiClient(config)
    try:
        project = client.get_project(str(config.project_id))
        console.print(f"[bold]Project:[/bold] {project.get('name', 'unknown')}")
        sbom = client.latest_sbom(str(config.project_id))
        if not sbom:
            console.print("[yellow]No SBOMs uploaded yet.[/yellow]")
            return
        console.print(
            f"[bold]Latest SBOM:[/bold] {sbom.get('format', '?')} "
            f"{sbom.get('spec_version', '')} - {sbom.get('status', '?')}, "
            f"{sbom.get('component_count', 0)} components"
        )
        score = client.get_score(str(config.project_id), sbom.get("id"))
        if score:
            console.print(
                f"[bold]Score:[/bold] {score.get('total', '?')}/10 "
                f"(grade {score.get('grade', '?')})"
            )
        else:
            console.print("[yellow]No score run yet.[/yellow]")
        findings = client.get_vulnerabilities(str(config.project_id))
        console.print(f"[bold]Vulnerabilities:[/bold] {len(findings)}")
        if findings:
            table = Table(title="Findings")
            table.add_column("Severity", style="bold")
            table.add_column("Advisory", style="cyan")
            for finding in findings[:20]:
                table.add_row(
                    str(finding.get("severity", "?")),
                    str(finding.get("advisory") or finding.get("advisory_id") or "-"),
                )
            console.print(table)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=getattr(exc, "exit_code", 3))
