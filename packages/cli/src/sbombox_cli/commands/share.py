"""Generate privacy-preserving SBOM reports."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console

app = typer.Typer(help="Share privacy-preserving reports.")
console = Console()

@app.command()
def share(
    sbom_path: Path = typer.Argument(..., help="Path to the SBOM file."),
    output: Path = typer.Option("report.json", "--output", "-o", help="File to write the report to."),
) -> None:
    """Generate a privacy-preserving SBOM report."""
    try:
        from sbombox_core import load, score
        from sbombox_core.share import privacy_report

        sbom = load(sbom_path.read_bytes())
        # ``privacy_report`` summarises a ScoreResult (aggregates only), so the
        # SBOM is scored first; no component identifiers leave this process.
        report = privacy_report(score(sbom))
    except Exception as exc:
        console.print(f"[red]Share failed:[/red] {exc}")
        raise typer.Exit(code=4)
    import json
    output.write_text(json.dumps(report, indent=2, default=str))
    console.print(f"[green]Report written to {output}[/green]")
