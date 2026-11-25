"""Score SBOM quality."""
from __future__ import annotations
import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Score SBOM quality.")
console = Console()

@app.command()
def score(
    sbom_path: Path = typer.Argument(..., help="Path to the SBOM file."),
    format: str = typer.Option("basic", "--format", "-f", help="Output: basic (one line), detailed (every check) or json."),
    fail_under: float = typer.Option(0.0, "--fail-under", help="Exit with code 1 if the score is below this value (0-10). 0 never fails."),
) -> None:
    """Score an SBOM and display results."""
    try:
        from sbombox_core import load, score as core_score
        sbom = load(sbom_path.read_bytes())
        result = core_score(sbom)
    except Exception as exc:
        console.print(f"[red]Scoring failed:[/red] {exc}")
        raise typer.Exit(code=4)
    if format == "json":
        console.print_json(json.dumps(result.model_dump(), default=str))
    elif format == "detailed":
        table = Table(title="SBOM Score (Detailed)")
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Check")
        table.add_column("Covered", justify="right")
        table.add_column("What it measures", style="dim")
        for cat in result.categories:
            for index, feat in enumerate(cat.features):
                first = index == 0
                covered = f"{feat.numerator}/{feat.denominator}" if feat.denominator else "-"
                style = "green" if feat.score >= 10 else ("yellow" if feat.score > 0 else "red")
                table.add_row(
                    cat.name if first else "",
                    f"{cat.score:.1f}" if first else "",
                    f"[{style}]{feat.name}: {feat.score:.1f}[/{style}]",
                    covered,
                    feat.description,
                    end_section=index == len(cat.features) - 1,
                )
        console.print(table)
        console.print(f"\n[bold]Total: {result.total:.1f}/10 - Grade: {result.grade.value}[/bold]")
    else:
        console.print(f"[bold]Score: {result.total:.1f}/10 - Grade: {result.grade.value}[/bold]")
    if fail_under > 0 and result.total < fail_under:
        console.print(f"[red]Score {result.total:.1f} is below threshold {fail_under}.[/red]")
        raise typer.Exit(code=1)
