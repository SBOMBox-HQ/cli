"""Auto-fix SBOM issues."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console

app = typer.Typer(help="Auto-fix SBOM issues.")
console = Console()

@app.command()
def fix(
    sbom_path: Path = typer.Argument(..., help="Path to the SBOM file."),
    output: Path = typer.Option(None, "--output", "-o", help="Write the result here instead of overwriting the input file."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without writing anything."),
) -> None:
    """Apply auto-fixes to an SBOM."""
    try:
        from sbombox_core import load, fix as core_fix
        sbom = load(sbom_path.read_bytes())
        result = core_fix(sbom)
    except Exception as exc:
        console.print(f"[red]Fix failed:[/red] {exc}")
        raise typer.Exit(code=4)
    if dry_run:
        console.print(f"[bold]Dry run:[/bold] {len(result.changes)} change(s) would be applied:")
        for change in result.changes:
            count = f" ({change.affected_count} component(s))" if change.affected_count else ""
            console.print(f"  - {change.rule}: {change.description}{count}")
        return
    out_path = output or sbom_path
    from sbombox_core.serialize import serialize_sbom

    # Keep the document in the format it came from; the fixer returns the model,
    # not the original bytes.
    fmt = (
        "spdx-2.3"
        if str(result.sbom.format).startswith("spdx")
        else f"cyclonedx-{result.sbom.spec_version or '1.6'}"
    )
    out_path.write_text(serialize_sbom(result.sbom, fmt))
    console.print(f"[green]Applied {len(result.changes)} fix(es) to {out_path}[/green]")
