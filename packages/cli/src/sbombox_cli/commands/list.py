"""List components in an SBOM."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="List SBOM components.")
console = Console()


def _license_label(choice: object) -> str:
    """Render a license choice as the identifier a human recognises.

    ``LicenseChoice`` is either a structured ``License`` or an SPDX expression;
    printing the pydantic repr leaks field names into the table.
    """
    licence = getattr(choice, "license", None)
    if licence is not None:
        return licence.id or licence.name or "unknown"
    return getattr(choice, "expression", None) or "unknown"

#: ``--missing`` filters: each keeps components where the check is falsy.
#: ``provenance`` matches the score's "any provenance" feature.
_MISSING = {
    "licenses": lambda c: c.licenses,
    "hashes": lambda c: c.hashes,
    "suppliers": lambda c: c.supplier and c.supplier.name,
    "authors": lambda c: c.author,
    "publishers": lambda c: c.publisher,
    "provenance": lambda c: (c.supplier and c.supplier.name) or c.author or c.publisher,
    "versions": lambda c: c.version,
}


@app.command(name="list")
def list_components(
    sbom_path: Path = typer.Argument(..., help="Path to the SBOM file."),
    missing: str = typer.Option(
        None, "--missing", "-m",
        help="Show only components missing this field: " + ", ".join(_MISSING) + ".",
    ),
) -> None:
    """List components in an SBOM."""
    if missing and missing not in _MISSING:
        console.print(f"[red]Unknown --missing value '{missing}'.[/red] Use one of: {', '.join(_MISSING)}.")
        raise typer.Exit(code=2)
    try:
        from sbombox_core import load
        sbom = load(sbom_path.read_bytes())
    except Exception as exc:
        console.print(f"[red]Failed to load SBOM:[/red] {exc}")
        raise typer.Exit(code=4)
    components = sbom.components
    if missing:
        components = [c for c in components if not _MISSING[missing](c)]
    table = Table(title=f"Components ({len(components)})")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("PURL")
    table.add_column("Licenses")
    table.add_column("Supplier")
    if missing in ("authors", "publishers", "provenance"):
        table.add_column("Author")
        table.add_column("Publisher")
    for comp in components:
        table.add_row(
            comp.name,
            comp.version or "-",
            comp.purl or "-",
            ", ".join(_license_label(l) for l in comp.licenses) if comp.licenses else "-",
            comp.supplier.name if comp.supplier else "-",
            *((comp.author or "-", comp.publisher or "-") if missing in ("authors", "publishers", "provenance") else ()),
        )
    console.print(table)
