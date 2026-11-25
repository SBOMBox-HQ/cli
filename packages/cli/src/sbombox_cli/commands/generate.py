"""Generate SBOMs from source."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console

app = typer.Typer(help="Generate SBOMs.")
console = Console()

def describe_generation(console: Console, result: object) -> None:
    """Say which tool ran, and warn when a missing lockfile makes the SBOM incomplete."""
    ecosystems = ", ".join(getattr(result, "ecosystems", []) or ["unknown"])
    console.print(f"Detected: [bold]{ecosystems}[/bold] - generated with [bold]{getattr(result, 'generator', '?')}[/bold]")
    missing = getattr(result, "missing_lockfiles", [])
    if missing:
        console.print(
            f"[yellow]No lockfile for {', '.join(missing)}:[/yellow] transitive dependencies may be missing "
            "and versions may be guessed. Commit your lockfile (e.g. package-lock.json, uv.lock, go.sum) "
            "for a complete SBOM."
        )


#: Short format names accepted on the command line mapped onto the versioned
#: spec ids that :mod:`sbombox_core.generate` and ``serialize`` speak.
_SPEC_FORMATS = {
    "cyclonedx": "cyclonedx-1.6",
    "cyclonedx-json": "cyclonedx-1.6",
    "spdx": "spdx-2.3",
    "spdx-json": "spdx-2.3",
}


def _spec_format(value: str) -> str:
    normalised = value.strip().lower()
    return _SPEC_FORMATS.get(normalised, normalised)

@app.command()
def generate(
    output: Path = typer.Option("sbom.json", "--output", "-o", help="File to write the SBOM to."),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format: cyclonedx (CycloneDX 1.6) or spdx (SPDX 2.3)."),
    upload: bool = typer.Option(False, "--upload", help="Upload the SBOM to the active project after generating it."),
    directory: Path = typer.Option(None, "--dir", help="Project directory to scan. Default: the current directory."),
    image: str = typer.Option(
        None, "--image", help="Container image to scan instead of a directory, e.g. ghcr.io/acme/api:1.4.0."
    ),
    platform: str = typer.Option(
        None, "--platform", help="With --image: platform of a multi-platform image, e.g. linux/arm64."
    ),
) -> None:
    """Detect ecosystem and generate an SBOM, for a directory or a container image."""
    from sbombox_core.generate import detect_ecosystem, generate_with_report
    from sbombox_core.serialize import serialize_sbom

    if image and directory is not None:
        console.print("[red]Use --dir or --image, not both.[/red]")
        raise typer.Exit(code=2)
    if platform and not image:
        console.print("[red]--platform only applies with --image.[/red]")
        raise typer.Exit(code=2)
    if image:
        from sbombox_core.generate.image import generate_image

        try:
            spec_format = _spec_format(format)
            result = generate_image(image, spec_format, platform=platform)
            output.write_text(serialize_sbom(result.sbom, spec_format))
        except Exception as exc:
            console.print(f"[red]Generation failed:[/red] {exc}")
            raise typer.Exit(code=4) from exc
        console.print(f"Image: [bold]{image}[/bold] - generated with [bold]{result.generator}[/bold]")
        _finish(output, upload)
        return

    root = (directory or Path(".")).resolve()
    ecosystems = detect_ecosystem(root)
    if ecosystems == ["generic"]:
        console.print(f"[red]Could not detect project ecosystem[/red] in {root}: no supported manifest or lockfile.")
        raise typer.Exit(code=4)
    try:
        spec_format = _spec_format(format)
        result = generate_with_report(root, ecosystems, spec_format)
        output.write_text(serialize_sbom(result.sbom, spec_format))
    except Exception as exc:
        console.print(f"[red]Generation failed:[/red] {exc}")
        raise typer.Exit(code=4)
    describe_generation(console, result)
    _finish(output, upload)


def _finish(output: Path, upload: bool) -> None:
    """Report where the SBOM went and upload it if asked."""
    console.print(f"[green]SBOM written to {output}[/green]")
    if upload:
        from sbombox_cli.commands.push import upload as upload_sbom

        response = upload_sbom(output)
        console.print(f"[green]SBOM uploaded:[/green] {response.get('id', 'ok')}")
