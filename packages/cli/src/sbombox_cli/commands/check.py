"""``sbombox check`` - a local quality gate for pre-commit hooks.

Generates an SBOM for the directory into a temporary file, scores it, and
exits 1 if the score is below ``--fail-under``. Offline: nothing is uploaded
and nothing is written to the repository unless ``--keep`` is given.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import typer
from rich.console import Console

console = Console()


def check(
    directory: Path = typer.Option(Path("."), "--dir", help="Project directory to scan."),
    fail_under: float = typer.Option(0.0, "--fail-under", help="Exit with code 1 if the score is below this value (0-10). 0 never fails."),
    profile: str = typer.Option(None, "--profile", "-p", help="Also report the result for this compliance ruleset, e.g. ntia-2021."),
    keep: Path = typer.Option(None, "--keep", help="Save the generated SBOM to this file."),
) -> None:
    """Generate and score an SBOM locally, without uploading. Built for pre-commit hooks."""
    from sbombox_core import check_compliance, load
    from sbombox_core import score as core_score
    from sbombox_core.generate import detect_ecosystem, generate_with_report
    from sbombox_core.serialize import serialize_sbom

    from sbombox_cli.commands.generate import describe_generation

    root = directory.resolve()
    ecosystems = detect_ecosystem(root)
    if ecosystems == ["generic"]:
        console.print("[yellow]sbombox check:[/yellow] no package manifest found, nothing to check.")
        return
    try:
        generated = generate_with_report(root, ecosystems, "cyclonedx-1.6")
        content = serialize_sbom(generated.sbom, "cyclonedx-1.6")
    except Exception as exc:
        console.print(f"[red]sbombox check: could not generate an SBOM:[/red] {exc}")
        console.print("Install a generator (curl -fsSL https://sbombox.com/install.sh | sh), "
                      "or skip once with SKIP=sbombox-check git commit ...")
        raise typer.Exit(code=4) from exc
    describe_generation(console, generated)

    if keep:
        keep.write_text(content)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sbom.json"
        path.write_text(content)
        loaded = load(path.read_bytes())
    result = core_score(loaded)

    weakest = sorted(
        (feat for cat in result.categories for feat in cat.features if feat.denominator and feat.score < 10),
        key=lambda feat: feat.score,
    )[:3]
    line = f"SBOM score {result.total:.1f}/10 (grade {result.grade.value}), {len(loaded.components)} components"
    if profile:
        compliance = check_compliance(loaded, profile=profile)
        line += f"; {profile}: {compliance.status.replace('_', ' ')}"
    console.print(line)
    for feat in weakest:
        console.print(f"  lowest: {feat.name} {feat.numerator}/{feat.denominator} - {feat.description}")

    if fail_under > 0 and result.total < fail_under:
        console.print(
            f"[red]Score {result.total:.1f} is below {fail_under}.[/red] "
            "Run `sbombox score <sbom> --format detailed` (use --keep to save the SBOM) to see why."
        )
        raise typer.Exit(code=1)
