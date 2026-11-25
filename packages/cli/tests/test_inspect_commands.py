"""``score --format detailed``, ``list --missing`` and ``fix --dry-run`` on a real SBOM."""
from __future__ import annotations

from pathlib import Path

from sbombox_cli.main import app
from typer.testing import CliRunner

FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "golden" / "cyclonedx-1.6-valid.json"
runner = CliRunner(env={"COLUMNS": "200"})


def test_detailed_score_shows_coverage_counts() -> None:
    result = runner.invoke(app, ["score", str(FIXTURE), "--format", "detailed"])
    assert result.exit_code == 0, result.output
    assert "0/3" in result.output and "3/3" in result.output


def test_list_missing_authors() -> None:
    result = runner.invoke(app, ["list", str(FIXTURE), "--missing", "authors"])
    assert result.exit_code == 0, result.output
    assert "Components (3)" in result.output


def test_list_rejects_unknown_filter() -> None:
    result = runner.invoke(app, ["list", str(FIXTURE), "--missing", "bogus"])
    assert result.exit_code == 2


def test_fix_dry_run_lists_changes() -> None:
    result = runner.invoke(app, ["fix", str(FIXTURE), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "add-timestamp" in result.output


def test_check_without_manifest_passes(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check", "--dir", str(tmp_path), "--fail-under", "9"])
    assert result.exit_code == 0, result.output
    assert "nothing to check" in result.output


def test_check_gates_on_score(tmp_path: Path) -> None:
    core = Path(__file__).resolve().parents[2] / "core"
    kept = tmp_path / "sbom.json"
    low = runner.invoke(app, ["check", "--dir", str(core), "--fail-under", "10", "--keep", str(kept)])
    assert low.exit_code == 1, low.output
    assert kept.is_file()
    ok = runner.invoke(app, ["check", "--dir", str(core)])
    assert ok.exit_code == 0, ok.output


def test_generate_rejects_dir_and_image_together() -> None:
    result = runner.invoke(app, ["generate", "--dir", ".", "--image", "alpine:3.20"])
    assert result.exit_code == 2
    assert "not both" in result.output


def test_generate_platform_needs_image() -> None:
    result = runner.invoke(app, ["generate", "--platform", "linux/arm64"])
    assert result.exit_code == 2


def test_generate_image_writes_the_sbom(tmp_path: Path, monkeypatch) -> None:
    import json

    from sbombox_core import load
    from sbombox_core.generate import GenerationResult

    sbom = load(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "library", "name": "busybox", "version": "1.36.1"}],
    }))
    seen = {}

    def fake(ref, fmt, platform=None):
        seen.update(ref=ref, fmt=fmt, platform=platform)
        return GenerationResult(sbom=sbom, generator="syft", ecosystems=["container"])

    monkeypatch.setattr("sbombox_core.generate.image.generate_image", fake)
    out = tmp_path / "image.json"
    result = runner.invoke(app, ["generate", "--image", "alpine:3.20", "--platform", "linux/arm64", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert seen == {"ref": "alpine:3.20", "fmt": "cyclonedx-1.6", "platform": "linux/arm64"}
    assert json.loads(out.read_text())["components"][0]["name"] == "busybox"
