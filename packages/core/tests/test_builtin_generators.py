"""Package managers' own SBOM commands: npm sbom, pnpm sbom, uv export."""
from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sbombox_core.generate import GENERATORS, generate_with_report, plan_generators

_NPM_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {"component": {"type": "application", "name": "demo", "version": "1.0.0"}},
    "components": [
        {
            "type": "library",
            "name": "ms",
            "version": "2.1.3",
            "purl": "pkg:npm/ms@2.1.3",
            "bom-ref": "ms@2.1.3",
        }
    ],
}

_PNPM_LOCK = """lockfileVersion: '9.0'

packages:

  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-%s}

  ms@2.1.3:
    resolution: {integrity: sha512-%s}
"""


def _sha512_b64(seed: bytes) -> str:
    import hashlib

    return base64.b64encode(hashlib.sha512(seed).digest()).decode()


def _npm_project(tmp_path: Path) -> Path:
    (tmp_path / "package.json").write_text('{"name": "demo", "version": "1.0.0"}')
    (tmp_path / "package-lock.json").write_text("{}")
    return tmp_path


def _available(*commands: str):
    return lambda c: c in commands


# --------------------------------------------------------------- planning


def test_npm_lockfile_puts_npm_sbom_first(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    assert plan_generators(["npm"], tmp_path)[:2] == ["npm-sbom", "npm"]


def test_pnpm_lockfile_uses_pnpm_not_npm(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    plan = plan_generators(["npm"], tmp_path)
    assert plan[:2] == ["pnpm-sbom", "pnpm-sbom-lockfile"]
    assert "npm-sbom" not in plan


def test_uv_lock_puts_uv_export_first(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n")
    assert plan_generators(["pypi"], tmp_path)[:2] == ["uv-cyclonedx", "pypi"]


def test_without_a_path_the_plan_is_unchanged() -> None:
    assert plan_generators(["npm"]) == ["npm", "cdxgen", "syft"]


def test_polyglot_still_prefers_universal_tools(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    (tmp_path / "uv.lock").write_text("version = 1\n")
    assert plan_generators(["npm", "pypi"], tmp_path)[:2] == ["cdxgen", "syft"]


def test_env_override_sets_the_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOMBOX_GENERATOR", "cyclonedx-npm, syft")
    assert plan_generators(["npm"], tmp_path) == ["cyclonedx-npm", "syft"]


def test_env_override_rejects_unknown_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOMBOX_GENERATOR", "npm-sbom,nope")
    with pytest.raises(RuntimeError, match="unknown generator.*nope"):
        plan_generators(["npm"])


def test_builtin_generators_leave_dev_dependencies_out() -> None:
    assert "--omit" in GENERATORS["npm-sbom"]["args"]
    assert "--prod" in GENERATORS["pnpm-sbom"]["args"]
    assert "--no-dev" in GENERATORS["uv-cyclonedx"]["args"]


# --------------------------------------------------------------- running


def test_npm_sbom_output_is_read_from_stdout(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        return MagicMock(returncode=0, stdout=json.dumps(_NPM_CDX).encode())

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("npm")),
        patch("sbombox_core.generate._tool_version", return_value=(12, 2, 0)),
    ):
        result = generate_with_report(tmp_path, ["npm"])

    assert result.generator == "npm sbom"
    assert calls[0][:2] == ["npm", "sbom"] and "--package-lock-only" in calls[0]
    assert [c.name for c in result.sbom.components] == ["ms"]
    assert not (tmp_path / ".sbombox-output.json").exists()


def test_old_npm_falls_back_to_cyclonedx_npm(tmp_path: Path) -> None:
    _npm_project(tmp_path)
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        (tmp_path / ".sbombox-output.json").write_text(json.dumps(_NPM_CDX))
        return MagicMock(returncode=0)

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("npm", "cyclonedx-npm")),
        patch("sbombox_core.generate._tool_version", return_value=(8, 19, 4)),
    ):
        result = generate_with_report(tmp_path, ["npm"])

    assert result.generator == "cyclonedx-npm"
    assert [c[0] for c in calls] == ["cyclonedx-npm"]


def test_stale_lockfile_error_is_explained(tmp_path: Path) -> None:
    _npm_project(tmp_path)

    def run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, stderr=b"npm error code ESBOMPROBLEMS\nmissing: x@1")

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("npm")),
        patch("sbombox_core.generate._tool_version", return_value=(12, 2, 0)),
        pytest.raises(RuntimeError, match=r"Run `npm install`, commit package-lock.json"),
    ):
        generate_with_report(tmp_path, ["npm"])


def test_empty_builtin_sbom_falls_through(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "requirements.txt").write_text("ms==1\n")
    empty = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []}
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        body = empty if cmd[0] == "uv" else _NPM_CDX
        (tmp_path / ".sbombox-output.json").write_text(json.dumps(body))
        return MagicMock(returncode=0)

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("uv", "cyclonedx-py")),
        patch("sbombox_core.generate._tool_version", return_value=(0, 12, 0)),
    ):
        result = generate_with_report(tmp_path, ["pypi"])

    assert [c[0] for c in calls] == ["uv", "cyclonedx-py"]
    assert result.generator == "cyclonedx-py"


def test_pnpm_hashes_are_filled_from_the_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "demo", "version": "1.0.0"}')
    scoped, plain = _sha512_b64(b"scoped"), _sha512_b64(b"ms")
    (tmp_path / "pnpm-lock.yaml").write_text(_PNPM_LOCK % (scoped, plain))
    body = dict(_NPM_CDX)
    body["components"] = [
        {"type": "library", "name": "ms", "version": "2.1.3", "purl": "pkg:npm/ms@2.1.3"},
        {"type": "library", "name": "pkg", "group": "@scope", "version": "1.0.0",
         "purl": "pkg:npm/%40scope/pkg@1.0.0"},
    ]
    calls: list[list[str]] = []

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        Path(cmd[cmd.index("--out") + 1]).write_text(json.dumps(body))
        return MagicMock(returncode=0)

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("pnpm")),
        patch("sbombox_core.generate._tool_version", return_value=(11, 28, 12)),
    ):
        result = generate_with_report(tmp_path, ["npm"], fmt="cyclonedx-1.6")

    assert calls[0][calls[0].index("--sbom-spec-version") + 1] == "1.6"
    digests = {c.name: c.hashes[0].content for c in result.sbom.components}
    assert digests["ms"] == base64.b64decode(plain).hex()
    assert digests["pkg"] == base64.b64decode(scoped).hex()


def test_uv_sdist_hashes_are_promoted(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1"\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    sdist = {"type": "distribution", "url": "https://files.example/amqp-5.4.0.tar.gz",
             "hashes": [{"alg": "SHA-256", "content": "a" * 64}]}
    wheel = {"type": "distribution", "url": "https://files.example/amqp-5.4.0-py3-none-any.whl",
             "hashes": [{"alg": "SHA-256", "content": "b" * 64}]}
    only_wheels = [dict(wheel), dict(wheel, url="https://files.example/x-1-cp312-macosx.whl")]
    body = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [
            {"type": "library", "name": "amqp", "version": "5.4.0", "purl": "pkg:pypi/amqp@5.4.0",
             "externalReferences": [wheel, sdist]},
            {"type": "library", "name": "x", "version": "1", "purl": "pkg:pypi/x@1",
             "externalReferences": only_wheels},
        ],
    }

    def run(cmd, **kwargs):
        Path(cmd[cmd.index("--output-file") + 1]).write_text(json.dumps(body))
        return MagicMock(returncode=0, stdout=b"")

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("uv")),
        patch("sbombox_core.generate._tool_version", return_value=(0, 12, 23)),
    ):
        result = generate_with_report(tmp_path, ["pypi"])

    hashes = {c.name: [h.content for h in c.hashes] for c in result.sbom.components}
    assert hashes["amqp"] == ["a" * 64]  # the sdist, not the wheel
    assert hashes["x"] == []  # several platform wheels: no single right answer


def test_go_and_rust_tools_get_their_real_flags() -> None:
    assert GENERATORS["golang"]["args"][:2] == ["mod", "-json"]
    assert "--format" in GENERATORS["cargo"]["args"] and "--output-format" not in GENERATORS["cargo"]["args"]


def test_cargo_member_copies_are_cleaned_up(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[workspace]\n")
    (tmp_path / "Cargo.lock").write_text("")
    member = tmp_path / "crates" / "core"
    member.mkdir(parents=True)

    def run(cmd, **kwargs):
        # cargo-cyclonedx writes <override>.json beside every Cargo.toml.
        for d in (tmp_path, member):
            (d / ".sbombox-output.json").write_text(json.dumps(_NPM_CDX))
        return MagicMock(returncode=0)

    with (
        patch("sbombox_core.generate.subprocess.run", side_effect=run),
        patch("sbombox_core.generate._is_available", side_effect=_available("cargo-cyclonedx")),
    ):
        result = generate_with_report(tmp_path, ["cargo"])

    assert result.generator == "cargo-cyclonedx"
    assert not list(tmp_path.rglob(".sbombox-output.json"))
