"""Which generator runs for which project, and lockfile detection."""
from __future__ import annotations

from pathlib import Path

from sbombox_core.generate import GENERATORS, detect_ecosystem, missing_lockfiles, plan_generators


def test_single_ecosystem_prefers_native_tool() -> None:
    assert plan_generators(["pypi"]) == ["pypi", "cdxgen", "syft"]
    assert plan_generators(["npm"])[0] == "npm"


def test_polyglot_prefers_universal_tool() -> None:
    assert plan_generators(["npm", "pypi"])[:2] == ["cdxgen", "syft"]


def test_no_native_tool_uses_universal() -> None:
    assert plan_generators(["maven"]) == ["cdxgen", "syft"]
    assert plan_generators(["generic"]) == ["cdxgen", "syft"]


def test_every_planned_name_is_a_generator() -> None:
    for ecosystems in (["pypi"], ["npm"], ["cargo"], ["golang"], ["maven"], ["npm", "golang"]):
        assert all(name in GENERATORS for name in plan_generators(ecosystems))


def test_manifests_without_lockfiles_are_detected(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module x\n")
    (tmp_path / "Cargo.toml").write_text("[package]\n")
    (tmp_path / "package.json").write_text("{}")
    assert set(detect_ecosystem(tmp_path)) == {"golang", "cargo", "npm"}
    assert set(missing_lockfiles(tmp_path, ["golang", "cargo", "npm"])) == {"golang", "cargo", "npm"}


def test_lockfile_present(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    assert missing_lockfiles(tmp_path, ["npm"]) == []


def test_npm_reads_lockfile_without_node_modules() -> None:
    assert "--package-lock-only" in GENERATORS["npm"]["args"]
