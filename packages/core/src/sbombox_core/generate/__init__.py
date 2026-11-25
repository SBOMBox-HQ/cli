"""SBOM generation - run native generators and fallback adapters.

Supports, in order of preference for a single-ecosystem project:
    - built-in package-manager commands, used when the project's lockfile and a
      new enough tool are present: ``npm sbom`` (npm 9.5+), ``pnpm sbom``
      (pnpm 11.1+) and ``uv export --format cyclonedx1.5`` (uv 0.9.11+)
    - ``cyclonedx-py`` (Python)
    - ``cyclonedx-npm`` (Node.js)
    - ``cargo-cyclonedx`` (Rust)
    - ``cyclonedx-gomod`` (Go)
    - ``cdxgen`` (universal fallback)
    - ``syft`` (universal fallback)

Usage::

    from sbombox_core.generate import generate
    sbom = generate(path=".", ecosystems="auto", fmt="cyclonedx-1.6")
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from sbombox_core.model.sbom import Sbom

__all__ = [
    "BUILTIN_GENERATORS",
    "GENERATORS",
    "GenerationResult",
    "detect_ecosystem",
    "generate",
    "generate_with_report",
    "missing_lockfiles",
    "plan_generators",
]

#: Ecosystems with a dedicated (package-manager-native) generator.
NATIVE_ECOSYSTEMS = ("pypi", "npm", "cargo", "golang")
#: Package managers' own SBOM commands, per ecosystem, best first. Each is
#: tried only when its lockfile is in the project and the tool is new enough
#: (see ``lockfiles`` and ``min_version`` in :data:`GENERATORS`). They need
#: nothing extra installed and read the package manager's own resolution.
BUILTIN_GENERATORS: dict[str, tuple[str, ...]] = {
    "npm": ("npm-sbom", "pnpm-sbom", "pnpm-sbom-lockfile"),
    "pypi": ("uv-cyclonedx",),
}
#: Environment variable that forces the generator order, e.g.
#: ``SBOMBOX_GENERATOR=cyclonedx-npm`` or ``SBOMBOX_GENERATOR=npm-sbom,syft``.
GENERATOR_ENV = "SBOMBOX_GENERATOR"
#: Generators that read every ecosystem. cdxgen first: in published comparisons
#: it is the more complete of the two (notably for Java and Python), but it
#: needs Node.js and is much slower, so it is only used when installed.
UNIVERSAL_GENERATORS = ("cdxgen", "syft")

#: Files that pin exact (including transitive) versions, per ecosystem.
#: Without one, every generator has to guess and transitive packages go missing.
LOCKFILES: dict[str, tuple[str, ...]] = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
    "pypi": ("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "requirements.txt"),
    "cargo": ("Cargo.lock",),
    "golang": ("go.sum",),
    "gem": ("Gemfile.lock",),
    "composer": ("composer.lock",),
}


@dataclass
class GenerationResult:
    """An SBOM plus how it was made, so callers can tell the user."""

    sbom: Sbom
    generator: str
    ecosystems: list[str]
    missing_lockfiles: list[str] = field(default_factory=list)


def plan_generators(ecosystems: list[str], path: str | Path | None = None) -> list[str]:
    """Order in which generators are tried for ``ecosystems``.

    * One ecosystem with a native generator: the package manager's built-in
      SBOM command first (when ``path`` holds its lockfile), then the native
      CycloneDX tool. Package manager tooling resolves that ecosystem's
      dependency tree most faithfully.
    * Several ecosystems (or none we recognise): a universal tool first, since a
      native tool would only see its own part of the repository.

    ``SBOMBOX_GENERATOR`` overrides the order. Unavailable tools are skipped at
    run time; a tool that fails falls through to the next.
    """
    forced = os.environ.get(GENERATOR_ENV, "").strip()
    if forced:
        names = [n.strip() for n in forced.split(",") if n.strip()]
        unknown = [n for n in names if n not in GENERATORS]
        if unknown:
            raise RuntimeError(
                f"{GENERATOR_ENV} names unknown generator(s) {', '.join(unknown)}. "
                f"Valid names: {', '.join(sorted(GENERATORS))}."
            )
        return names

    native = [eco for eco in ecosystems if eco in NATIVE_ECOSYSTEMS]
    builtin = [] if path is None else _builtin_candidates(ecosystems, Path(path))
    universal = list(UNIVERSAL_GENERATORS)
    if len(ecosystems) == 1 and native:
        return builtin + native + universal
    return universal + builtin + native


def _builtin_candidates(ecosystems: list[str], path: Path) -> list[str]:
    """Built-in package-manager generators whose lockfile is in ``path``."""
    names: list[str] = []
    for eco in ecosystems:
        for name in BUILTIN_GENERATORS.get(eco, ()):
            if any((path / lock).is_file() for lock in GENERATORS[name]["lockfiles"]):
                names.append(name)
    return names


def missing_lockfiles(path: str | Path, ecosystems: list[str]) -> list[str]:
    """Ecosystems in ``ecosystems`` with no lockfile in ``path``."""
    root = Path(path)
    return [
        eco
        for eco in ecosystems
        if eco in LOCKFILES and not any((root / name).is_file() for name in LOCKFILES[eco])
    ]


def generate(
    path: str | Path = ".",
    ecosystems: str | list[str] = "auto",
    fmt: str = "cyclonedx-1.6",
    enrich: bool = False,
) -> Sbom:
    """Generate an SBOM from a project directory.

    Args:
        path: Path to the project root.
        ecosystems: Ecosystem(s) to scan - ``"auto"`` detects from lock files
            and manifests, or a list like ``["npm", "pypi"]``.
        fmt: Output format - ``"cyclonedx-1.6"``, ``"cyclonedx-1.7"``, ``"spdx-2.3"``.
        enrich: Whether to enrich components with registry data.

    Returns:
        The generated :class:`Sbom`.

    Raises:
        RuntimeError: if no suitable generator is found.
    """
    return generate_with_report(path, ecosystems, fmt).sbom


def generate_with_report(
    path: str | Path = ".",
    ecosystems: str | list[str] = "auto",
    fmt: str = "cyclonedx-1.6",
) -> GenerationResult:
    """Like :func:`generate`, also saying which generator ran and which lockfiles are missing."""
    project_path = Path(path).resolve()

    if ecosystems == "auto":
        ecosystems = detect_ecosystem(project_path)
    if isinstance(ecosystems, str):
        ecosystems = [ecosystems]

    errors: list[str] = []
    tried: set[tuple[str, ...]] = set()
    for name in plan_generators(ecosystems, project_path):
        generator = GENERATORS[name]
        # Aliases (e.g. "npm" and "cyclonedx-npm") run the same command line once.
        key = (generator["command"], *generator.get("args", []))
        if key in tried or not _is_available(generator["command"]):
            continue
        if not _new_enough(generator):
            continue
        tried.add(key)
        try:
            sbom = _run_generator(generator, project_path, fmt, ecosystem=name)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        return GenerationResult(
            sbom=sbom,
            generator=generator.get("label", generator["command"]),
            ecosystems=ecosystems,
            missing_lockfiles=missing_lockfiles(project_path, ecosystems),
        )

    if errors:
        raise RuntimeError("; ".join(errors))
    raise RuntimeError(
        f"No SBOM generator found for ecosystems {ecosystems}. "
        "Install one with: curl -fsSL https://sbombox.com/install.sh | sh"
    )


def detect_ecosystem(path: str | Path = ".") -> list[str]:
    """Detect project ecosystems from lock files and manifests.

    Args:
        path: Path to the project root.

    Returns:
        A list of ecosystem names (e.g. ``["npm", "pypi"]``).
    """
    project_path = Path(path).resolve()
    ecosystems: list[str] = []

    # Lockfiles and manifests both count: a manifest-only project is still that
    # ecosystem (see :func:`missing_lockfiles` for the accuracy caveat).
    indicators = {
        "package-lock.json": "npm",
        "npm-shrinkwrap.json": "npm",
        "package.json": "npm",
        "yarn.lock": "npm",
        "pnpm-lock.yaml": "npm",
        "requirements.txt": "pypi",
        "Pipfile.lock": "pypi",
        "poetry.lock": "pypi",
        "uv.lock": "pypi",
        "pdm.lock": "pypi",
        "pyproject.toml": "pypi",
        "setup.py": "pypi",
        "Cargo.lock": "cargo",
        "Cargo.toml": "cargo",
        "go.sum": "golang",
        "go.mod": "golang",
        "Gemfile.lock": "gem",
        "pom.xml": "maven",
        "build.gradle": "maven",
        "build.gradle.kts": "maven",
        "composer.lock": "composer",
        "composer.json": "composer",
    }

    for filename, eco in indicators.items():
        if (project_path / filename).is_file():
            if eco not in ecosystems:
                ecosystems.append(eco)

    return ecosystems or ["generic"]


# --------------------------------------------------------- internals


def _is_available(command: str) -> bool:
    """Check if a command is available on PATH."""
    return shutil.which(command) is not None


@cache
def _tool_version(command: str) -> tuple[int, ...] | None:
    """``command --version`` as a tuple of ints, or ``None`` if unknown."""
    try:
        proc = subprocess.run([command, "--version"], capture_output=True, timeout=30, check=True)
        out = proc.stdout.decode(errors="replace") if isinstance(proc.stdout, bytes) else ""
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(part) for part in match.groups()) if match else None


def _new_enough(generator: dict[str, Any]) -> bool:
    """True when the generator has no minimum version, or the tool meets it.

    An unknown version counts as too old: the next generator in the plan is a
    safer bet than a command that may not exist in this tool's release.
    """
    minimum = generator.get("min_version")
    if minimum is None:
        return True
    version = _tool_version(generator["command"])
    return version is not None and version >= minimum


def _explain_failure(command: str, stderr: str) -> str:
    """Turn a generator's raw error into one the user can act on."""
    if "ESBOMPROBLEMS" in stderr:
        return (
            "npm sbom found packages missing from, or invalid in, package-lock.json. "
            "Run `npm install`, commit package-lock.json, and try again."
        )
    if command == "uv" and ("--locked" in stderr or "needs to be updated" in stderr):
        return "uv.lock is out of date. Run `uv lock`, commit uv.lock, and try again."
    return stderr


def _remove_member_outputs(project_path: Path, name: str) -> None:
    """Delete copies of ``name`` that cargo-cyclonedx wrote next to workspace members."""
    skip = {".git", "target", "node_modules", ".venv"}
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in skip]
        if name in files:
            (Path(root) / name).unlink(missing_ok=True)


def _promote_distribution_hashes(sbom: Sbom) -> Sbom:
    """Copy each component's source-distribution hash onto the component.

    ``uv export --format cyclonedx1.5`` records SHA-256 digests only on the
    ``distribution`` external references (one per sdist and wheel), so the
    component itself looks unhashed. The sdist is the one artifact every
    platform shares, so its digest is promoted; failing that, a lone artifact's.
    """
    for component in sbom.components:
        if component.hashes:
            continue
        dists = [r for r in component.external_references if r.type == "distribution" and r.hashes]
        sdists = [r for r in dists if not r.url.endswith(".whl")]
        chosen = sdists[0] if sdists else (dists[0] if len(dists) == 1 else None)
        if chosen:
            component.hashes = list(chosen.hashes)
    return sbom


def _backfill_pnpm_hashes(sbom: Sbom, project_path: Path) -> Sbom:
    """Add SHA-512 hashes from ``pnpm-lock.yaml`` to components that lack one.

    ``pnpm sbom`` leaves hashes out even though the lockfile pins each
    tarball's integrity. That integrity is the same digest ``npm sbom``
    reports, so copying it over loses nothing and fixes the integrity score.
    """
    lockfile = project_path / "pnpm-lock.yaml"
    if not lockfile.is_file():
        return sbom
    from urllib.parse import unquote

    from sbombox_core.model.common import Hash

    integrity: dict[str, str] = {}
    current: str | None = None
    for line in lockfile.read_text(errors="replace").splitlines():
        key = re.match(r"^  '?(@?[^\s'@]+(?:/[^\s'@]+)?@[^\s'(:]+)'?:\s*$", line)
        if key:
            current = key.group(1)
            continue
        found = re.search(r"integrity:\s*sha512-([A-Za-z0-9+/=]+)", line)
        if found and current:
            with contextlib.suppress(ValueError):
                integrity[current] = base64.b64decode(found.group(1)).hex()
            current = None

    for component in sbom.components:
        if component.hashes or not component.purl or not component.purl.startswith("pkg:npm/"):
            continue
        coordinate = unquote(component.purl[len("pkg:npm/"):].split("?", 1)[0].split("#", 1)[0])
        digest = integrity.get(coordinate)
        if digest:
            component.hashes = [Hash(alg="SHA-512", content=digest)]
    return sbom


def _cyclonedx_version(fmt: str) -> str:
    """CycloneDX spec version to ask generators for.

    SPDX output is produced by converting the generated CycloneDX document, so
    ``spdx-2.3`` must not leak its "2.3" into a CycloneDX version flag.
    """
    if fmt.startswith("cyclonedx-"):
        return fmt.split("-", 1)[1]
    return "1.6"


def _python_args(project_path: Path, workdir: Path) -> list[str]:
    """Pick the cyclonedx-py subcommand for the Python project layout.

    Preference: Poetry lock, Pipenv lock, requirements.txt, uv.lock (exported to
    pinned requirements via ``uv export``), and finally the PEP 621
    ``[project].dependencies`` declared in pyproject.toml.
    """
    pyproject = project_path / "pyproject.toml"
    root = ["--pyproject", str(pyproject)] if pyproject.is_file() else []

    if (project_path / "poetry.lock").is_file():
        return ["poetry", "--sv", "{version}", "-o", "{output}", str(project_path)]
    if (project_path / "Pipfile.lock").is_file():
        return ["pipenv", *root, "--sv", "{version}", "-o", "{output}", str(project_path)]

    requirements = project_path / "requirements.txt"
    if not requirements.is_file():
        requirements = workdir / "requirements.txt"
        lines = _uv_export(project_path, requirements) if (project_path / "uv.lock").is_file() else None
        if lines is None:
            if not pyproject.is_file():
                raise RuntimeError(
                    "Generator cyclonedx-py failed: no requirements.txt, poetry.lock, "
                    "Pipfile.lock, uv.lock or pyproject.toml found."
                )
            requirements.write_text("\n".join(_declared_dependencies(pyproject)) + "\n")

    return ["requirements", *root, "--sv", "{version}", "-o", "{output}", str(requirements)]


def _uv_export(project_path: Path, target: Path) -> list[str] | None:
    """Export uv.lock to a pinned requirements file; ``None`` if that fails."""
    if not _is_available("uv"):
        return None
    base = ["uv", "export", "--frozen", "--no-hashes", "--no-header", "--format", "requirements-txt"]
    # --all-packages covers every member of a uv workspace (exporting only the
    # root of a workspace yields an empty list). Older uv lacks these flags, so
    # fall back to the single-project form.
    for flags in (["--all-packages", "--no-emit-workspace"], ["--no-emit-project"]):
        try:
            subprocess.run([*base, *flags, "-o", str(target)], cwd=project_path,
                           capture_output=True, check=True, timeout=120)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if target.is_file():
            return target.read_text().splitlines()
    return None


def _declared_dependencies(pyproject: Path) -> list[str]:
    """Return PEP 508 strings from ``[project].dependencies``."""
    try:
        data = tomllib.loads(pyproject.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"Generator cyclonedx-py failed: cannot read {pyproject}: {exc}") from exc
    deps = data.get("project", {}).get("dependencies", [])
    return [d for d in deps if isinstance(d, str)]


def _run_generator(
    generator: dict[str, Any],
    project_path: Path,
    fmt: str,
    ecosystem: str | None = None,
) -> Sbom:
    """Run a generator command and parse the output."""
    command = generator["command"]
    output_file = project_path / ".sbombox-output.json"

    with tempfile.TemporaryDirectory(prefix="sbombox-") as tmp:
        if command == "cyclonedx-py":
            args_template = _python_args(project_path, Path(tmp))
        else:
            args_template = generator.get("args", [])

        subs = {
            "{version}": _cyclonedx_version(fmt),
            # pnpm writes CycloneDX 1.5-1.7; anything else is asked for as 1.6.
            "{pnpm_version}": v if (v := _cyclonedx_version(fmt)) in ("1.5", "1.6", "1.7") else "1.6",
            "{path}": str(project_path),
            "{output}": str(output_file),
        }
        args = []
        for a in args_template:
            for key, value in subs.items():
                a = a.replace(key, value)
            args.append(a)

        label = generator.get("label", command)
        try:
            proc = subprocess.run([command, *args], cwd=project_path, capture_output=True, check=True, timeout=300)
            if generator.get("stdout"):
                # Built-in commands such as `npm sbom` only print the document.
                output_file.write_bytes(proc.stdout if isinstance(proc.stdout, bytes) else b"")
            if not output_file.is_file() or output_file.stat().st_size == 0:
                raise RuntimeError(f"Generator {label} produced no output.")
            from sbombox_core import load

            sbom = load(output_file)
            if not sbom.components and generator.get("lockfiles"):
                # A lockfile with packages should never yield an empty SBOM;
                # let the next generator try instead of uploading nothing.
                raise RuntimeError(f"Generator {label} produced an SBOM with no components.")
            if command == "pnpm":
                sbom = _backfill_pnpm_hashes(sbom, project_path)
            elif command == "uv":
                sbom = _promote_distribution_hashes(sbom)
            return sbom
        except subprocess.CalledProcessError as exc:
            # Surface the generator's own diagnostics: without them a bare exit
            # code gives the caller nothing to act on.
            stderr = (exc.stderr or b"").decode(errors="replace").strip()
            raise RuntimeError(f"Generator {label} failed: {_explain_failure(command, stderr) or exc}") from exc
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Generator {label} failed: {exc}") from exc
        finally:
            # Never leave a partial/empty output file in the user's project.
            output_file.unlink(missing_ok=True)
            if command == "cargo-cyclonedx":
                _remove_member_outputs(project_path, output_file.name)


def _gen_cyclonedx_py(project_path: Path, fmt: str) -> Sbom:
    """Generate via cyclonedx-py."""
    return _run_generator(GENERATORS["cyclonedx-py"], project_path, fmt)


#: cargo-cyclonedx writes ``<name>.json`` next to every Cargo.toml in the
#: workspace; naming it after our output file puts the root crate's SBOM where
#: the runner reads it (members' copies are removed afterwards). It supports
#: CycloneDX up to 1.5 and defaults to 1.3.
CARGO_ARGS = ["cyclonedx", "--format", "json", "--spec-version", "1.5", "--override-filename", ".sbombox-output"]
#: ``mod`` covers every module the main module's packages require; ``-json``
#: because the default output is XML.
GOMOD_ARGS = ["mod", "-json", "-output", "{output}", "{path}"]

GENERATORS: dict[str, dict[str, Any]] = {
    # --- Built-in package-manager commands (see BUILTIN_GENERATORS) -------
    # Release SBOMs describe what ships, so dev dependencies are left out, and
    # the root is an application. The lockfile is read directly, so a fresh CI
    # checkout works without installing anything.
    "npm-sbom": {
        "command": "npm",
        "label": "npm sbom",
        "args": [
            "sbom", "--sbom-format", "cyclonedx", "--sbom-type", "application",
            "--omit", "dev", "--package-lock-only",
        ],
        "stdout": True,
        "lockfiles": ("package-lock.json", "npm-shrinkwrap.json"),
        "min_version": (9, 5, 0),
    },
    # pnpm reads licenses from its store; with an empty store it fails and the
    # lockfile-only variant below runs instead (no licenses, same packages).
    "pnpm-sbom": {
        "command": "pnpm",
        "label": "pnpm sbom",
        "args": [
            "sbom", "--sbom-format", "cyclonedx", "--sbom-spec-version", "{pnpm_version}",
            "--sbom-type", "application", "--prod", "--out", "{output}",
        ],
        "lockfiles": ("pnpm-lock.yaml",),
        "min_version": (11, 1, 0),
    },
    "pnpm-sbom-lockfile": {
        "command": "pnpm",
        "label": "pnpm sbom --lockfile-only",
        "args": [
            "sbom", "--sbom-format", "cyclonedx", "--sbom-spec-version", "{pnpm_version}",
            "--sbom-type", "application", "--prod", "--lockfile-only", "--out", "{output}",
        ],
        "lockfiles": ("pnpm-lock.yaml",),
        "min_version": (11, 1, 0),
    },
    # --all-packages: exporting only a workspace root yields an empty SBOM.
    "uv-cyclonedx": {
        "command": "uv",
        "label": "uv export",
        "args": [
            "export", "--format", "cyclonedx1.5", "--frozen", "--all-packages",
            "--no-dev", "--output-file", "{output}",
        ],
        "lockfiles": ("uv.lock",),
        "min_version": (0, 9, 11),
    },
    # --- Native and universal CycloneDX generators ----------------------
    "pypi": {
        "command": "cyclonedx-py",
        # Arguments are chosen per project layout by ``_python_args``.
        "args": [],
    },
    "cyclonedx-py": {
        "command": "cyclonedx-py",
        "args": [],
    },
    # --package-lock-only: read the lockfile, so a fresh CI checkout without
    # node_modules works (otherwise `npm ls` fails and the tool is skipped).
    "npm": {
        "command": "cyclonedx-npm",
        "args": ["--package-lock-only", "--output-file", "{output}"],
    },
    "cyclonedx-npm": {
        "command": "cyclonedx-npm",
        "args": ["--package-lock-only", "--output-file", "{output}"],
    },
    "cargo": {
        "command": "cargo-cyclonedx",
        "args": CARGO_ARGS,
    },
    "cargo-cyclonedx": {
        "command": "cargo-cyclonedx",
        "args": CARGO_ARGS,
    },
    "golang": {
        "command": "cyclonedx-gomod",
        "args": GOMOD_ARGS,
    },
    "cyclonedx-gomod": {
        "command": "cyclonedx-gomod",
        "args": GOMOD_ARGS,
    },
    "cdxgen": {
        "command": "cdxgen",
        "args": ["-o", "{output}", "{path}"],
    },
    "syft": {
        "command": "syft",
        "args": ["dir:{path}", "-o", "cyclonedx-json@{version}", "--file", "{output}"],
    },
}
