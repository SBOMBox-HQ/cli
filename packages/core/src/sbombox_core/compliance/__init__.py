"""SBOM compliance checking engine.

Checks an SBOM against versioned compliance profiles.  Each profile is a YAML
file declaring requirements; each requirement has a Python check function.

Profiles:
    - ``bsi-tr-03183-2@2.1.0``
    - ``bsi-tr-03183-2@2.0.0``
    - ``bsi-tr-03183-2@1.1``
    - ``fsct-v3``
    - ``ntia-2021``
    - ``cisa-2026``
    - ``cisa-2025`` (August 2025 draft; superseded by ``cisa-2026``)
    - ``openchain-telco``
    - ``cra-readiness``

Short aliases (``ntia``, ``cisa``, ``bsi``, ``cra``), as stored in project
settings, resolve to the current version of each standard; see
:data:`PROFILE_ALIASES`.

Usage::

    from sbombox_core import check_compliance
    result = check_compliance(sbom, "bsi-tr-03183-2@2.1.0")  # -> ComplianceResult
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from sbombox_core.model.results import ComplianceResult, RequirementResult
from sbombox_core.model.sbom import Sbom

# uuid7 is available in Python 3.14+; fall back to uuid4 for older versions.
_uuid7 = getattr(_uuid, "uuid7", None) or _uuid.uuid4

__all__ = ["PROFILE_ALIASES", "check_compliance", "list_profiles", "load_profile", "resolve_profile"]

_PROFILES_DIR = Path(__file__).parent / "profiles"

#: Short names (used as keys in project ``compliance_profiles`` settings) mapped
#: to the current profile for each standard.  Update the target here when a
#: standard publishes a new version; pinned identifiers keep working.
PROFILE_ALIASES: dict[str, str] = {
    "ntia": "ntia-2021",
    "cisa": "cisa-2026",
    "bsi": "bsi-tr-03183-2@2.1.0",
    "cra": "cra-readiness",
    "fsct": "fsct-v3",
    "openchain": "openchain-telco",
}


def resolve_profile(profile: str) -> str:
    """Return the full profile identifier for *profile*, expanding short aliases."""
    return PROFILE_ALIASES.get(profile.strip().lower(), profile) if profile else profile


def check_compliance(
    sbom: Sbom,
    profile: str = "ntia-2021",
) -> ComplianceResult:
    """Check *sbom* against the named compliance *profile*.

    Args:
        sbom: The parsed SBOM to check.
        profile: Profile identifier, e.g. ``"bsi-tr-03183-2@2.1.0"``.

    Returns:
        A :class:`ComplianceResult` with per-requirement findings.
    """
    profile_data = load_profile(profile)
    profile_name = profile_data.get("name", profile)
    profile_version = profile_data.get("version", "")

    requirements: list[RequirementResult] = []
    for req in profile_data.get("requirements", []):
        result = _evaluate_requirement(sbom, req)
        requirements.append(result)

    required_reqs = [r for r in requirements if r.level == "required"]
    optional_reqs = [r for r in requirements if r.level == "optional"]

    required_score = _calc_score(required_reqs)
    optional_score = _calc_score(optional_reqs)
    overall = round(required_score * 0.8 + optional_score * 0.2, 2)

    status = _derive_status(required_score, optional_score)
    recommendations = _build_recommendations(requirements)

    from sbombox_core import __version__

    return ComplianceResult(
        profile=profile_name,
        profile_version=profile_version,
        requirements=requirements,
        required_score=required_score,
        optional_score=optional_score,
        overall=overall,
        status=status,
        recommendations=recommendations,
        run_id=str(_uuid7()),
        timestamp=datetime.now(UTC),
        core_version=__version__,
        ruleset_version=profile_version,
    )


def list_profiles() -> list[str]:
    """Return the identifiers of all available compliance profiles."""
    if not _PROFILES_DIR.is_dir():
        return []
    profiles: list[str] = []
    for path in sorted(_PROFILES_DIR.glob("*.yaml")):
        profiles.append(path.stem)
    return profiles


def load_profile(profile: str) -> dict[str, Any]:
    """Load a profile YAML file by identifier.

    Short aliases such as ``cisa`` resolve through :data:`PROFILE_ALIASES`.
    Falls back to a built-in definition when the YAML file is missing.
    """
    profile = resolve_profile(profile)
    path = _PROFILES_DIR / f"{profile}.yaml"
    if path.is_file():
        from ruamel.yaml import YAML

        yaml = YAML(typ="safe")
        with path.open() as fh:
            data = yaml.load(fh) or {}
        return data

    # Built-in fallback profiles
    return _BUILTIN_PROFILES.get(profile, _BUILTIN_PROFILES.get("ntia-2021", {}))


# --------------------------------------------------------- internals


def _evaluate_requirement(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Run a single requirement check against *sbom*."""
    req_id = req.get("id", "unknown")
    title = req.get("title", "")
    section_ref = req.get("section_ref")
    level = req.get("level", "required")
    check_fn_name = req.get("check", "")

    check_fn = _CHECK_FUNCTIONS.get(check_fn_name)
    if check_fn is None:
        return RequirementResult(
            id=req_id,
            title=title,
            section_ref=section_ref,
            level=level,
            status="fail",
            message=f"Unknown check function: {check_fn_name}",
        )

    return check_fn(sbom, req)


def _calc_score(requirements: list[RequirementResult]) -> float:
    """Calculate a 0-10 score from a list of requirement results."""
    if not requirements:
        return 10.0
    passing = sum(1 for r in requirements if r.status == "pass")
    partial = sum(1 for r in requirements if r.status == "partial")
    return round(((passing + partial * 0.5) / len(requirements)) * 10, 2)


def _derive_status(required_score: float, optional_score: float) -> str:
    """Derive an overall compliance status from scores."""
    if required_score >= 9.0:
        return "conforms"
    if required_score >= 7.0:
        return "minor_gaps"
    if required_score >= 4.0:
        return "partial"
    return "does_not_conform"


def _build_recommendations(requirements: list[RequirementResult]) -> list[str]:
    """Build a list of recommendations from failing requirements."""
    recs: list[str] = []
    for req in requirements:
        if req.status != "pass" and req.fix_hint:
            recs.append(req.fix_hint)
    return recs


# --------------------------------------------------------- check functions


def _check_name_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have a name."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.name)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have a name.",
        fix_hint="Add name to all components." if passing < total else None,
    )


def _check_version_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have a version."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.version)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have a version.",
        fix_hint="Add version to all components." if passing < total else None,
    )


def _check_purl_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have a purl."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.purl)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have a purl.",
        fix_hint="Add Package URL (purl) to all components." if passing < total else None,
    )


def _check_supplier_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have supplier/author/publisher info."""
    total = len(sbom.components)
    passing = sum(
        1 for c in sbom.components if (c.supplier and c.supplier.name) or c.author or c.publisher
    )
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have supplier information.",
        fix_hint="Add supplier/author/publisher to all components." if passing < total else None,
    )


def _check_hashes_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have at least one hash."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.hashes)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have hash digests.",
        fix_hint="Add hash digests (SHA-256 recommended) to all components." if passing < total else None,
    )


def _check_licenses_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that all components have license information."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.licenses)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have license information.",
        fix_hint="Add license information to all components." if passing < total else None,
    )


def _check_dependency_graph(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that a dependency graph is present."""
    has_graph = len(sbom.dependencies) > 0
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if has_graph else "fail",
        affected=len(sbom.dependencies),
        total=max(len(sbom.components), 1),
        message=f"Dependency graph has {len(sbom.dependencies)} entries." if has_graph else "No dependency graph found.",
        fix_hint="Include a dependency graph in the SBOM." if not has_graph else None,
    )


def _check_metadata_timestamp(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that metadata includes a timestamp."""
    has_ts = sbom.metadata and sbom.metadata.timestamp is not None
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if has_ts else "fail",
        affected=1 if has_ts else 0,
        total=1,
        message="Metadata timestamp present." if has_ts else "Metadata timestamp missing.",
        fix_hint="Add a timestamp to the SBOM metadata." if not has_ts else None,
    )


def _check_root_component(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that metadata declares a root component."""
    has_root = sbom.metadata and sbom.metadata.component is not None
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if has_root else "fail",
        affected=1 if has_root else 0,
        total=1,
        message="Root component declared." if has_root else "No root component in metadata.",
        fix_hint="Declare the root component in SBOM metadata." if not has_root else None,
    )


def _check_no_embedded_vulns(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Check that the SBOM does not carry embedded vulnerability claims."""
    vuln_count = len(sbom.vulnerabilities)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "optional"),
        status="pass" if vuln_count == 0 else "partial",
        affected=0 if vuln_count else 1,
        total=1,
        message=f"No embedded vulnerabilities." if vuln_count == 0 else f"{vuln_count} embedded vulnerability claims found.",
        fix_hint="Remove embedded vulnerability claims; use advisory sources instead." if vuln_count else None,
    )


# --------------------------------------------------------- CISA 2026 checks
#
# The 2026 minimum elements add document-level fields that the format-neutral
# model does not carry (signature, lifecycles, serial number).  These checks
# read them from ``Sbom.raw_data`` for CycloneDX and from SPDX creation info
# (kept in ``metadata.properties``) for SPDX.

#: Words that state where in the lifecycle an SPDX 2.x SBOM was produced.  SPDX
#: 2.3 has no dedicated field, so the creator or document comment is read.
_GENERATION_CONTEXT_WORDS = (
    "source", "build", "binary", "deployed", "runtime", "analyzed", "analysed", "design", "pre-build", "post-build",
)


def _raw(sbom: Sbom) -> dict[str, Any]:
    return sbom.raw_data if isinstance(sbom.raw_data, dict) else {}


def _doc_result(
    req: dict[str, Any], ok: bool, yes: str, no: str, hint: str, partial: bool = False
) -> RequirementResult:
    """Result for a single document-level field (total is always 1)."""
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if ok else ("partial" if partial else "fail"),
        affected=1 if ok else 0,
        total=1,
        message=yes if ok else no,
        fix_hint=None if ok else hint,
    )


def _check_sbom_author(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The SBOM names who produced it: an author, or a manufacturer or supplier."""
    md = sbom.metadata
    names = [a.name for a in md.authors if a.name]
    for org in (md.manufacture, md.supplier):
        if org and org.name:
            names.append(org.name)
    return _doc_result(
        req,
        bool(names),
        f"SBOM author: {', '.join(names[:3])}.",
        "No SBOM author in the metadata.",
        "Name the SBOM author: CycloneDX metadata.authors (or manufacturer), "
        "SPDX creationInfo.creators as Person or Organization.",
    )


def _check_sbom_signature(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The SBOM carries an embedded signature (CycloneDX ``signature``)."""
    signed = bool(_raw(sbom).get("signature")) if sbom.format.value == "cyclonedx" else False
    return _doc_result(
        req,
        signed,
        "SBOM carries an embedded signature.",
        "No embedded signature. A detached signature or attestation also meets this element "
        "but is not visible in the file.",
        "Sign the SBOM: an embedded CycloneDX signature, or a detached signature or attestation "
        "(for example cosign) stored with the release.",
    )


def _check_format_name(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The document declares a machine-processable format (CycloneDX or SPDX)."""
    raw = _raw(sbom)
    if sbom.format.value == "cyclonedx":
        declared = str(raw.get("bomFormat", "")).strip().lower() == "cyclonedx" or not raw
        label = "CycloneDX"
    else:
        declared = True  # the SPDX parser only accepts documents that declare SPDX
        label = "SPDX"
    return _doc_result(
        req,
        declared,
        f"Format: {label}.",
        f"Document parses as {label} but does not declare bomFormat.",
        'Declare the format, for example "bomFormat": "CycloneDX".',
    )


def _check_format_version(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The document declares the version of its format."""
    version = (sbom.spec_version or "").strip()
    return _doc_result(
        req,
        bool(version),
        f"Format version: {version}.",
        "No format version declared.",
        "Declare the format version: CycloneDX specVersion or SPDX spdxVersion.",
    )


def _check_generation_context(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The SBOM states when in the lifecycle it was produced."""
    if sbom.format.value == "cyclonedx":
        lifecycles = (_raw(sbom).get("metadata") or {}).get("lifecycles") or []
        phases = [
            str(lc.get("phase") or lc.get("name"))
            for lc in lifecycles
            if isinstance(lc, dict) and (lc.get("phase") or lc.get("name"))
        ]
        return _doc_result(
            req,
            bool(phases),
            f"Generation context: {', '.join(phases)}.",
            "No generation context (metadata.lifecycles).",
            "Record when the SBOM was produced in metadata.lifecycles, for example phase "
            "pre-build, build or post-build (CycloneDX 1.5+).",
        )
    props = sbom.metadata.properties
    comment = " ".join(props.get(k, "") for k in ("spdx:creatorComment", "spdx:documentComment")).lower()
    found = [w for w in _GENERATION_CONTEXT_WORDS if w in comment]
    return _doc_result(
        req,
        bool(found),
        f"Generation context stated in the document comment ({found[0] if found else ''}).",
        "No generation context. SPDX 2.3 has no dedicated field.",
        "State the generation context (source, build or post-build binary) in "
        "creationInfo.comment, or use SPDX 3.0 sbomType.",
    )


def _check_tool_name(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The SBOM names the tool that generated it."""
    names = [t.display_name() for t in sbom.metadata.tools if t.name]
    return _doc_result(
        req,
        bool(names),
        f"Generated by: {', '.join(names[:3])}.",
        "No generating tool recorded.",
        "Keep the generator in the SBOM: CycloneDX metadata.tools, SPDX creationInfo.creators as 'Tool: name-version'.",
    )


def _check_tool_version(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Every named tool also carries its version."""
    tools = [t for t in sbom.metadata.tools if t.name]
    versioned = [t for t in tools if t.version]
    ok = bool(tools) and len(versioned) == len(tools)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if ok else ("partial" if versioned else "fail"),
        affected=len(versioned),
        total=max(len(tools), 1),
        message=f"{len(versioned)}/{len(tools)} tools have a version." if tools else "No generating tool recorded.",
        fix_hint=None if ok else "Record the version of every tool that generated the SBOM.",
    )


def _check_sbom_version(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """The document can be told apart from earlier revisions of itself."""
    if sbom.format.value == "cyclonedx":
        raw = _raw(sbom)
        serial = str(raw.get("serialNumber") or "").strip()
        version = raw.get("version")
        return _doc_result(
            req,
            bool(serial),
            f"SBOM {serial}, version {version if version is not None else 1}.",
            "No serialNumber, so revisions of this SBOM cannot be told apart.",
            'Add a serialNumber (urn:uuid:...) and increment "version" on every revision of the same SBOM.',
        )
    namespace = sbom.metadata.properties.get("spdx:documentNamespace", "")
    return _doc_result(
        req,
        bool(namespace),
        f"Document namespace: {namespace}.",
        "No documentNamespace.",
        "Give each SPDX document revision a unique documentNamespace.",
    )


def _check_identifier_present(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Every component has at least one lookup identifier: a purl or a CPE."""
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if c.purl or c.cpe)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components have a purl or CPE identifier.",
        fix_hint="Add a Package URL (purl) or CPE to every component." if passing < total else None,
    )


def _check_hash_algorithm(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Every hashed component names a recognised hash algorithm.

    Hashes with an unrecognised algorithm are dropped at parse time, so a
    component passes when at least one hash with a known algorithm remains.
    """
    total = len(sbom.components)
    passing = sum(1 for c in sbom.components if any(h.alg for h in c.hashes))
    weak = sum(1 for c in sbom.components if c.hashes and all(h.alg.value in ("MD5", "SHA-1") for h in c.hashes))
    message = f"{passing}/{total} components have a hash with a declared algorithm."
    if weak:
        message += f" {weak} use only MD5 or SHA-1."
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "required"),
        status="pass" if passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=message,
        fix_hint=(
            "Declare the hash algorithm for every component hash; prefer SHA-256 or stronger."
            if passing < total or weak
            else None
        ),
    )


def _check_dependency_coverage(sbom: Sbom, req: dict[str, Any]) -> RequirementResult:
    """Every component is reachable in the dependency graph (no orphans)."""
    total = len(sbom.components)
    in_graph: set[str] = set()
    for dep in sbom.dependencies:
        in_graph.add(dep.ref)
        in_graph.update(dep.depends_on)
    passing = sum(1 for c in sbom.components if c.bom_ref and c.bom_ref in in_graph)
    return RequirementResult(
        id=req.get("id", ""),
        title=req.get("title", ""),
        section_ref=req.get("section_ref"),
        level=req.get("level", "optional"),
        status="pass" if total and passing == total else ("partial" if passing > 0 else "fail"),
        affected=passing,
        total=total,
        message=f"{passing}/{total} components appear in the dependency graph.",
        fix_hint=(
            "Include every component, including transitive dependencies, in the dependency graph."
            if passing < total
            else None
        ),
    )


#: Registry of check functions by name.
_CHECK_FUNCTIONS: dict[str, Callable[[Sbom, dict[str, Any]], RequirementResult]] = {
    "name_present": _check_name_present,
    "version_present": _check_version_present,
    "purl_present": _check_purl_present,
    "supplier_present": _check_supplier_present,
    "hashes_present": _check_hashes_present,
    "licenses_present": _check_licenses_present,
    "dependency_graph": _check_dependency_graph,
    "metadata_timestamp": _check_metadata_timestamp,
    "root_component": _check_root_component,
    "no_embedded_vulns": _check_no_embedded_vulns,
    "sbom_author": _check_sbom_author,
    "sbom_signature": _check_sbom_signature,
    "format_name": _check_format_name,
    "format_version": _check_format_version,
    "generation_context": _check_generation_context,
    "tool_name": _check_tool_name,
    "tool_version": _check_tool_version,
    "sbom_version": _check_sbom_version,
    "identifier_present": _check_identifier_present,
    "hash_algorithm": _check_hash_algorithm,
    "dependency_coverage": _check_dependency_coverage,
}


# --------------------------------------------------------- built-in profiles

_BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "ntia-2021": {
        "name": "NTIA Minimum Elements",
        "version": "2021",
        "description": "NTIA SBOM Minimum Elements (2021)",
        "requirements": [
            {"id": "ntia-1", "title": "Component name", "check": "name_present", "level": "required"},
            {"id": "ntia-2", "title": "Component version", "check": "version_present", "level": "required"},
            {"id": "ntia-3", "title": "Component identifier (purl)", "check": "purl_present", "level": "required"},
            {"id": "ntia-4", "title": "Supplier/author", "check": "supplier_present", "level": "required"},
            {"id": "ntia-5", "title": "Dependency relationship", "check": "dependency_graph", "level": "required"},
            {"id": "ntia-6", "title": "SBOM timestamp", "check": "metadata_timestamp", "level": "required"},
            {"id": "ntia-7", "title": "SBOM authors", "check": "root_component", "level": "optional"},
        ],
    },
    "cisa-2025": {
        "name": "CISA SBOM Guidelines",
        "version": "2025",
        "description": "CISA SBOM Guidelines (2025)",
        "requirements": [
            {"id": "cisa-1", "title": "Component name", "check": "name_present", "level": "required"},
            {"id": "cisa-2", "title": "Component version", "check": "version_present", "level": "required"},
            {"id": "cisa-3", "title": "Component purl", "check": "purl_present", "level": "required"},
            {"id": "cisa-4", "title": "Supplier information", "check": "supplier_present", "level": "required"},
            {"id": "cisa-5", "title": "Hash digests", "check": "hashes_present", "level": "required"},
            {"id": "cisa-6", "title": "License information", "check": "licenses_present", "level": "required"},
            {"id": "cisa-7", "title": "Dependency graph", "check": "dependency_graph", "level": "required"},
            {"id": "cisa-8", "title": "SBOM timestamp", "check": "metadata_timestamp", "level": "required"},
            {"id": "cisa-9", "title": "Root component", "check": "root_component", "level": "optional"},
            {"id": "cisa-10", "title": "No embedded vulns", "check": "no_embedded_vulns", "level": "optional"},
        ],
    },
    "bsi-tr-03183-2@2.1.0": {
        "name": "BSI TR-03183-2",
        "version": "2.1.0",
        "description": "BSI Technical Guideline TR-03183-2 v2.1.0 - SBOM for critical infrastructure",
        "requirements": [
            {"id": "bsi-1", "title": "Component name", "check": "name_present", "level": "required"},
            {"id": "bsi-2", "title": "Component version", "check": "version_present", "level": "required"},
            {"id": "bsi-3", "title": "Component purl", "check": "purl_present", "level": "required"},
            {"id": "bsi-4", "title": "Supplier information", "check": "supplier_present", "level": "required"},
            {"id": "bsi-5", "title": "Hash digests", "check": "hashes_present", "level": "required"},
            {"id": "bsi-6", "title": "License information", "check": "licenses_present", "level": "required"},
            {"id": "bsi-7", "title": "Dependency graph", "check": "dependency_graph", "level": "required"},
            {"id": "bsi-8", "title": "SBOM timestamp", "check": "metadata_timestamp", "level": "required"},
            {"id": "bsi-9", "title": "Root component", "check": "root_component", "level": "required"},
            {"id": "bsi-10", "title": "No embedded vulns", "check": "no_embedded_vulns", "level": "optional"},
        ],
    },
    "cra-readiness": {
        "name": "CRA Readiness",
        "version": "1.0",
        "description": "EU Cyber Resilience Act - SBOM readiness check",
        "requirements": [
            {"id": "cra-1", "title": "Component name", "check": "name_present", "level": "required"},
            {"id": "cra-2", "title": "Component version", "check": "version_present", "level": "required"},
            {"id": "cra-3", "title": "Component purl", "check": "purl_present", "level": "required"},
            {"id": "cra-4", "title": "Supplier information", "check": "supplier_present", "level": "required"},
            {"id": "cra-5", "title": "Hash digests", "check": "hashes_present", "level": "required"},
            {"id": "cra-6", "title": "License information", "check": "licenses_present", "level": "required"},
            {"id": "cra-7", "title": "Dependency graph", "check": "dependency_graph", "level": "required"},
            {"id": "cra-8", "title": "SBOM timestamp", "check": "metadata_timestamp", "level": "required"},
            {"id": "cra-9", "title": "Root component", "check": "root_component", "level": "required"},
            {"id": "cra-10", "title": "No embedded vulns", "check": "no_embedded_vulns", "level": "optional"},
        ],
    },
}
