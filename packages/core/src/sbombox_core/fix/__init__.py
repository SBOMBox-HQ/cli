"""Idempotent SBOM auto-fixes.

Each fix rule is a pure function that takes an SBOM and returns a (possibly
modified) copy.  The :func:`fix` entry point runs the requested rules in order
and collects a changelog of what changed.

Available rules:
    - ``add-timestamp`` - ensure metadata has a timestamp.
    - ``normalize-licenses`` - canonicalise license expressions to SPDX.
    - ``fill-purls`` - attempt to fill missing purls from name/version.
    - ``deduplicate`` - merge components with identical identity keys.
    - ``add-missing-hashes`` - placeholder: cannot fabricate hashes.

Usage::

    from sbombox_core import fix
    fixed, changes = fix(sbom, rules=["add-timestamp", "normalize-licenses"])
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any, Callable

from sbombox_core.model.results import FixChange, FixResult
from sbombox_core.model.sbom import Sbom
from sbombox_core.normalize import normalize_component
from sbombox_core.util.licenses import normalize_license_expression

__all__ = ["fix", "AVAILABLE_RULES"]

type FixRule = Callable[[Sbom], tuple[Sbom, int]]


def fix(
    sbom: Sbom,
    rules: list[str] | None = None,
) -> FixResult:
    """Apply auto-fixes to *sbom* and return the result with a changelog.

    Args:
        sbom: The SBOM to fix.
        rules: List of rule names to apply.  ``None`` means all rules.

    Returns:
        A :class:`FixResult` with the fixed SBOM and a list of changes.
    """
    result = sbom.model_copy(deep=True)
    changes: list[FixChange] = []

    selected = rules or list(AVAILABLE_RULES.keys())

    for rule_name in selected:
        rule_fn = AVAILABLE_RULES.get(rule_name)
        if rule_fn is None:
            continue
        before_count = _count_modifiable(result)
        result, affected = rule_fn(result)
        if affected > 0:
            changes.append(
                FixChange(
                    rule=rule_name,
                    description=_RULE_DESCRIPTIONS.get(rule_name, rule_name),
                    affected_count=affected,
                )
            )

    return FixResult(sbom=result, changes=changes)


def _count_modifiable(sbom: Sbom) -> int:
    return len(sbom.components)


# --------------------------------------------------------- fix rules


def _fix_add_timestamp(sbom: Sbom) -> tuple[Sbom, int]:
    """Ensure metadata has a timestamp."""
    if sbom.metadata and sbom.metadata.timestamp is None:
        sbom.metadata.timestamp = datetime.now(UTC)
        return sbom, 1
    return sbom, 0


def _fix_normalize_licenses(sbom: Sbom) -> tuple[Sbom, int]:
    """Canonicalise license expressions to SPDX form."""
    affected = 0
    for component in sbom.components:
        changed = False
        for lc in component.licenses:
            if lc.expression:
                normalised = normalize_license_expression(lc.expression)
                if normalised != lc.expression:
                    lc.expression = normalised
                    changed = True
            elif lc.license and lc.license.id:
                normalised = normalize_license_expression(lc.license.id)
                if normalised != lc.license.id:
                    lc.license.id = normalised
                    changed = True
        if changed:
            affected += 1
    return sbom, affected


def _fix_fill_purls(sbom: Sbom) -> tuple[Sbom, int]:
    """Attempt to fill missing purls from name/version/type.

    Only fills when the component has a name and a recognisable ecosystem
    can be inferred.  Does NOT overwrite existing purls.
    """
    affected = 0
    for component in sbom.components:
        if component.purl:
            continue
        if not component.name:
            continue
        # Build a minimal purl from available info
        purl_type = _infer_purl_type(component)
        if purl_type:
            version_part = f"@{component.version}" if component.version else ""
            namespace_part = f"{component.group}/" if component.group else ""
            component.purl = f"pkg:{purl_type}/{namespace_part}{component.name}{version_part}"
            affected += 1
    return sbom, affected


def _infer_purl_type(component: Any) -> str | None:
    """Infer a purl type from the component's properties or type."""
    # Check properties for ecosystem hints
    props = component.properties or {}
    for key in ("cdx:npm:package:name", "npm:package:name"):
        if key in props:
            return "npm"
    for key in ("cdx:pypi:package:name", "pypi:package:name"):
        if key in props:
            return "pypi"

    # Infer from component type
    type_str = str(component.type).lower() if component.type else ""
    if "npm" in type_str or "node" in type_str:
        return "npm"
    if "python" in type_str or "pip" in type_str:
        return "pypi"

    return None


def _fix_deduplicate(sbom: Sbom) -> tuple[Sbom, int]:
    """Merge components with identical identity keys."""
    seen: dict[str, int] = {}
    unique: list[Any] = []
    removed = 0

    for component in sbom.components:
        key = component.identity_key()
        if key in seen:
            removed += 1
        else:
            seen[key] = len(unique)
            unique.append(component)

    sbom.components = unique
    return sbom, removed


def _fix_add_missing_hashes(sbom: Sbom) -> tuple[Sbom, int]:
    """Placeholder: cannot fabricate hashes, but reports missing ones."""
    # This rule is a no-op for the fixer - it can only report, not create hashes.
    return sbom, 0


# --------------------------------------------------------- registry

_RULE_DESCRIPTIONS: dict[str, str] = {
    "add-timestamp": "Ensure SBOM metadata has a timestamp.",
    "normalize-licenses": "Canonicalise license expressions to SPDX form.",
    "fill-purls": "Fill missing Package URLs from component metadata.",
    "deduplicate": "Merge components with identical identity keys.",
    "add-missing-hashes": "Report components missing hash digests (no-op fix).",
}

AVAILABLE_RULES: dict[str, FixRule] = {
    "add-timestamp": _fix_add_timestamp,
    "normalize-licenses": _fix_normalize_licenses,
    "fill-purls": _fix_fill_purls,
    "deduplicate": _fix_deduplicate,
    "add-missing-hashes": _fix_add_missing_hashes,
}
