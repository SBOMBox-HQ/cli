"""SBOM-to-SBOM diff engine.

Compares two SBOMs and produces a :class:`~sbombox_core.model.results.DiffResult`
describing which components were added, removed, or changed, plus dependency
graph deltas.

Matching is by purl (preferred) or by the component identity key
(group/name/version/type).

Usage::

    from sbombox_core import diff
    result = diff(sbom_a, sbom_b)  # -> DiffResult
"""

from __future__ import annotations

from sbombox_core.model.component import Component
from sbombox_core.model.results import ComponentChange, DiffResult
from sbombox_core.model.sbom import Sbom

__all__ = ["diff", "diff_sboms"]


def diff(sbom_a: Sbom, sbom_b: Sbom) -> DiffResult:
    """Compute the delta between two SBOMs.

    Components are matched by identity key (purl preferred, else the
    group/name/version/type tuple).  Matched components are then compared
    field-by-field to detect changes.

    Args:
        sbom_a: The "before" SBOM.
        sbom_b: The "after" SBOM.

    Returns:
        A :class:`DiffResult` with added, removed, and changed components.
    """
    return diff_sboms(sbom_a, sbom_b)


def diff_sboms(sbom_a: Sbom, sbom_b: Sbom) -> DiffResult:
    """Alias for :func:`diff`."""
    index_a = _build_index(sbom_a)
    index_b = _build_index(sbom_b)

    keys_a = set(index_a.keys())
    keys_b = set(index_b.keys())

    added_keys = keys_b - keys_a
    removed_keys = keys_a - keys_b
    common_keys = keys_a & keys_b

    added = [index_b[k] for k in added_keys]
    removed = [index_a[k] for k in removed_keys]

    changed: list[ComponentChange] = []
    for key in common_keys:
        comp_a = index_a[key]
        comp_b = index_b[key]
        change = _compare_components(comp_a, comp_b)
        if change is not None:
            changed.append(change)

    # Dependency graph delta
    graph_a = sbom_a.dependency_graph()
    graph_b = sbom_b.dependency_graph()

    dep_added: list[str] = []
    dep_removed: list[str] = []

    all_edges_a = _flatten_edges(graph_a)
    all_edges_b = _flatten_edges(graph_b)

    for edge in all_edges_b - all_edges_a:
        dep_added.append(edge)
    for edge in all_edges_a - all_edges_b:
        dep_removed.append(edge)

    return DiffResult(
        added=added,
        removed=removed,
        changed=changed,
        dependency_added=dep_added,
        dependency_removed=dep_removed,
    )


# --------------------------------------------------------- internals


def _build_index(sbom: Sbom) -> dict[str, Component]:
    """Build a {identity_key: component} index from an SBOM."""
    index: dict[str, Component] = {}
    for component in sbom.components:
        key = component.identity_key()
        index[key] = component
    return index


def _compare_components(a: Component, b: Component) -> ComponentChange | None:
    """Compare two matched components and return a change record if different."""
    fields_changed: list[str] = []
    old_values: dict[str, object] = {}
    new_values: dict[str, object] = {}

    # Compare key fields
    for field_name in ("version", "purl", "description", "supplier", "author", "publisher"):
        val_a = getattr(a, field_name, None)
        val_b = getattr(b, field_name, None)
        if _normalise(val_a) != _normalise(val_b):
            fields_changed.append(field_name)
            old_values[field_name] = val_a
            new_values[field_name] = val_b

    # Compare hashes
    hashes_a = {h.alg: h.content for h in a.hashes}
    hashes_b = {h.alg: h.content for h in b.hashes}
    if hashes_a != hashes_b:
        fields_changed.append("hashes")
        old_values["hashes"] = [h.model_dump() for h in a.hashes]
        new_values["hashes"] = [h.model_dump() for h in b.hashes]

    # Compare licenses
    lic_a = sorted(str(lc) for lc in a.licenses)
    lic_b = sorted(str(lc) for lc in b.licenses)
    if lic_a != lic_b:
        fields_changed.append("licenses")
        old_values["licenses"] = [lc.model_dump() for lc in a.licenses]
        new_values["licenses"] = [lc.model_dump() for lc in b.licenses]

    if not fields_changed:
        return None

    return ComponentChange(
        component=b,
        fields_changed=fields_changed,
        old_values=old_values,
        new_values=new_values,
    )


def _normalise(value: object) -> object:
    """Normalise a value for comparison (strip strings, None-ify empties)."""
    if isinstance(value, str):
        return value.strip() or None
    return value


def _flatten_edges(graph: dict[str, list[str]]) -> set[str]:
    """Flatten a dependency graph into a set of 'from->to' edge strings."""
    edges: set[str] = set()
    for ref, deps in graph.items():
        for dep in deps:
            edges.add(f"{ref}->{dep}")
    return edges
