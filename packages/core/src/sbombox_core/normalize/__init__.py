"""SBOM normalisation pipeline.

Normalisation makes SBOMs from different producers comparable: purls are
validated, licenses are canonical SPDX expressions, timestamps are ISO-8601,
dependency graphs are completed and embedded vulnerabilities are stripped so
the scanner can re-derive them from configured advisory sources.

The entry point is :func:`normalize`, which returns a *new* :class:`Sbom`
(the original is never mutated).
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sbombox_core.model.sbom import Sbom
from sbombox_core.util.licenses import normalize_license_expression
from sbombox_core.util.purl import validate_purl

if TYPE_CHECKING:
    from sbombox_core.model.component import Component

__all__ = ["normalize", "normalize_component", "normalize_sbom_metadata"]


def normalize(sbom: Sbom) -> Sbom:
    """Return a normalised deep-copy of *sbom*.

    The original document is never mutated; callers that want the normalised
    version replace their reference with the return value.
    """
    normalised = sbom.model_copy(deep=True)
    normalize_sbom_metadata(normalised)
    normalised.components = [normalize_component(c) for c in normalised.components]
    _complete_dependency_graph(normalised)
    _strip_embedded_vulnerabilities(normalised)
    return normalised


def normalize_component(component: Component) -> Component:
    """Normalise a single component in place and return it.

    * Invalid purls are cleared (they would poison matching downstream).
    * License expressions are canonicalised to SPDX form.
    * Missing suppliers are filled from author/publisher when possible.
    """
    if component.purl and not validate_purl(component.purl):
        component.purl = None

    if component.licenses:
        for lc in component.licenses:
            if lc.expression:
                lc.expression = normalize_license_expression(lc.expression)
            elif lc.license and lc.license.id:
                lc.license.id = normalize_license_expression(lc.license.id)

    if component.supplier is None or not component.supplier.name:
        fallback = component.author or component.publisher
        if fallback:
            from sbombox_core.model.common import Supplier

            component.supplier = Supplier(name=fallback)

    return component


def normalize_sbom_metadata(sbom: Sbom) -> None:
    """Normalise timestamps and top-level metadata in place."""
    if sbom.metadata and sbom.metadata.timestamp:
        ts = sbom.metadata.timestamp
        if ts.tzinfo is None:
            sbom.metadata.timestamp = ts.replace(tzinfo=UTC)
    elif sbom.metadata:
        sbom.metadata.timestamp = datetime.now(UTC)


def _complete_dependency_graph(sbom: Sbom) -> None:
    """Ensure every bom-ref that appears as a dependency target also has a node.

    Producers sometimes list edges without declaring the target node.  Adding
    empty placeholder entries keeps the graph walkable and prevents downstream
    code from crashing on missing refs.
    """
    from sbombox_core.model.dependency import Dependency

    known_refs = sbom.refs
    graph = sbom.dependency_graph()

    missing_refs: set[str] = set()
    for ref, deps in graph.items():
        if ref not in known_refs:
            missing_refs.add(ref)
        for dep in deps:
            if dep not in known_refs:
                missing_refs.add(dep)

    for ref in missing_refs:
        sbom.dependencies.append(Dependency(ref=ref, depends_on=[]))


def _strip_embedded_vulnerabilities(sbom: Sbom) -> None:
    """Clear embedded vulnerability entries.

    The source document's vulnerability section carries *untrusted producer
    claims*.  Normalisation strips them so the scanner re-derives vulnerability
    state from configured advisory sources, ensuring consistent results.
    """
    sbom.vulnerabilities = []
