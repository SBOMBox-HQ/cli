"""SBOM quality scoring engine.

Scores an SBOM across 8 categories, each 0-10, weighted to a total 0-10.
Produces a :class:`~sbombox_core.model.results.ScoreResult`.

Categories:
    1. **Identification** - purl, CPE, name, version coverage.
    2. **Provenance** - supplier, author, publisher coverage.
    3. **Integrity** - hash coverage (SHA-256 or better).
    4. **Completeness** - dependency graph coverage.
    5. **Licensing** - license coverage, valid SPDX identifiers.
    6. **Vulnerability** - absence of embedded untrusted vulns.
    7. **Structural** - valid format, spec version, metadata.
    8. **Component Quality** - version coverage, non-deprecated.

Usage::

    from sbombox_core import score
    result = score(sbom)  # -> ScoreResult
"""

from __future__ import annotations

import uuid as _uuid
from datetime import UTC, datetime
from typing import Any

from sbombox_core.model.results import Grade, ScoreCategory, ScoreFeature, ScoreResult
from sbombox_core.model.sbom import Sbom

# uuid7 is available in Python 3.14+; fall back to uuid4 for older versions.
_uuid7 = getattr(_uuid, "uuid7", None) or _uuid.uuid4

__all__ = ["DEFAULT_WEIGHTS", "score", "score_sbom"]

#: Default category weights (sum = 8.0, normalised at scoring time).
DEFAULT_WEIGHTS: dict[str, float] = {
    "identification": 1.5,
    "provenance": 1.0,
    "integrity": 1.5,
    "completeness": 1.0,
    "licensing": 1.0,
    "vulnerability": 0.5,
    "structural": 0.5,
    "component_quality": 1.0,
}


def score(
    sbom: Sbom,
    profile: str = "default",
    weights: dict[str, float] | None = None,
) -> ScoreResult:
    """Score *sbom* and return a :class:`ScoreResult`.

    Args:
        sbom: The parsed SBOM to score.
        profile: Name of the scoring profile (informational).
        weights: Optional override for category weights.  Missing categories
            fall back to :data:`DEFAULT_WEIGHTS`.
    """
    effective_weights = {**DEFAULT_WEIGHTS, **(weights or {})}

    categories: list[ScoreCategory] = [
        _score_identification(sbom),
        _score_provenance(sbom),
        _score_integrity(sbom),
        _score_completeness(sbom),
        _score_licensing(sbom),
        _score_vulnerability(sbom),
        _score_structural(sbom),
        _score_component_quality(sbom),
    ]

    for cat in categories:
        cat.weight = effective_weights.get(cat.name, 1.0)

    total_weight = sum(c.weight for c in categories) or 1.0
    weighted_sum = sum(c.score * c.weight for c in categories)
    total = round(weighted_sum / total_weight, 2)

    from sbombox_core import __version__

    return ScoreResult(
        total=total,
        grade=Grade.from_score(total),
        categories=categories,
        run_id=str(_uuid7()),
        timestamp=datetime.now(UTC),
        core_version=__version__,
        profile=profile,
    )


#: Alias kept for callers that prefer an explicit verb.
score_sbom = score


# ------------------------------------------------------------------ helpers


def _safe_ratio(numerator: int, denominator: int) -> float:
    """Return ``numerator / denominator`` scaled to 0-10, or 0.0 when empty."""
    if denominator == 0:
        return 0.0
    return round((numerator / denominator) * 10, 2)


def _count_components(sbom: Sbom) -> int:
    """Return the number of non-root components in *sbom*."""
    return len(sbom.components)


# --------------------------------------------------------- category scorers


def _score_identification(sbom: Sbom) -> ScoreCategory:
    """Category 1: how well components are identified (purl, CPE, version)."""
    components = sbom.components
    n = len(components)

    with_purl = sum(1 for c in components if c.purl)
    with_cpe = sum(1 for c in components if c.cpe)
    with_version = sum(1 for c in components if c.version)
    with_name = sum(1 for c in components if c.name)

    features = [
        ScoreFeature(
            name="purl_coverage",
            score=_safe_ratio(with_purl, n),
            numerator=with_purl,
            denominator=n,
            description="Components with a valid Package URL.",
        ),
        ScoreFeature(
            name="cpe_coverage",
            score=_safe_ratio(with_cpe, n),
            numerator=with_cpe,
            denominator=n,
            description="Components with a CPE identifier.",
        ),
        ScoreFeature(
            name="version_coverage",
            score=_safe_ratio(with_version, n),
            numerator=with_version,
            denominator=n,
            description="Components with a declared version.",
        ),
        ScoreFeature(
            name="name_coverage",
            score=_safe_ratio(with_name, n),
            numerator=with_name,
            denominator=n,
            description="Components with a non-empty name.",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="identification", score=round(cat_score, 2), features=features)


def _score_provenance(sbom: Sbom) -> ScoreCategory:
    """Category 2: supplier / author / publisher coverage."""
    components = sbom.components
    n = len(components)

    with_supplier = sum(1 for c in components if c.supplier and c.supplier.name)
    with_author = sum(1 for c in components if c.author)
    with_publisher = sum(1 for c in components if c.publisher)
    with_any = sum(1 for c in components if (c.supplier and c.supplier.name) or c.author or c.publisher)

    features = [
        ScoreFeature(
            name="supplier_coverage",
            score=_safe_ratio(with_supplier, n),
            numerator=with_supplier,
            denominator=n,
            description="Components with a named supplier.",
        ),
        ScoreFeature(
            name="author_coverage",
            score=_safe_ratio(with_author, n),
            numerator=with_author,
            denominator=n,
            description="Components with a declared author.",
        ),
        ScoreFeature(
            name="publisher_coverage",
            score=_safe_ratio(with_publisher, n),
            numerator=with_publisher,
            denominator=n,
            description="Components with a declared publisher.",
        ),
        ScoreFeature(
            name="any_provenance",
            score=_safe_ratio(with_any, n),
            numerator=with_any,
            denominator=n,
            description="Components with at least one provenance field.",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="provenance", score=round(cat_score, 2), features=features)


def _score_integrity(sbom: Sbom) -> ScoreCategory:
    """Category 3: hash coverage - are components accompanied by digests?"""
    components = sbom.components
    n = len(components)

    with_any_hash = sum(1 for c in components if c.hashes)
    with_sha256 = sum(
        1 for c in components if any(h.alg in ("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE3") for h in c.hashes)
    )

    features = [
        ScoreFeature(
            name="hash_coverage",
            score=_safe_ratio(with_any_hash, n),
            numerator=with_any_hash,
            denominator=n,
            description="Components with at least one hash.",
        ),
        ScoreFeature(
            name="strong_hash_coverage",
            score=_safe_ratio(with_sha256, n),
            numerator=with_sha256,
            denominator=n,
            description="Components with a strong hash (SHA-256 or better).",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="integrity", score=round(cat_score, 2), features=features)


def _score_completeness(sbom: Sbom) -> ScoreCategory:
    """Category 4: dependency graph coverage."""
    components = sbom.components
    deps = sbom.dependencies
    n = len(components)

    refs_with_deps = sum(1 for d in deps if d.depends_on)
    total_refs = len(deps)

    # How many component bom-refs appear in the dependency graph at all?
    component_refs = {c.bom_ref for c in components if c.bom_ref}
    graph_refs = {d.ref for d in deps}
    covered = len(component_refs & graph_refs)

    features = [
        ScoreFeature(
            name="graph_coverage",
            score=_safe_ratio(covered, len(component_refs) if component_refs else n),
            numerator=covered,
            denominator=len(component_refs) if component_refs else n,
            description="Components that appear in the dependency graph.",
        ),
        ScoreFeature(
            name="graph_density",
            score=min(10.0, round((refs_with_deps / max(total_refs, 1)) * 10, 2)),
            numerator=refs_with_deps,
            denominator=total_refs,
            description="Dependency nodes that have at least one edge.",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="completeness", score=round(cat_score, 2), features=features)


def _score_licensing(sbom: Sbom) -> ScoreCategory:
    """Category 5: license coverage and SPDX validity."""
    components = sbom.components
    n = len(components)

    with_license = sum(1 for c in components if c.licenses)
    with_valid_spdx = 0
    for c in components:
        if not c.licenses:
            continue
        all_valid = True
        for lc in c.licenses:
            expr = lc.expression or (lc.license.id if lc.license else None)
            if expr:
                from sbombox_core.util.licenses import is_valid_spdx_license

                if not is_valid_spdx_license(expr):
                    all_valid = False
                    break
            # Bare license names without an id/expression are not verifiable
        if all_valid and c.licenses:
            with_valid_spdx += 1

    features = [
        ScoreFeature(
            name="license_coverage",
            score=_safe_ratio(with_license, n),
            numerator=with_license,
            denominator=n,
            description="Components with at least one license declaration.",
        ),
        ScoreFeature(
            name="valid_spdx",
            score=_safe_ratio(with_valid_spdx, n),
            numerator=with_valid_spdx,
            denominator=n,
            description="Components with valid SPDX license identifiers.",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="licensing", score=round(cat_score, 2), features=features)


def _score_vulnerability(sbom: Sbom) -> ScoreCategory:
    """Category 6: embedded vulnerability state.

    A high score means the document does *not* carry untrusted embedded
    vulnerability claims (which normalisation strips).  An SBOM with no
    embedded vulns scores 10; one that carried many scores low.
    """
    vuln_count = len(sbom.vulnerabilities)
    n = max(len(sbom.components), 1)

    # Ratio of components that are NOT mentioned in embedded vulns
    affected_refs: set[str] = set()
    for v in sbom.vulnerabilities:
        for a in v.affects:
            if a.ref:
                affected_refs.add(a.ref)

    unaffected = len(sbom.components) - sum(
        1 for c in sbom.components if c.bom_ref and c.bom_ref in affected_refs
    )

    features = [
        ScoreFeature(
            name="no_embedded_vulns",
            score=10.0 if vuln_count == 0 else max(0.0, round(10 - (vuln_count / n) * 10, 2)),
            numerator=0 if vuln_count else n,
            denominator=n,
            description="SBOM does not carry embedded vulnerability claims.",
        ),
    ]

    cat_score = features[0].score
    return ScoreCategory(name="vulnerability", score=round(cat_score, 2), features=features)


def _score_structural(sbom: Sbom) -> ScoreCategory:
    """Category 7: structural validity - format, spec version, metadata."""
    features: list[ScoreFeature] = []

    # Format is set
    format_score = 10.0 if sbom.format else 0.0
    features.append(
        ScoreFeature(
            name="valid_format",
            score=format_score,
            numerator=1 if format_score else 0,
            denominator=1,
            description="SBOM has a recognised format (CycloneDX or SPDX).",
        )
    )

    # Spec version is present
    spec_score = 10.0 if sbom.spec_version else 0.0
    features.append(
        ScoreFeature(
            name="spec_version",
            score=spec_score,
            numerator=1 if spec_score else 0,
            denominator=1,
            description="SBOM declares a specification version.",
        )
    )

    # Metadata timestamp
    ts_score = 10.0 if (sbom.metadata and sbom.metadata.timestamp) else 0.0
    features.append(
        ScoreFeature(
            name="metadata_timestamp",
            score=ts_score,
            numerator=1 if ts_score else 0,
            denominator=1,
            description="SBOM metadata includes a timestamp.",
        )
    )

    # Has metadata component (the root component)
    root_score = 10.0 if (sbom.metadata and sbom.metadata.component) else 0.0
    features.append(
        ScoreFeature(
            name="root_component",
            score=root_score,
            numerator=1 if root_score else 0,
            denominator=1,
            description="SBOM metadata declares a root component.",
        )
    )

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="structural", score=round(cat_score, 2), features=features)


def _score_component_quality(sbom: Sbom) -> ScoreCategory:
    """Category 8: component-level quality signals."""
    components = sbom.components
    n = len(components)

    with_version = sum(1 for c in components if c.version)
    with_purl = sum(1 for c in components if c.purl)

    # Components that have at least a purl or a version (minimal quality bar)
    with_minimal = sum(1 for c in components if c.purl or c.version)

    features = [
        ScoreFeature(
            name="version_declared",
            score=_safe_ratio(with_version, n),
            numerator=with_version,
            denominator=n,
            description="Components with a declared version string.",
        ),
        ScoreFeature(
            name="minimal_identity",
            score=_safe_ratio(with_minimal, n),
            numerator=with_minimal,
            denominator=n,
            description="Components with at least a purl or version.",
        ),
    ]

    cat_score = sum(f.score for f in features) / len(features) if features else 0.0
    return ScoreCategory(name="component_quality", score=round(cat_score, 2), features=features)
