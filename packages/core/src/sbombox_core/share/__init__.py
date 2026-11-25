"""Privacy-preserving SBOM report sharing.

Generates a summary report that contains only scores and aggregate counts -
no component names, versions, or other identifying data - suitable for sharing
with third parties without leaking the software inventory.

Usage::

    from sbombox_core.share import privacy_report
    report = privacy_report(score_result)
"""

from __future__ import annotations

from typing import Any

from sbombox_core.model.results import ComplianceResult, ScoreResult

__all__ = ["privacy_report"]


def privacy_report(
    result: ScoreResult | ComplianceResult,
) -> dict[str, Any]:
    """Generate a privacy-preserving summary from a scoring or compliance result.

    The returned dict contains only aggregate data - scores, counts, grades -
    with no component names, purls, or other identifying information.
    """
    if isinstance(result, ScoreResult):
        return {
            "type": "score",
            "total": result.total,
            "grade": result.grade.value,
            "profile": result.profile,
            "core_version": result.core_version,
            "timestamp": result.timestamp.isoformat(),
            "categories": [
                {
                    "name": cat.name,
                    "score": cat.score,
                    "weight": cat.weight,
                    "feature_count": len(cat.features),
                    "avg_feature_score": (
                        sum(f.score for f in cat.features) / len(cat.features) if cat.features else 0.0
                    ),
                }
                for cat in result.categories
            ],
        }

    # ComplianceResult
    return {
        "type": "compliance",
        "profile": result.profile,
        "profile_version": result.profile_version,
        "status": result.status,
        "required_score": result.required_score,
        "optional_score": result.optional_score,
        "overall": result.overall,
        "core_version": result.core_version,
        "timestamp": result.timestamp.isoformat(),
        "requirement_summary": {
            "total": len(result.requirements),
            "passing": sum(1 for r in result.requirements if r.status == "pass"),
            "partial": sum(1 for r in result.requirements if r.status == "partial"),
            "failing": sum(1 for r in result.requirements if r.status == "fail"),
        },
    }
