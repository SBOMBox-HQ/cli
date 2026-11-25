"""Tests for the scoring engine - :func:`sbombox_core.score`.

Verifies that scoring produces well-formed :class:`ScoreResult` objects,
grade boundaries are correct, default weights sum properly, all 8 categories
are present, and edge cases (empty SBOM, perfect SBOM) behave sensibly.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core import load, score
from sbombox_core.model.results import Grade, ScoreResult
from sbombox_core.score import DEFAULT_WEIGHTS

from tests.fixtures import CDX_JSON, SPDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_score_returns_score_result
# ---------------------------------------------------------------------------


def test_score_returns_score_result():
    """Score a golden CycloneDX fixture; verify ScoreResult shape."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = score(sbom)

    assert isinstance(result, ScoreResult)
    assert 0.0 <= result.total <= 10.0
    assert isinstance(result.grade, Grade)
    assert result.grade in set(Grade)
    assert isinstance(result.categories, list)
    assert len(result.categories) > 0
    assert result.run_id  # non-empty


# ---------------------------------------------------------------------------
# test_score_grade_boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score_value, expected_grade",
    [
        (9.0, Grade.A),
        (10.0, Grade.A),
        (8.0, Grade.B),
        (8.99, Grade.B),
        (7.0, Grade.C),
        (7.99, Grade.C),
        (6.0, Grade.D),
        (6.99, Grade.D),
        (0.0, Grade.F),
        (5.99, Grade.F),
    ],
)
def test_score_grade_boundaries(score_value, expected_grade):
    """Verify Grade.from_score maps boundaries correctly."""
    assert Grade.from_score(score_value) == expected_grade


# ---------------------------------------------------------------------------
# test_score_default_weights_sum
# ---------------------------------------------------------------------------


def test_score_default_weights_sum():
    """DEFAULT_WEIGHTS must sum to 8.0 (the normalisation denominator)."""
    assert sum(DEFAULT_WEIGHTS.values()) == pytest.approx(8.0)


# ---------------------------------------------------------------------------
# test_score_categories_present
# ---------------------------------------------------------------------------


def test_score_categories_present():
    """All 8 scoring categories must appear in the result."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = score(sbom)

    category_names = {cat.name for cat in result.categories}
    expected = {
        "identification",
        "provenance",
        "integrity",
        "completeness",
        "licensing",
        "vulnerability",
        "structural",
        "component_quality",
    }
    assert category_names == expected


# ---------------------------------------------------------------------------
# test_score_empty_sbom_low_grade
# ---------------------------------------------------------------------------


def test_score_empty_sbom_low_grade():
    """An SBOM with no components should score low (grade D or F)."""
    empty_cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2024-05-01T10:00:00Z",
            "component": {
                "bom-ref": "app",
                "type": "application",
                "name": "empty-app",
                "version": "1.0.0",
            },
        },
        "components": [],
    }
    sbom = load(json.dumps(empty_cdx))
    result = score(sbom)

    assert result.total < 6.0
    assert result.grade in (Grade.D, Grade.F)


# ---------------------------------------------------------------------------
# test_score_perfect_sbom_high_grade
# ---------------------------------------------------------------------------


def test_score_perfect_sbom_high_grade():
    """A well-formed SBOM with purls, hashes, licenses should score high."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = score(sbom)

    # The CDX_JSON fixture has purls, licenses, hashes, dependencies, metadata
    # - it should score reasonably well (>= 5.0 at minimum).
    assert result.total >= 5.0
    assert result.grade in (Grade.A, Grade.B, Grade.C, Grade.D)
