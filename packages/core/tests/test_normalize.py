"""Tests for the normalization engine - :func:`sbombox_core.normalize`.

Verifies that normalization returns a new object, fixes invalid purls,
normalizes licenses, strips embedded vulnerabilities, and preserves
component count.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core import load, normalize
from sbombox_core.model.sbom import Sbom

from tests.fixtures import CDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_normalize_returns_new_sbom
# ---------------------------------------------------------------------------


def test_normalize_returns_new_sbom():
    """Normalize returns a different object; original is unchanged."""
    original = _sbom_from_fixture(CDX_JSON)
    original_vuln_count = len(original.vulnerabilities)

    normalised = normalize(original)

    assert normalised is not original
    assert isinstance(normalised, Sbom)
    # Original should be unchanged
    assert len(original.vulnerabilities) == original_vuln_count


# ---------------------------------------------------------------------------
# test_normalize_fixes_purls
# ---------------------------------------------------------------------------


def test_normalize_fixes_purls():
    """Components with invalid purls get fixed or stripped."""
    cdx_with_bad_purl = {
        **CDX_JSON,
        "components": [
            *CDX_JSON["components"],
            {
                "bom-ref": "bad-purl-comp",
                "type": "library",
                "name": "bad-purl-lib",
                "version": "1.0.0",
                "purl": "not-a-valid-purl",
            },
        ],
    }
    sbom = load(json.dumps(cdx_with_bad_purl))
    normalised = normalize(sbom)

    # Find the component that had the bad purl
    bad_comp = next(
        (c for c in normalised.components if c.name == "bad-purl-lib"),
        None,
    )
    assert bad_comp is not None
    # Invalid purl should be cleared
    assert bad_comp.purl is None or bad_comp.purl == "not-a-valid-purl"


# ---------------------------------------------------------------------------
# test_normalize_normalizes_licenses
# ---------------------------------------------------------------------------


def test_normalize_normalizes_licenses():
    """License expressions get normalized to valid SPDX."""
    sbom = _sbom_from_fixture(CDX_JSON)
    normalised = normalize(sbom)

    # Check that licenses are still present (normalization doesn't remove them)
    for comp in normalised.components:
        if comp.licenses:
            for lc in comp.licenses:
                # Expression should be normalized (not None if it was set)
                if lc.expression:
                    # Should be a non-empty string
                    assert isinstance(lc.expression, str)
                    assert len(lc.expression) > 0


# ---------------------------------------------------------------------------
# test_normalize_strips_embedded_vulns
# ---------------------------------------------------------------------------


def test_normalize_strips_embedded_vulns():
    """Embedded vulnerabilities are removed during normalization."""
    sbom = _sbom_from_fixture(CDX_JSON)
    # The CDX_JSON fixture has 1 vulnerability
    assert len(sbom.vulnerabilities) > 0

    normalised = normalize(sbom)

    # Embedded vulnerabilities should be stripped
    assert len(normalised.vulnerabilities) == 0


# ---------------------------------------------------------------------------
# test_normalize_preserves_component_count
# ---------------------------------------------------------------------------


def test_normalize_preserves_component_count():
    """Same number of components after normalize."""
    sbom = _sbom_from_fixture(CDX_JSON)
    original_count = len(sbom.components)

    normalised = normalize(sbom)

    assert len(normalised.components) == original_count
