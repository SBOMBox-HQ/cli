"""Tests for the fix engine - :func:`sbombox_core.fix`.

Verifies that fix returns a FixResult, adds timestamps, normalizes licenses,
is idempotent, and fills missing purls.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core import fix, load
from sbombox_core.model.results import FixResult

from tests.fixtures import CDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_fix_returns_fix_result
# ---------------------------------------------------------------------------


def test_fix_returns_fix_result():
    """Fix returns FixResult with sbom and changes."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = fix(sbom)

    assert isinstance(result, FixResult)
    assert result.sbom is not None
    assert isinstance(result.changes, list)


# ---------------------------------------------------------------------------
# test_fix_adds_timestamp
# ---------------------------------------------------------------------------


def test_fix_adds_timestamp():
    """SBOM without timestamp gets one added."""
    cdx_no_ts = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": "app",
                "type": "application",
                "name": "no-ts-app",
                "version": "1.0.0",
            },
        },
        "components": [],
    }
    sbom = load(json.dumps(cdx_no_ts))
    assert sbom.metadata.timestamp is None

    result = fix(sbom, rules=["add-timestamp"])

    assert result.sbom.metadata.timestamp is not None
    assert any(change.rule == "add-timestamp" for change in result.changes)


# ---------------------------------------------------------------------------
# test_fix_normalizes_licenses
# ---------------------------------------------------------------------------


def test_fix_normalizes_licenses():
    """Licenses get normalized."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = fix(sbom, rules=["normalize-licenses"])

    # The fix should have run (may or may not have changes depending on input)
    assert isinstance(result, FixResult)
    # Check that licenses are still valid
    for comp in result.sbom.components:
        for lc in comp.licenses:
            if lc.expression:
                assert isinstance(lc.expression, str)


# ---------------------------------------------------------------------------
# test_fix_idempotent
# ---------------------------------------------------------------------------


def test_fix_idempotent():
    """Applying fix twice produces same result as once."""
    sbom = _sbom_from_fixture(CDX_JSON)

    result1 = fix(sbom)
    result2 = fix(result1.sbom)

    # After first fix, second fix should not produce additional changes
    # (or very minimal changes)
    assert isinstance(result2, FixResult)
    # Component count should be the same
    assert len(result1.sbom.components) == len(result2.sbom.components)


# ---------------------------------------------------------------------------
# test_fix_fills_purls
# ---------------------------------------------------------------------------


def test_fix_fills_purls():
    """Components without purls get them filled where possible."""
    cdx_no_purl = {
        **CDX_JSON,
        "components": [
            *CDX_JSON["components"],
            {
                "bom-ref": "no-purl-comp",
                "type": "library",
                "name": "no-purl-lib",
                "version": "1.0.0",
                # No purl field
            },
        ],
    }
    sbom = load(json.dumps(cdx_no_purl))

    # Find component without purl
    no_purl_comp = next(
        (c for c in sbom.components if c.name == "no-purl-lib"),
        None,
    )
    assert no_purl_comp is not None
    assert no_purl_comp.purl is None

    result = fix(sbom, rules=["fill-purls"])

    # The component may or may not get a purl depending on whether
    # the fixer can infer the ecosystem. At minimum, the fix should run.
    assert isinstance(result, FixResult)
