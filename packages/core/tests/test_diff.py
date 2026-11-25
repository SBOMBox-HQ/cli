"""Tests for the diff engine - :func:`sbombox_core.diff`.

Verifies that diff of identical SBOMs is empty, added/removed/changed
components are detected correctly, and the summary dict has correct counts.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core import diff, load
from sbombox_core.model.results import DiffResult

from tests.fixtures import CDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_diff_identical_sboms
# ---------------------------------------------------------------------------


def test_diff_identical_sboms():
    """Diff of same SBOM is empty."""
    sbom_a = _sbom_from_fixture(CDX_JSON)
    sbom_b = _sbom_from_fixture(CDX_JSON)

    result = diff(sbom_a, sbom_b)

    assert isinstance(result, DiffResult)
    assert result.is_empty
    assert len(result.added) == 0
    assert len(result.removed) == 0
    assert len(result.changed) == 0


# ---------------------------------------------------------------------------
# test_diff_added_components
# ---------------------------------------------------------------------------


def test_diff_added_components():
    """Adding a component shows in diff.added."""
    sbom_a = _sbom_from_fixture(CDX_JSON)

    cdx_with_extra = {
        **CDX_JSON,
        "components": [
            *CDX_JSON["components"],
            {
                "bom-ref": "pkg:npm/lodash@4.17.21",
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
            },
        ],
    }
    sbom_b = load(json.dumps(cdx_with_extra))

    result = diff(sbom_a, sbom_b)

    assert len(result.added) == 1
    assert result.added[0].name == "lodash"
    assert len(result.removed) == 0


# ---------------------------------------------------------------------------
# test_diff_removed_components
# ---------------------------------------------------------------------------


def test_diff_removed_components():
    """Removing a component shows in diff.removed."""
    sbom_a = _sbom_from_fixture(CDX_JSON)

    # Drop the last component from the "after" document: a component that is
    # present in ``a`` but absent from ``b`` has been removed.
    cdx_with_less = {
        **CDX_JSON,
        "components": CDX_JSON["components"][:-1],
    }
    sbom_b = load(json.dumps(cdx_with_less))

    result = diff(sbom_a, sbom_b)

    assert len(result.removed) == 1
    assert result.removed[0].name == "requests"
    assert len(result.added) == 0


# ---------------------------------------------------------------------------
# test_diff_changed_components
# ---------------------------------------------------------------------------


def test_diff_changed_components():
    """Changing a version shows in diff.changed."""
    sbom_a = _sbom_from_fixture(CDX_JSON)

    # Change the version of the first component
    modified_components = [
        {
            **CDX_JSON["components"][0],
            "version": "99.99.99",  # Changed version
        },
        *CDX_JSON["components"][1:],
    ]
    cdx_modified = {**CDX_JSON, "components": modified_components}
    sbom_b = load(json.dumps(cdx_modified))

    result = diff(sbom_a, sbom_b)

    assert len(result.changed) == 1
    assert "version" in result.changed[0].fields_changed


# ---------------------------------------------------------------------------
# test_diff_summary
# ---------------------------------------------------------------------------


def test_diff_summary():
    """Verify summary dict has correct counts."""
    sbom_a = _sbom_from_fixture(CDX_JSON)

    cdx_with_changes = {
        **CDX_JSON,
        "components": [
            # Modified first component (version change)
            {
                **CDX_JSON["components"][0],
                "version": "99.99.99",
            },
            # Added new component
            {
                "bom-ref": "pkg:npm/lodash@4.17.21",
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
            },
        ],
    }
    sbom_b = load(json.dumps(cdx_with_changes))

    result = diff(sbom_a, sbom_b)
    summary = result.summary()

    assert isinstance(summary, dict)
    assert "added" in summary
    assert "removed" in summary
    assert "changed" in summary
    assert summary["added"] == 1
    assert summary["changed"] == 1
    # ``requests`` is in the before-document but not the after-document, so it
    # is a removal even though the test only intended to add and change.
    assert summary["removed"] == 1
