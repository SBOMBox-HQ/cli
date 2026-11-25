"""Tests for serialization - :mod:`sbombox_core.serialize`.

Verifies round-trip parsing and serialization for CycloneDX and SPDX,
and that the output conforms to the expected spec versions.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core import load
from sbombox_core.serialize import to_cyclonedx_json, to_spdx_json

from tests.fixtures import CDX_JSON, SPDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_roundtrip_cyclonedx
# ---------------------------------------------------------------------------


def test_roundtrip_cyclonedx():
    """Parse → serialize → parse; verify component counts match."""
    sbom_original = _sbom_from_fixture(CDX_JSON)
    original_count = len(sbom_original.components)

    # Serialize to CycloneDX JSON
    cdx_doc = to_cyclonedx_json(sbom_original, version="1.6")
    cdx_text = json.dumps(cdx_doc)

    # Parse back
    sbom_roundtrip = load(cdx_text)

    assert len(sbom_roundtrip.components) == original_count


# ---------------------------------------------------------------------------
# test_roundtrip_spdx
# ---------------------------------------------------------------------------


def test_roundtrip_spdx():
    """Parse → serialize → parse; verify component counts match for SPDX."""
    sbom_original = _sbom_from_fixture(SPDX_JSON)
    original_count = len(sbom_original.components)

    # Serialize to SPDX JSON
    spdx_doc = to_spdx_json(sbom_original)
    spdx_text = json.dumps(spdx_doc)

    # Parse back
    sbom_roundtrip = load(spdx_text)

    assert len(sbom_roundtrip.components) == original_count


# ---------------------------------------------------------------------------
# test_serialize_cyclonedx_16
# ---------------------------------------------------------------------------


def test_serialize_cyclonedx_16():
    """Verify output is valid CycloneDX 1.6."""
    sbom = _sbom_from_fixture(CDX_JSON)

    cdx_doc = to_cyclonedx_json(sbom, version="1.6")

    assert cdx_doc["bomFormat"] == "CycloneDX"
    assert cdx_doc["specVersion"] == "1.6"
    assert "components" in cdx_doc
    assert isinstance(cdx_doc["components"], list)


# ---------------------------------------------------------------------------
# test_serialize_cyclonedx_17
# ---------------------------------------------------------------------------


def test_serialize_cyclonedx_17():
    """Verify output is valid CycloneDX 1.7."""
    sbom = _sbom_from_fixture(CDX_JSON)

    cdx_doc = to_cyclonedx_json(sbom, version="1.7")

    assert cdx_doc["bomFormat"] == "CycloneDX"
    assert cdx_doc["specVersion"] == "1.7"
    assert "components" in cdx_doc
    assert isinstance(cdx_doc["components"], list)
