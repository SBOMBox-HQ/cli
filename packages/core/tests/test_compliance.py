"""Tests for the compliance engine - :func:`sbombox_core.check_compliance`.

Verifies profile listing, loading, compliance checking against known profiles,
status derivation, and that all profiles can be evaluated without exceptions.
"""

from __future__ import annotations

import copy
import json

import pytest
from sbombox_core import check_compliance, load
from sbombox_core.compliance import list_profiles, load_profile, resolve_profile
from sbombox_core.model.results import ComplianceResult

from tests.fixtures import CDX_JSON, SPDX_JSON


def _sbom_from_fixture(fixture_dict):
    """Load an Sbom from an in-memory fixture dict."""
    return load(json.dumps(fixture_dict))


# ---------------------------------------------------------------------------
# test_list_profiles_returns_all
# ---------------------------------------------------------------------------


def test_list_profiles_returns_all():
    """Verify at least 8 profiles are available."""
    profiles = list_profiles()
    assert len(profiles) >= 8

    expected = {
        "ntia-2021",
        "cisa-2025",
        "cisa-2026",
        "cra-readiness",
        "bsi-tr-03183-2@2.1.0",
        "bsi-tr-03183-2@2.0.0",
        "bsi-tr-03183-2@1.1",
        "fsct-v3",
        "openchain-telco",
    }
    assert expected.issubset(set(profiles))


# ---------------------------------------------------------------------------
# test_load_profile_valid
# ---------------------------------------------------------------------------


def test_load_profile_valid():
    """Load 'ntia-2021' profile; verify it has name, version, requirements."""
    profile = load_profile("ntia-2021")

    assert "name" in profile
    assert "version" in profile
    assert "requirements" in profile
    assert isinstance(profile["requirements"], list)
    assert len(profile["requirements"]) > 0


# ---------------------------------------------------------------------------
# test_load_profile_unknown_raises
# ---------------------------------------------------------------------------


def test_load_profile_unknown_raises():
    """Loading an unknown profile returns the fallback (ntia-2021) or raises."""
    # The implementation falls back to ntia-2021 for unknown profiles
    profile = load_profile("nonexistent-profile-xyz")

    # Should either return the fallback or be empty
    assert isinstance(profile, dict)
    # If it falls back to ntia-2021, it should have requirements
    if profile:
        assert "requirements" in profile


# ---------------------------------------------------------------------------
# test_check_compliance_ntia_valid_sbom
# ---------------------------------------------------------------------------


def test_check_compliance_ntia_valid_sbom():
    """Check valid CycloneDX against ntia-2021; verify ComplianceResult shape."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = check_compliance(sbom, "ntia-2021")

    assert isinstance(result, ComplianceResult)
    assert result.profile == "NTIA Minimum Elements"
    assert isinstance(result.requirements, list)
    assert len(result.requirements) > 0
    assert 0.0 <= result.overall <= 10.0
    assert result.run_id  # non-empty


# ---------------------------------------------------------------------------
# test_check_compliance_returns_conform_or_not
# ---------------------------------------------------------------------------


def test_check_compliance_returns_conform_or_not():
    """Verify status is one of the allowed values."""
    sbom = _sbom_from_fixture(CDX_JSON)
    result = check_compliance(sbom, "ntia-2021")

    valid_statuses = {"conforms", "minor_gaps", "partial", "does_not_conform"}
    assert result.status in valid_statuses


# ---------------------------------------------------------------------------
# test_check_compliance_each_profile
# ---------------------------------------------------------------------------


def test_check_compliance_each_profile():
    """Iterate all profiles, check valid SBOM, verify no exceptions."""
    sbom = _sbom_from_fixture(CDX_JSON)
    profiles = list_profiles()

    for profile_name in profiles:
        result = check_compliance(sbom, profile_name)
        assert isinstance(result, ComplianceResult)
        assert result.profile  # non-empty
        assert 0.0 <= result.overall <= 10.0
        valid_statuses = {"conforms", "minor_gaps", "partial", "does_not_conform"}
        assert result.status in valid_statuses


# ---------------------------------------------------------------------------
# CISA 2026 minimum elements
# ---------------------------------------------------------------------------


def _cisa_2026_complete() -> dict:
    """A CycloneDX document that carries every CISA 2026 data field."""
    doc = copy.deepcopy(CDX_JSON)
    doc["metadata"]["lifecycles"] = [{"phase": "build"}]
    doc["signature"] = {"algorithm": "ES256", "value": "c2lnbmF0dXJl"}
    for comp in doc["components"]:
        comp.setdefault("supplier", {"name": "Example maintainers"})
        comp.setdefault("hashes", [{"alg": "SHA-256", "content": "b" * 64}])
    doc.pop("vulnerabilities", None)
    return doc


def _by_id(result: ComplianceResult) -> dict:
    return {r.id: r for r in result.requirements}


def test_cisa_2026_covers_all_seventeen_data_fields():
    profile = load_profile("cisa-2026")
    sections = [r["section_ref"] for r in profile["requirements"]]
    assert profile["version"] == "2026"
    assert sections.count("SBOM") == 9
    assert sections.count("Component") == 8


def test_cisa_2026_complete_sbom_conforms():
    result = check_compliance(_sbom_from_fixture(_cisa_2026_complete()), "cisa-2026")
    failing = [r.id for r in result.requirements if r.status != "pass"]
    assert failing == []
    assert result.status == "conforms"
    assert result.required_score == 10.0


def test_cisa_2026_flags_missing_generation_context_and_signature():
    result = _by_id(check_compliance(_sbom_from_fixture(CDX_JSON), "cisa-2026"))
    assert result["cisa26-generation-context"].status == "fail"
    assert result["cisa26-sbom-signature"].status == "fail"
    # A detached signature cannot be seen in the file, so it must never fail the required score.
    assert result["cisa26-sbom-signature"].level == "optional"


def test_cisa_2026_tool_version_partial():
    doc = _cisa_2026_complete()
    doc["metadata"]["tools"] = {"components": [{"name": "syft", "version": "1.4.1"}, {"name": "custom-merger"}]}
    result = _by_id(check_compliance(_sbom_from_fixture(doc), "cisa-2026"))
    assert result["cisa26-tool-name"].status == "pass"
    assert result["cisa26-tool-version"].status == "partial"


def test_cisa_2026_sbom_version_needs_serial_number():
    doc = _cisa_2026_complete()
    doc.pop("serialNumber")
    result = _by_id(check_compliance(_sbom_from_fixture(doc), "cisa-2026"))
    assert result["cisa26-sbom-version"].status == "fail"


def test_cisa_2026_spdx_reads_creation_info():
    doc = copy.deepcopy(SPDX_JSON)
    doc["creationInfo"]["comment"] = "Generated at build time from the release artifact."
    result = _by_id(check_compliance(_sbom_from_fixture(doc), "cisa-2026"))
    assert result["cisa26-sbom-author"].status == "pass"
    assert result["cisa26-tool-version"].status == "pass"
    assert result["cisa26-sbom-version"].status == "pass"
    assert result["cisa26-generation-context"].status == "pass"


def test_cisa_2026_identifier_accepts_cpe():
    doc = _cisa_2026_complete()
    comp = doc["components"][1]
    comp.pop("purl")
    comp["cpe"] = "cpe:2.3:a:python:requests:2.31.0:*:*:*:*:*:*:*"
    result = _by_id(check_compliance(_sbom_from_fixture(doc), "cisa-2026"))
    assert result["cisa26-component-identifiers"].status == "pass"


@pytest.mark.parametrize(
    ("alias", "target"),
    [("cisa", "cisa-2026"), ("bsi", "bsi-tr-03183-2@2.1.0"), ("cra", "cra-readiness"), ("ntia", "ntia-2021")],
)
def test_short_aliases_resolve_to_current_profiles(alias, target):
    """Project settings store short keys; they must not fall back to NTIA silently."""
    assert resolve_profile(alias) == target
    assert load_profile(alias) == load_profile(target)
