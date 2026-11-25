"""Tests for VEX output - :mod:`sbombox_core.vex`.

Verifies CycloneDX VEX generation, parsing VEX statements from documents,
and valid VEX status values.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sbombox_core.model.vex import VexStatement, VexStatus
from sbombox_core.vex import parse_vex_statements, vex_to_cyclonedx

# ---------------------------------------------------------------------------
# test_generate_vex_cyclonedx
# ---------------------------------------------------------------------------


def test_generate_vex_cyclonedx():
    """Generate CycloneDX VEX; verify structure."""
    statements = [
        VexStatement(
            vulnerability_id="CVE-2022-24999",
            status=VexStatus.NOT_AFFECTED,
            justification="vulnerable_code_not_present",
            details="The vulnerable code is not present in this product.",
            timestamp=datetime.now(UTC),
        ),
        VexStatement(
            vulnerability_id="CVE-2023-12345",
            status=VexStatus.AFFECTED,
            details="This product is affected by the vulnerability.",
            timestamp=datetime.now(UTC),
        ),
    ]

    vex_doc = vex_to_cyclonedx(statements)

    assert vex_doc["bomFormat"] == "CycloneDX"
    assert "vulnerabilities" in vex_doc
    assert len(vex_doc["vulnerabilities"]) == 2
    assert vex_doc["vulnerabilities"][0]["id"] == "CVE-2022-24999"
    assert vex_doc["vulnerabilities"][1]["id"] == "CVE-2023-12345"


# ---------------------------------------------------------------------------
# test_parse_vex_statements
# ---------------------------------------------------------------------------


def test_parse_vex_statements():
    """Parse VEX statements from a CycloneDX VEX document."""
    cdx_vex_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "vulnerabilities": [
            {
                "id": "CVE-2022-24999",
                "analysis": {
                    "state": "not_affected",
                    "justification": "vulnerable_code_not_present",
                    "detail": "The vulnerable code is not present.",
                },
            },
            {
                "id": "CVE-2023-12345",
                "analysis": {
                    "state": "affected",
                    "detail": "Product is affected.",
                },
            },
        ],
    }

    statements = parse_vex_statements(cdx_vex_doc)

    assert len(statements) == 2
    assert statements[0].vulnerability_id == "CVE-2022-24999"
    assert statements[0].status == VexStatus.NOT_AFFECTED
    assert statements[1].vulnerability_id == "CVE-2023-12345"
    assert statements[1].status == VexStatus.AFFECTED


# ---------------------------------------------------------------------------
# test_vex_status_values
# ---------------------------------------------------------------------------


def test_vex_status_values():
    """Verify valid VEX statuses."""
    # All four canonical VEX statuses should be defined
    assert VexStatus.NOT_AFFECTED == "not_affected"
    assert VexStatus.AFFECTED == "affected"
    assert VexStatus.FIXED == "fixed"
    assert VexStatus.UNDER_INVESTIGATION == "under_investigation"

    # Verify we can create statements with each status
    for status in VexStatus:
        stmt = VexStatement(
            vulnerability_id="CVE-TEST",
            status=status,
        )
        assert stmt.status == status


# ---------------------------------------------------------------------------
# CycloneDX vocabulary and strict document parsing
# ---------------------------------------------------------------------------

from sbombox_core.vex import VexParseError, parse_vex_document  # noqa: E402


def test_export_uses_cyclonedx_states():
    statements = [
        VexStatement(vulnerability_id="CVE-1", status=VexStatus.AFFECTED, justification="component_not_present"),
        VexStatement(vulnerability_id="CVE-2", status=VexStatus.FIXED),
        VexStatement(vulnerability_id="CVE-3", status=VexStatus.UNDER_INVESTIGATION),
        VexStatement(vulnerability_id="CVE-4", status=VexStatus.NOT_AFFECTED, justification="component_not_present"),
        VexStatement(vulnerability_id="CVE-5", status=VexStatus.NOT_AFFECTED, justification="requires_configuration"),
    ]
    vulns = {v["id"]: v["analysis"] for v in vex_to_cyclonedx(statements)["vulnerabilities"]}
    assert vulns["CVE-1"] == {"state": "exploitable"}
    assert vulns["CVE-2"]["state"] == "resolved"
    assert vulns["CVE-3"]["state"] == "in_triage"
    assert vulns["CVE-4"]["justification"] == "code_not_present"
    assert vulns["CVE-5"]["justification"] == "requires_configuration"


def test_export_drops_invalid_responses():
    stmt = VexStatement(vulnerability_id="CVE-1", status=VexStatus.AFFECTED, response=["update", "call us"])
    assert vex_to_cyclonedx([stmt])["vulnerabilities"][0]["analysis"]["response"] == ["update"]


def test_parse_document_detects_openvex():
    doc = parse_vex_document({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [
            {"vulnerability": {"name": "CVE-1"}, "status": "fixed", "justification": "component_not_present"},
            {"vulnerability": "CVE-2", "status": "not_affected", "justification": "component_not_present"},
        ],
    })
    assert doc.format == "openvex"
    assert doc.statements[0].status == VexStatus.FIXED
    assert doc.statements[0].justification is None
    assert doc.statements[1].justification == "component_not_present"


def test_parse_document_cdx_false_positive():
    doc = parse_vex_document({"bomFormat": "CycloneDX", "vulnerabilities": [
        {"id": "CVE-1", "analysis": {"state": "false_positive"}},
    ]})
    assert doc.statements[0].status == VexStatus.NOT_AFFECTED
    assert doc.statements[0].justification == "component_not_present"


def test_parse_document_collects_all_errors():
    with pytest.raises(VexParseError) as exc:
        parse_vex_document({"bomFormat": "CycloneDX", "vulnerabilities": [
            {"id": "CVE-1", "analysis": {"state": "nope"}},
            {"analysis": {"state": "resolved"}},
        ]})
    assert len(exc.value.errors) == 2


def test_parse_document_rejects_csaf_with_guidance():
    with pytest.raises(VexParseError, match="CSAF"):
        parse_vex_document({"document": {"category": "csaf_vex"}})
