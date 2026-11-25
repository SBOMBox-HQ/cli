"""VEX (Vulnerability Exploitability eXchange) read/write.

Reads CycloneDX VEX and OpenVEX documents; writes CycloneDX VEX and CSAF 2.0.

Statements are stored in the OpenVEX vocabulary (see
:class:`~sbombox_core.model.vex.VexStatement`). CycloneDX uses different words
for the same ideas, so every read and write goes through the crosswalks below.
They follow the CISA "VEX Status Justifications" mapping and match the browser
VEX generator (``ui-next/lib/sbom/vex.ts``), so a file exported here imports
back without changes.

Usage::

    from sbombox_core.vex import parse_vex_document, vex_to_cyclonedx

    doc = parse_vex_document(json.load(fh))
    cdx = vex_to_cyclonedx(doc.statements)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from sbombox_core.model.vex import VexStatement, VexStatus

__all__ = [
    "CDX_JUSTIFICATIONS",
    "CDX_RESPONSES",
    "VexDocument",
    "VexParseError",
    "parse_openvex",
    "parse_vex_document",
    "parse_vex_statements",
    "vex_to_csaf",
    "vex_to_cyclonedx",
]

# --------------------------------------------------------- crosswalks

#: OpenVEX status -> CycloneDX ``analysis.state``.
_STATUS_TO_CDX: dict[VexStatus, str] = {
    VexStatus.NOT_AFFECTED: "not_affected",
    VexStatus.AFFECTED: "exploitable",
    VexStatus.FIXED: "resolved",
    VexStatus.UNDER_INVESTIGATION: "in_triage",
}

#: CycloneDX ``analysis.state`` -> OpenVEX status. ``affected`` is not a
#: CycloneDX state, but SBOMBox exports before November 2026 wrote it, so it is
#: accepted on import.
_CDX_TO_STATUS: dict[str, VexStatus] = {
    "not_affected": VexStatus.NOT_AFFECTED,
    "false_positive": VexStatus.NOT_AFFECTED,
    "exploitable": VexStatus.AFFECTED,
    "affected": VexStatus.AFFECTED,
    "resolved": VexStatus.FIXED,
    "resolved_with_pedigree": VexStatus.FIXED,
    "in_triage": VexStatus.UNDER_INVESTIGATION,
}

#: Every ``analysis.justification`` value CycloneDX 1.5 and 1.6 allow.
CDX_JUSTIFICATIONS: frozenset[str] = frozenset({
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
})

#: Every ``analysis.response`` value CycloneDX 1.5 and 1.6 allow.
CDX_RESPONSES: frozenset[str] = frozenset({
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
})

#: OpenVEX justification -> CycloneDX justification.
_JUSTIFICATION_TO_CDX: dict[str, str] = {
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

#: CycloneDX justification -> OpenVEX justification, where one exists. CycloneDX
#: values with no OpenVEX equivalent (``requires_configuration`` and others) are
#: kept as they are, so no detail is lost and they export unchanged.
_CDX_TO_JUSTIFICATION: dict[str, str] = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _cdx_justification(value: str | None) -> str | None:
    """Return the CycloneDX spelling of a stored justification, or ``None``."""
    key = _norm(value)
    if not key:
        return None
    if key in CDX_JUSTIFICATIONS:
        return key
    return _JUSTIFICATION_TO_CDX.get(key)


# --------------------------------------------------------- write


def vex_to_cyclonedx(
    statements: list[VexStatement],
    bom_ref: str | None = None,
) -> dict[str, Any]:
    """Convert VEX statements to a CycloneDX 1.5 VEX document.

    Statuses and justifications are translated to the CycloneDX vocabulary.
    Empty fields are left out rather than written as empty strings, because
    CycloneDX validates ``justification`` and ``response`` against fixed lists.

    Args:
        statements: List of VEX statements.
        bom_ref: Optional bom-ref of the product the statements apply to. When
            given, each vulnerability lists it under ``affects``.

    Returns:
        A CycloneDX-shaped dict.
    """
    vulnerabilities: list[dict[str, Any]] = []
    for stmt in statements:
        analysis: dict[str, Any] = {"state": _STATUS_TO_CDX[stmt.status]}
        if stmt.status == VexStatus.NOT_AFFECTED:
            justification = _cdx_justification(stmt.justification)
            if justification:
                analysis["justification"] = justification
        responses = [r for r in (_norm(r) for r in stmt.response) if r in CDX_RESPONSES]
        if responses:
            analysis["response"] = responses
        if stmt.details:
            analysis["detail"] = stmt.details
        if stmt.timestamp:
            analysis["lastUpdated"] = stmt.timestamp.isoformat()

        vuln: dict[str, Any] = {"id": stmt.vulnerability_id, "analysis": analysis}
        if bom_ref:
            vuln["affects"] = [{"ref": bom_ref}]
        vulnerabilities.append(vuln)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {"components": [{"type": "application", "name": "sbombox"}]},
        },
        "vulnerabilities": vulnerabilities,
    }


def vex_to_csaf(statements: list[VexStatement]) -> dict[str, Any]:
    """Convert VEX statements to CSAF 2.0 format.

    Args:
        statements: List of VEX statements.

    Returns:
        A CSAF 2.0-shaped dict.
    """
    vulnerabilities: list[dict[str, Any]] = []
    for stmt in statements:
        vuln: dict[str, Any] = {
            "cve": stmt.vulnerability_id,
            "flags": [],
            "product_status": {},
        }
        if stmt.status == VexStatus.NOT_AFFECTED:
            vuln["product_status"]["known_not_affected"] = ["PRODUCT_ID"]
        elif stmt.status == VexStatus.AFFECTED:
            vuln["product_status"]["known_affected"] = ["PRODUCT_ID"]
        elif stmt.status == VexStatus.FIXED:
            vuln["product_status"]["fixed"] = ["PRODUCT_ID"]
        elif stmt.status == VexStatus.UNDER_INVESTIGATION:
            vuln["product_status"]["under_investigation"] = ["PRODUCT_ID"]

        if stmt.justification:
            vuln["flags"].append({"label": stmt.justification})

        vulnerabilities.append(vuln)

    return {
        "document": {
            "category": "csaf_vex",
            "csaf_version": "2.0",
            "title": "SBOMBox VEX Document",
            "tracking": {
                "current_release_date": datetime.now(UTC).isoformat(),
                "id": "SBOMBOX-VEX-001",
                "initial_release_date": datetime.now(UTC).isoformat(),
                "revision_history": [{"date": datetime.now(UTC).isoformat(), "number": "1", "summary": "Initial"}],
                "status": "final",
                "version": "1",
            },
        },
        "vulnerabilities": vulnerabilities,
    }


# --------------------------------------------------------- read


class VexParseError(ValueError):
    """A VEX document could not be read. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass
class VexDocument:
    """The statements read from one VEX document."""

    format: str  # "cyclonedx" or "openvex"
    statements: list[VexStatement] = field(default_factory=list)
    #: Entries that carry no decision (a CycloneDX vulnerability with no
    #: ``analysis.state``). They are findings, not VEX statements.
    unanalysed: int = 0


def parse_vex_statements(data: dict[str, Any]) -> list[VexStatement]:
    """Parse VEX statements from a CycloneDX VEX document.

    Lenient: an entry with no ``analysis.state`` is read as ``affected`` and an
    unknown state as ``under_investigation``. Use :func:`parse_vex_document` to
    reject bad input instead.

    Args:
        data: A CycloneDX-shaped dict with vulnerability entries.

    Returns:
        A list of :class:`VexStatement` objects.
    """
    statements: list[VexStatement] = []
    for vuln in data.get("vulnerabilities", []):
        analysis = vuln.get("analysis") or {}
        state = _norm(analysis.get("state") or "affected")
        statements.append(_cdx_statement(vuln, _CDX_TO_STATUS.get(state, VexStatus.UNDER_INVESTIGATION)))
    return statements


def _cdx_statement(vuln: dict[str, Any], status: VexStatus) -> VexStatement:
    analysis = vuln.get("analysis") or {}
    raw_justification = _norm(analysis.get("justification"))
    justification = _CDX_TO_JUSTIFICATION.get(raw_justification, raw_justification) or None
    if _norm(analysis.get("state")) == "false_positive" and not justification:
        # A false positive means the scanner matched the wrong component.
        justification = "component_not_present"
    return VexStatement(
        vulnerability_id=str(vuln.get("id") or "").strip(),
        status=status,
        justification=justification if status == VexStatus.NOT_AFFECTED else None,
        response=analysis.get("response") or [],
        details=analysis.get("detail") or None,
        timestamp=analysis.get("lastUpdated") or None,
    )


def _parse_cyclonedx(data: dict[str, Any]) -> VexDocument:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise VexParseError(["This CycloneDX file has no 'vulnerabilities' list, so it holds no VEX statements."])
    doc = VexDocument(format="cyclonedx")
    errors: list[str] = []
    for index, vuln in enumerate(vulns):
        label = f"vulnerabilities[{index}]"
        if not isinstance(vuln, dict):
            errors.append(f"{label}: expected an object.")
            continue
        if not str(vuln.get("id") or "").strip():
            errors.append(f"{label}: missing 'id'.")
            continue
        analysis = vuln.get("analysis")
        state = _norm(analysis.get("state")) if isinstance(analysis, dict) else ""
        if not state:
            doc.unanalysed += 1
            continue
        status = _CDX_TO_STATUS.get(state)
        if status is None:
            errors.append(
                f"{label} ({vuln['id']}): unknown analysis.state '{analysis['state']}'. "
                f"Expected one of: {', '.join(sorted(_CDX_TO_STATUS))}."
            )
            continue
        try:
            doc.statements.append(_cdx_statement(vuln, status))
        except ValidationError as exc:
            errors.append(f"{label} ({vuln['id']}): {exc.errors()[0]['msg']}.")
    if errors:
        raise VexParseError(errors)
    return doc


def parse_openvex(data: dict[str, Any]) -> list[VexStatement]:
    """Parse the statements of an OpenVEX document.

    Raises:
        VexParseError: if any statement is missing a vulnerability or status.
    """
    raw = data.get("statements")
    if not isinstance(raw, list):
        raise VexParseError(["This OpenVEX file has no 'statements' list."])
    statements: list[VexStatement] = []
    errors: list[str] = []
    for index, item in enumerate(raw):
        label = f"statements[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label}: expected an object.")
            continue
        vuln = item.get("vulnerability")
        if isinstance(vuln, dict):
            vuln_id = vuln.get("name") or vuln.get("@id") or ""
        else:
            vuln_id = vuln or item.get("vulnerability_id") or ""
        vuln_id = str(vuln_id).strip()
        if not vuln_id:
            errors.append(f"{label}: missing 'vulnerability'.")
            continue
        details = "\n\n".join(
            text.strip()
            for text in (item.get("impact_statement"), item.get("action_statement"), item.get("status_notes"))
            if isinstance(text, str) and text.strip()
        )
        try:
            stmt = VexStatement(
                vulnerability_id=vuln_id,
                status=item.get("status"),
                justification=item.get("justification") or None,
                details=details or None,
                timestamp=item.get("timestamp") or data.get("timestamp") or None,
                products=item.get("products") or [],
            )
        except ValidationError:
            errors.append(
                f"{label} ({vuln_id}): unknown status '{item.get('status')}'. "
                f"Expected one of: {', '.join(s.value for s in VexStatus)}."
            )
            continue
        if stmt.status != VexStatus.NOT_AFFECTED:
            stmt.justification = None
        statements.append(stmt)
    if errors:
        raise VexParseError(errors)
    return statements


def parse_vex_document(data: Any) -> VexDocument:
    """Detect the format of a VEX document and read every statement in it.

    Strict: any entry that cannot be read raises, listing every problem, so a
    caller can reject the whole file rather than import part of it.

    Supports CycloneDX VEX (1.4 to 1.6, standalone or embedded in an SBOM) and
    OpenVEX.

    Raises:
        VexParseError: if the format is unknown or any statement is invalid.
    """
    if not isinstance(data, dict):
        raise VexParseError(["Expected a JSON object at the top level."])
    context = str(data.get("@context") or "")
    if "openvex" in context.lower() or ("statements" in data and "vulnerabilities" not in data):
        return VexDocument(format="openvex", statements=parse_openvex(data))
    if data.get("bomFormat") == "CycloneDX" or "vulnerabilities" in data:
        return _parse_cyclonedx(data)
    document = data.get("document")
    if isinstance(document, dict) and document.get("category") == "csaf_vex":
        raise VexParseError(["CSAF VEX import is not supported yet. Convert the file to CycloneDX or OpenVEX first."])
    raise VexParseError(["Not a recognised VEX document. Upload a CycloneDX VEX or OpenVEX JSON file."])
