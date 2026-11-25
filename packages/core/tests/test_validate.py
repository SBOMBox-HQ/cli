"""Tests for :mod:`sbombox_core.validate`.

Two layers, two jobs, and the split is the thing most worth pinning down:

* ``validate_schema`` reads the *raw* document and checks shape - presence,
  type, spec vocabulary, duplicates.
* ``validate_semantic`` reads the *parsed* model and checks quality plus
  cross-references - purls, license identifiers, digest lengths, dangling refs.

``validate_document`` merges them, so the tests also assert that a flaw is
reported exactly once: a duplicated finding at two paths that look identical is
worse than no finding, because it teaches callers to ignore the report.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sbombox_core.model import Component, Metadata, Sbom, SbomFormat
from sbombox_core.parse import parse_sbom
from sbombox_core.validate import (
    ValidationResult,
    ValidationSeverity,
    validate_cyclonedx_schema,
    validate_document,
    validate_sbom,
    validate_spdx_schema,
)

from tests.fixtures import CDX_JSON, CDX_JSON_SALVAGE, CDX_XML, DOCUMENTS, SPDX_JSON

SERIALISATIONS = list(DOCUMENTS)

ERROR = ValidationSeverity.ERROR
WARNING = ValidationSeverity.WARNING


def messages(result: ValidationResult) -> str:
    """Flatten findings into one searchable blob of ``path :: message`` lines."""
    return "\n".join(f"{issue.path or ''} :: {issue.message}" for issue in result.issues)


def severities(result: ValidationResult, message_fragment: str) -> set[ValidationSeverity]:
    return {issue.severity for issue in result.issues if message_fragment in issue.message}


# --------------------------------------------------------------------------- #
# known-good documents
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_a_real_document_has_no_errors(name: str) -> None:
    """The fixtures are ordinary SBOMs; an error here means a false positive.

    Warnings are allowed - the fixtures carry a deliberately short digest and a
    deliberately dropped component - but nothing that would make a caller reject
    an otherwise usable document.
    """
    result = validate_document(DOCUMENTS[name])
    errors = [issue for issue in result.issues if issue.severity is ERROR]
    assert result.valid, f"{name}: {[issue.message for issue in errors]}"
    assert not errors


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_validation_never_raises(name: str) -> None:
    """A validator that throws cannot be pointed at untrusted input."""
    assert isinstance(validate_document(DOCUMENTS[name]), ValidationResult)


def test_a_clean_document_reports_nothing_at_all() -> None:
    """Minimal but complete: no findings means no noise for a conforming SBOM."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2025-01-01T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "sbombox", "version": "0.1.0"}]},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:npm/express@4.18.2",
                "name": "express",
                "version": "4.18.2",
                "purl": "pkg:npm/express@4.18.2",
                "licenses": [{"license": {"id": "MIT"}}],
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            }
        ],
        "dependencies": [{"ref": "pkg:npm/express@4.18.2", "dependsOn": []}],
    }
    result = validate_document(json.dumps(document))
    assert result.valid
    assert result.issues == []


# --------------------------------------------------------------------------- #
# schema layer - CycloneDX shape
# --------------------------------------------------------------------------- #

CDX_NO_BOM_FORMAT: dict[str, Any] = {
    "specVersion": "1.6",
    "version": 1,
    "components": [{"type": "library", "name": "a", "version": "1"}],
}


def test_an_unlabelled_document_is_not_guessable() -> None:
    """Without ``bomFormat`` there is no way to know which spec to check against."""
    result = validate_document(json.dumps(CDX_NO_BOM_FORMAT))
    assert not result.valid
    assert "not a recognisable" in messages(result)


def test_an_explicit_format_hint_makes_the_missing_field_reportable() -> None:
    """With a hint the validator knows what it expected, so it can say so."""
    result = validate_document(json.dumps(CDX_NO_BOM_FORMAT), format="cyclonedx")
    assert not result.valid
    assert "Required field 'bomFormat' is missing" in messages(result)


def test_a_missing_spec_version_is_an_error() -> None:
    document = {"bomFormat": "CycloneDX", "version": 1, "components": [{"type": "library", "name": "a"}]}
    result = validate_document(json.dumps(document))
    assert not result.valid
    assert "specVersion" in messages(result)


def test_a_bad_serial_number_and_zero_revision_are_both_errors() -> None:
    """``serialNumber`` must be a URN and ``version`` a positive integer."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "not-a-urn",
        "version": 0,
        "components": [],
    }
    result = validate_document(json.dumps(document))
    assert not result.valid
    assert "serialNumber" in messages(result)
    assert "revision" in messages(result)


def test_a_revision_written_as_a_string_is_accepted() -> None:
    """XML and tag-value have no number type, so ``"1"`` must not be rejected."""
    issues = validate_cyclonedx_schema({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "1"}, "1.6")
    assert not [issue for issue in issues if issue.severity is ERROR]


def test_duplicate_bom_refs_are_an_error() -> None:
    """A duplicated ref makes every ``dependsOn`` pointing at it ambiguous."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"timestamp": "2025-01-01T00:00:00Z"},
        "components": [
            {"type": "library", "name": "a", "version": "1", "bom-ref": "dup"},
            {"type": "library", "name": "b", "version": "2", "bom-ref": "dup"},
        ],
    }
    result = validate_document(json.dumps(document))
    assert not result.valid
    assert "Duplicate bom-ref" in messages(result)


def test_a_component_that_is_not_an_object_is_reported() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": ["not-a-component"],
    }
    result = validate_document(json.dumps(document))
    assert not result.valid
    assert "components[0]" in messages(result)


def test_a_spec_version_mismatch_is_reported_against_the_requested_version() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [{"type": "library", "name": "a", "version": "1"}],
    }
    issues = validate_cyclonedx_schema(document, "1.6")
    assert any("was expected" in issue.message for issue in issues)


# --------------------------------------------------------------------------- #
# schema layer - SPDX shape
# --------------------------------------------------------------------------- #

SPDX_BROKEN: dict[str, Any] = {
    "spdxVersion": "SPDX-2.3",
    "name": "broken",
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://example.com/broken",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-a",
            "name": "a",
            "versionInfo": "1",
            "downloadLocation": "not-a-uri",
            "checksums": [{"algorithm": "SHA256"}],
            "externalRefs": [{"referenceType": "purl"}],
        },
        {"SPDXID": "SPDXRef-Package-a", "name": "duplicate", "downloadLocation": "NOASSERTION"},
        {"name": "no-id", "downloadLocation": "NOASSERTION"},
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "SOMETIMES_DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Ghost",
        },
        {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ""},
    ],
}


def test_spdx_structural_defects_are_all_reported() -> None:
    result = validate_document(json.dumps(SPDX_BROKEN))
    blob = messages(result)

    assert not result.valid
    for expected in (
        "creationInfo",
        "Duplicate SPDXID",
        "has no SPDXID",
        "not a URI",
        "Checksum has no checksumValue",
        "has no locator",
        "not a known SPDX relationship",
        "no relationshipType",
        "relatedSpdxElement[0] is empty",
    ):
        assert expected in blob, f"missing finding {expected!r} in:\n{blob}"


def test_a_missing_spdx_version_is_an_error() -> None:
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "no-version",
        "dataLicense": "CC0-1.0",
        "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: sbombox"]},
        "packages": [{"SPDXID": "SPDXRef-P", "name": "p", "downloadLocation": "NOASSERTION"}],
    }
    result = validate_document(json.dumps(document))
    assert not result.valid
    assert "spdxVersion" in messages(result)


def test_a_patch_spec_version_is_accepted() -> None:
    """``SPDX-3.0.1`` is a real release; a ``major.minor``-only pattern rejects it."""
    document = dict(SPDX_JSON)
    document["spdxVersion"] = "SPDX-3.0.1"
    issues = validate_spdx_schema(document, "3.0.1")
    assert not [issue for issue in issues if "must look like" in issue.message]


def test_an_spdx_version_mismatch_is_reported() -> None:
    issues = validate_spdx_schema(SPDX_JSON, "2.2")
    assert any("was expected" in issue.message for issue in issues)


# --------------------------------------------------------------------------- #
# semantic layer - quality and cross-references
# --------------------------------------------------------------------------- #

MESSY: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {"timestamp": "2025-01-01T00:00:00Z"},
    "components": [
        {
            "type": "library",
            "name": "weird",
            "bom-ref": "weird",
            "purl": "pkg:not-a-purl",
            "hashes": [
                {"alg": "SHA-256", "content": "deadbeef"},
                {"alg": "SHA-1", "content": "z" * 40},
            ],
            "licenses": [{"license": {"id": "Totally-Not-A-License"}}],
        },
        {"type": "library", "version": "1", "bom-ref": "no-name"},
        {
            "type": "library",
            "name": "dupe-purl",
            "version": "1",
            "bom-ref": "dupe-1",
            "purl": "pkg:npm/express@4.18.2",
            "licenses": [{"expression": "MIT AND Apache-2.0"}],
        },
        {
            # Same purl as ``dupe-1`` under a different name and ref: a duplicate
            # only a purl comparison can see.
            "type": "library",
            "name": "dupe-purl-2",
            "version": "1",
            "bom-ref": "dupe-2",
            "purl": "pkg:npm/express@4.18.2",
        },
    ],
    "dependencies": [
        # ``ghost`` points at nothing, which is the dangling-reference case.
        {"ref": "ghost", "dependsOn": ["phantom"]},
        {"ref": "weird", "dependsOn": ["dupe-1"]},
    ],
}


def test_semantic_findings_are_reported_at_the_right_severity() -> None:
    """A nameless component is unusable; a missing version is only suspicious."""
    result = validate_document(json.dumps(MESSY))
    blob = messages(result)

    assert not result.valid
    for expected in (
        "malformed purl",
        "not a hexadecimal",
        "characters long, expected 64",
        "not in the SPDX license list",
        "has no name",
        "has no version",
        "share the purl",
        "does not match any component",
        "unknown ref",
    ):
        assert expected in blob, f"missing finding {expected!r} in:\n{blob}"

    assert severities(result, "has no name") == {ERROR}
    assert severities(result, "has no version") == {WARNING}
    assert severities(result, "share the purl") == {WARNING}
    assert severities(result, "malformed purl") == {WARNING}


def test_a_valid_license_expression_is_not_flagged() -> None:
    """``MIT AND Apache-2.0`` is well-formed even though it is not a single id."""
    result = validate_document(json.dumps(MESSY))
    assert "is not a valid SPDX expression" not in messages(result)


def test_an_empty_inventory_is_valid_but_warned() -> None:
    """Zero components is legal (a services-only BOM) but almost always a mistake."""
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    result = validate_document(json.dumps(document))

    assert result.valid
    assert "no components" in messages(result)
    assert "no metadata timestamp" in messages(result)


def test_dropped_entries_are_surfaced_as_findings() -> None:
    """The parser salvages what it can; the report has to say what it lost."""
    sbom = parse_sbom(json.dumps(CDX_JSON_SALVAGE))
    assert sbom.dropped_entries

    result = validate_sbom(sbom)
    assert severities(result, "was dropped") == {ERROR}
    assert not result.valid


def test_the_metadata_component_counts_as_a_known_ref() -> None:
    """``dependsOn`` may point at the described component, not just the inventory."""
    result = validate_document(CDX_XML)
    assert "does not match any component" not in messages(result)


# --------------------------------------------------------------------------- #
# validate_sbom - the model-level entry point
# --------------------------------------------------------------------------- #


def test_validate_sbom_works_on_an_already_parsed_model() -> None:
    sbom = parse_sbom(json.dumps(CDX_JSON))
    result = validate_sbom(sbom)

    assert isinstance(result, ValidationResult)
    assert result.valid, [issue.message for issue in result.issues if issue.severity is ERROR]
    assert result.issues, "the fixture has a dangling dependency, so there must be at least one warning"


def test_validate_sbom_reports_a_dangling_dependency() -> None:
    sbom = parse_sbom(json.dumps(CDX_JSON))
    result = validate_sbom(sbom)
    assert "missing-ref" in messages(result)


def test_validate_sbom_accepts_bytes_and_a_filename() -> None:
    """The document-level entry point takes whatever ``parse_sbom`` takes."""
    result = validate_document(CDX_XML, "bom.xml")
    assert isinstance(result, ValidationResult)


# --------------------------------------------------------------------------- #
# unusable input
# --------------------------------------------------------------------------- #


def test_a_document_that_is_not_an_sbom_is_invalid_not_raised() -> None:
    result = validate_document('{"hello": "world"}')
    assert not result.valid
    assert "not a recognisable" in messages(result)


def test_an_empty_document_is_invalid_not_raised() -> None:
    result = validate_document("   ")
    assert not result.valid
    assert "empty" in messages(result)


def test_a_truncated_document_explains_that_it_could_not_be_decoded() -> None:
    result = validate_document('{"bomFormat": "CycloneDX",')
    assert not result.valid
    assert "could not be decoded" in messages(result)


def test_a_parse_failure_is_not_reported_twice() -> None:
    """The schema layer already said the document is unrecognisable; one is enough."""
    result = validate_document('{"hello": "world"}')
    assert len([issue for issue in result.issues if "not a recognisable" in issue.message]) == 1


def test_merged_findings_contain_no_exact_duplicates() -> None:
    """Two layers describing one flaw must collapse into a single line."""
    for name in SERIALISATIONS:
        result = validate_document(DOCUMENTS[name])
        keys = [(issue.severity, issue.message, issue.path, issue.component_ref) for issue in result.issues]
        assert len(keys) == len(set(keys)), f"{name} reported a duplicate finding"


def test_a_model_built_by_hand_is_validated_without_a_document() -> None:
    """``validate_sbom`` must not depend on ``raw_data`` being present."""
    sbom = Sbom(
        format=SbomFormat.CYCLONEDX,
        spec_version="1.6",
        metadata=Metadata(),
        components=[Component(name="express", version="4.18.2", purl="pkg:npm/express@4.18.2")],
        dependencies=[],
    )
    result = validate_sbom(sbom)
    assert result.valid
    assert any("no metadata timestamp" in issue.message for issue in result.issues)
