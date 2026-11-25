"""Tests for :mod:`sbombox_core.parse`.

The emphasis is on *mapping*, not on happy-path plumbing: each serialisation
has to land in the same normalised :class:`~sbombox_core.model.sbom.Sbom`, with
the same field names and the same vocabulary, or the layers above it cannot
treat CycloneDX and SPDX alike.
"""

from __future__ import annotations

import json

import pytest
from sbombox_core.errors import MalformedDocumentError, SbomParseError, UnsupportedFormatError
from sbombox_core.model.sbom import SbomFormat
from sbombox_core.parse import parse_sbom, read_sbom_file
from sbombox_core.parse.sniff import detect_format
from sbombox_core.validate import validate_semantic

from tests.fixtures import CDX_JSON, CDX_JSON_SALVAGE, CDX_XML, CDX_YAML, DETECTED, DOCUMENTS, SPDX_JSON

SERIALISATIONS = list(DOCUMENTS)


# --------------------------------------------------------------------------- #
# format detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_detect_format_identifies_every_serialisation(name: str) -> None:
    """Sniffing alone must route a document, with no filename and no hint."""
    expected_format, expected_version = DETECTED[name]
    fmt, version = detect_format(DOCUMENTS[name])
    assert fmt == SbomFormat(expected_format)
    assert version == expected_version


def test_detect_format_accepts_text_and_bytes_alike() -> None:
    """A caller should not have to know whether it is holding ``str`` or ``bytes``."""
    assert detect_format(json.dumps(CDX_JSON)) == detect_format(json.dumps(CDX_JSON).encode())


def test_detect_format_rejects_a_document_that_is_not_an_sbom() -> None:
    """Valid JSON that is not an SBOM is a routing failure, not a parse failure."""
    with pytest.raises(UnsupportedFormatError):
        detect_format('{"hello": "world"}')


def test_detect_format_distinguishes_broken_from_unsupported() -> None:
    """A truncated CycloneDX document is recognisable but undecodable.

    Collapsing the two would tell a user "wrong file" when the real answer is
    "your file is corrupt" - the one detail they can act on.
    """
    with pytest.raises(MalformedDocumentError):
        detect_format('{"bomFormat": "CycloneDX",')


def test_detect_format_rejects_blank_input() -> None:
    with pytest.raises(SbomParseError):
        detect_format("   ")


# --------------------------------------------------------------------------- #
# parsing, all serialisations
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_preserves_format_and_spec_version(name: str) -> None:
    sbom = parse_sbom(DOCUMENTS[name])
    expected_format, expected_version = DETECTED[name]
    assert sbom.format == SbomFormat(expected_format)
    assert sbom.spec_version == expected_version


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_produces_a_non_empty_inventory(name: str) -> None:
    """Every fixture describes at least one package; losing them all is a bug."""
    sbom = parse_sbom(DOCUMENTS[name])
    assert sbom.components, f"{name} produced no components"
    assert all(component.name for component in sbom.components)


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_captures_metadata_timestamp(name: str) -> None:
    """All seven fixtures carry a creation timestamp; it must survive mapping."""
    sbom = parse_sbom(DOCUMENTS[name])
    assert sbom.metadata.timestamp is not None, f"{name} lost metadata.timestamp"


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_extracts_at_least_one_purl(name: str) -> None:
    """purls are the join key for enrichment, so every fixture must yield one."""
    sbom = parse_sbom(DOCUMENTS[name])
    purls = [component.purl for component in sbom.iter_components() if component.purl]
    assert purls, f"{name} produced no purls"


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_keeps_the_raw_document_for_round_tripping(name: str) -> None:
    """``raw_data`` exists so a fix pass can rewrite the original, not a copy."""
    sbom = parse_sbom(DOCUMENTS[name])
    assert sbom.raw_data


# --------------------------------------------------------------------------- #
# CycloneDX specifics
# --------------------------------------------------------------------------- #


def test_cyclonedx_json_maps_every_component_field() -> None:
    sbom = parse_sbom(json.dumps(CDX_JSON))
    express = next(component for component in sbom.components if component.name == "express")

    assert express.bom_ref == "pkg:npm/express@4.18.2"
    assert express.type.value == "library"
    assert express.version == "4.18.2"
    assert express.purl == "pkg:npm/express@4.18.2"
    assert express.scope == "required"
    assert express.supplier is not None
    assert express.supplier.name == "TJ Holowaychuk"
    assert express.properties == {"syft:language": "javascript"}
    assert [(reference.type, reference.url) for reference in express.external_references] == [
        ("website", "https://expressjs.com")
    ]
    assert [(digest.alg.value, digest.content) for digest in express.hashes] == [("SHA-256", "a" * 64)]


def test_cyclonedx_json_maps_both_license_spellings() -> None:
    """``license.id`` and ``expression`` are different shapes for the same idea."""
    sbom = parse_sbom(json.dumps(CDX_JSON))
    by_name = {component.name: component for component in sbom.components}

    identified = by_name["express"].licenses[0]
    assert identified.license is not None
    assert identified.license.id == "MIT"
    assert identified.expression is None

    expressed = by_name["requests"].licenses[0]
    assert expressed.expression == "Apache-2.0 AND MIT"
    assert expressed.license is None


def test_cyclonedx_json_maps_metadata_tools_and_authors() -> None:
    sbom = parse_sbom(json.dumps(CDX_JSON))

    assert [(tool.name, tool.version) for tool in sbom.metadata.tools] == [("syft", "1.4.1")]
    assert [(author.name, author.email) for author in sbom.metadata.authors] == [("Jane Doe", "jane@example.com")]
    assert sbom.metadata.supplier is not None
    assert sbom.metadata.supplier.name == "Acme Inc"
    assert sbom.metadata.component is not None
    assert sbom.metadata.component.name == "acme-app"


def test_cyclonedx_json_maps_dependencies_vulnerabilities_and_services() -> None:
    sbom = parse_sbom(json.dumps(CDX_JSON))

    assert [(dependency.ref, dependency.depends_on) for dependency in sbom.dependencies] == [
        ("pkg:generic/acme-app@1.0.0", ["pkg:npm/express@4.18.2"]),
        ("pkg:npm/express@4.18.2", ["pkg:pypi/requests@2.31.0", "missing-ref"]),
    ]

    vulnerability = sbom.vulnerabilities[0]
    assert vulnerability.id == "CVE-2022-24999"
    assert vulnerability.ratings[0].severity.value == "high"
    assert vulnerability.ratings[0].score == 7.5
    assert [target.ref for target in vulnerability.affects] == ["pkg:npm/express@4.18.2"]

    service = sbom.services[0]
    assert service.name == "api"
    assert service.endpoints == ["https://api.example.com/v1"]
    assert service.authenticated is True
    assert service.x_trust_boundary is True

    assert [(reference.type, reference.url) for reference in sbom.external_references] == [
        ("vcs", "https://github.com/acme/app")
    ]


def test_cyclonedx_drops_an_unmappable_component_instead_of_failing() -> None:
    """One nameless record must not cost the caller the other two."""
    sbom = parse_sbom(json.dumps(CDX_JSON_SALVAGE))
    assert [component.name for component in sbom.components] == ["express", "requests"]
    assert sbom.dropped_entries, "the dropped record should be reported, not swallowed"


def test_cyclonedx_xml_uses_the_legacy_tools_shape() -> None:
    """1.4/1.5 XML nests ``<tool>`` directly; 1.5+ JSON nests ``components``."""
    sbom = parse_sbom(CDX_XML)
    assert [(tool.vendor, tool.name, tool.version) for tool in sbom.metadata.tools] == [("anchore", "syft", "0.90.0")]
    assert sbom.metadata.component is not None
    assert sbom.metadata.component.bom_ref == "app-1"


def test_cyclonedx_xml_flattens_namespaced_elements() -> None:
    sbom = parse_sbom(CDX_XML)
    express = next(component for component in sbom.components if component.name == "express")

    assert express.purl == "pkg:npm/express@4.18.2"
    assert express.licenses[0].license is not None
    assert express.licenses[0].license.id == "MIT"
    assert express.properties == {"k": "v"}
    assert [dependency.ref for dependency in sbom.dependencies] == ["app-1"]
    assert sbom.vulnerabilities[0].id == "CVE-2022-24999"


def test_cyclonedx_yaml_is_routed_by_content_not_extension() -> None:
    sbom = parse_sbom(CDX_YAML)
    assert sbom.format is SbomFormat.CYCLONEDX
    assert sbom.spec_version == "1.4"
    assert [component.name for component in sbom.components] == ["express"]


def test_cyclonedx_rejects_malformed_xml() -> None:
    with pytest.raises(MalformedDocumentError):
        parse_sbom(b"<bom><components>")


def test_an_unsupported_spec_version_still_parses() -> None:
    """Parsing is best-effort; refusing an unknown version would strand the data.

    A future CycloneDX release is a superset of today's field vocabulary, so
    rejecting it would throw away a readable inventory.  The version is
    reported by validation instead, which is where a caller can decide.
    """
    document = {**CDX_JSON, "specVersion": "0.9"}
    sbom = parse_sbom(json.dumps(document))

    assert sbom.spec_version == "0.9"
    assert sbom.components

    findings = validate_semantic(sbom)
    assert any("not a supported spec version" in issue.message for issue in findings.issues)


def test_a_format_hint_overrides_detection() -> None:
    """The hint is authoritative: an SPDX document parsed as CycloneDX must fail."""
    with pytest.raises(SbomParseError):
        parse_sbom(json.dumps(SPDX_JSON), format="cyclonedx")


def test_an_unknown_format_hint_is_rejected() -> None:
    with pytest.raises(UnsupportedFormatError):
        parse_sbom(json.dumps(CDX_JSON), format="csaf")


# --------------------------------------------------------------------------- #
# SPDX specifics
# --------------------------------------------------------------------------- #


def test_spdx_json_maps_packages_to_components() -> None:
    sbom = parse_sbom(json.dumps(SPDX_JSON))
    by_ref = {component.bom_ref: component for component in sbom.components}

    # The described package is the document's subject, so it becomes
    # ``metadata.component`` and is deliberately absent from the inventory.
    assert set(by_ref) == {"SPDXRef-Package-express", "SPDXRef-Package-requests"}

    express = by_ref["SPDXRef-Package-express"]
    assert express.name == "express"
    assert express.version == "4.18.2"
    assert express.purl == "pkg:npm/express@4.18.2"
    assert express.cpe == "cpe:2.3:a:express:express:4.18.2:*:*:*:*:*:*:*"
    assert express.hashes[0].alg.value == "SHA-256"
    assert express.hashes[0].content == "a" * 64
    assert express.licenses[0].license is not None
    assert express.licenses[0].license.id == "MIT"

    requests = by_ref["SPDXRef-Package-requests"]
    assert requests.licenses[0].expression == "Apache-2.0 AND MIT"


def test_spdx_json_maps_supplier_and_originator() -> None:
    sbom = parse_sbom(json.dumps(SPDX_JSON))
    by_ref = {component.bom_ref: component for component in sbom.components}

    app = sbom.metadata.component
    assert app is not None
    assert app.bom_ref == "SPDXRef-Package-app"
    assert app.supplier is not None
    assert app.supplier.name == "Acme Inc"
    assert app.type.value == "application"

    express = by_ref["SPDXRef-Package-express"]
    assert express.author == "TJ Holowaychuk"


def test_spdx_json_maps_creation_info_to_metadata() -> None:
    sbom = parse_sbom(json.dumps(SPDX_JSON))

    assert [(tool.name, tool.version) for tool in sbom.metadata.tools] == [("syft", "1.4.1")]
    # ``Tool:`` creators become tools; every other creator becomes an author.
    # SPDX has no document-level supplier field, so nothing is invented here -
    # the organization stays an author and the package keeps its own supplier.
    assert [(author.name, author.email) for author in sbom.metadata.authors] == [
        ("Acme Inc", None),
        ("Jane Doe", "jane@example.com"),
    ]
    assert sbom.metadata.supplier is None
    assert sbom.metadata.properties["spdx:licenseListVersion"] == "3.21"


def test_spdx_json_folds_relationships_into_dependency_edges() -> None:
    """``DEPENDENCY_OF`` is ``DEPENDS_ON`` backwards and must be inverted.

    The fixture states express→requests directly *and* requests
    ``DEPENDENCY_OF`` express.  Both describe one edge, so the merged graph must
    not duplicate it.
    """
    sbom = parse_sbom(json.dumps(SPDX_JSON))
    edges = {dependency.ref: dependency.depends_on for dependency in sbom.dependencies}

    assert edges["SPDXRef-Package-app"] == ["SPDXRef-Package-express"]
    assert edges["SPDXRef-Package-express"] == ["SPDXRef-Package-requests"]
    assert "SPDXRef-Package-requests" not in edges


def test_spdx_json_uses_the_described_package_as_metadata_component() -> None:
    sbom = parse_sbom(json.dumps(SPDX_JSON))
    assert sbom.metadata.component is not None
    assert sbom.metadata.component.bom_ref == "SPDXRef-Package-app"


def test_spdx3_jsonld_is_normalised_onto_the_2x_shape() -> None:
    """3.0 renames almost everything; the parsed model must not show it."""
    sbom = parse_sbom(DOCUMENTS["spdx3-jsonld"])

    assert sbom.format is SbomFormat.SPDX
    assert sbom.metadata.component is not None
    assert sbom.metadata.component.name == "acme-app"
    assert sbom.metadata.component.version == "1.0.0"
    assert sbom.metadata.component.purl == "pkg:generic/acme-app@1.0.0"
    assert sbom.metadata.component.licenses[0].license is not None
    assert sbom.metadata.component.licenses[0].license.id == "Apache-2.0"

    lib = next(component for component in sbom.components if component.name == "acme-lib")
    assert lib.version == "2.1.0"

    edges = {dependency.ref: dependency.depends_on for dependency in sbom.dependencies}
    assert edges["SPDXRef-Package-app"] == ["SPDXRef-Package-lib"]


def test_spdx_rdf_resolves_uris_to_local_refs() -> None:
    """RDF identifies elements by absolute URI; the model uses the fragment."""
    sbom = parse_sbom(DOCUMENTS["spdx-rdf"])

    assert sbom.spec_version == "2.2"
    refs = {component.bom_ref for component in sbom.iter_components()}
    assert refs == {"SPDXRef-Package-app", "SPDXRef-Package-lib"}

    app = next(component for component in sbom.iter_components() if component.bom_ref == "SPDXRef-Package-app")
    assert app.purl == "pkg:generic/acme-app@1.0.0"
    assert app.supplier is not None
    assert app.supplier.name == "Acme Inc"

    edges = {dependency.ref: dependency.depends_on for dependency in sbom.dependencies}
    assert edges == {"SPDXRef-Package-app": ["SPDXRef-Package-lib"]}


def test_spdx_tag_value_folds_continuation_lines() -> None:
    sbom = parse_sbom(DOCUMENTS["spdx-tag-value"])
    app = next(component for component in sbom.iter_components() if component.name == "acme-app")

    assert app.version == "1.0.0"
    assert app.description == "A multi line\ndescription here"
    assert app.purl == "pkg:generic/acme-app@1.0.0"
    assert app.type.value == "application"

    express = next(component for component in sbom.iter_components() if component.name == "express")
    assert express.hashes[0].content == "a" * 64

    edges = {dependency.ref: dependency.depends_on for dependency in sbom.dependencies}
    assert edges == {"SPDXRef-Package-app": ["SPDXRef-Package-express"]}


# --------------------------------------------------------------------------- #
# the dispatcher's own contract
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", SERIALISATIONS)
def test_parse_is_idempotent(name: str) -> None:
    """Parsing twice must give the same model; nothing may mutate the input."""
    first = parse_sbom(DOCUMENTS[name])
    second = parse_sbom(DOCUMENTS[name])
    assert first.model_dump() == second.model_dump()


def test_read_sbom_file_matches_parse_sbom(tmp_path) -> None:
    """Reading from disk must be indistinguishable from parsing the same bytes."""
    path = tmp_path / "bom.xml"
    path.write_bytes(CDX_XML)

    assert read_sbom_file(path).model_dump() == parse_sbom(CDX_XML).model_dump()


def test_read_sbom_file_reports_a_missing_file_clearly(tmp_path) -> None:
    """A typo'd path should say so, not fall through to "cannot detect format"."""
    with pytest.raises(SbomParseError, match="(?i)read|open|exist"):
        read_sbom_file(tmp_path / "absent.json")
