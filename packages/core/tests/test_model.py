"""Tests for the Pydantic models in :mod:`sbombox_core.model`.

The models are the contract every other layer codes against, so what matters
here is not that a field exists but that the models are *forgiving on input and
strict on output*: they accept the many spellings CycloneDX and SPDX use for the
same idea, and they refuse to construct an object that cannot be reasoned about.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sbombox_core.model import (
    COMPONENT_TYPE_ALIASES,
    ComplianceResult,
    Component,
    ComponentChange,
    ComponentType,
    Dependency,
    DiffResult,
    ExternalReference,
    FixChange,
    FixResult,
    Grade,
    Hash,
    HashAlgorithm,
    License,
    LicenseChoice,
    Metadata,
    Property,
    RequirementResult,
    Sbom,
    SbomFormat,
    ScoreCategory,
    ScoreFeature,
    ScoreResult,
    Service,
    Supplier,
    Tool,
    VexJustification,
    VexStatement,
    VexStatus,
    split_name_email,
)

# --------------------------------------------------------------------------- #
# Component
# --------------------------------------------------------------------------- #

SPEC_COMPONENT_TYPES = [
    "library",
    "framework",
    "application",
    "container",
    "device",
    "firmware",
    "file",
    "operating-system",
]


@pytest.mark.parametrize("value", SPEC_COMPONENT_TYPES)
def test_the_specified_component_types_exist(value: str) -> None:
    assert ComponentType(value)


def test_a_component_defaults_to_library() -> None:
    """Most SBOM entries are libraries; making callers say so invites guessing."""
    assert Component(name="express").type is ComponentType.LIBRARY


def test_a_component_without_a_name_cannot_be_built() -> None:
    """A nameless component cannot be matched against an advisory database."""
    with pytest.raises(ValidationError):
        Component(version="1.0")  # type: ignore[call-arg]


def test_a_blank_name_is_treated_as_missing() -> None:
    with pytest.raises(ValidationError):
        Component(name="   ")


@pytest.mark.parametrize("key", ["bom-ref", "bomRef", "bom_ref"])
def test_bom_ref_accepts_every_spelling(key: str) -> None:
    assert Component(**{"name": "a", key: "ref-1"}).bom_ref == "ref-1"


@pytest.mark.parametrize(("alias", "expected"), list(COMPONENT_TYPE_ALIASES.items()))
def test_component_type_aliases_resolve(alias: str, expected: str) -> None:
    """``SPDX primaryPackagePurpose`` and CycloneDX disagree; both must land."""
    assert Component(name="a", type=alias).type.value == expected


def test_an_unknown_component_type_degrades_to_library() -> None:
    """A type SBOMBox does not model must not cost the whole component.

    Losing an entry means losing its vulnerabilities, which is far worse than
    mis-labelling it; the original document survives in :attr:`Sbom.raw_data`.
    """
    assert Component(name="a", type="spaceship").type is ComponentType.LIBRARY


@pytest.mark.parametrize(
    ("spelling", "expected"),
    [
        ("LIBRARY", ComponentType.LIBRARY),  # canonical value, wrong case
        (" Library ", ComponentType.LIBRARY),  # padded
        ("operating_system", ComponentType.OPERATING_SYSTEM),  # underscores
        ("container", ComponentType.CONTAINER),  # canonical value, lower case
    ],
)
def test_component_types_survive_case_and_separator_noise(spelling: str, expected: ComponentType) -> None:
    """The alias table above covers vocabulary; this covers sloppy spelling."""
    assert Component(name="a", type=spelling).type is expected


@pytest.mark.parametrize("key", ["externalReferences", "externalRefs", "external_references"])
def test_external_references_accept_every_spelling(key: str) -> None:
    component = Component(**{"name": "a", key: [{"type": "website", "url": "https://x.example"}]})
    assert [reference.url for reference in component.external_references] == ["https://x.example"]


def test_properties_accept_a_list_of_name_value_pairs() -> None:
    """CycloneDX uses a list of objects; the model keeps a plain mapping."""
    component = Component(name="a", properties=[{"name": "k", "value": "v"}])  # type: ignore[arg-type]
    assert component.properties == {"k": "v"}


def test_properties_accept_a_mapping() -> None:
    assert Component(name="a", properties={"k": "v"}).properties == {"k": "v"}


def test_display_name_combines_group_and_version() -> None:
    assert Component(name="log4j-core", group="org.apache.logging.log4j", version="2.17.1").display_name() == (
        "org.apache.logging.log4j/log4j-core@2.17.1"
    )


def test_display_name_degrades_without_a_group_or_version() -> None:
    assert Component(name="express").display_name() == "express"
    assert Component(name="express", version="4.18.2").display_name() == "express@4.18.2"


def test_surrounding_whitespace_is_stripped_from_text_fields() -> None:
    """Producers pad fields; padded purls silently break every downstream join."""
    component = Component(name="  express  ", version=" 4.18.2 ", purl="  pkg:npm/express@4.18.2  ")
    assert component.name == "express"
    assert component.version == "4.18.2"
    assert component.purl == "pkg:npm/express@4.18.2"


def test_a_component_can_be_rebuilt_from_its_own_dump() -> None:
    """Round-tripping is what makes the fix-and-rewrite flow possible."""
    component = Component(name="express", version="4.18.2", purl="pkg:npm/express@4.18.2", scope="required")
    assert Component.model_validate(component.model_dump()) == component


# --------------------------------------------------------------------------- #
# common: hashes, licenses, suppliers, external references
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"])
def test_the_required_hash_algorithms_exist(value: str) -> None:
    assert HashAlgorithm(value)


@pytest.mark.parametrize(("spelling", "canonical"), [("sha256", "SHA-256"), ("SHA1", "SHA-1"), ("md5", "MD5")])
def test_hash_algorithms_are_canonicalised(spelling: str, canonical: str) -> None:
    """SPDX writes ``SHA256``, CycloneDX writes ``SHA-256``."""
    assert Hash(alg=spelling, content="a" * 64).alg.value == canonical


def test_an_unknown_hash_algorithm_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Hash(alg="ROT-13", content="abc")


@pytest.mark.parametrize("key", ["content", "value", "checksumValue", "hashValue"])
def test_hash_content_accepts_every_spelling(key: str) -> None:
    assert Hash(**{"alg": "SHA-256", key: "a" * 64}).content == "a" * 64


def test_a_license_takes_an_id_or_a_name() -> None:
    """``id`` wins when both are present, per the SPDX/CycloneDX convention."""
    assert License(id="MIT").id == "MIT"
    assert License(name="Acme EULA").name == "Acme EULA"
    both = License(id="MIT", name="MIT License")
    assert both.id == "MIT"
    assert both.name == "MIT License"


def test_a_license_with_neither_id_nor_name_is_still_accepted() -> None:
    """Producers do emit empty license records; the model keeps them shapeless.

    Rejecting them here would fail the enclosing component and lose an
    inventory entry over a missing license, so the gap is reported by
    :func:`sbombox_core.validate.validate_semantic` instead.
    """
    empty = License()
    assert empty.id is None
    assert empty.name is None


def test_a_license_choice_wraps_a_bare_license() -> None:
    """``{"id": "MIT"}`` and ``{"license": {"id": "MIT"}}`` mean the same thing."""
    wrapped = LicenseChoice.model_validate({"license": {"id": "MIT"}})
    bare = LicenseChoice.model_validate({"id": "MIT"})

    assert wrapped.license is not None
    assert wrapped.license.id == "MIT"
    assert bare.license is not None
    assert bare.license.id == "MIT"


def test_a_license_choice_can_hold_an_expression_instead() -> None:
    choice = LicenseChoice(expression="MIT OR Apache-2.0")
    assert choice.expression == "MIT OR Apache-2.0"
    assert choice.license is None


def test_license_text_is_unwrapped_from_its_content_envelope() -> None:
    choice = LicenseChoice.model_validate({"license": {"id": "MIT", "text": {"content": "Permission is..."}}})
    assert choice.license is not None
    assert choice.license.text == "Permission is..."


def test_a_supplier_keeps_every_url_it_is_given() -> None:
    """CycloneDX allows several URLs and dropping one would lose provenance."""
    supplier = Supplier.model_validate({"name": "Acme", "url": ["https://a.example", "https://b.example"]})
    assert supplier.name == "Acme"
    assert supplier.url == ["https://a.example", "https://b.example"]


def test_a_single_supplier_url_is_wrapped_in_a_list() -> None:
    """XML collapses a one-element list into a scalar, so both shapes arrive."""
    assert Supplier.model_validate({"name": "Acme", "url": "https://a.example"}).url == ["https://a.example"]
    assert Supplier(name="Acme").url == []


def test_an_external_reference_accepts_the_spdx_spellings() -> None:
    reference = ExternalReference.model_validate(
        {"referenceType": "purl", "referenceLocator": "pkg:npm/express@4.18.2"}
    )
    assert reference.type == "purl"
    assert reference.url == "pkg:npm/express@4.18.2"


def test_a_property_is_a_name_value_pair() -> None:
    assert Property(name="k", value="v").model_dump() == {"name": "k", "value": "v"}


# --------------------------------------------------------------------------- #
# metadata
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Jane Doe <jane@example.com>", {"name": "Jane Doe", "email": "jane@example.com"}),
        ("Person: Jane Doe (jane@example.com)", {"name": "Jane Doe", "email": "jane@example.com"}),
        ("Organization: Acme Inc", {"name": "Acme Inc", "email": None}),
        ("jane@example.com", {"name": "jane@example.com", "email": None}),
        ("", {"name": None, "email": None}),
    ],
)
def test_split_name_email_handles_both_conventions(raw: str, expected: dict[str, str | None]) -> None:
    assert split_name_email(raw) == expected


def test_metadata_defaults_to_an_empty_but_valid_document() -> None:
    metadata = Metadata()
    assert metadata.timestamp is None
    assert metadata.tools == []
    assert metadata.component is None


def test_a_tool_keeps_its_vendor_and_hashes() -> None:
    tool = Tool(vendor="anchore", name="syft", version="1.4.1", hashes=[{"alg": "SHA-256", "content": "a" * 64}])
    assert tool.vendor == "anchore"
    assert tool.hashes[0].alg is HashAlgorithm.SHA256


def test_metadata_accepts_the_cyclonedx_tools_object_shape() -> None:
    """1.5 moved ``metadata.tools`` from an array to ``{components: [...]}``."""
    metadata = Metadata.model_validate({"tools": {"components": [{"name": "syft", "version": "1.4.1"}]}})
    assert [(tool.name, tool.version) for tool in metadata.tools] == [("syft", "1.4.1")]


def test_metadata_accepts_the_legacy_tools_array_shape() -> None:
    metadata = Metadata.model_validate({"tools": [{"vendor": "anchore", "name": "syft", "version": "0.90.0"}]})
    assert metadata.tools[0].vendor == "anchore"


# --------------------------------------------------------------------------- #
# dependencies, services, vex
# --------------------------------------------------------------------------- #


def test_a_dependency_accepts_camel_case() -> None:
    dependency = Dependency.model_validate({"ref": "a", "dependsOn": ["b", "c"]})
    assert dependency.depends_on == ["b", "c"]
    assert not dependency.is_leaf


def test_a_dependency_accepts_a_single_string() -> None:
    """Some producers emit a scalar where the spec requires an array."""
    assert Dependency.model_validate({"ref": "a", "dependsOn": "b"}).depends_on == ["b"]


def test_a_leaf_dependency_reports_itself() -> None:
    dependency = Dependency(ref="a")
    assert dependency.is_leaf
    assert dependency.refs() == ["a"]


def test_a_service_keeps_its_trust_boundary_flag() -> None:
    service = Service.model_validate(
        {"bom-ref": "svc", "name": "api", "endpoints": ["https://x"], "x-trust-boundary": True}
    )
    assert service.x_trust_boundary is True
    assert service.endpoints == ["https://x"]


def test_vex_status_uses_the_four_canonical_values() -> None:
    assert {status.value for status in VexStatus} == {"not_affected", "affected", "fixed", "under_investigation"}


def test_a_vex_statement_accepts_an_openvex_status_spelling() -> None:
    statement = VexStatement.model_validate({"vulnerability_id": "CVE-1", "status": "not_affected"})
    assert statement.status is VexStatus.NOT_AFFECTED


def test_an_unknown_vex_status_is_rejected() -> None:
    with pytest.raises(ValidationError):
        VexStatement.model_validate({"vulnerability_id": "CVE-1", "status": "maybe_affected"})


def test_a_vex_justification_is_drawn_from_the_openvex_vocabulary() -> None:
    assert VexJustification("component_not_present")


# --------------------------------------------------------------------------- #
# Sbom
# --------------------------------------------------------------------------- #


def make_sbom(**overrides) -> Sbom:
    payload = {
        "format": SbomFormat.CYCLONEDX,
        "spec_version": "1.6",
        "metadata": Metadata(),
        "components": [Component(name="express", version="4.18.2", purl="pkg:npm/express@4.18.2", bom_ref="e")],
        "dependencies": [Dependency(ref="e", depends_on=["r"])],
    }
    payload.update(overrides)
    return Sbom(**payload)


def test_an_sbom_needs_a_format_version_metadata_and_inventory() -> None:
    with pytest.raises(ValidationError):
        Sbom()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("raw_format", "expected"),
    [
        ("cyclonedx", SbomFormat.CYCLONEDX),
        ("CycloneDX", SbomFormat.CYCLONEDX),
        ("spdx", SbomFormat.SPDX),
        ("SPDX-2.3", SbomFormat.SPDX),
        (SbomFormat.CYCLONEDX, SbomFormat.CYCLONEDX),
    ],
)
def test_the_format_is_normalised(raw_format: str, expected: SbomFormat) -> None:
    assert make_sbom(format=raw_format).format is expected


@pytest.mark.parametrize(
    ("raw_version", "expected"),
    [("SPDX-2.3", "2.3"), ("spdx-2.2", "2.2"), ("CycloneDX 1.6", "1.6"), ("1.6", "1.6"), ("3.0.1", "3.0.1")],
)
def test_the_spec_version_loses_its_format_prefix(raw_version: str, expected: str) -> None:
    """The format is already a field; repeating it in the version is noise."""
    assert make_sbom(spec_version=raw_version).spec_version == expected


def test_optional_sections_default_to_empty() -> None:
    sbom = make_sbom()
    assert sbom.vulnerabilities == []
    assert sbom.services == []
    assert sbom.external_references == []
    assert sbom.raw_data is None


def test_field_names_can_be_given_in_either_convention() -> None:
    """``populate_by_name`` means the model's own names work alongside the aliases."""
    sbom = Sbom.model_validate(
        {
            "format": "spdx",
            "spec_version": "2.3",
            "metadata": {},
            "components": [],
            "dependencies": [],
            "external_references": [{"type": "vcs", "url": "https://x"}],
        }
    )
    assert sbom.external_references[0].type == "vcs"

    camel = Sbom.model_validate(
        {
            "format": "spdx",
            "specVersion": "2.3",
            "metadata": {},
            "components": [],
            "dependencies": [],
            "externalReferences": [{"type": "vcs", "url": "https://x"}],
        }
    )
    assert camel.external_references[0].type == "vcs"


def test_iter_components_includes_the_described_component() -> None:
    """The subject of the document is a component too, and is usually the app."""
    sbom = make_sbom(metadata=Metadata(component=Component(name="acme-app", bom_ref="app")))
    assert [component.name for component in sbom.iter_components()] == ["acme-app", "express"]


def test_refs_collects_component_service_and_vulnerability_refs() -> None:
    from sbombox_core.model import Vulnerability

    sbom = make_sbom(
        metadata=Metadata(component=Component(name="app", bom_ref="app")),
        services=[Service(name="api", bom_ref="svc")],
        vulnerabilities=[Vulnerability(id="CVE-1", bom_ref="v1")],
    )
    assert sbom.refs == {"app", "e", "svc", "v1"}


def test_component_by_ref_finds_the_described_component() -> None:
    sbom = make_sbom(metadata=Metadata(component=Component(name="app", bom_ref="app")))
    assert sbom.component_by_ref("app") is not None
    assert sbom.component_by_ref("app").name == "app"
    assert sbom.component_by_ref("nope") is None


def test_components_by_purl_groups_case_insensitively() -> None:
    sbom = make_sbom(
        components=[
            Component(name="a", purl="pkg:npm/express@4.18.2"),
            Component(name="b", purl="PKG:NPM/EXPRESS@4.18.2"),
            Component(name="c"),
        ]
    )
    grouped = sbom.components_by_purl()
    assert list(grouped) == ["pkg:npm/express@4.18.2"]
    assert [component.name for component in grouped["pkg:npm/express@4.18.2"]] == ["a", "b"]


def test_the_dependency_graph_merges_repeated_refs() -> None:
    """SPDX often states one edge in two places; the graph must not double it."""
    sbom = make_sbom(
        dependencies=[
            Dependency(ref="a", depends_on=["b"]),
            Dependency(ref="a", depends_on=["b", "c"]),
        ]
    )
    assert sbom.dependency_graph() == {"a": ["b", "c"]}


def test_summary_counts_only_what_it_claims_to() -> None:
    sbom = make_sbom()
    summary = sbom.summary()

    assert summary["format"] == "cyclonedx"
    assert summary["spec_version"] == "1.6"
    assert summary["components"] == 1
    assert summary["dependencies"] == 1
    assert summary["with_purl"] == 1
    assert summary["with_version"] == 1
    assert summary["with_license"] == 0


def test_a_malformed_component_is_dropped_and_counted() -> None:
    """The salvage path is what lets one bad record survive a 400-package SBOM."""
    sbom = Sbom.model_validate(
        {
            "format": "cyclonedx",
            "spec_version": "1.6",
            "metadata": {},
            "components": [
                {"name": "good", "version": "1"},
                {"version": "2"},
                {"name": "also-good"},
            ],
            "dependencies": [],
        }
    )
    assert [component.name for component in sbom.components] == ["good", "also-good"]
    assert sbom.dropped_components == 1
    assert sbom.dropped_entries == {"components": 1}


def test_drop_counts_are_not_serialised_into_the_document() -> None:
    """They are a diagnostic about the load, not content of the SBOM."""
    sbom = Sbom.model_validate(
        {
            "format": "cyclonedx",
            "spec_version": "1.6",
            "metadata": {},
            "components": [{"version": "2"}],
            "dependencies": [],
        }
    )
    assert "dropped_entries" not in sbom.model_dump()
    assert sbom.dropped_components == 1


def test_a_malformed_service_or_vulnerability_is_dropped_too() -> None:
    sbom = Sbom.model_validate(
        {
            "format": "cyclonedx",
            "spec_version": "1.6",
            "metadata": {},
            "components": [],
            "dependencies": [],
            "services": [{"name": "api"}, "not-a-service"],
            "vulnerabilities": [{"id": "CVE-1"}, {"description": "no id but still modelled"}],
        }
    )
    assert sbom.dropped_entries.get("services") == 1
    assert [service.name for service in sbom.services] == ["api"]


def test_raw_data_is_preserved_verbatim() -> None:
    """Round-tripping needs the original document, not a reconstruction."""
    original = {"bomFormat": "CycloneDX", "specVersion": "1.6", "unknownField": {"kept": True}}
    sbom = Sbom(
        format=SbomFormat.CYCLONEDX,
        spec_version="1.6",
        metadata=Metadata(),
        components=[],
        dependencies=[],
        raw_data=original,
    )
    assert sbom.raw_data == original


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #


def test_grade_covers_the_five_letter_bands() -> None:
    assert [grade.value for grade in Grade] == ["A", "B", "C", "D", "F"]


def test_a_score_category_applies_its_weight() -> None:
    category = ScoreCategory(name="inventory", score=8.0, weight=0.5)
    assert category.weighted_score == 4.0


def test_a_score_feature_records_its_ratio() -> None:
    feature = ScoreFeature(name="purls", score=5.0, numerator=10, denominator=20, description="half")
    assert (feature.numerator, feature.denominator) == (10, 20)


def test_a_score_result_stamps_its_own_run() -> None:
    result = ScoreResult(total=8.5, grade=Grade.A, run_id="run-1", profile="default")
    assert result.timestamp.tzinfo is not None
    assert result.timestamp <= datetime.now(UTC)
    assert result.categories == []


def test_a_requirement_result_defaults_to_a_required_failure() -> None:
    """Defaulting to "pass" would let a missing check read as a clean bill."""
    requirement = RequirementResult(id="R1", title="Components have versions")
    assert requirement.level == "required"
    assert requirement.status == "fail"
    assert requirement.affected == 0


def test_a_requirement_result_rejects_an_unknown_status() -> None:
    with pytest.raises(ValidationError):
        RequirementResult(id="R1", title="t", status="mostly-fine")  # type: ignore[arg-type]


def test_a_compliance_result_defaults_to_does_not_conform() -> None:
    result = ComplianceResult(profile="sbombox-basic", run_id="run-1")
    assert result.status == "does_not_conform"
    assert result.overall == 0.0


def test_a_compliance_result_rejects_an_unknown_conformance_status() -> None:
    with pytest.raises(ValidationError):
        ComplianceResult(profile="p", run_id="r", status="conforms-ish")  # type: ignore[arg-type]


def test_a_diff_result_groups_added_removed_and_changed() -> None:
    component = Component(name="express", version="4.18.2")
    diff = DiffResult(
        added=[component],
        removed=[Component(name="left-pad", version="1.3.0")],
        changed=[
            ComponentChange(
                component=component,
                fields_changed=["version"],
                old_values={"version": "4.18.1"},
                new_values={"version": "4.18.2"},
            )
        ],
        dependency_added=["pkg:npm/express@4.18.2"],
        dependency_removed=["pkg:npm/left-pad@1.3.0"],
    )
    assert diff.changed[0].fields_changed == ["version"]
    assert diff.changed[0].old_values == {"version": "4.18.1"}


def test_a_fix_result_carries_the_repaired_document() -> None:
    sbom = make_sbom()
    result = FixResult(sbom=sbom, changes=[FixChange(rule="require-version", description="added", affected_count=3)])

    assert result.sbom is sbom
    assert result.changes[0].affected_count == 3


def test_results_survive_a_json_round_trip() -> None:
    """These are the payloads the API returns; they must serialise cleanly."""
    result = ScoreResult(total=7.0, grade=Grade.B, run_id="run-1", profile="default")
    restored = ScoreResult.model_validate_json(result.model_dump_json())
    assert restored.grade is Grade.B
    assert restored.run_id == "run-1"
