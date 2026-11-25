"""Structural (schema-level) validation of raw SBOM documents.

The official CycloneDX and SPDX JSON Schemas are large, versioned separately and
licensed for redistribution rather than embedding, so this module implements the
checks that matter operationally: the required top-level fields, the array/object
shapes the parsers depend on, and the cross-references that make a document
internally consistent.  Where a vendored schema is added later it can slot in
behind the same function signatures.

Validation runs *before* parsing on purpose.  A parser is deliberately forgiving
- it drops what it cannot model so one bad record cannot sink a document - which
means parsing alone cannot tell you that a producer is broken.  These checks can.

The division of labour with :mod:`.semantic` is strict: this module checks
*shape* - is the field present, is it the right type, is the value drawn from
the specification's vocabulary - and leaves everything else to the semantic
layer, which has the parsed model and produces the better message.  That
includes cross-references: a dangling ``dependsOn`` is reported once, there.
Overlapping the two would report every flaw twice, at two paths that look
identical but index different things.
"""

from __future__ import annotations

import json
import re
from io import StringIO
from typing import Any

from ruamel.yaml import YAML

from sbombox_core.model.sbom import SbomFormat
from sbombox_core.parse.cyclonedx import cyclonedx_xml_to_dict
from sbombox_core.parse.sniff import (
    ContainerKind,
    detect_container,
    detect_format,
    normalize_spec_version,
    parse_xml_root,
    to_text,
)
from sbombox_core.parse.spdx import (
    external_ref_category,
    external_ref_locator,
    external_ref_type,
    normalize_relationship_type,
    spdx_document_to_dict,
    spdx_rdf_to_dict,
    spdx_tag_value_to_dict,
)
from sbombox_core.validate.semantic import ValidationIssue, ValidationSeverity

__all__ = [
    "ValidationError",
    "validate_cyclonedx_schema",
    "validate_schema",
    "validate_spdx_schema",
]

#: Structural findings use the same issue type as semantic ones so the two lists
#: can be merged by :func:`sbombox_core.validate.validate_document` unchanged.
ValidationError = ValidationIssue

_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_SERIAL = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_SPDX_VERSION = re.compile(r"^SPDX-\d+\.\d+(?:\.\d+)?$", re.IGNORECASE)
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_CREATOR_PREFIX = re.compile(r"^(Person|Organization|Tool)\s*:", re.IGNORECASE)

#: CycloneDX component types accepted without a warning.
_CYCLONEDX_TYPES = frozenset(
    {
        "application",
        "container",
        "cryptographic-asset",
        "data",
        "device",
        "device-model",
        "file",
        "firmware",
        "framework",
        "library",
        "machine-learning-model",
        "operating-system",
        "platform",
    }
)

#: SPDX relationship types SBOMBox recognises.  Anything else still parses; it is
#: reported because it usually means a producer misspelled the value.
_SPDX_RELATIONSHIPS = frozenset(
    {
        "AMENDS",
        "ANCESTOR_OF",
        "BUILD_DEPENDENCY_OF",
        "BUILD_TOOL_OF",
        "CONTAINED_BY",
        "CONTAINS",
        "COPY_OF",
        "DATA_FILE_OF",
        "DEPENDENCY_MANIFEST_OF",
        "DEPENDENCY_OF",
        "DEPENDS_ON",
        "DESCENDANT_OF",
        "DESCRIBED_BY",
        "DESCRIBES",
        "DOCUMENTATION_OF",
        "DYNAMIC_LINK",
        "EXAMPLE_OF",
        "EXPANDED_FROM_ARCHIVE",
        "FILE_ADDED",
        "FILE_DELETED",
        "FILE_MODIFIED",
        "GENERATED_FROM",
        "GENERATES",
        "HAS_PREREQUISITE",
        "METAFILE_OF",
        "NOASSERTION",
        "OPTIONAL_COMPONENT_OF",
        "OTHER",
        "PACKAGE_OF",
        "PATCH_APPLIED",
        "PATCH_FOR",
        "PREREQUISITE_FOR",
        "PROVIDED_DEPENDENCY_OF",
        "REQUIREMENT_DESCRIPTION_FOR",
        "SPECIFICATION_FOR",
        "STATIC_LINK",
        "TEST_CASE_OF",
        "TEST_DATA_OF",
        "TEST_DEPENDENCY_OF",
        "TEST_OF",
        "TEST_TOOL_OF",
        "VARIANT_OF",
    }
)

_SPDX_PLACEHOLDERS = frozenset({"NOASSERTION", "NONE"})


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #


def validate_schema(
    data: dict[str, Any] | bytes | str,
    fmt: SbomFormat | str | None = None,
    version: str = "",
) -> list[ValidationIssue]:
    """Validate a raw document, dispatching on its detected format.

    Args:
        data: A decoded document, or the raw bytes/text of one.
        fmt: Optional format override; detected from *data* when omitted.
        version: Expected spec version, e.g. ``"1.6"`` or ``"2.3"``.

    Returns:
        Every structural finding, possibly empty.
    """
    resolved, reason = _resolve_format(data, fmt)
    if resolved is SbomFormat.CYCLONEDX:
        return validate_cyclonedx_schema(data, version)
    if resolved is SbomFormat.SPDX:
        return validate_spdx_schema(data, version)

    reporter = _Reporter()
    reporter.error(f"The document is not a recognisable CycloneDX or SPDX SBOM: {reason}")
    return reporter.result()


def validate_cyclonedx_schema(data: dict[str, Any] | bytes | str, version: str = "") -> list[ValidationIssue]:
    """Structurally validate a CycloneDX document.

    Args:
        data: A decoded JSON document, or raw JSON/XML/YAML content.
        version: Expected spec version (``"1.4"`` .. ``"1.7"``); compared with
            the document's own ``specVersion`` when given.
    """
    reporter = _Reporter()
    document = _decode(data, SbomFormat.CYCLONEDX, reporter)
    if document is None:
        return reporter.result()

    _cyclonedx_header(document, version, reporter)
    metadata = _expect_object(document.get("metadata"), "metadata", reporter, required=False)
    if metadata is not None:
        _cyclonedx_metadata(metadata, reporter)

    _cyclonedx_components(document, reporter)
    _cyclonedx_services(document, reporter)
    _cyclonedx_dependencies(document, reporter)
    _cyclonedx_vulnerabilities(document, reporter)
    _cyclonedx_external_references(document.get("externalReferences"), "externalReferences", reporter)

    return reporter.result()


def validate_spdx_schema(data: dict[str, Any] | bytes | str, version: str = "") -> list[ValidationIssue]:
    """Structurally validate an SPDX document (2.x or 3.0).

    3.0 JSON-LD element graphs are normalised to the 2.x shape first, so the
    checks below describe one field vocabulary.

    Args:
        data: A decoded JSON document, or raw JSON/RDF-XML/tag-value content.
        version: Expected spec version (``"2.2"``, ``"2.3"`` or ``"3.0"``).
    """
    reporter = _Reporter()
    document = _decode(data, SbomFormat.SPDX, reporter)
    if document is None:
        return reporter.result()

    _spdx_header(document, version, reporter)
    _spdx_creation_info(document, reporter)
    _spdx_packages(document, reporter)
    _spdx_files(document, reporter)
    _spdx_relationships(document, reporter)
    _spdx_extracted_licenses(document, reporter)

    return reporter.result()


# --------------------------------------------------------------------------- #
# reporter
# --------------------------------------------------------------------------- #


class _Reporter:
    """Accumulates findings; schema validation never short-circuits."""

    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    def error(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=message,
                path=path,
                component_ref=component_ref,
            )
        )

    def warning(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message=message,
                path=path,
                component_ref=component_ref,
            )
        )

    def info(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.issues.append(
            ValidationIssue(
                severity=ValidationSeverity.INFO,
                message=message,
                path=path,
                component_ref=component_ref,
            )
        )

    def result(self) -> list[ValidationIssue]:
        return list(self.issues)


# --------------------------------------------------------------------------- #
# decoding and shared shape checks
# --------------------------------------------------------------------------- #


def _resolve_format(
    data: dict[str, Any] | bytes | str, fmt: SbomFormat | str | None
) -> tuple[SbomFormat | None, str]:
    """Return the format to validate against, plus why detection failed.

    The reason is only used for the error message when no format could be
    established, but it is the difference between "not an SBOM" and "an SBOM
    whose JSON is truncated" - which is what the user actually needs to know.
    """
    if isinstance(fmt, SbomFormat):
        return fmt, ""
    if isinstance(fmt, str) and fmt.strip():
        text = fmt.strip().lower()
        if text.startswith("cyclonedx") or text == "cdx":
            return SbomFormat.CYCLONEDX, ""
        if text.startswith("spdx"):
            return SbomFormat.SPDX, ""
        return None, f"{fmt!r} is not a known SBOM format"
    if isinstance(data, dict):
        return _resolve_mapping_format(data)
    try:
        detected, _ = detect_format(data)
    except ValueError as exc:
        return None, str(exc)
    return detected, ""


def _resolve_mapping_format(data: dict[str, Any]) -> tuple[SbomFormat | None, str]:
    """Identify an already-decoded document by the keys only one format uses.

    :func:`~sbombox_core.parse.sniff.detect_format` reads text, and a mapping has
    none - handing it over would reach ``bytes.decode`` and raise ``AttributeError``
    instead of reporting "not an SBOM".  The keys checked here are the same ones
    the text sniffer looks for.
    """
    if "bomFormat" in data or "specVersion" in data:
        return SbomFormat.CYCLONEDX, ""
    if "spdxVersion" in data or "SPDXID" in data or "@graph" in data or "@context" in data:
        return SbomFormat.SPDX, ""
    return None, "the document object carries neither a 'bomFormat' nor an 'spdxVersion' key"


def _decode(data: dict[str, Any] | bytes | str, fmt: SbomFormat, reporter: _Reporter) -> dict[str, Any] | None:
    """Return *data* as a mapping, reporting why it could not be decoded."""
    if isinstance(data, dict):
        return data
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    elif isinstance(data, str):
        raw = data.encode()
    else:
        reporter.error(f"Expected a document object or raw content, got {_type_name(data)}")
        return None

    if not raw.strip():
        reporter.error("The document is empty")
        return None
    try:
        return _decode_content(raw, fmt)
    except ValueError as exc:  # covers JSONDecodeError and SbomParseError
        reporter.error(f"The document could not be decoded: {exc}")
        return None


def _decode_content(raw: bytes, fmt: SbomFormat) -> dict[str, Any] | None:
    text = to_text(raw)
    kind = detect_container(text)

    if kind is ContainerKind.TAG_VALUE:
        return spdx_tag_value_to_dict(text)

    if kind is ContainerKind.XML:
        root = parse_xml_root(raw)
        localname = root.tag.rpartition("}")[2].lower() if isinstance(root.tag, str) else ""
        return cyclonedx_xml_to_dict(root) if localname == "bom" else spdx_rdf_to_dict(root)

    decoded = _decode_json_or_yaml(text)
    if isinstance(decoded, list):
        # SPDX 3.0 is occasionally published as a bare element array.
        decoded = {"@graph": decoded}
    if isinstance(decoded, dict) and fmt is SbomFormat.SPDX:
        return spdx_document_to_dict(decoded)
    return decoded if isinstance(decoded, dict) else None


def _decode_json_or_yaml(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    yaml = YAML(typ="safe")
    try:
        return yaml.load(StringIO(text))
    except Exception as exc:  # noqa: BLE001 - ruamel raises its own hierarchy
        raise ValueError(f"content is neither valid JSON nor YAML: {exc}") from exc


def _expect_object(
    value: Any,
    path: str,
    reporter: _Reporter,
    *,
    required: bool = True,
) -> dict[str, Any] | None:
    """Return *value* when it is a mapping, reporting a finding otherwise."""
    if isinstance(value, dict):
        return value
    if value is None:
        if required:
            reporter.error(f"Required object {path!r} is missing", path=path)
        return None
    if isinstance(value, (str, bytes)) and not _text(value):
        if required:
            reporter.error(f"Required object {path!r} is missing", path=path)
        return None
    reporter.error(f"{path} must be an object, got {_type_name(value)}", path=path)
    return None


def _expect_array(
    value: Any,
    path: str,
    reporter: _Reporter,
    *,
    required: bool = True,
) -> list[Any]:
    """Return *value* when it is a list, reporting a finding otherwise."""
    if isinstance(value, list):
        return value
    if value is None:
        if required:
            reporter.error(f"Required array {path!r} is missing", path=path)
        return []
    reporter.error(f"{path} must be an array, got {_type_name(value)}", path=path)
    return []


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return ""


def _type_name(value: Any) -> str:
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if value is None:
        return "null"
    return type(value).__name__


def _positive_int(value: Any) -> int | None:
    """Return *value* as a positive integer, accepting the string form.

    XML and tag-value serialisations have no number type, so a revision of
    ``1`` arrives as ``"1"``; rejecting it would fail every XML SBOM.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 1 else None
    if isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
        return number if number >= 1 else None
    return None


def _require_string(
    container: dict[str, Any],
    key: str,
    path: str | None,
    reporter: _Reporter,
    *,
    required: bool = True,
    allow_placeholder: bool = True,
) -> str | None:
    """Return a non-empty string field, reporting when it is absent or mistyped."""
    value = container.get(key)
    field_path = f"{path}.{key}" if path else key

    if value is None:
        if required:
            reporter.error(f"Required field {field_path!r} is missing", path=field_path)
        return None
    if not isinstance(value, str):
        reporter.error(f"{field_path} must be a string, got {_type_name(value)}", path=field_path)
        return None

    text = value.strip()
    if not text:
        if required:
            reporter.error(f"Field {field_path!r} is empty", path=field_path)
        return None
    if not allow_placeholder and text.upper() in _SPDX_PLACEHOLDERS:
        reporter.warning(f"{field_path} is set to the placeholder {text!r}", path=field_path)
        return None
    return text


# --------------------------------------------------------------------------- #
# CycloneDX
# --------------------------------------------------------------------------- #


def _cyclonedx_header(document: dict[str, Any], version: str, reporter: _Reporter) -> None:
    """Validate ``bomFormat``, ``specVersion``, ``version`` and ``serialNumber``."""
    bom_format = document.get("bomFormat")
    if bom_format is None:
        reporter.error("Required field 'bomFormat' is missing", path="bomFormat")
    elif _text(bom_format).lower() != "cyclonedx":
        reporter.error(f"bomFormat must be 'CycloneDX', got {bom_format!r}", path="bomFormat")

    spec_version = _text(document.get("specVersion"))
    if not spec_version:
        reporter.error("Required field 'specVersion' is missing", path="specVersion")
    elif not _VERSION.match(spec_version):
        reporter.error(f"specVersion {spec_version!r} is not a 'major.minor' version", path="specVersion")
    elif version and normalize_spec_version(version) != normalize_spec_version(spec_version):
        reporter.error(
            f"specVersion is {spec_version!r} but {normalize_spec_version(version)!r} was expected",
            path="specVersion",
        )

    revision = document.get("version")
    if revision is None:
        reporter.warning("The BOM revision number 'version' is missing", path="version")
    elif _positive_int(revision) is None:
        reporter.error(f"BOM revision 'version' must be a positive integer, got {revision!r}", path="version")

    serial = _text(document.get("serialNumber"))
    if serial and not _SERIAL.match(serial):
        reporter.warning(f"serialNumber {serial!r} is not a URN UUID", path="serialNumber")


def _cyclonedx_metadata(metadata: dict, reporter: _Reporter) -> None:
    """Validate the ``metadata`` object."""
    timestamp = metadata.get("timestamp")
    if timestamp is None:
        reporter.warning("metadata.timestamp is missing", path="metadata.timestamp")
    elif not isinstance(timestamp, str) or not _TIMESTAMP.match(timestamp.strip()):
        reporter.warning(
            f"metadata.timestamp {timestamp!r} is not an ISO-8601 date-time",
            path="metadata.timestamp",
        )

    tools = metadata.get("tools")
    if tools is not None and not isinstance(tools, (dict, list)):
        reporter.error(f"metadata.tools must be an array or object, got {_type_name(tools)}", path="metadata.tools")

    component = metadata.get("component")
    if component is not None:
        if not isinstance(component, dict):
            reporter.error(
                f"metadata.component must be an object, got {_type_name(component)}",
                path="metadata.component",
            )
        elif not _text(component.get("name")):
            reporter.error("metadata.component has no name", path="metadata.component.name")


def _cyclonedx_components(document: dict[str, Any], reporter: _Reporter) -> None:
    """Validate the ``components`` array."""
    if "components" not in document:
        reporter.warning("The document declares no components", path="components")
        return

    entries = _expect_array(document.get("components"), "components", reporter)
    refs: set[str] = set()

    for index, entry in enumerate(entries):
        path = f"components[{index}]"
        component = _expect_object(entry, path, reporter)
        if component is None:
            continue

        name = _text(component.get("name"))
        if not name:
            reporter.error("Component has no name", path=f"{path}.name")

        component_type = component.get("type")
        if component_type is None:
            reporter.warning(f"Component {name!r} has no type", path=f"{path}.type")
        elif _text(component_type) not in _CYCLONEDX_TYPES:
            reporter.warning(
                f"Component {name!r} has an unknown type {component_type!r}",
                path=f"{path}.type",
            )

        version = component.get("version")
        if version is not None and not isinstance(version, str):
            reporter.error(
                f"Component {name!r} version must be a string, got {_type_name(version)}",
                path=f"{path}.version",
            )

        bom_ref = _text(component.get("bom-ref"))
        if bom_ref:
            if bom_ref in refs:
                reporter.error(f"Duplicate bom-ref {bom_ref!r}", path=f"{path}.bom-ref", component_ref=bom_ref)
            refs.add(bom_ref)

        _cyclonedx_hashes(component.get("hashes"), f"{path}.hashes", reporter)
        _cyclonedx_licenses(component.get("licenses"), f"{path}.licenses", reporter)
        _cyclonedx_properties(component.get("properties"), f"{path}.properties", reporter)
        _cyclonedx_external_references(component.get("externalReferences"), f"{path}.externalReferences", reporter)


def _cyclonedx_hashes(value: Any, path: str, reporter: _Reporter) -> None:
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        digest = _expect_object(entry, f"{path}[{index}]", reporter)
        if digest is None:
            continue
        if not _text(digest.get("alg")):
            reporter.error("Hash has no algorithm", path=f"{path}[{index}].alg")
        if not _text(digest.get("content")):
            reporter.error("Hash has no digest value", path=f"{path}[{index}].content")


def _cyclonedx_licenses(value: Any, path: str, reporter: _Reporter) -> None:
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        choice = _expect_object(entry, f"{path}[{index}]", reporter)
        if choice is None:
            continue
        if "license" not in choice and "expression" not in choice:
            reporter.warning(
                "License entry has neither a 'license' object nor an 'expression'",
                path=f"{path}[{index}]",
            )


def _cyclonedx_properties(value: Any, path: str, reporter: _Reporter) -> None:
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        prop = _expect_object(entry, f"{path}[{index}]", reporter)
        if prop is not None and not _text(prop.get("name")):
            reporter.error("Property has no name", path=f"{path}[{index}].name")


def _cyclonedx_external_references(value: Any, path: str, reporter: _Reporter) -> None:
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        reference = _expect_object(entry, f"{path}[{index}]", reporter)
        if reference is None:
            continue
        if not _text(reference.get("type")):
            reporter.error("External reference has no type", path=f"{path}[{index}].type")
        if not _text(reference.get("url")):
            reporter.error("External reference has no url", path=f"{path}[{index}].url")


def _cyclonedx_services(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(document.get("services"), "services", reporter, required=False)
    for index, entry in enumerate(entries):
        path = f"services[{index}]"
        service = _expect_object(entry, path, reporter)
        if service is None:
            continue
        if not _text(service.get("name")):
            reporter.error("Service has no name", path=f"{path}.name")


def _cyclonedx_dependencies(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(document.get("dependencies"), "dependencies", reporter, required=False)
    for index, entry in enumerate(entries):
        path = f"dependencies[{index}]"
        dependency = _expect_object(entry, path, reporter)
        if dependency is None:
            continue

        if not _text(dependency.get("ref")):
            reporter.error("Dependency has no ref", path=f"{path}.ref")

        depends_on = _expect_array(dependency.get("dependsOn"), f"{path}.dependsOn", reporter, required=False)
        for position, target in enumerate(depends_on):
            if not _text(target):
                reporter.error(
                    f"dependsOn[{position}] must be a non-empty string, got {_type_name(target)}",
                    path=f"{path}.dependsOn[{position}]",
                )


def _cyclonedx_vulnerabilities(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(document.get("vulnerabilities"), "vulnerabilities", reporter, required=False)
    for index, entry in enumerate(entries):
        path = f"vulnerabilities[{index}]"
        vulnerability = _expect_object(entry, path, reporter)
        if vulnerability is None:
            continue
        if not _text(vulnerability.get("id")) and not _text(vulnerability.get("bom-ref")):
            reporter.warning("Vulnerability has neither an id nor a bom-ref", path=path)

        for position, target in enumerate(
            _expect_array(vulnerability.get("affects"), f"{path}.affects", reporter, required=False)
        ):
            affected = _expect_object(target, f"{path}.affects[{position}]", reporter)
            if affected is None:
                continue
            if not _text(affected.get("ref")):
                reporter.error("Affected target has no ref", path=f"{path}.affects[{position}].ref")


# --------------------------------------------------------------------------- #
# SPDX
# --------------------------------------------------------------------------- #


def _spdx_header(document: dict[str, Any], version: str, reporter: _Reporter) -> None:
    """Validate the document-level fields."""
    spec_version = _text(document.get("spdxVersion"))
    if not spec_version:
        reporter.error("Required field 'spdxVersion' is missing", path="spdxVersion")
    elif not _SPDX_VERSION.match(spec_version):
        reporter.error(
            f"spdxVersion {spec_version!r} must look like 'SPDX-2.3'",
            path="spdxVersion",
        )
    elif version and normalize_spec_version(version) != normalize_spec_version(spec_version):
        reporter.error(
            f"spdxVersion is {spec_version!r} but {normalize_spec_version(version)!r} was expected",
            path="spdxVersion",
        )

    document_id = _text(document.get("SPDXID"))
    if not document_id:
        reporter.error("Required field 'SPDXID' is missing", path="SPDXID")
    elif document_id != "SPDXRef-DOCUMENT":
        reporter.warning(
            f"The document SPDXID is {document_id!r}; the spec requires 'SPDXRef-DOCUMENT'",
            path="SPDXID",
        )

    _require_string(document, "name", None, reporter, allow_placeholder=False)

    data_license = _text(document.get("dataLicense"))
    if not data_license:
        reporter.error("Required field 'dataLicense' is missing", path="dataLicense")
    elif data_license != "CC0-1.0":
        reporter.warning(
            f"dataLicense is {data_license!r}; SPDX requires 'CC0-1.0'",
            path="dataLicense",
        )

    namespace = _text(document.get("documentNamespace"))
    if not namespace:
        reporter.warning("documentNamespace is missing", path="documentNamespace")
    elif not _URI.match(namespace):
        reporter.warning(f"documentNamespace {namespace!r} is not a URI", path="documentNamespace")


def _spdx_creation_info(document: dict[str, Any], reporter: _Reporter) -> None:
    creation = _expect_object(document.get("creationInfo"), "creationInfo", reporter)
    if creation is None:
        return

    created = creation.get("created")
    if created is None:
        reporter.error("Required field 'creationInfo.created' is missing", path="creationInfo.created")
    elif not isinstance(created, str) or not _TIMESTAMP.match(created.strip()):
        reporter.warning(
            f"creationInfo.created {created!r} is not an ISO-8601 date-time",
            path="creationInfo.created",
        )

    creators = _expect_array(creation.get("creators"), "creationInfo.creators", reporter)
    if not creators:
        reporter.error("creationInfo.creators must name at least one creator", path="creationInfo.creators")
    for index, creator in enumerate(creators):
        path = f"creationInfo.creators[{index}]"
        text = _text(creator)
        if not text:
            reporter.error(f"Creator {index} is not a string", path=path)
        elif not _CREATOR_PREFIX.match(text):
            reporter.warning(
                f"Creator {text!r} is not prefixed with 'Person:', 'Organization:' or 'Tool:'",
                path=path,
            )


def _spdx_packages(document: dict[str, Any], reporter: _Reporter) -> None:
    if "packages" not in document and "files" not in document:
        reporter.warning("The document describes neither packages nor files", path="packages")
        return

    entries = _expect_array(document.get("packages"), "packages", reporter, required=False)
    ids: set[str] = set()

    for index, entry in enumerate(entries):
        path = f"packages[{index}]"
        package = _expect_object(entry, path, reporter)
        if package is None:
            continue

        spdx_id = _text(package.get("SPDXID"))
        if not spdx_id:
            reporter.error("Package has no SPDXID", path=f"{path}.SPDXID")
        elif spdx_id in ids:
            reporter.error(f"Duplicate SPDXID {spdx_id!r}", path=f"{path}.SPDXID", component_ref=spdx_id)
        else:
            ids.add(spdx_id)

        if not _text(package.get("name")):
            reporter.error("Package has no name", path=f"{path}.name")

        download = _text(package.get("downloadLocation"))
        if not download:
            reporter.warning("Package has no downloadLocation", path=f"{path}.downloadLocation")
        elif download.upper() not in _SPDX_PLACEHOLDERS and not _URI.match(download):
            reporter.warning(
                f"downloadLocation {download!r} is not a URI",
                path=f"{path}.downloadLocation",
            )

        for field in ("licenseConcluded", "licenseDeclared"):
            if not _text(package.get(field)):
                reporter.warning(f"Package has no {field}", path=f"{path}.{field}")

        if not _text(package.get("copyrightText")):
            reporter.info("Package has no copyrightText", path=f"{path}.copyrightText")

        _spdx_checksums(package.get("checksums"), f"{path}.checksums", reporter)
        _spdx_external_refs(package.get("externalRefs"), f"{path}.externalRefs", reporter)

        files_analyzed = package.get("filesAnalyzed")
        if files_analyzed is False and package.get("hasFiles"):
            reporter.warning(
                "filesAnalyzed is false but the package lists hasFiles",
                path=f"{path}.filesAnalyzed",
            )


def _spdx_files(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(document.get("files"), "files", reporter, required=False)
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        path = f"files[{index}]"
        file_entry = _expect_object(entry, path, reporter)
        if file_entry is None:
            continue
        spdx_id = _text(file_entry.get("SPDXID"))
        if not spdx_id:
            reporter.error("File has no SPDXID", path=f"{path}.SPDXID")
        elif spdx_id in ids:
            reporter.error(f"Duplicate SPDXID {spdx_id!r}", path=f"{path}.SPDXID")
        else:
            ids.add(spdx_id)
        if not _text(file_entry.get("fileName")):
            reporter.warning("File has no fileName", path=f"{path}.fileName")


def _spdx_checksums(value: Any, path: str, reporter: _Reporter) -> None:
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        checksum = _expect_object(entry, f"{path}[{index}]", reporter)
        if checksum is None:
            continue
        if not _text(checksum.get("algorithm")):
            reporter.error("Checksum has no algorithm", path=f"{path}[{index}].algorithm")
        if not _text(checksum.get("checksumValue")):
            reporter.error("Checksum has no checksumValue", path=f"{path}[{index}].checksumValue")


def _spdx_external_refs(value: Any, path: str, reporter: _Reporter) -> None:
    """Validate ``externalRefs`` through the dialect-tolerant accessors.

    The 2.x JSON spelling (``referenceType``/``referenceLocator``) and the 3.0
    and tag-value spellings (``externalRefType``/``externalRefLocator``) are
    both legitimate, so reading the keys directly would report valid documents.
    """
    if value is None:
        return
    for index, entry in enumerate(_expect_array(value, path, reporter, required=False)):
        reference = _expect_object(entry, f"{path}[{index}]", reporter)
        if reference is None:
            continue
        if not external_ref_type(reference):
            reporter.error("External reference has no type", path=f"{path}[{index}].referenceType")
        if not external_ref_locator(reference):
            reporter.error("External reference has no locator", path=f"{path}[{index}].referenceLocator")
        if not external_ref_category(reference):
            reporter.warning(
                "External reference has no category",
                path=f"{path}[{index}].referenceCategory",
            )


def _spdx_relationships(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(document.get("relationships"), "relationships", reporter, required=False)
    for index, entry in enumerate(entries):
        path = f"relationships[{index}]"
        relationship = _expect_object(entry, path, reporter)
        if relationship is None:
            continue

        if not _text(relationship.get("spdxElementId")):
            reporter.error("Relationship has no spdxElementId", path=f"{path}.spdxElementId")

        kind = _text(relationship.get("relationshipType"))
        if not kind:
            reporter.error("Relationship has no relationshipType", path=f"{path}.relationshipType")
        elif normalize_relationship_type(kind) not in _SPDX_RELATIONSHIPS:
            reporter.warning(
                f"Relationship type {kind!r} is not a known SPDX relationship",
                path=f"{path}.relationshipType",
            )

        target = relationship.get("relatedSpdxElement")
        targets = target if isinstance(target, list) else [target]
        for position, item in enumerate(targets):
            if not _text(item):
                reporter.error(
                    f"relatedSpdxElement[{position}] is empty",
                    path=f"{path}.relatedSpdxElement",
                )


def _spdx_extracted_licenses(document: dict[str, Any], reporter: _Reporter) -> None:
    entries = _expect_array(
        document.get("hasExtractedLicensingInfos"),
        "hasExtractedLicensingInfos",
        reporter,
        required=False,
    )
    for index, entry in enumerate(entries):
        path = f"hasExtractedLicensingInfos[{index}]"
        info = _expect_object(entry, path, reporter)
        if info is None:
            continue
        if not _text(info.get("licenseId")):
            reporter.error("Extracted license has no licenseId", path=f"{path}.licenseId")
        if not _text(info.get("extractedText")):
            reporter.warning("Extracted license has no extractedText", path=f"{path}.extractedText")
