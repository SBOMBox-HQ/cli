"""SPDX parsers for spec versions 2.2, 2.3 and 3.0.

Three serialisations are supported - JSON, RDF/XML and tag-value - plus the
JSON-LD element graph introduced by SPDX 3.0.  Rather than maintaining four
mappings, every non-JSON serialisation is first rewritten into the SPDX 2.x
JSON shape and then handed to :func:`parse_spdx_json`, which holds the single
authoritative field mapping.

Mapping summary (SPDX -> internal model):

===========================  =========================================
SPDX                         SBOMBox
===========================  =========================================
``packages[]``               ``components[]``
``SPDXID``                   ``Component.bom_ref``
``versionInfo``              ``Component.version``
``primaryPackagePurpose``    ``Component.type``
``supplier`` / ``originator`` ``Component.supplier`` / ``Component.author``
``licenseConcluded``         ``Component.licenses`` (preferred)
``licenseDeclared``          ``Component.licenses`` (fallback)
``externalRefs`` (purl)      ``Component.purl``
``externalRefs`` (cpe23Type) ``Component.cpe``
``checksums``                ``Component.hashes``
``relationships``            ``dependencies`` (DEPENDS_ON / CONTAINS / ...)
``creationInfo``             ``metadata`` (created / creators)
``documentDescribes``        ``metadata.component``
===========================  =========================================
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sbombox_core.errors import SbomParseError
from sbombox_core.model.metadata import split_name_email
from sbombox_core.model.sbom import Sbom, SbomFormat
from sbombox_core.parse.sniff import normalize_spec_version, parse_xml_root, to_text

if TYPE_CHECKING:
    from lxml import etree

__all__ = [
    "SUPPORTED_SPEC_VERSIONS",
    "external_ref_category",
    "external_ref_locator",
    "external_ref_type",
    "normalize_relationship_type",
    "parse_spdx_json",
    "parse_spdx_tag_value",
    "parse_spdx_xml",
    "spdx_document_to_dict",
    "spdx_rdf_to_dict",
    "spdx_tag_value_to_dict",
]

#: Spec versions the parser is tested against.  2.x documents outside the set
#: still parse - the vocabulary is stable - but validation flags the version.
SUPPORTED_SPEC_VERSIONS: tuple[str, ...] = ("2.2", "2.3", "3.0")

#: Relationship types that mean "the subject uses the object".
_DEPENDENCY_RELATIONSHIPS = frozenset({"DEPENDS_ON", "CONTAINS", "STATIC_LINK", "DYNAMIC_LINK"})
#: Relationship types that mean the same, with subject and object swapped.
_INVERSE_DEPENDENCY_RELATIONSHIPS = frozenset({"DEPENDENCY_OF", "CONTAINED_BY"})

#: SPDX values that stand for "unknown" and must not be stored as data.
_PLACEHOLDERS = frozenset({"NOASSERTION", "NONE"})

_LICENSE_OPERATORS = re.compile(r"\s(AND|OR|WITH)\s|[()]")
_TOOL_VERSION = re.compile(r"^(?P<name>.+?)[\s:@\-]+v?(?P<version>\d[\w.+\-]*)$")
_EXTERNAL_REF = re.compile(r"^\s*(?P<category>\S+)\s+(?P<type>\S+)\s+(?P<locator>\S+)\s*$")
_CHECKSUM = re.compile(r"^\s*(?P<algorithm>[A-Za-z0-9\-_]+)\s*:\s*(?P<value>\S+)\s*$")
#: Splits camelCase so ``dependsOn`` can become ``DEPENDS_ON``.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

#: RDF namespaces and prefixes used by SPDX documents.
_RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
_SPDX_LICENSES_PREFIX = "http://spdx.org/licenses/"
_SPDX_REFERENCES_PREFIX = "http://spdx.org/rdf/references/"
_RELATIONSHIP_TYPE_MARKER = "relationshipType/"
_CHECKSUM_ALGORITHM_MARKER = "checksumAlgorithm_"


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #


def parse_spdx_json(data: dict) -> Sbom:
    """Parse a decoded SPDX JSON document into an :class:`Sbom`.

    Accepts SPDX 2.2/2.3 documents as well as SPDX 3.0 JSON-LD element graphs,
    which are normalised to the 2.x shape first.

    Raises:
        SbomParseError: if *data* is not a mapping or carries no SPDX markers.
    """
    if not isinstance(data, dict):
        raise SbomParseError(f"SPDX documents must be JSON objects, got {type(data).__name__}")

    document = spdx_document_to_dict(data)

    if not document.get("spdxVersion") and not document.get("packages") and not document.get("creationInfo"):
        raise SbomParseError("Document does not look like SPDX: no spdxVersion, packages or creationInfo")

    spec_version = normalize_spec_version(document.get("spdxVersion")) or _infer_spec_version(data)

    packages = [package for package in _as_list(document.get("packages")) if isinstance(package, dict)]
    described_refs = _described_refs(document)

    components: list[dict[str, Any]] = []
    described_component: dict[str, Any] | None = None
    for package in packages:
        payload = _component_from_package(package)
        if payload is None:
            continue
        ref = payload.get("bom-ref")
        if described_component is None and ref and ref in described_refs:
            # The described package is the subject of the document, not a member
            # of the inventory, so it maps onto ``metadata.component``.
            described_component = payload
            continue
        components.append(payload)

    payload: dict[str, Any] = {
        "format": SbomFormat.SPDX,
        "spec_version": spec_version,
        "metadata": _build_metadata(document, described_component),
        "components": components,
        "dependencies": _build_dependencies(document),
        "raw_data": data,
    }

    try:
        return Sbom.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - re-raised with document context
        raise SbomParseError(f"Could not read the SPDX document: {exc}") from exc


def parse_spdx_xml(content: bytes) -> Sbom:
    """Parse an SPDX RDF/XML document into an :class:`Sbom`.

    Raises:
        SbomParseError: if the content is not well-formed XML or not SPDX.
    """
    raw = content if isinstance(content, bytes) else to_text(content).encode()
    root = parse_xml_root(raw)

    document = spdx_rdf_to_dict(root)
    if not document.get("packages") and not document.get("spdxVersion"):
        raise SbomParseError("Document does not look like SPDX: no packages and no specVersion found")
    return parse_spdx_json(document)


def parse_spdx_tag_value(content: bytes | str) -> Sbom:
    """Parse an SPDX tag-value (``.spdx``) document into an :class:`Sbom`.

    Raises:
        SbomParseError: if the content carries no SPDX tags.
    """
    document = spdx_tag_value_to_dict(to_text(content))
    if not document.get("spdxVersion") and not document.get("packages"):
        raise SbomParseError("Document does not look like SPDX tag-value: no SPDXVersion or PackageName tags found")
    return parse_spdx_json(document)


# --------------------------------------------------------------------------- #
# SPDX 2.x JSON -> internal model
# --------------------------------------------------------------------------- #


def _build_metadata(document: dict[str, Any], described: dict[str, Any] | None) -> dict[str, Any]:
    """Map ``creationInfo`` plus document-level fields onto :class:`Metadata`."""
    creation = document.get("creationInfo")
    creation = creation if isinstance(creation, dict) else {}

    tools: list[dict[str, Any]] = []
    authors: list[dict[str, Any]] = []
    for creator in _as_list(creation.get("creators")):
        if isinstance(creator, dict):
            tools.append(_tool_from_mapping(creator))
            continue
        if not isinstance(creator, str):
            continue
        kind, _, remainder = creator.partition(":")
        value = remainder.strip() if remainder.strip() else kind.strip()
        if kind.strip().lower() == "tool":
            tools.append(_parse_tool_string(value))
        else:
            authors.append(split_name_email(creator))

    properties: dict[str, str] = {}
    for key, source in (
        ("spdx:SPDXID", document.get("SPDXID")),
        ("spdx:name", document.get("name")),
        ("spdx:dataLicense", document.get("dataLicense")),
        ("spdx:documentNamespace", document.get("documentNamespace")),
        ("spdx:documentComment", document.get("comment")),
        ("spdx:licenseListVersion", creation.get("licenseListVersion")),
        ("spdx:creatorComment", creation.get("comment")),
    ):
        if isinstance(source, str) and source.strip() and source.strip().upper() not in _PLACEHOLDERS:
            properties[key] = source.strip()

    return {
        "timestamp": creation.get("created"),
        "tools": tools,
        "authors": authors,
        "component": described,
        "properties": properties,
    }


def _component_from_package(package: dict[str, Any]) -> dict[str, Any] | None:
    """Map one SPDX package onto the internal component payload.

    Returns ``None`` when the package has no usable name, in which case there is
    nothing to model and the entry is skipped rather than fabricated.
    """
    name = _text(package.get("name"))
    if not name:
        return None

    external_refs = _external_references(package)
    purl, cpe = _extract_identifiers(package, external_refs)

    payload: dict[str, Any] = {
        "bom-ref": _text(package.get("SPDXID")) or _text(package.get("spdxId")),
        "type": package.get("primaryPackagePurpose") or "library",
        "name": name,
        "version": _text(package.get("versionInfo")) or _text(package.get("packageVersion")),
        "description": _text(package.get("description")) or _text(package.get("summary")),
        "purl": purl,
        "cpe": cpe,
        "supplier": _parse_actor(package.get("supplier")),
        "author": _actor_name(package.get("originator")),
        "licenses": _licenses_from_spdx(package.get("licenseConcluded"), package.get("licenseDeclared")),
        "hashes": _hashes_from_spdx(package),
        "externalReferences": external_refs,
        "properties": _package_properties(package),
    }
    return {key: value for key, value in payload.items() if value not in (None, [], {})}


def _package_properties(package: dict[str, Any]) -> dict[str, str]:
    """Keep the SPDX-only fields that have no CycloneDX equivalent."""
    properties: dict[str, str] = {}
    for key, source in (
        ("spdx:downloadLocation", package.get("downloadLocation")),
        ("spdx:copyrightText", package.get("copyrightText")),
        ("spdx:sourceInfo", package.get("sourceInfo")),
        ("spdx:packageFileName", package.get("packageFileName")),
        ("spdx:comment", package.get("comment")),
        ("spdx:primaryPackagePurpose", package.get("primaryPackagePurpose")),
    ):
        text = _text(source)
        if text and text.upper() not in _PLACEHOLDERS:
            properties[key] = text
    return properties


def _external_references(package: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert SPDX ``externalRefs`` (plus homepage/download links) to references."""
    references: list[dict[str, Any]] = []
    for entry in _as_list(package.get("externalRefs")):
        if not isinstance(entry, dict):
            continue
        ref_type = external_ref_type(entry) or "other"
        references.append(
            {
                "type": ref_type,
                "url": external_ref_locator(entry) or "",
                "comment": _text(entry.get("comment")),
            }
        )

    homepage = _text(package.get("homepage"))
    if homepage:
        references.append({"type": "website", "url": homepage})

    download = _text(package.get("downloadLocation"))
    if download and download.upper() not in _PLACEHOLDERS:
        references.append({"type": "distribution", "url": download})

    return references


def external_ref_type(entry: dict[str, Any]) -> str | None:
    """Return an external reference's type across the SPDX 2.x/3.0 spellings.

    SPDX 2.x JSON says ``referenceType``, SPDX 3.0 and the tag-value converter
    say ``externalRefType``.  Both reach this accessor so neither the parser nor
    the validator has to know which dialect a document arrived in.
    """
    for key in ("externalRefType", "referenceType"):
        text = _text(entry.get(key))
        if text:
            return text
    return None


def external_ref_category(entry: dict[str, Any]) -> str | None:
    """Return an external reference's category across the SPDX spellings."""
    for key in ("externalRefCategory", "referenceCategory"):
        text = _text(entry.get(key))
        if text:
            return text
    return None


def external_ref_locator(entry: dict[str, Any]) -> str | None:
    """Return the external reference locator, unwrapping the 3.0 list form."""
    for key in ("externalRefLocator", "referenceLocator", "locator"):
        locator = entry.get(key)
        if isinstance(locator, list):
            for item in locator:
                text = _text(item)
                if text:
                    return text
            continue
        text = _text(locator)
        if text:
            return text
    return None


def _extract_identifiers(package: dict[str, Any], references: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """Pull the purl and CPE out of ``externalRefs``, falling back to URLs."""
    purl: str | None = None
    cpe: str | None = None

    for entry in _as_list(package.get("externalRefs")):
        if not isinstance(entry, dict):
            continue
        ref_type = (external_ref_type(entry) or "").lower()
        value = external_ref_locator(entry)
        if not value:
            continue
        if ref_type == "purl" and purl is None:
            purl = value
        elif ref_type in {"cpe23type", "cpe22type", "cpe"} and cpe is None:
            cpe = value

    if purl is None:
        for reference in references:
            url = reference.get("url", "")
            if url.startswith("pkg:"):
                purl = url
                break

    return purl, cpe


def _hashes_from_spdx(package: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert SPDX ``checksums`` into internal hash payloads."""
    hashes: list[dict[str, Any]] = []
    for entry in _as_list(package.get("checksums")) or _as_list(package.get("checksum")):
        if isinstance(entry, str):
            match = _CHECKSUM.match(entry)
            if match:
                hashes.append({"alg": _algorithm_name(match.group("algorithm")), "content": match.group("value")})
            continue
        if not isinstance(entry, dict):
            continue
        alg = _text(entry.get("algorithm")) or _text(entry.get("checksumAlgorithm"))
        value = _text(entry.get("checksumValue")) or _text(entry.get("value"))
        if alg and value:
            hashes.append({"alg": _algorithm_name(alg), "content": value})
    return hashes


def _algorithm_name(raw: str) -> str:
    """Strip the RDF enumeration prefix from a checksum algorithm name.

    ``checksumAlgorithm_sha256`` -> ``sha256``; anything else passes through
    for :class:`~sbombox_core.model.common.Hash` to canonicalise.
    """
    text = raw.strip()
    if _CHECKSUM_ALGORITHM_MARKER in text:
        text = text.rsplit(_CHECKSUM_ALGORITHM_MARKER, 1)[-1]
    return text


def _licenses_from_spdx(*values: Any) -> list[dict[str, Any]]:
    """Convert SPDX license fields into license choices, dropping placeholders."""
    choices: list[dict[str, Any]] = []
    seen: set[str] = set()

    for value in values:
        for candidate in _as_list(value):
            text = _license_value(candidate)
            if not text or text.upper() in _PLACEHOLDERS:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            if _LICENSE_OPERATORS.search(text):
                choices.append({"expression": text})
            else:
                choices.append({"license": {"id": text}})
    return choices


def _license_value(value: Any) -> str | None:
    """Flatten an SPDX license, which may be a string or a 3.0 License object."""
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, dict):
        for key in ("licenseId", "spdxId", "licenseText", "name", "identifier"):
            text = _text(value.get(key))
            if text:
                return text
    return None


def normalize_relationship_type(value: Any) -> str:
    """Return the canonical ``UPPER_SNAKE`` spelling of a relationship type.

    SPDX JSON uses ``DEPENDS_ON`` while RDF resources use camelCase URIs such
    as ``.../relationshipType/dependsOn``; both must compare equal.
    """
    text = _text(value)
    if not text:
        return ""
    text = text.replace("-", "_")
    if text.isupper():
        return text
    return _CAMEL_BOUNDARY.sub("_", text).upper()


def _build_dependencies(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Fold SPDX relationships into dependency edges, merging shared subjects."""
    edges: dict[str, list[str]] = {}

    for relationship in _iter_relationships(document):
        kind = normalize_relationship_type(relationship.get("relationshipType"))
        subject = _ref(relationship.get("spdxElementId"))
        raw_targets = relationship.get("relatedSpdxElement") or relationship.get("to")
        targets = [target for target in (_ref(item) for item in _as_list(raw_targets)) if target]

        if not subject or not targets:
            continue
        if kind in _INVERSE_DEPENDENCY_RELATIONSHIPS:
            subject, targets = targets[0], [subject]
            targets = [target for target in targets if target]
        elif kind not in _DEPENDENCY_RELATIONSHIPS:
            continue

        if _is_document_ref(subject):
            continue

        bucket = edges.setdefault(subject, [])
        for target in targets:
            if target != subject and not _is_document_ref(target) and target not in bucket:
                bucket.append(target)

    return [{"ref": ref, "dependsOn": depends_on} for ref, depends_on in edges.items() if depends_on]


def _iter_relationships(document: dict[str, Any]):
    """Yield every relationship mapping, including per-element ones (SPDX 3.0)."""
    for relationship in _as_list(document.get("relationships")):
        if isinstance(relationship, dict):
            yield relationship

    for section in ("packages", "files", "snippets"):
        for element in _as_list(document.get(section)):
            if not isinstance(element, dict):
                continue
            for relationship in _as_list(element.get("relationships")):
                if isinstance(relationship, dict):
                    # Per-element relationships omit the subject; it is implied.
                    if not relationship.get("spdxElementId"):
                        subject = element.get("SPDXID") or element.get("spdxId")
                        relationship = {**relationship, "spdxElementId": subject}
                    yield relationship


def _described_refs(document: dict[str, Any]) -> set[str]:
    """Return the SPDXIDs the document declares as its subject."""
    refs = {_ref(item) for item in _as_list(document.get("documentDescribes"))}
    refs.discard("")

    for relationship in _iter_relationships(document):
        kind = normalize_relationship_type(relationship.get("relationshipType"))
        if kind not in {"DESCRIBES", "DESCRIBED_BY"}:
            continue
        if _is_document_ref(_ref(relationship.get("spdxElementId"))):
            target = _ref(relationship.get("relatedSpdxElement"))
            if target:
                refs.add(target)
        else:
            source = _ref(relationship.get("spdxElementId"))
            if source:
                refs.add(source)
    return refs


def _is_document_ref(ref: str) -> bool:
    return ref.upper() in {"SPDXREF-DOCUMENT", "NOASSERTION"} or ref.upper().endswith(":DOCUMENT")


def _ref(value: Any) -> str:
    """Normalise an SPDX identifier, unwrapping 3.0 element references."""
    if isinstance(value, dict):
        for key in ("spdxId", "SPDXID", "@id", "id"):
            text = _text(value.get(key))
            if text:
                return text
        return ""
    if isinstance(value, list):
        return _ref(value[0]) if value else ""
    return _text(value) or ""


def _text(value: Any) -> str | None:
    """Return a stripped string, or ``None`` for empty/absent values."""
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _parse_tool_string(raw: str) -> dict[str, Any]:
    """Split ``"syft-1.5.0"`` / ``"syft:1.5.0"`` into a tool name and version."""
    text = raw.strip()
    if not text:
        return {}
    match = _TOOL_VERSION.match(text)
    if match:
        return {"name": match.group("name").strip(), "version": match.group("version")}
    return {"name": text}


def _tool_from_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Build a tool from an SPDX 3.0 ``Tool`` element."""
    return {
        "name": _text(value.get("name")) or _text(value.get("toolName")),
        "version": _text(value.get("version")) or _text(value.get("toolVersion")),
        "vendor": _text(value.get("vendor")),
    }


def _parse_actor(value: Any) -> dict[str, Any] | None:
    """Convert an SPDX supplier/originator into the internal supplier shape."""
    entry = value[0] if isinstance(value, list) and value else value

    if isinstance(entry, dict):
        name = _text(entry.get("name")) or _actor_name(entry)
        email = _text(entry.get("email"))
        supplier: dict[str, Any] = {"name": name}
        if email:
            supplier["contact"] = [{"email": email}]
        return supplier if supplier.get("name") or supplier.get("contact") else None

    if not isinstance(entry, str):
        return None

    text = entry.strip()
    if not text or text.upper() in _PLACEHOLDERS:
        return None

    contact = split_name_email(text)
    supplier = {"name": contact.get("name")}
    if contact.get("email"):
        supplier["contact"] = [{"email": contact["email"]}]
    return supplier if supplier.get("name") or supplier.get("contact") else None


def _actor_name(value: Any) -> str | None:
    """Return just the name part of an SPDX actor (person/organization)."""
    entry = value[0] if isinstance(value, list) and value else value
    if isinstance(entry, dict):
        return _text(entry.get("name")) or _text(entry.get("person")) or _text(entry.get("organization"))
    if not isinstance(entry, str):
        return None
    text = entry.strip()
    if not text or text.upper() in _PLACEHOLDERS:
        return None
    return split_name_email(text).get("name")


def _infer_spec_version(data: dict[str, Any]) -> str:
    """Guess a spec version for documents that do not declare one."""
    context = data.get("@context")
    contexts = context if isinstance(context, list) else [context]
    for entry in contexts:
        if isinstance(entry, str):
            match = re.search(r"spdx\.org/rdf/(\d+\.\d+(?:\.\d+)?)", entry)
            if match:
                return match.group(1)
    if "@graph" in data or "elements" in data:
        return "3.0"
    return "2.3"


# --------------------------------------------------------------------------- #
# SPDX 3.0 JSON-LD -> SPDX 2.x JSON
# --------------------------------------------------------------------------- #


def spdx_document_to_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Return an SPDX 2.x-shaped document, converting 3.0 graphs if needed.

    Public because schema validation needs the same normalised view the parser
    works from: checking a 3.0 document against 2.x field names would report
    problems that do not exist.
    """
    if not _looks_like_spdx3(data):
        return data
    return _spdx3_to_spdx2(data)


def _looks_like_spdx3(data: dict[str, Any]) -> bool:
    """Detect the SPDX 3.0 JSON-LD element-graph layout."""
    if isinstance(data.get("@graph"), list) or isinstance(data.get("elements"), list):
        return True

    context = data.get("@context")
    contexts = context if isinstance(context, list) else [context]
    for entry in contexts:
        if isinstance(entry, str) and "spdx.org/rdf/3" in entry:
            return True
        if isinstance(entry, dict) and "spdx" in entry:
            return True

    return str(data.get("@type", "")).lower().endswith("spdxdocument")


def _spdx3_to_spdx2(data: dict[str, Any]) -> dict[str, Any]:
    """Rewrite an SPDX 3.0 element graph as an SPDX 2.3-shaped document."""
    elements = _as_list(data.get("@graph")) or _as_list(data.get("elements"))
    if not elements and data.get("@type"):
        elements = [data]

    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    document: dict[str, Any] = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "creationInfo": {},
    }

    for element in elements:
        if not isinstance(element, dict):
            continue
        kind = str(element.get("@type") or "").lower()
        nested = _as_list(element.get("relationship")) or _as_list(element.get("relationships"))
        for relationship in nested:
            if not isinstance(relationship, dict):
                continue
            # A relationship nested in an element omits its subject: it is the
            # element itself.
            subject = relationship.get("spdxElementId") or element.get("spdxId") or element.get("SPDXID")
            relationships.append(_spdx3_relationship_to_spdx2(relationship, subject))

        if kind.endswith("package"):
            packages.append(_spdx3_package_to_spdx2(element))
        elif kind.endswith("spdxdocument") or kind.endswith("collection"):
            document.update(_spdx3_document_to_spdx2(element))

    document["spdxVersion"] = document.get("spdxVersion") or f"SPDX-{_infer_spec_version(data)}"
    document["packages"] = packages
    document["relationships"] = relationships
    return document


def _spdx3_relationship_to_spdx2(relationship: dict[str, Any], subject: Any) -> dict[str, Any]:
    """Map an SPDX 3.0 ``Relationship`` onto the 2.x field vocabulary.

    3.0 spells the endpoints ``from``/``to`` and writes the type in camelCase;
    2.x spells them ``spdxElementId``/``relatedSpdxElement`` and writes the type
    in ``UPPER_SNAKE``.  Converting here means everything downstream sees one
    shape.
    """
    converted = dict(relationship)
    converted["spdxElementId"] = relationship.get("spdxElementId") or relationship.get("from") or subject
    if "relatedSpdxElement" not in converted and "to" in relationship:
        converted["relatedSpdxElement"] = relationship["to"]
    if relationship.get("relationshipType"):
        converted["relationshipType"] = normalize_relationship_type(relationship["relationshipType"])
    converted.pop("from", None)
    converted.pop("to", None)
    return converted


def _spdx3_package_to_spdx2(element: dict[str, Any]) -> dict[str, Any]:
    """Map an SPDX 3.0 ``Package`` element onto the 2.x package shape."""
    checksums = _as_list(element.get("checksum")) or _as_list(element.get("checksums"))
    external_refs = _as_list(element.get("externalRef")) or _as_list(element.get("externalRefs"))

    return {
        "SPDXID": _text(element.get("spdxId")) or _text(element.get("SPDXID")),
        "name": _text(element.get("name")),
        "versionInfo": _text(element.get("packageVersion")) or _text(element.get("versionInfo")),
        "description": _text(element.get("description")) or _text(element.get("summary")),
        "supplier": element.get("suppliedBy"),
        "originator": element.get("originator"),
        "downloadLocation": _text(element.get("downloadLocation")),
        "licenseConcluded": _license_value(element.get("licenseConcluded")),
        "licenseDeclared": _license_value(element.get("licenseDeclared")),
        "copyrightText": _text(element.get("copyrightText")),
        "primaryPackagePurpose": _text(element.get("primaryPackagePurpose")),
        "packageFileName": _text(element.get("packageFileName")),
        "checksums": checksums,
        "externalRefs": external_refs,
    }


def _spdx3_document_to_spdx2(element: dict[str, Any]) -> dict[str, Any]:
    """Map an SPDX 3.0 ``SpdxDocument`` element onto 2.x document fields."""
    creation = element.get("creationInfo")
    creation = creation if isinstance(creation, dict) else {}

    creators: list[str] = []
    for actor in _as_list(creation.get("createdBy")):
        if isinstance(actor, dict):
            name = _text(actor.get("name"))
            if name:
                kind = "Organization" if str(actor.get("@type", "")).lower().endswith("organization") else "Person"
                email = _text(actor.get("email"))
                creators.append(f"{kind}: {name} ({email})" if email else f"{kind}: {name}")
        elif isinstance(actor, str):
            creators.append(actor)

    for tool in _as_list(creation.get("createdUsing")):
        if isinstance(tool, dict):
            name = _text(tool.get("name"))
            version = _text(tool.get("version"))
            if name:
                creators.append(f"Tool: {name}-{version}" if version else f"Tool: {name}")
        elif isinstance(tool, str):
            creators.append(f"Tool: {tool}")

    described = _as_list(element.get("element")) or _as_list(element.get("describes"))

    return {
        "SPDXID": _text(element.get("spdxId")) or "SPDXRef-DOCUMENT",
        "name": _text(element.get("name")),
        "documentNamespace": _text(element.get("elementNamespace")) or _text(element.get("documentNamespace")),
        "comment": _text(element.get("_comment")) or _text(element.get("comment")),
        "spdxVersion": _spdx3_spec_version(element),
        "creationInfo": {
            "created": creation.get("created"),
            "creators": creators,
            "licenseListVersion": _text(creation.get("licenseListVersion")),
            "comment": _text(creation.get("_comment")) or _text(creation.get("comment")),
        },
        "documentDescribes": [ref for ref in (_ref(item) for item in described) if ref],
    }


def _spdx3_spec_version(element: dict[str, Any]) -> str | None:
    """Return the ``SPDX-x.y`` string implied by an element's context/version."""
    creation = element.get("creationInfo")
    creation = creation if isinstance(creation, dict) else {}

    for value in (element.get("specVersion"), creation.get("specVersion")):
        text = _text(value)
        if text:
            return f"SPDX-{normalize_spec_version(text)}"

    context = element.get("@context")
    if isinstance(context, str):
        match = re.search(r"spdx\.org/rdf/(\d+\.\d+(?:\.\d+)?)", context)
        if match:
            return f"SPDX-{match.group(1)}"
    return None


# --------------------------------------------------------------------------- #
# SPDX RDF/XML -> SPDX 2.x JSON
# --------------------------------------------------------------------------- #


def spdx_rdf_to_dict(root: etree._Element) -> dict[str, Any]:
    """Rewrite an SPDX RDF/XML tree as an SPDX 2.3-shaped document."""
    document: dict[str, Any] = {}
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    nodes = [root] if _localname(root).lower() in {"spdxdocument", "document"} else _element_children(root)
    for node in nodes:
        kind = _localname(node).lower()
        converted = _rdf_node(node)
        if kind == "package":
            packages.append(_rdf_package_to_spdx2(converted))
        elif kind in {"spdxdocument", "document"}:
            document = _rdf_document_to_spdx2(converted)
        elif kind == "relationship":
            relationships.append(_rdf_relationship_to_spdx2(converted))

    for package in packages:
        # A relationship nested inside a Package omits its subject, which is the
        # package itself; without injecting it the edge has no source.
        subject = package.get("SPDXID")
        for entry in package.pop("relationships", []):
            if isinstance(entry, dict) and not entry.get("spdxElementId"):
                entry = {**entry, "spdxElementId": subject}
            relationships.append(entry)

    if packages:
        document["packages"] = packages
    if relationships:
        document["relationships"] = [*_as_list(document.get("relationships")), *relationships]
    return document


def _rdf_package_to_spdx2(node: dict[str, Any]) -> dict[str, Any]:
    """Map RDF ``spdx:Package`` properties onto the 2.x package shape."""
    return {
        "SPDXID": node.get("SPDXID"),
        "name": node.get("name"),
        "versionInfo": node.get("versionInfo"),
        "description": node.get("description") or node.get("summary"),
        "summary": node.get("summary"),
        "supplier": node.get("supplier"),
        "originator": node.get("originator"),
        "downloadLocation": node.get("downloadLocation"),
        "licenseConcluded": _license_value(node.get("licenseConcluded")),
        "licenseDeclared": _license_value(node.get("licenseDeclared")),
        "copyrightText": node.get("copyrightText"),
        "primaryPackagePurpose": node.get("primaryPackagePurpose"),
        "packageFileName": node.get("packageFileName"),
        "checksums": _as_list(node.get("checksum")),
        "externalRefs": _as_list(node.get("externalRef")),
        "relationships": _as_list(node.get("relationship")),
    }


def _rdf_document_to_spdx2(node: dict[str, Any]) -> dict[str, Any]:
    """Map the RDF ``spdx:SpdxDocument`` node onto 2.x document fields."""
    creation = node.get("creationInfo")
    if isinstance(creation, list):
        creation = creation[0] if creation else {}
    creation = creation if isinstance(creation, dict) else {}

    described = [
        rel.get("relatedSpdxElement")
        for rel in _as_list(node.get("relationship"))
        if isinstance(rel, dict) and normalize_relationship_type(rel.get("relationshipType")) == "DESCRIBES"
    ]
    doc_id = _text(node.get("SPDXID")) or "SPDXRef-DOCUMENT"

    return {
        "spdxVersion": node.get("specVersion"),
        "SPDXID": doc_id,
        "name": node.get("name"),
        "dataLicense": _license_value(node.get("dataLicense")) or "CC0-1.0",
        "documentNamespace": _rdf_namespace(node),
        "comment": node.get("comment"),
        "creationInfo": {
            "created": creation.get("created"),
            "creators": _as_list(creation.get("creator")),
            "licenseListVersion": creation.get("licenseListVersion"),
            "comment": creation.get("comment"),
        },
        "documentDescribes": [ref for ref in (_ref(item) for item in described) if ref],
        "relationships": [
            rel if rel.get("spdxElementId") else {**rel, "spdxElementId": doc_id}
            for rel in _as_list(node.get("relationship"))
            if isinstance(rel, dict)
        ],
    }


def _rdf_relationship_to_spdx2(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "spdxElementId": node.get("spdxElementId") or node.get("SPDXID"),
        "relationshipType": node.get("relationshipType"),
        "relatedSpdxElement": node.get("relatedSpdxElement"),
        "comment": node.get("comment"),
    }


def _rdf_node(node: etree._Element) -> dict[str, Any]:
    """Convert one RDF node into ``{property: value | [values]}``."""
    result: dict[str, Any] = {}

    for name, value in node.attrib.items():
        local = _localname_of(name)
        if local == "about":
            result["SPDXID"] = _normalize_rdf_ref(value)
            result["_about"] = value
        elif local == "ID":
            result.setdefault("SPDXID", value)

    collected: dict[str, list[Any]] = {}
    for child in _element_children(node):
        value = _rdf_property(child)
        if value is not None:
            collected.setdefault(_localname(child), []).append(value)

    for name, values in collected.items():
        result[name] = values[0] if len(values) == 1 else values
    return result


def _rdf_property(element: etree._Element) -> Any:
    """Return the value of one RDF property element."""
    resource = element.get(f"{{{_RDF_NS}}}resource")
    if resource:
        return _normalize_rdf_ref(resource)

    nested = _element_children(element)
    if nested:
        if len(nested) == 1:
            return _rdf_node(nested[0])
        return [_rdf_node(child) for child in nested]

    text = (element.text or "").strip()
    return text or None


def _rdf_namespace(node: dict[str, Any]) -> str | None:
    """Return the document namespace, derived from ``rdf:about`` when present."""
    explicit = _text(node.get("documentNamespace"))
    if explicit:
        return explicit
    about = _text(node.get("_about"))
    if not about:
        return None
    return about.rsplit("#", 1)[0] or about


def _normalize_rdf_ref(uri: str) -> str:
    """Turn an RDF reference into the plain identifier SPDX JSON would use."""
    if not uri:
        return ""
    if uri.startswith(_SPDX_LICENSES_PREFIX):
        return uri[len(_SPDX_LICENSES_PREFIX) :]
    if uri.startswith(_SPDX_REFERENCES_PREFIX):
        # ``http://spdx.org/rdf/references/purl`` -> ``purl``
        return uri[len(_SPDX_REFERENCES_PREFIX) :]
    if _RELATIONSHIP_TYPE_MARKER in uri:
        return uri.rsplit("/", 1)[-1]
    if "#" in uri:
        return uri.rsplit("#", 1)[-1]
    return uri


# --------------------------------------------------------------------------- #
# SPDX tag-value -> SPDX 2.x JSON
# --------------------------------------------------------------------------- #

#: Tag -> SPDX 2.x JSON field, for document level.
_DOCUMENT_TAGS: dict[str, str] = {
    "SPDXVersion": "spdxVersion",
    "DataLicense": "dataLicense",
    "SPDXID": "SPDXID",
    "DocumentName": "name",
    "DocumentNamespace": "documentNamespace",
    "DocumentComment": "comment",
    "ExternalDocumentRef": "externalDocumentRefs",
}

#: Tag -> SPDX 2.x JSON field, for packages.
_PACKAGE_TAGS: dict[str, str] = {
    "SPDXID": "SPDXID",
    "PackageVersion": "versionInfo",
    "PackageDescription": "description",
    "PackageSummary": "summary",
    "PackageSupplier": "supplier",
    "PackageOriginator": "originator",
    "PackageDownloadLocation": "downloadLocation",
    "PackageLicenseConcluded": "licenseConcluded",
    "PackageLicenseDeclared": "licenseDeclared",
    "PackageCopyrightText": "copyrightText",
    "PackageComment": "comment",
    "PackageFileName": "packageFileName",
    "PrimaryPackagePurpose": "primaryPackagePurpose",
    "PackageSourceInfo": "sourceInfo",
}


def spdx_tag_value_to_dict(text: str) -> dict[str, Any]:
    """Rewrite SPDX tag-value content as an SPDX 2.3-shaped document."""
    document: dict[str, Any] = {"creationInfo": {"creators": []}, "packages": [], "relationships": []}
    package: dict[str, Any] | None = None
    mode = "document"
    last_target: dict[str, Any] | None = None
    last_field: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        # Continuation lines are indented and belong to the previous tag.
        if line[:1] in {" ", "\t"} and last_target is not None and last_field is not None:
            previous = last_target[last_field]
            last_target[last_field] = f"{previous}\n{line.strip()}" if isinstance(previous, str) else line.strip()
            continue

        tag, separator, value = line.partition(":")
        if not separator:
            continue
        tag = tag.strip()
        value = value.strip()

        if tag == "PackageName":
            package = {"name": value}
            document["packages"].append(package)
            mode = "package"
            last_target, last_field = None, None
            continue
        if tag in {"FileName", "SnippetName"}:
            mode = "file"
            package = None
            last_target, last_field = None, None
            continue
        if tag == "Relationship":
            _add_tag_relationship(document, value)
            last_target, last_field = None, None
            continue

        if mode == "file" or (mode == "package" and package is None):
            continue

        if mode == "document":
            last_target, last_field = _apply_document_tag(document, tag, value)
        else:
            last_target, last_field = _apply_package_tag(package, tag, value)

    if not document.get("name"):
        document.pop("name", None)
    return document


def _apply_document_tag(document: dict[str, Any], tag: str, value: str) -> tuple[dict[str, Any] | None, str | None]:
    """Store one document-level tag, returning where a continuation would go."""
    if tag == "Creator":
        document["creationInfo"]["creators"].append(value)
        return None, None
    if tag == "Created":
        document["creationInfo"]["created"] = value
        return document["creationInfo"], "created"
    if tag == "CreatorComment":
        document["creationInfo"]["comment"] = value
        return document["creationInfo"], "comment"
    if tag == "LicenseListVersion":
        document["creationInfo"]["licenseListVersion"] = value
        return document["creationInfo"], "licenseListVersion"

    field = _DOCUMENT_TAGS.get(tag)
    if field is None:
        return None, None
    document[field] = value
    return document, field


def _apply_package_tag(package: dict[str, Any], tag: str, value: str) -> tuple[dict[str, Any] | None, str | None]:
    """Store one package-level tag, returning where a continuation would go."""
    if tag == "PackageChecksum":
        match = _CHECKSUM.match(value)
        if match:
            package.setdefault("checksums", []).append(
                {"algorithm": match.group("algorithm"), "checksumValue": match.group("value")}
            )
        return None, None

    if tag == "ExternalRef":
        match = _EXTERNAL_REF.match(value)
        if match:
            package.setdefault("externalRefs", []).append(
                {
                    "externalRefCategory": match.group("category"),
                    "externalRefType": match.group("type"),
                    "externalRefLocator": match.group("locator"),
                }
            )
        return None, None

    if tag == "PackageLicenseInfoFromFiles":
        package.setdefault("licenseInfoFromFiles", []).append(value)
        return None, None

    field = _PACKAGE_TAGS.get(tag)
    if field is None:
        return None, None
    package[field] = value
    return package, field


def _add_tag_relationship(document: dict[str, Any], value: str) -> None:
    """Parse ``A DESCRIBES B`` into a relationship record."""
    parts = value.split()
    if len(parts) < 3:
        return
    document["relationships"].append(
        {"spdxElementId": parts[0], "relationshipType": parts[1], "relatedSpdxElement": parts[2]}
    )


# --------------------------------------------------------------------------- #
# XML helpers
# --------------------------------------------------------------------------- #


def _element_children(element: etree._Element) -> list[etree._Element]:
    return [child for child in element if isinstance(child.tag, str)]


def _localname(element: etree._Element) -> str:
    return _localname_of(element.tag) if isinstance(element.tag, str) else ""


def _localname_of(tag: str) -> str:
    return tag.rpartition("}")[2]
