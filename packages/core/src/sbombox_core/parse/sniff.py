"""Format detection ("sniffing") for SBOM documents.

Producers do not reliably label their output, and file extensions lie: a
``bom.json`` may be SPDX and a ``sbom.xml`` may be CycloneDX.  Detection here is
content-based, so callers can hand in raw bytes and get a definite answer.

Two orthogonal things are detected:

* the **container** - JSON, XML, YAML or SPDX tag-value;
* the **specification** - CycloneDX or SPDX, plus the spec version.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum

from lxml import etree

from sbombox_core.errors import MalformedDocumentError, SbomParseError, UnsupportedFormatError
from sbombox_core.model.sbom import SbomFormat

__all__ = [
    "ContainerKind",
    "detect_container",
    "detect_format",
    "normalize_spec_version",
    "parse_xml_root",
    "to_text",
]


class ContainerKind(StrEnum):
    """The serialisation an SBOM document is wrapped in."""

    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    TAG_VALUE = "tag-value"
    UNKNOWN = "unknown"


#: ``SPDX-2.3`` -> ``2.3``; also strips a leading ``v``.
_SPDX_VERSION = re.compile(r"SPDX[-\s]*(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_BARE_VERSION = re.compile(r"^v?(\d+\.\d+(?:\.\d+)?)$")
#: CycloneDX XML namespace, e.g. ``http://cyclonedx.org/schema/bom/1.6``.
_CDX_NAMESPACE = re.compile(r"cyclonedx\.org/schema/bom/(\d+\.\d+(?:\.\d+)?)")
#: SPDX 3.x JSON-LD context URL, e.g. ``https://spdx.org/rdf/3.0.1/spdx-context.jsonld``.
_SPDX3_CONTEXT = re.compile(r"spdx\.org/rdf/(\d+\.\d+(?:\.\d+)?)")
_TAG_VALUE_HEADER = re.compile(r"^\s*(?:SPDXVersion|spdxVersion|SPDXID)\s*:", re.MULTILINE)
#: How many leading characters are enough to spot the container and root element.
_HEADER_CHARS = 16384


def to_text(content: bytes | str) -> str:
    """Decode *content* to text, tolerating a BOM and non-UTF-8 XML declarations."""
    if isinstance(content, str):
        return content
    if not content:
        return ""
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def normalize_spec_version(raw: object) -> str:
    """Reduce any spec version spelling to a bare ``major.minor[.patch]``.

    ``SPDX-2.3`` -> ``2.3``, ``CycloneDX 1.6`` -> ``1.6``, ``v1.5`` -> ``1.5``.
    Unrecognised values are returned stripped, and ``None`` becomes ``""``.
    """
    if raw is None:
        return ""
    if isinstance(raw, (int, float)):
        return str(raw)
    text = str(raw).strip()
    if not text:
        return ""

    match = _SPDX_VERSION.search(text)
    if match:
        return match.group(1)

    match = _CDX_NAMESPACE.search(text)
    if match:
        return match.group(1)

    match = _BARE_VERSION.match(text.lstrip("v"))
    if match:
        return match.group(1)

    digits = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
    return digits.group(1) if digits else text


def detect_container(content: bytes | str) -> ContainerKind:
    """Return the serialisation *content* uses."""
    text = to_text(content).lstrip()
    if not text:
        return ContainerKind.UNKNOWN
    if text[0] == "<":
        return ContainerKind.XML
    if text[0] in "{[":
        return ContainerKind.JSON
    if _TAG_VALUE_HEADER.match(text):
        return ContainerKind.TAG_VALUE
    if _looks_like_yaml_mapping(text):
        return ContainerKind.YAML
    return ContainerKind.UNKNOWN


def _looks_like_yaml_mapping(text: str) -> bool:
    """Cheap check for ``key: value`` YAML before paying for a full parse.

    Only the first meaningful line decides it: a YAML document either opens with
    a mapping or it does not, and scanning deeper would let an indented block
    inside some other serialisation masquerade as one.
    """
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "---", "%")):
            continue
        return bool(re.match(r"^[\w\"'@.$\-\s]+:\s", stripped)) or stripped.endswith(":")
    return False


def detect_format(content: bytes | str) -> tuple[SbomFormat, str]:
    """Detect the SBOM specification and version of *content*.

    Returns a ``(format, spec_version)`` pair, for example
    ``(SbomFormat.CYCLONEDX, "1.6")``.  ``spec_version`` is ``""`` when the
    document does not declare one.

    Raises:
        UnsupportedFormatError: if the content carries no CycloneDX or SPDX
            markers, so there is nothing to route it to.
        MalformedDocumentError: if the content is a supported serialisation
            that cannot be decoded (broken JSON, broken YAML, broken XML).

    Both derive from :class:`~sbombox_core.errors.SbomParseError`, which itself
    derives from :class:`ValueError`, so ``except ValueError`` still catches
    every detection failure.
    """
    text = to_text(content)
    if not text.strip():
        raise MalformedDocumentError("Cannot detect SBOM format: the document is empty")

    kind = detect_container(text)

    if kind is ContainerKind.JSON:
        return _detect_from_json(text)
    if kind is ContainerKind.XML:
        return _detect_from_xml(content)
    if kind is ContainerKind.TAG_VALUE:
        return _detect_from_tag_value(text)
    if kind is ContainerKind.YAML:
        return _detect_from_yaml(text)

    # Last resort: some producers prepend a byte-order mark, a shebang-like
    # comment or HTTP headers.  Scan the raw text for the tell-tale keys.
    return _detect_from_loose_text(text)


def _detect_from_json(text: str) -> tuple[SbomFormat, str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedDocumentError(f"Content looks like JSON but could not be decoded: {exc}") from exc
    return _detect_from_mapping(data)


def _detect_from_yaml(text: str) -> tuple[SbomFormat, str]:
    try:
        from ruamel.yaml import YAML
    except ImportError as exc:  # pragma: no cover - ruamel.yaml is a hard dependency
        raise SbomParseError("YAML SBOMs require the 'ruamel.yaml' package") from exc

    from io import StringIO

    yaml = YAML(typ="safe")
    try:
        data = yaml.load(StringIO(text))
    except Exception as exc:  # noqa: BLE001 - ruamel raises its own hierarchy
        raise MalformedDocumentError(f"Content looks like YAML but could not be decoded: {exc}") from exc
    return _detect_from_mapping(data)


def _detect_from_mapping(data: object) -> tuple[SbomFormat, str]:
    """Classify an already-decoded JSON/YAML mapping."""
    if isinstance(data, list):
        # SPDX 3.0 JSON-LD is sometimes published as a bare element array.
        for entry in data:
            if isinstance(entry, dict):
                return _detect_from_mapping(entry)
        raise UnsupportedFormatError("Cannot detect SBOM format: the document is an array with no recognisable element")

    if not isinstance(data, dict):
        raise UnsupportedFormatError(f"Cannot detect SBOM format: expected an object, got {type(data).__name__}")

    bom_format = data.get("bomFormat")
    if isinstance(bom_format, str) and bom_format.strip().lower() == "cyclonedx":
        return SbomFormat.CYCLONEDX, normalize_spec_version(data.get("specVersion"))

    spdx_version = data.get("spdxVersion")
    if isinstance(spdx_version, str) and spdx_version.strip():
        return SbomFormat.SPDX, normalize_spec_version(spdx_version)

    # SPDX 3.0 JSON-LD: a @context pointing at spdx.org plus an element graph.
    context = data.get("@context")
    contexts = context if isinstance(context, list) else [context]
    for entry in contexts:
        if isinstance(entry, str) and "spdx.org" in entry:
            match = _SPDX3_CONTEXT.search(entry)
            return SbomFormat.SPDX, match.group(1) if match else "3.0"

    if isinstance(data.get("@graph"), list) or isinstance(data.get("elements"), list):
        elements = data.get("@graph") or data.get("elements")
        version = _spdx3_version_from_elements(elements)
        if version is not None:
            return SbomFormat.SPDX, version

    # SPDX 2.x without a spdxVersion (some hand-written documents).
    if "creationInfo" in data and ("packages" in data or "relationships" in data):
        return SbomFormat.SPDX, "2.3"

    if "components" in data and ("dependencies" in data or "metadata" in data):
        return SbomFormat.CYCLONEDX, normalize_spec_version(data.get("specVersion")) or "1.5"

    raise UnsupportedFormatError(
        "Cannot detect SBOM format: the document has neither a CycloneDX 'bomFormat' key nor an SPDX 'spdxVersion' key"
    )


def _spdx3_version_from_elements(elements: object) -> str | None:
    """Find the spec version inside an SPDX 3.0 element graph, if stated."""
    if not isinstance(elements, list):
        return None
    for element in elements:
        if not isinstance(element, dict):
            continue
        spec_version = element.get("specVersion")
        if isinstance(spec_version, str) and spec_version.strip():
            return normalize_spec_version(spec_version)
        if str(element.get("@type", "")).lower().endswith("spdxdocument"):
            context = element.get("@context")
            if isinstance(context, str):
                match = _SPDX3_CONTEXT.search(context)
                if match:
                    return match.group(1)
            return "3.0"
    return None


def _detect_from_tag_value(text: str) -> tuple[SbomFormat, str]:
    match = re.search(r"^\s*SPDXVersion\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if match:
        return SbomFormat.SPDX, normalize_spec_version(match.group(1))
    return SbomFormat.SPDX, ""


def _detect_from_xml(content: bytes | str) -> tuple[SbomFormat, str]:
    """Classify an XML document, preferring a real parse over text scanning."""
    raw = content if isinstance(content, bytes) else to_text(content).encode()

    root = _parse_xml_root(raw)
    if root is not None:
        detected = _detect_from_xml_root(root)
        if detected is not None:
            return detected

    text = to_text(content)
    return _detect_from_loose_text(text)


def parse_xml_root(raw: bytes) -> etree._Element:
    """Parse *raw* strictly, refusing entity expansion.

    SBOMs arrive from third parties, so the parser must not read local files or
    expand entities.  Unlike :func:`detect_format`, a malformed document is a
    hard failure here rather than a signal to fall back to text scanning.

    Raises:
        MalformedDocumentError: if *raw* is not well-formed XML.
    """
    parser = etree.XMLParser(recover=False, resolve_entities=False, huge_tree=False, load_dtd=False)
    try:
        root = etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise MalformedDocumentError(f"Document is not well-formed XML: {exc}") from exc
    if root is None:  # pragma: no cover - defensive, lxml raises instead
        raise MalformedDocumentError("Document is empty")
    return root


def _parse_xml_root(raw: bytes) -> etree._Element | None:
    """Return the root element, or ``None`` when the document is malformed.

    Deliberately tolerant (``recover=True``) and distinct from
    :func:`parse_xml_root`: detection wants a partial tree to look at, parsing
    wants a guarantee.
    """
    parser = etree.XMLParser(recover=True, resolve_entities=False, huge_tree=False)
    try:
        return etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError:
        return None


def _detect_from_xml_root(root: etree._Element) -> tuple[SbomFormat, str] | None:
    """Classify an XML document from its root element, or ``None`` if unknown."""
    tag = root.tag
    if not isinstance(tag, str):  # comment or processing instruction
        return None

    namespace, _, localname = tag.rpartition("}")
    namespace = namespace.lstrip("{")
    localname = localname.lower()

    if "cyclonedx.org" in namespace or (localname == "bom" and not namespace):
        version = normalize_spec_version(root.get("specVersion"))
        if not version:
            match = _CDX_NAMESPACE.search(namespace)
            version = match.group(1) if match else ""
        return SbomFormat.CYCLONEDX, version

    if "spdx.org" in namespace or localname in {"spdxdocument", "rdf"}:
        version = _spdx_version_from_xml(root)
        # An RDF root only counts as SPDX when it actually carries SPDX terms.
        if not version and localname == "rdf":
            serialised = etree.tostring(root, encoding="unicode")
            if "spdx.org" not in serialised[:_HEADER_CHARS]:
                return None
        return SbomFormat.SPDX, version

    return None


def _spdx_version_from_xml(root: etree._Element) -> str:
    """Pull ``specVersion`` out of an SPDX XML/RDF tree, if it is stated."""
    for element in root.iter():
        element_tag = element.tag
        if isinstance(element_tag, str) and element_tag.rpartition("}")[2].lower() == "specversion":
            version = normalize_spec_version((element.text or "").strip())
            if version:
                return version

    for value in root.attrib.values():
        match = _SPDX_VERSION.search(str(value))
        if match:
            return match.group(1)
    return ""


def _detect_from_loose_text(text: str) -> tuple[SbomFormat, str]:
    """Regex-based detection used when structured parsing is not possible."""
    header = text[:_HEADER_CHARS]

    if "bomFormat" in header and "CycloneDX" in header:
        match = re.search(r'"specVersion"\s*:\s*"([^"]+)"', text)
        return SbomFormat.CYCLONEDX, normalize_spec_version(match.group(1)) if match else ""

    namespace_match = _CDX_NAMESPACE.search(header)
    if namespace_match:
        return SbomFormat.CYCLONEDX, namespace_match.group(1)

    if "spdxVersion" in header or "SPDXVersion" in header or "spdx.org" in header or "<SpdxDocument" in header:
        match = _SPDX_VERSION.search(text)
        return SbomFormat.SPDX, match.group(1) if match else ""

    raise UnsupportedFormatError("Cannot detect SBOM format: no CycloneDX or SPDX markers were found in the document")
