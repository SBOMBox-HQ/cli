"""CycloneDX parsers (JSON and XML) for spec versions 1.4 through 1.7.

CycloneDX is the richer of the two formats SBOMBox reads, and its field names
are close enough to the internal model that parsing is mostly a matter of
key normalisation plus a few shape fix-ups for the 1.4 -> 1.5 ``tools``
migration.  Both entry points funnel into :func:`parse_cyclonedx_json`; the XML
reader converts the tree into the equivalent JSON-shaped dictionaries first so
there is exactly one mapping to maintain.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from sbombox_core.errors import SbomParseError
from sbombox_core.model.sbom import Sbom, SbomFormat
from sbombox_core.parse.sniff import normalize_spec_version, parse_xml_root, to_text

if TYPE_CHECKING:
    from collections.abc import Callable

    from lxml import etree

__all__ = [
    "SUPPORTED_SPEC_VERSIONS",
    "cyclonedx_xml_to_dict",
    "parse_cyclonedx_json",
    "parse_cyclonedx_xml",
]

#: Spec versions the parser is tested against.  Documents outside this set are
#: still parsed on a best-effort basis - the field vocabulary is a superset -
#: but validation will flag the version as unsupported.
SUPPORTED_SPEC_VERSIONS: tuple[str, ...] = ("1.4", "1.5", "1.6", "1.7")

#: CycloneDX namespaces by spec version, used to recognise XML documents.
BOM_NAMESPACES: dict[str, str] = {
    version: f"http://cyclonedx.org/schema/bom/{version}"
    for version in ("1.0", "1.1", "1.2", "1.3", *SUPPORTED_SPEC_VERSIONS)
}


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def parse_cyclonedx_json(data: dict) -> Sbom:
    """Parse a decoded CycloneDX JSON (or YAML) document into an :class:`Sbom`.

    Args:
        data: The document as a mapping, typically from :func:`json.loads`.

    Raises:
        SbomParseError: if *data* is not a mapping or is not a CycloneDX BOM.
    """
    if not isinstance(data, dict):
        raise SbomParseError(f"CycloneDX documents must be JSON objects, got {type(data).__name__}")

    bom_format = data.get("bomFormat")
    if bom_format is not None and str(bom_format).strip().lower() != "cyclonedx":
        raise SbomParseError(f"Document declares bomFormat={bom_format!r}, expected 'CycloneDX'")

    spec_version = normalize_spec_version(data.get("specVersion"))

    payload: dict[str, Any] = {
        "format": SbomFormat.CYCLONEDX,
        "spec_version": spec_version,
        "metadata": _as_mapping(data.get("metadata")),
        "components": _as_list(data.get("components")),
        "dependencies": _as_list(data.get("dependencies")),
        "vulnerabilities": _as_list(data.get("vulnerabilities")),
        "services": _as_list(data.get("services")),
        "external_references": _as_list(data.get("externalReferences")),
        "raw_data": data,
    }

    try:
        return Sbom.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - re-raised with document context
        raise SbomParseError(f"Could not read the CycloneDX document: {exc}") from exc


# --------------------------------------------------------------------------- #
# XML
# --------------------------------------------------------------------------- #


def parse_cyclonedx_xml(content: bytes) -> Sbom:
    """Parse a CycloneDX XML document into an :class:`Sbom`.

    The XML tree is rewritten as the equivalent JSON-shaped dictionaries and
    handed to :func:`parse_cyclonedx_json`, so both serialisations share one
    field mapping.  ``raw_data`` therefore holds the *converted* document rather
    than the original bytes.

    Raises:
        SbomParseError: if the content is not well-formed XML or has a
            non-``bom`` root element.
    """
    raw = content if isinstance(content, bytes) else to_text(content).encode()
    root = parse_xml_root(raw)

    if _localname(root) != "bom":
        raise SbomParseError(f"Not a CycloneDX document: expected a <bom> root element, got <{_localname(root)}>")

    return parse_cyclonedx_json(cyclonedx_xml_to_dict(root))


def cyclonedx_xml_to_dict(root: etree._Element) -> dict[str, Any]:
    """Convert a CycloneDX ``<bom>`` element into its JSON-equivalent mapping.

    Exposed because the writer and the schema validator need the same
    normalised view of an XML document.
    """
    data: dict[str, Any] = {"bomFormat": "CycloneDX"}

    for name, value in root.attrib.items():
        if "}" not in name:  # skip namespaced attributes such as xsi:schemaLocation
            data[name] = value

    namespace = _namespace(root)
    if not data.get("specVersion") and namespace:
        # ``xmlns="http://cyclonedx.org/schema/bom/1.5"`` carries the version.
        data["specVersion"] = normalize_spec_version(namespace)

    for child in _element_children(root):
        data[_localname(child)] = _convert_element(child)
    return data


# -- generic XML -> JSON conversion ------------------------------------------ #


def _element_children(element: etree._Element) -> list[etree._Element]:
    """Return real child elements, skipping comments and processing instructions."""
    return [child for child in element if isinstance(child.tag, str)]


def _localname(element: etree._Element) -> str:
    tag = element.tag
    return tag.rpartition("}")[2] if isinstance(tag, str) else ""


def _namespace(element: etree._Element) -> str:
    tag = element.tag
    if not isinstance(tag, str):
        return ""
    namespace, _, _ = tag.rpartition("}")
    return namespace.lstrip("{")


def _element_text(element: etree._Element) -> str | None:
    text = (element.text or "").strip()
    return text or None


def _as_list_of_objects(element: etree._Element) -> list[Any]:
    return [_convert_element(child) for child in _element_children(element)]


def _as_list_of_text(element: etree._Element) -> list[Any]:
    return [_element_text(child) or "" for child in _element_children(element)]


def _hash_element(element: etree._Element) -> dict[str, Any]:
    """``<hash alg="SHA-256">hex</hash>`` -> ``{"alg": .., "content": ..}``."""
    return {"alg": element.get("alg") or "", "content": _element_text(element) or ""}


def _property_element(element: etree._Element) -> dict[str, Any]:
    """``<property name="k">v</property>`` -> ``{"name": "k", "value": "v"}``."""
    return {"name": element.get("name") or "", "value": _element_text(element) or ""}


def _license_choice_element(element: etree._Element) -> dict[str, Any]:
    """``<license>`` and ``<expression>`` both live inside ``<licenses>``."""
    if _localname(element) == "expression":
        return {"expression": _element_text(element) or ""}
    return {"license": _convert_element(element)}


def _dependency_element(element: etree._Element) -> dict[str, Any]:
    """Convert one ``<dependency>`` into its JSON equivalent.

    CycloneDX XML nests the edges - ``<dependency ref="a"><dependency
    ref="b"/></dependency>`` - where JSON spells them ``{"ref": "a", "dependsOn":
    ["b"]}``.  A ``<dependsOn>`` child is accepted too, since some producers
    emit it.
    """
    depends_on: list[str] = []
    for child in _element_children(element):
        name = _localname(child)
        if name == "dependency":
            ref = child.get("ref") or _element_text(child) or ""
        elif name == "dependsOn":
            ref = _element_text(child) or ""
        else:
            continue
        if ref and ref not in depends_on:
            depends_on.append(ref)
    return {"ref": element.get("ref") or "", "dependsOn": depends_on}


def _affects_element(element: etree._Element) -> list[Any]:
    """``<affects><target><ref>x</ref></target></affects>`` -> ``[{"ref": "x"}]``."""
    targets: list[Any] = []
    for child in _element_children(element):
        converted = _convert_element(child)
        if _localname(child) == "target" and not isinstance(converted, dict):
            converted = {"ref": converted}
        targets.append(converted)
    return targets


def _dataflow_element(element: etree._Element) -> dict[str, Any]:
    """``<dataflow flow="inbound" classification="public">name</dataflow>``."""
    return {
        "flow": element.get("flow") or element.get("type") or "",
        "classification": element.get("classification") or "",
        "name": _element_text(element),
    }


def _tools_element(element: etree._Element) -> Any:
    """Handle both the 1.4 ``<tool>`` list and the 1.5+ ``<components>`` object."""
    children = _element_children(element)
    names = {_localname(child) for child in children}
    if "components" in names or "services" in names:
        return _object_element(element)
    return [_convert_element(child) for child in children]


#: Container elements that serialise a JSON array, keyed by element name.
_LIST_CONTAINERS: dict[str, Callable[[etree._Element], Any]] = {
    "advisories": _as_list_of_objects,
    "affects": _affects_element,
    "authors": _as_list_of_objects,
    "components": _as_list_of_objects,
    "contacts": _as_list_of_objects,
    "cwes": _as_list_of_text,
    "data": lambda el: [_dataflow_element(c) for c in _element_children(el)],
    "dependencies": lambda el: [_dependency_element(c) for c in _element_children(el)],
    "endpoints": _as_list_of_text,
    "externalReferences": _as_list_of_objects,
    "hashes": lambda el: [_hash_element(c) for c in _element_children(el)],
    "licenses": lambda el: [_license_choice_element(c) for c in _element_children(el)],
    "properties": lambda el: [_property_element(c) for c in _element_children(el)],
    "ratings": _as_list_of_objects,
    "recommendations": _as_list_of_text,
    "references": _as_list_of_objects,
    "response": _as_list_of_text,
    "services": _as_list_of_objects,
    "tags": _as_list_of_text,
    "tools": _tools_element,
    "urls": _as_list_of_text,
    "versions": _as_list_of_objects,
    "vulnerabilities": _as_list_of_objects,
}


def _convert_element(element: etree._Element) -> Any:
    """Convert one XML element into its JSON-equivalent value."""
    handler = _LIST_CONTAINERS.get(_localname(element))
    if handler is not None:
        return handler(element)
    return _object_element(element)


def _object_element(element: etree._Element) -> Any:
    """Convert an element into a mapping, a string, or a list of either.

    Attributes become keys (so ``bom-ref`` survives), repeated child elements
    collapse into arrays, and an element with both attributes and text stores
    the text under ``content`` - which is exactly how CycloneDX JSON spells
    ``hash``, ``property`` and license ``text``.
    """
    result: dict[str, Any] = {name: value for name, value in element.attrib.items() if "}" not in name}

    children = _element_children(element)
    if not children:
        text = _element_text(element)
        if text is None:
            return result or None
        if result:
            result["content"] = text
            return result
        return text

    occurrences = Counter(_localname(child) for child in children)
    for child in children:
        name = _localname(child)
        value = _convert_element(child)
        if occurrences[name] > 1:
            result.setdefault(name, []).append(value)
        else:
            result[name] = value
    return result


# --------------------------------------------------------------------------- #
# small input helpers
# --------------------------------------------------------------------------- #


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """Coerce a section value to a list, tolerating scalar and object shapes."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return [value]
