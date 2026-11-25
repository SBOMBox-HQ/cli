"""SBOM parsing - the single entry point for turning documents into models.

:func:`parse_sbom` accepts raw bytes or text, works out which specification and
serialisation the document uses, and hands it to the matching parser.  Callers
that already know the answer can pass a ``filename`` hint or an explicit
``format``, which is useful when a document is delivered over HTTP without a
name and the container detection is ambiguous.

Everything here is offline: no schema is downloaded and no network call is made.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML

from sbombox_core.errors import MalformedDocumentError, SbomParseError, UnsupportedFormatError
from sbombox_core.model.sbom import Sbom, SbomFormat
from sbombox_core.parse.cyclonedx import parse_cyclonedx_json, parse_cyclonedx_xml
from sbombox_core.parse.sniff import (
    ContainerKind,
    detect_container,
    detect_format,
    normalize_spec_version,
    to_text,
)
from sbombox_core.parse.spdx import parse_spdx_json, parse_spdx_tag_value, parse_spdx_xml

__all__ = [
    "parse_sbom",
    "read_sbom_file",
]

#: A reader decodes one container and delegates to a format-specific parser.
_Reader = Callable[[bytes | str, str, str], Sbom]

#: File extensions that identify a serialisation without looking at the content.
_EXTENSION_CONTAINERS: dict[str, ContainerKind] = {
    ".json": ContainerKind.JSON,
    ".jsonld": ContainerKind.JSON,
    ".xml": ContainerKind.XML,
    ".rdf": ContainerKind.XML,
    ".yaml": ContainerKind.YAML,
    ".yml": ContainerKind.YAML,
    ".spdx": ContainerKind.TAG_VALUE,
    ".tv": ContainerKind.TAG_VALUE,
}


def parse_sbom(
    content: bytes | str,
    filename: str | None = None,
    *,
    format: str | SbomFormat | None = None,  # noqa: A002 - mirrors the public CLI flag
) -> Sbom:
    """Parse an SBOM document into an :class:`~sbombox_core.model.sbom.Sbom`.

    The specification (CycloneDX or SPDX) and the serialisation (JSON, XML,
    YAML or SPDX tag-value) are both detected from *content*; *filename* is only
    consulted as a tie-breaker and *format* as an override.

    Args:
        content: The document, as bytes or text.
        filename: Optional original file name, used to infer the serialisation.
        format: Optional format hint, ``"cyclonedx"`` or ``"spdx"``.

    Returns:
        The parsed :class:`Sbom`.  The original document is retained on
        :attr:`Sbom.raw_data` so callers can round-trip it.

    Raises:
        UnsupportedFormatError: if the document is not CycloneDX or SPDX.
        SbomParseError: if the document is recognised but cannot be read.
    """
    if content is None:
        raise SbomParseError("No content to parse")

    text = to_text(content)
    if not text.strip():
        raise SbomParseError("The document is empty")

    hint = _as_format(format)
    detected_format, detected_version = _detect(text, content, hint)

    if hint is not None and detected_format is not hint:
        raise UnsupportedFormatError(f"Document was declared {hint.value} but looks like {detected_format.value}")

    container = _container(text, filename)
    parser = _select_parser(detected_format, container)
    return parser(content, text, detected_version)


def read_sbom_file(path: str | Path) -> Sbom:
    """Read and parse the SBOM stored at *path*.

    Raises:
        SbomParseError: if the file cannot be read.
    """
    location = Path(path)
    try:
        raw = location.read_bytes()
    except OSError as exc:
        raise SbomParseError(f"Could not read {location}: {exc}") from exc
    return parse_sbom(raw, filename=location.name)


# --------------------------------------------------------------------------- #
# routing
# --------------------------------------------------------------------------- #


def _detect(text: str, content: bytes | str, hint: SbomFormat | None) -> tuple[SbomFormat, str]:
    """Return the ``(format, spec_version)`` pair, honouring an explicit hint.

    Detection failures are passed through untouched: :mod:`.sniff` already
    distinguishes "this is not an SBOM" (:class:`UnsupportedFormatError`) from
    "this is a broken SBOM" (:class:`MalformedDocumentError`), and flattening
    the two would throw away the one detail a user can act on.
    """
    try:
        return detect_format(content)
    except ValueError as exc:
        if hint is not None:
            # With an explicit hint we can still route on the container alone.
            return hint, _version_from_text(text, hint)
        if isinstance(exc, SbomParseError):
            raise
        raise UnsupportedFormatError(str(exc)) from exc


def _version_from_text(text: str, hint: SbomFormat) -> str:
    """Best-effort version scrape used only when detection failed outright."""
    marker = "spdxversion" if hint is SbomFormat.SPDX else "specversion"
    for line in text.splitlines()[:200]:
        if marker not in line.lower():
            continue
        _, _, value = line.partition(":")
        version = normalize_spec_version(value.strip().strip("\"',"))
        if version:
            return version
    return ""


def _container(text: str, filename: str | None) -> ContainerKind:
    """Determine the serialisation, falling back to the file extension."""
    kind = detect_container(text)
    if kind is not ContainerKind.UNKNOWN:
        return kind
    if filename:
        return _EXTENSION_CONTAINERS.get(Path(filename).suffix.lower(), ContainerKind.UNKNOWN)
    return ContainerKind.UNKNOWN


def _select_parser(fmt: SbomFormat, container: ContainerKind) -> _Reader:
    """Return the reader callable for a ``(format, container)`` pair."""
    if fmt is SbomFormat.CYCLONEDX:
        if container is ContainerKind.XML:
            return _read_cyclonedx_xml
        return _read_cyclonedx_json
    if container is ContainerKind.TAG_VALUE:
        return _read_spdx_tag_value
    if container is ContainerKind.XML:
        return _read_spdx_xml
    return _read_spdx_json


def _as_format(value: str | SbomFormat | None) -> SbomFormat | None:
    if value is None:
        return None
    if isinstance(value, SbomFormat):
        return value
    text = str(value).strip().lower()
    if text in {"cyclonedx", "cdx", "cyclone-dx", "1"}:
        return SbomFormat.CYCLONEDX
    if text in {"spdx", "spdx2", "spdx3", "2"}:
        return SbomFormat.SPDX
    raise UnsupportedFormatError(f"Unknown SBOM format {value!r}: expected 'cyclonedx' or 'spdx'")


# --------------------------------------------------------------------------- #
# readers: each decodes the container then calls the format-specific parser
# --------------------------------------------------------------------------- #


def _read_cyclonedx_json(content: bytes | str, text: str, version: str) -> Sbom:
    data = _decode_jsonish(text)
    return parse_cyclonedx_json(_as_mapping(data, "CycloneDX"))


def _read_cyclonedx_xml(content: bytes | str, text: str, version: str) -> Sbom:
    return parse_cyclonedx_xml(content if isinstance(content, bytes) else text.encode())


def _read_spdx_json(content: bytes | str, text: str, version: str) -> Sbom:
    data = _decode_jsonish(text)
    if isinstance(data, list):
        # SPDX 3.0 is occasionally published as a bare element array.
        data = {"@graph": data}
    return parse_spdx_json(_as_mapping(data, "SPDX"))


def _read_spdx_xml(content: bytes | str, text: str, version: str) -> Sbom:
    return parse_spdx_xml(content if isinstance(content, bytes) else text.encode())


def _read_spdx_tag_value(content: bytes | str, text: str, version: str) -> Sbom:
    return parse_spdx_tag_value(text)


def _decode_jsonish(text: str) -> object:
    """Decode JSON, falling back to YAML (JSON is a subset of YAML anyway)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    return _decode_yaml(text)


def _decode_yaml(text: str) -> object:
    yaml = YAML(typ="safe")
    try:
        return yaml.load(StringIO(text))
    except Exception as exc:  # noqa: BLE001 - ruamel raises its own hierarchy
        raise MalformedDocumentError(f"The document is not valid JSON or YAML: {exc}") from exc


def _as_mapping(data: object, label: str) -> dict:
    if isinstance(data, dict):
        return data
    raise SbomParseError(f"{label} documents must be objects, got {type(data).__name__}")
