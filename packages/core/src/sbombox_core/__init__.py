"""SBOMBox Core - parse, validate, score, and check compliance of SBOMs.

This package is the shared foundation for both the ``sbombox`` CLI and the API
server.  It deliberately has no framework dependencies - no Django, no Typer, no
HTTP client in the import path - so it can be embedded anywhere, and every
operation is offline: a document is never fetched, and no schema is downloaded.

The public surface is intentionally small::

    from sbombox_core import load, validate_sbom

    sbom = load("bom.json")            # path, bytes or text; format auto-detected
    report = validate_sbom(sbom)       # semantic findings, never raises

Callers that need finer control can drop a level: :func:`parse_sbom` for the
parser, :func:`validate_document` for both validation layers over a raw
document, and :mod:`sbombox_core.model` for the data model itself.
"""

from __future__ import annotations

from pathlib import Path

from sbombox_core.compliance import check_compliance
from sbombox_core.diff import diff
from sbombox_core.errors import (
    MalformedDocumentError,
    SbomboxError,
    SbomParseError,
    SbomValidationError,
    UnsupportedFormatError,
)
from sbombox_core.fix import fix
from sbombox_core.model import (
    ComplianceResult,
    Component,
    DiffResult,
    FixResult,
    Sbom,
    SbomFormat,
    ScoreResult,
)
from sbombox_core.normalize import normalize
from sbombox_core.parse import parse_sbom, read_sbom_file
from sbombox_core.score import score
from sbombox_core.validate import (
    ValidationResult,
    validate_document,
    validate_sbom,
)

#: Kept in step with ``[project].version`` in ``pyproject.toml``.  A literal
#: rather than ``importlib.metadata`` so the value is still correct when the
#: package is imported straight from a source tree.
__version__ = "0.1.1"

__all__ = [
    "Component",
    "ComplianceResult",
    "DiffResult",
    "FixResult",
    "MalformedDocumentError",
    "PathOrContent",
    "Sbom",
    "SbomFormat",
    "SbomParseError",
    "SbomValidationError",
    "SbomboxError",
    "ScoreResult",
    "UnsupportedFormatError",
    "ValidationResult",
    "__version__",
    "check_compliance",
    "diff",
    "fix",
    "load",
    "normalize",
    "parse_sbom",
    "read_sbom_file",
    "score",
    "validate_document",
    "validate_sbom",
]

#: What :func:`load` accepts: a filesystem path, or the document itself.
type PathOrContent = str | bytes | bytearray | Path

#: Extensions that identify a file as an SBOM without opening it.
_SBOM_SUFFIXES = frozenset({".json", ".jsonld", ".xml", ".rdf", ".yaml", ".yml", ".spdx", ".tv", ".bom"})

#: Anything longer than this is a document, not a filename.
_MAX_PATH_LENGTH = 4096


def load(path_or_content: PathOrContent, format: str | SbomFormat | None = None) -> Sbom:  # noqa: A002
    """Load an SBOM from a file path, raw bytes, or document text.

    The specification (CycloneDX or SPDX) and the serialisation (JSON, XML,
    YAML or SPDX tag-value) are both detected from the content, so the same
    call handles every document SBOMBox can read.

    Args:
        path_or_content: A filesystem path, or the document itself as ``bytes``
            or ``str``.  A ``str`` is treated as a path when it looks like one
            - see :func:`_is_path_like` - and as content otherwise.
        format: Optional format hint, ``"cyclonedx"`` or ``"spdx"``.  Useful for
            documents delivered without a name whose container is ambiguous.
            A hint that contradicts the content is an error, not a fallback:
            silently parsing SPDX as CycloneDX would produce an empty inventory
            that looks valid.

    Returns:
        The parsed :class:`~sbombox_core.model.Sbom`.

    Raises:
        TypeError: if *path_or_content* is none of the accepted types.
        SbomParseError: if the file cannot be read.
        UnsupportedFormatError: if the content is not a recognised SBOM.
        MalformedDocumentError: if it is a recognised serialisation that is
            broken (truncated JSON, ill-formed XML).
    """
    if isinstance(path_or_content, Path):
        return read_sbom_file(path_or_content)

    if isinstance(path_or_content, (bytes, bytearray)):
        return parse_sbom(bytes(path_or_content), format=format)

    if isinstance(path_or_content, str):
        text = path_or_content
        if _is_path_like(text):
            return read_sbom_file(text)
        return parse_sbom(text, format=format)

    raise TypeError(f"load() expects a path, bytes or str, got {type(path_or_content).__name__}")


def _is_path_like(text: str) -> bool:
    """Decide whether a ``str`` argument names a file rather than holds a document.

    Every serialisation SBOMBox reads starts with markup - ``{`` for JSON, ``<``
    for XML - or spans several lines, and no plausible filename does either.
    What survives that filter is settled by a known SBOM extension, then by the
    shape of the string, then by the filesystem, so ``load("bom.json")`` and
    ``load("out/bom")`` both report a missing file rather than a mysterious
    parse error, while ``load(handle.read())`` parses the text.
    """
    candidate = text.strip()
    if not candidate or len(candidate) > _MAX_PATH_LENGTH:
        return False
    if "\n" in candidate or "\r" in candidate or "\x00" in candidate:
        return False
    if candidate[0] in "{<[":
        return False

    path = Path(candidate)
    if path.suffix.lower() in _SBOM_SUFFIXES:
        return True
    # A dotted or relative/absolute name is a path even when it has no SBOM
    # extension and does not exist yet - the caller meant a file.
    if len(path.parts) > 1 or candidate[0] in ".~":
        return True
    return path.is_file()
