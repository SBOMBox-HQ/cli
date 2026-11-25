"""Exception hierarchy for ``sbombox_core``.

Every error raised by the library derives from :class:`SbomboxError`, so callers
can catch a single type.  The subclasses exist so the CLI and API can translate
failures into the right exit code or HTTP status without string matching.
"""

from __future__ import annotations

__all__ = [
    "MalformedDocumentError",
    "SbomParseError",
    "SbomValidationError",
    "SbomboxError",
    "UnsupportedFormatError",
]


class SbomboxError(Exception):
    """Base class for every error raised by ``sbombox_core``."""


class SbomParseError(SbomboxError, ValueError):
    """Raised when a document cannot be parsed into an :class:`~sbombox_core.model.Sbom`.

    Inherits from :class:`ValueError` so callers that only expect ``ValueError``
    from JSON/YAML decoding keep working.
    """


class UnsupportedFormatError(SbomParseError):
    """Raised when the input is an SBOM format or variant SBOMBox cannot read."""


class MalformedDocumentError(SbomParseError):
    """Raised when the input is a supported serialisation that cannot be decoded.

    Kept apart from :class:`UnsupportedFormatError` because the two mean
    different things to a caller: an unsupported format is a 415/"wrong file",
    a malformed document is a 422/"your file is corrupt".
    """


class SbomValidationError(SbomboxError):
    """Raised when a document is structurally invalid and cannot be recovered."""
