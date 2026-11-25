"""SBOM validation - schema (structural) and semantic checks.

Two layers, deliberately separate:

:func:`validate_schema`
    Works on the *raw* document, before parsing.  It answers "did the producer
    emit something shaped like a CycloneDX/SPDX SBOM?".

:func:`validate_semantic`
    Works on the parsed :class:`~sbombox_core.model.sbom.Sbom`.  It answers "is
    the inventory good enough to score, match vulnerabilities against, or check
    for compliance?".

:func:`validate_document` runs both, which is what the CLI and API want;
:func:`validate_sbom` runs only the semantic layer, which is what callers that
already hold an ``Sbom`` want.

Nothing here touches the network: an SBOM that cannot be checked offline should
not be reported as valid just because a lookup timed out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sbombox_core.errors import SbomParseError
from sbombox_core.parse import parse_sbom
from sbombox_core.validate.schema import (
    ValidationError,
    validate_cyclonedx_schema,
    validate_schema,
    validate_spdx_schema,
)
from sbombox_core.validate.semantic import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
    validate_semantic,
)

if TYPE_CHECKING:
    from sbombox_core.model.sbom import Sbom, SbomFormat

__all__ = [
    "ValidationError",
    "ValidationIssue",
    "ValidationResult",
    "ValidationSeverity",
    "validate_cyclonedx_schema",
    "validate_document",
    "validate_sbom",
    "validate_schema",
    "validate_semantic",
    "validate_spdx_schema",
]


def validate_sbom(sbom: Sbom) -> ValidationResult:
    """Run the semantic checks against an already-parsed *sbom*.

    The result is never fatal: an SBOM full of problems still returns a
    :class:`ValidationResult`, with :attr:`ValidationResult.valid` set to
    ``False`` when any finding is an error.
    """
    return validate_semantic(sbom)


def validate_document(
    content: bytes | str,
    filename: str | None = None,
    *,
    format: str | SbomFormat | None = None,  # noqa: A002 - mirrors the public CLI flag
    version: str = "",
) -> ValidationResult:
    """Validate a raw document through both layers.

    Args:
        content: The document, as bytes or text.
        filename: Optional original file name, used to infer the serialisation.
        format: Optional format hint, ``"cyclonedx"`` or ``"spdx"``.
        version: Expected spec version, compared against what the document says.

    Returns:
        The merged schema and semantic findings.  When the document cannot be
        parsed at all, the schema findings are returned with a single error
        explaining the parse failure - that is far more actionable than a stack
        trace, and it is why the structural layer runs first.

    Note:
        Paths from the schema layer index the *raw* document, while paths from
        the semantic layer index the *parsed* model.  The two diverge when the
        parser dropped an entry, which is itself reported.  Findings that both
        layers phrase identically are de-duplicated so the merged list stays
        readable.
    """
    issues: list[ValidationIssue] = list(validate_schema(content, format, version))

    try:
        sbom = parse_sbom(content, filename, format=format)
    except SbomParseError as exc:
        return ValidationResult(valid=False, issues=_with_parse_failure(issues, exc))

    issues.extend(validate_semantic(sbom).issues)
    issues = _unique(issues)
    valid = not any(issue.severity is ValidationSeverity.ERROR for issue in issues)
    return ValidationResult(valid=valid, issues=issues)


def _with_parse_failure(issues: list[ValidationIssue], exc: SbomParseError) -> list[ValidationIssue]:
    """Append the parse failure unless the schema layer already said the same.

    An unrecognisable document fails detection twice - once here, once in the
    parser - for the identical reason.  Reporting it twice tells the user
    nothing new and makes the finding count meaningless.
    """
    message = str(exc)
    if message and not any(message in issue.message for issue in issues):
        issues.append(ValidationIssue(severity=ValidationSeverity.ERROR, message=message))
    if not issues:
        issues.append(ValidationIssue(severity=ValidationSeverity.ERROR, message=message or repr(exc)))
    return _unique(issues)


def _unique(issues: list[ValidationIssue]) -> list[ValidationIssue]:
    """Drop repeats, keeping the first occurrence and the original order.

    Both layers legitimately notice some of the same flaws - a component with
    no name, say - and the caller wants to read about it once.
    """
    seen: set[tuple[ValidationSeverity, str, str | None, str | None]] = set()
    unique: list[ValidationIssue] = []
    for issue in issues:
        key = (issue.severity, issue.message, issue.path, issue.component_ref)
        if key in seen:
            continue
        seen.add(key)
        unique.append(issue)
    return unique
