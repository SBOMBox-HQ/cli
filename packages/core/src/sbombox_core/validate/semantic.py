"""Semantic validation of a parsed :class:`~sbombox_core.model.sbom.Sbom`.

Schema validation answers "is this a well-formed document?"; semantic validation
answers "is this a *useful* one?".  An SBOM can be perfectly valid against its
JSON Schema and still be worthless - every component missing a version, half the
purls malformed, dependency edges pointing at nothing.  The checks here are the
ones that decide whether a score or compliance run can be trusted.

Severity is deliberately conservative: only findings that make the inventory
wrong (a missing name, a duplicated bom-ref) are errors.  Everything that makes
it merely less useful is a warning, so a producer's imperfect output still
flows through the pipeline and surfaces as a report rather than a hard failure.
"""

from __future__ import annotations

from collections import Counter
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from sbombox_core.parse.cyclonedx import SUPPORTED_SPEC_VERSIONS as CYCLONEDX_VERSIONS
from sbombox_core.parse.spdx import SUPPORTED_SPEC_VERSIONS as SPDX_VERSIONS
from sbombox_core.util.hashes import EXPECTED_LENGTHS, normalize_algorithm
from sbombox_core.util.licenses import is_valid_spdx_license
from sbombox_core.util.purl import validate_purl

if TYPE_CHECKING:
    from sbombox_core.model.component import Component
    from sbombox_core.model.sbom import Sbom

__all__ = [
    "ValidationIssue",
    "ValidationResult",
    "ValidationSeverity",
    "validate_semantic",
]


class ValidationSeverity(StrEnum):
    """How much a finding should matter to the caller."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A single finding produced by schema or semantic validation.

    Attributes:
        severity: Whether the finding blocks use of the SBOM.
        message: A human-readable explanation, safe to show to end users.
        path: Pointer into the document, e.g. ``components[3].purl``.
        component_ref: The bom-ref of the component the finding is about, when
            the finding is component-scoped.
    """

    model_config = ConfigDict(populate_by_name=True)

    severity: ValidationSeverity
    message: str
    path: str | None = None
    component_ref: str | None = None


class ValidationResult(BaseModel):
    """The outcome of a validation run."""

    model_config = ConfigDict(populate_by_name=True)

    valid: bool
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        """Only the findings that make the SBOM unusable."""
        return [issue for issue in self.issues if issue.severity is ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Only the findings that reduce the SBOM's usefulness."""
        return [issue for issue in self.issues if issue.severity is ValidationSeverity.WARNING]

    @property
    def infos(self) -> list[ValidationIssue]:
        """Only the purely informational findings."""
        return [issue for issue in self.issues if issue.severity is ValidationSeverity.INFO]

    def count(self, severity: ValidationSeverity) -> int:
        """Return how many findings carry *severity*."""
        return sum(1 for issue in self.issues if issue.severity is severity)

    def summary(self) -> dict[str, int | bool]:
        """Return small counts for logs, CLI output and API responses."""
        return {
            "valid": self.valid,
            "errors": self.count(ValidationSeverity.ERROR),
            "warnings": self.count(ValidationSeverity.WARNING),
            "infos": self.count(ValidationSeverity.INFO),
        }


class _Reporter:
    """Collects issues and derives :attr:`ValidationResult.valid` from them."""

    def __init__(self) -> None:
        self.issues: list[ValidationIssue] = []

    def add(
        self,
        severity: ValidationSeverity,
        message: str,
        path: str | None = None,
        component_ref: str | None = None,
    ) -> None:
        self.issues.append(ValidationIssue(severity=severity, message=message, path=path, component_ref=component_ref))

    def error(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.add(ValidationSeverity.ERROR, message, path, component_ref)

    def warning(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.add(ValidationSeverity.WARNING, message, path, component_ref)

    def info(self, message: str, path: str | None = None, component_ref: str | None = None) -> None:
        self.add(ValidationSeverity.INFO, message, path, component_ref)

    def result(self) -> ValidationResult:
        """Return the findings, marking the document invalid on any error."""
        valid = not any(issue.severity is ValidationSeverity.ERROR for issue in self.issues)
        return ValidationResult(valid=valid, issues=self.issues)


def validate_semantic(sbom: Sbom) -> ValidationResult:
    """Run every semantic check against a parsed *sbom*.

    The function never raises and never mutates *sbom*: an SBOM that arrives
    here has already survived parsing, so the job is to describe what survived
    and what did not.
    """
    reporter = _Reporter()

    _check_spec_version(sbom, reporter)
    _check_dropped_entries(sbom, reporter)
    _check_metadata(sbom, reporter)
    _check_inventory(sbom, reporter)
    _check_dependencies(sbom, reporter)

    return reporter.result()


# --------------------------------------------------------------------------- #
# document level
# --------------------------------------------------------------------------- #


def _check_spec_version(sbom: Sbom, reporter: _Reporter) -> None:
    supported = CYCLONEDX_VERSIONS if sbom.format.value == "cyclonedx" else SPDX_VERSIONS
    if not sbom.spec_version:
        reporter.warning(
            f"The document does not declare a {sbom.format.value} spec version",
            path="spec_version",
        )
        return

    major_minor = ".".join(sbom.spec_version.split(".")[:2])
    if major_minor not in supported:
        reporter.warning(
            f"{sbom.format.value} {sbom.spec_version} is not a supported spec version "
            f"(supported: {', '.join(supported)})",
            path="spec_version",
        )


def _check_dropped_entries(sbom: Sbom, reporter: _Reporter) -> None:
    """Surface records the parser had to discard.

    Silently losing components would understate the inventory - and therefore
    the vulnerability exposure - so every drop is reported.
    """
    for section, count in sorted(sbom.dropped_entries.items()):
        reporter.error(
            f"{count} {section} entr{'y' if count == 1 else 'ies'} could not be parsed and "
            f"{'was' if count == 1 else 'were'} dropped",
            path=section,
        )


def _check_metadata(sbom: Sbom, reporter: _Reporter) -> None:
    if sbom.metadata.timestamp is None:
        reporter.warning(
            "The SBOM has no metadata timestamp, so its age cannot be determined",
            path="metadata.timestamp",
        )
    if not sbom.metadata.tools:
        reporter.info(
            "The SBOM does not name the tool that produced it",
            path="metadata.tools",
        )


# --------------------------------------------------------------------------- #
# inventory
# --------------------------------------------------------------------------- #


def _check_inventory(sbom: Sbom, reporter: _Reporter) -> None:
    # The described component is part of the inventory for validation purposes,
    # so it gets the same scrutiny; the path keeps it distinguishable.
    entries: list[tuple[str, Component]] = []
    if sbom.metadata.component is not None:
        entries.append(("metadata.component", sbom.metadata.component))
    entries.extend((f"components[{index}]", component) for index, component in enumerate(sbom.components))

    if not entries:
        reporter.warning("The SBOM contains no components", path="components")

    refs: Counter[str] = Counter()
    purls: Counter[str] = Counter()

    for path, component in entries:
        label = component.display_name()

        if not component.name:
            reporter.error("Component has no name", path=path, component_ref=component.bom_ref)

        if not component.version:
            reporter.warning(
                f"Component {label} has no version, so vulnerabilities cannot be matched to it",
                path=f"{path}.version",
                component_ref=component.bom_ref,
            )

        if component.bom_ref:
            refs[component.bom_ref] += 1

        if component.purl:
            if not validate_purl(component.purl):
                reporter.warning(
                    f"Component {label} has a malformed purl: {component.purl}",
                    path=f"{path}.purl",
                    component_ref=component.bom_ref,
                )
            key = component.purl.lower()
            purls[key] += 1

        _check_licenses(component, f"{path}.licenses", reporter)
        _check_hashes(component, f"{path}.hashes", reporter)

        if not component.licenses:
            reporter.info(
                f"Component {label} declares no license",
                path=f"{path}.licenses",
                component_ref=component.bom_ref,
            )

    for ref, count in refs.items():
        if count > 1:
            reporter.error(
                f"bom-ref {ref!r} is used by {count} components; refs must be unique",
                path="components",
                component_ref=ref,
            )

    for key, count in purls.items():
        if count > 1:
            reporter.warning(
                f"{count} components share the purl {key!r}",
                path="components",
            )


def _check_licenses(component: Component, path: str, reporter: _Reporter) -> None:
    """Flag license identifiers that are not in the SPDX license list."""
    for choice in component.licenses:
        if choice.expression:
            if not is_valid_spdx_license(choice.expression):
                reporter.warning(
                    f"License expression {choice.expression!r} is not a valid SPDX expression",
                    path=path,
                    component_ref=component.bom_ref,
                )
            continue

        license_id = choice.license.id if choice.license is not None else None
        if license_id and not is_valid_spdx_license(license_id):
            reporter.warning(
                f"License id {license_id!r} is not in the SPDX license list",
                path=path,
                component_ref=component.bom_ref,
            )


def _check_hashes(component: Component, path: str, reporter: _Reporter) -> None:
    """Flag digests whose length or alphabet does not match the algorithm."""
    for index, digest in enumerate(component.hashes):
        algorithm = digest.alg.value
        expected = EXPECTED_LENGTHS.get(normalize_algorithm(algorithm) or algorithm)
        if expected is None:
            continue  # HashAlgorithm only admits digests with a known length
        content = digest.content or ""
        digest_path = f"{path}[{index}]"

        if len(content) != expected:
            reporter.warning(
                f"{algorithm} digest is {len(content)} characters long, expected {expected}",
                path=digest_path,
                component_ref=component.bom_ref,
            )
        elif not _is_hex(content):
            reporter.warning(
                f"{algorithm} digest {content!r} is not a hexadecimal string",
                path=digest_path,
                component_ref=component.bom_ref,
            )


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- #
# dependency graph
# --------------------------------------------------------------------------- #


def _check_dependencies(sbom: Sbom, reporter: _Reporter) -> None:
    known = sbom.refs
    if not known:
        return  # nothing to resolve edges against; component checks cover it

    for index, dependency in enumerate(sbom.dependencies):
        if dependency.ref not in known:
            reporter.warning(
                f"Dependency ref {dependency.ref!r} does not match any component, service or vulnerability",
                path=f"dependencies[{index}].ref",
                component_ref=dependency.ref,
            )
        for position, ref in enumerate(dependency.depends_on):
            if ref not in known:
                reporter.warning(
                    f"Dependency {dependency.ref!r} refers to unknown ref {ref!r}",
                    path=f"dependencies[{index}].dependsOn[{position}]",
                    component_ref=dependency.ref,
                )
