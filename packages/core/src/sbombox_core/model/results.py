"""Result models produced by the scoring, compliance, diff and fix engines.

These are the *outputs* of a run.  They are plain data with no behaviour beyond
small derived helpers, so they can be serialised straight into a JSON report,
stored by the API, or rendered by the CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sbombox_core.model.component import Component
from sbombox_core.model.sbom import Sbom

__all__ = [
    "ComplianceResult",
    "ComponentChange",
    "DiffResult",
    "FixChange",
    "FixResult",
    "Grade",
    "RequirementResult",
    "ScoreCategory",
    "ScoreFeature",
    "ScoreResult",
]


class ScoreFeature(BaseModel):
    """One measurable feature contributing to a category score.

    ``score`` is the normalised 0-10 value; ``numerator``/``denominator`` keep
    the raw counts so reports can say *"42 of 50 components have a purl"*
    instead of just ``8.4``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str
    score: float = 0.0
    numerator: int = 0
    denominator: int = 0
    description: str = ""

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: object) -> object:
        if value is None:
            return 0.0
        return value

    @property
    def ratio(self) -> float:
        """Return ``numerator / denominator``, or ``0.0`` when empty."""
        return self.numerator / self.denominator if self.denominator else 0.0


class ScoreCategory(BaseModel):
    """A weighted group of features - for example *completeness* or *freshness*."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str
    score: float = 0.0
    weight: float = 1.0
    features: list[ScoreFeature] = Field(default_factory=list)

    @property
    def weighted_score(self) -> float:
        """Return ``score * weight``."""
        return self.score * self.weight


class Grade(StrEnum):
    """Letter grade derived from a 0-10 score."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @classmethod
    def from_score(cls, score: float) -> Grade:
        """Map a 0-10 score onto a letter grade (A >= 9, B >= 8, C >= 7, D >= 6)."""
        if score >= 9:
            return cls.A
        if score >= 8:
            return cls.B
        if score >= 7:
            return cls.C
        if score >= 6:
            return cls.D
        return cls.F


class ScoreResult(BaseModel):
    """The outcome of scoring one SBOM against a ruleset profile."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    total: float = 0.0
    grade: Grade = Grade.F
    categories: list[ScoreCategory] = Field(default_factory=list)
    run_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    core_version: str = ""
    ruleset_version: str = ""
    profile: str = ""

    @field_validator("grade", mode="before")
    @classmethod
    def _coerce_grade(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().upper() or Grade.F.value
        return value


class RequirementResult(BaseModel):
    """The outcome of a single compliance requirement check."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str  # noqa: A003
    title: str
    section_ref: str | None = None
    level: Literal["required", "optional"] = "required"
    status: Literal["pass", "partial", "fail"] = "fail"
    affected: int = 0
    total: int = 0
    message: str = ""
    fix_hint: str | None = None

    @property
    def is_passing(self) -> bool:
        """Return ``True`` for a fully satisfied requirement."""
        return self.status == "pass"

    @property
    def ratio(self) -> float:
        """Return ``affected / total``, or ``0.0`` when the check is not scoped."""
        return self.affected / self.total if self.total else 0.0


class ComplianceResult(BaseModel):
    """The outcome of checking an SBOM against a compliance profile."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    profile: str
    profile_version: str = ""
    requirements: list[RequirementResult] = Field(default_factory=list)
    required_score: float = 0.0
    optional_score: float = 0.0
    overall: float = 0.0
    status: Literal["conforms", "minor_gaps", "partial", "does_not_conform"] = "does_not_conform"
    recommendations: list[str] = Field(default_factory=list)
    run_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    core_version: str = ""
    ruleset_version: str = ""

    def requirements_for(self, level: Literal["required", "optional"]) -> list[RequirementResult]:
        """Return the requirement results at the given level."""
        return [requirement for requirement in self.requirements if requirement.level == level]

    @property
    def failing_required(self) -> list[RequirementResult]:
        """Return required requirements that did not fully pass."""
        return [
            requirement
            for requirement in self.requirements
            if requirement.level == "required" and requirement.status != "pass"
        ]


class ComponentChange(BaseModel):
    """A field-level change to a component between two SBOM revisions."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    component: Component
    fields_changed: list[str] = Field(default_factory=list)
    old_values: dict[str, Any] = Field(default_factory=dict)
    new_values: dict[str, Any] = Field(default_factory=dict)


class DiffResult(BaseModel):
    """The delta between two SBOMs (typically two builds of the same product)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    added: list[Component] = Field(default_factory=list)
    removed: list[Component] = Field(default_factory=list)
    changed: list[ComponentChange] = Field(default_factory=list)
    dependency_added: list[str] = Field(default_factory=list)
    dependency_removed: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Return ``True`` when nothing at all changed."""
        return not (self.added or self.removed or self.changed or self.dependency_added or self.dependency_removed)

    def summary(self) -> dict[str, int]:
        """Return per-kind change counts for one-line CLI output."""
        return {
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "dependency_added": len(self.dependency_added),
            "dependency_removed": len(self.dependency_removed),
        }


class FixChange(BaseModel):
    """A description of one automated remediation applied to an SBOM."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    rule: str
    description: str = ""
    affected_count: int = 0


class FixResult(BaseModel):
    """The repaired SBOM plus a changelog of what the fixer did."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    sbom: Sbom
    changes: list[FixChange] = Field(default_factory=list)

    @property
    def total_affected(self) -> int:
        """Return the summed ``affected_count`` across all applied changes."""
        return sum(change.affected_count for change in self.changes)

    @property
    def was_modified(self) -> bool:
        """Return ``True`` when at least one fix was applied."""
        return bool(self.changes)
