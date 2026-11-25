"""The dependency graph edges of an SBOM."""

from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

__all__ = ["Dependency"]


class Dependency(BaseModel):
    """A node in the dependency graph and the refs it directly depends on.

    ``ref`` and every entry of ``depends_on`` are bom-refs (CycloneDX) or SPDX
    identifiers; both are kept verbatim so the graph can be written back out
    losslessly.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    ref: str
    depends_on: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("depends_on", "dependsOn", "dependencies"),
    )

    @field_validator("depends_on", mode="before")
    @classmethod
    def _coerce_depends_on(cls, value: object) -> object:
        """Accept a single string ref where an array is expected."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    @property
    def is_leaf(self) -> bool:
        """Return ``True`` when this node declares no dependencies."""
        return not self.depends_on

    def refs(self) -> list[str]:
        """Return every ref mentioned by this edge, including the node itself."""
        return [self.ref, *self.depends_on]
