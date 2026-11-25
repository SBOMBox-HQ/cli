"""The normalised SBOM document - the single shape every parser produces.

Whatever the input format (CycloneDX JSON/XML, SPDX JSON/XML/tag-value), the
rest of SBOMBox only ever sees an :class:`Sbom`.  Field names follow CycloneDX
where the two formats overlap, because that vocabulary is the more granular of
the two.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from sbombox_core.model.common import ExternalReference
from sbombox_core.model.component import Component
from sbombox_core.model.dependency import Dependency
from sbombox_core.model.metadata import Metadata
from sbombox_core.model.service import Service
from sbombox_core.model.vulnerability import Vulnerability

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = ["Sbom", "SbomFormat"]

#: ``SPDX-2.3`` -> ``2.3``, ``CycloneDX 1.6`` -> ``1.6``.
_SPEC_VERSION_PREFIX = re.compile(r"^(?:spdx|cyclonedx)[\s\-]*", re.IGNORECASE)

#: Document sections validated entry-by-entry so one bad record cannot sink the
#: whole load, mapped to the model each entry must satisfy.
_SALVAGEABLE_SECTIONS: dict[str, type[BaseModel]] = {
    "components": Component,
    "dependencies": Dependency,
    "services": Service,
    "vulnerabilities": Vulnerability,
}


def _salvage(entries: object, model_cls: type[BaseModel]) -> tuple[list[Any], int]:
    """Validate *entries* one by one, returning ``(kept, dropped_count)``."""
    if not isinstance(entries, list):
        return [], 0

    kept: list[Any] = []
    dropped = 0
    for entry in entries:
        if isinstance(entry, model_cls):
            kept.append(entry)
            continue
        if not isinstance(entry, dict):
            dropped += 1
            continue
        try:
            kept.append(model_cls.model_validate(entry))
        except ValidationError:
            dropped += 1
    return kept, dropped


class SbomFormat(StrEnum):
    """The source specification an SBOM was written in."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class Sbom(BaseModel):
    """A parsed, format-independent Software Bill of Materials."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore", arbitrary_types_allowed=True)

    format: SbomFormat
    spec_version: str = Field(validation_alias=AliasChoices("spec_version", "specVersion"))
    metadata: Metadata = Field(default_factory=Metadata)
    components: list[Component] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    #: Vulnerabilities embedded in the source document.  These are *untrusted*
    #: producer claims: normalisation strips them and the scanner re-derives
    #: vulnerability state from configured advisory sources.
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    external_references: list[ExternalReference] = Field(
        default_factory=list,
        validation_alias=AliasChoices("external_references", "externalReferences"),
    )
    #: The untouched source document, kept so the SBOM can be written back out
    #: without losing fields SBOMBox does not model.
    raw_data: dict | None = None

    #: Counts of entries dropped per section because they could not be modelled
    #: (a missing component ``name``, an unknown enum value, ...).  Excluded
    #: from serialisation on purpose: it is a diagnostic for
    #: :func:`sbombox_core.validate.validate_semantic`, not document content.
    _dropped: dict[str, int] = PrivateAttr(default_factory=dict)

    @field_validator("spec_version", mode="before")
    @classmethod
    def _normalise_spec_version(cls, value: object) -> object:
        if isinstance(value, str):
            return _SPEC_VERSION_PREFIX.sub("", value.strip()) or value.strip()
        return value

    @field_validator("format", mode="before")
    @classmethod
    def _normalise_format(cls, value: object) -> object:
        if isinstance(value, SbomFormat):
            return value
        if isinstance(value, str):
            text = value.strip().lower()
            if text.startswith("cyclonedx"):
                return SbomFormat.CYCLONEDX.value
            if text.startswith("spdx"):
                return SbomFormat.SPDX.value
            return text
        return value

    @model_validator(mode="wrap")
    @classmethod
    def _salvage_sections(cls, data: Any, handler: Callable[[Any], Any]) -> Sbom:
        """Drop unusable section entries instead of failing the whole load.

        A single malformed record from a buggy producer must not make an
        otherwise complete SBOM unloadable.  The per-section drop counts are
        retained on the instance so validation can still report them.
        """
        dropped: dict[str, int] = {}
        if isinstance(data, dict):
            replacements = {}
            for section, model_cls in _SALVAGEABLE_SECTIONS.items():
                if section not in data:
                    continue
                kept, lost = _salvage(data[section], model_cls)
                if lost:
                    replacements[section] = kept
                    dropped[section] = lost
            if replacements:
                data = {**data, **replacements}

        sbom: Sbom = handler(data)
        if dropped:
            sbom._dropped = dropped
        return sbom

    @property
    def dropped_components(self) -> int:
        """How many component entries were discarded while loading."""
        return self._dropped.get("components", 0)

    @property
    def dropped_entries(self) -> dict[str, int]:
        """How many entries were discarded while loading, keyed by section."""
        return dict(self._dropped)

    # ------------------------------------------------------------------ lookups

    def iter_components(self) -> Iterator[Component]:
        """Yield every component, including the one described by ``metadata``."""
        if self.metadata.component is not None:
            yield self.metadata.component
        yield from self.components

    @property
    def refs(self) -> set[str]:
        """Return the set of all bom-refs / SPDXIDs known to this document."""
        found: set[str] = set()
        for component in self.iter_components():
            if component.bom_ref:
                found.add(component.bom_ref)
        for service in self.services:
            if service.bom_ref:
                found.add(service.bom_ref)
        for vulnerability in self.vulnerabilities:
            if vulnerability.bom_ref:
                found.add(vulnerability.bom_ref)
        return found

    def component_by_ref(self, ref: str) -> Component | None:
        """Return the component with bom-ref *ref*, or ``None``."""
        for component in self.iter_components():
            if component.bom_ref == ref:
                return component
        return None

    def components_by_purl(self) -> dict[str, list[Component]]:
        """Group components by lower-cased purl (components without one omitted)."""
        grouped: dict[str, list[Component]] = {}
        for component in self.components:
            if component.purl:
                grouped.setdefault(component.purl.lower(), []).append(component)
        return grouped

    def dependency_graph(self) -> dict[str, list[str]]:
        """Return the dependency graph as a ``{ref: [depends_on, ...]}`` map.

        Repeated refs are merged, which happens when a document expresses the
        same edge in several places (SPDX relationship lists, for example).
        """
        graph: dict[str, list[str]] = {}
        for dependency in self.dependencies:
            bucket = graph.setdefault(dependency.ref, [])
            for ref in dependency.depends_on:
                if ref not in bucket:
                    bucket.append(ref)
        return graph

    def summary(self) -> dict[str, int | str]:
        """Return small counts for logs, CLI output and API responses."""
        return {
            "format": self.format.value,
            "spec_version": self.spec_version,
            "components": len(self.components),
            "dependencies": len(self.dependencies),
            "services": len(self.services),
            "vulnerabilities": len(self.vulnerabilities),
            "with_purl": sum(1 for component in self.components if component.purl),
            "with_version": sum(1 for component in self.components if component.version),
            "with_license": sum(1 for component in self.components if component.licenses),
        }
