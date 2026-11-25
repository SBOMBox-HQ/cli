"""The component model - the atom every SBOM is built from."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from sbombox_core.model.common import (
    ExternalReference,
    Hash,
    LicenseChoice,
    Supplier,
    drop_unknown_hash_algorithms,
)

__all__ = ["COMPONENT_TYPE_ALIASES", "Component", "ComponentType"]


class ComponentType(StrEnum):
    """The kind of thing a component is.

    Values follow the CycloneDX 1.4-1.7 ``component.type`` enumeration, which
    is the superset of the SPDX ``primaryPackagePurpose`` vocabulary.
    """

    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    CONTAINER = "container"
    DEVICE = "device"
    DEVICE_MODEL = "device-model"
    FIRMWARE = "firmware"
    FILE = "file"
    OPERATING_SYSTEM = "operating-system"
    MACHINE_LEARNING_MODEL = "machine-learning-model"
    DATA = "data"
    CRYPTOGRAPHIC_ASSET = "cryptographic-asset"


#: SPDX values that mean "unknown" / "not applicable" rather than real data.
_SPDX_PLACEHOLDERS = frozenset({"NOASSERTION", "NONE"})

#: Alternative spellings accepted on input, keyed by their lower-cased form.
#: SPDX uses ``SOURCE``/``ARCHIVE`` purposes that have no CycloneDX equivalent;
#: they are folded into the closest match rather than dropped.
COMPONENT_TYPE_ALIASES: dict[str, str] = {
    "library": ComponentType.LIBRARY.value,
    "libraries": ComponentType.LIBRARY.value,
    "lib": ComponentType.LIBRARY.value,
    "source": ComponentType.FILE.value,
    "archive": ComponentType.FILE.value,
    "other": ComponentType.LIBRARY.value,
    "framework": ComponentType.FRAMEWORK.value,
    "application": ComponentType.APPLICATION.value,
    "container": ComponentType.CONTAINER.value,
    "device": ComponentType.DEVICE.value,
    "device-model": ComponentType.DEVICE_MODEL.value,
    "devicemodel": ComponentType.DEVICE_MODEL.value,
    "model": ComponentType.DEVICE_MODEL.value,
    "firmware": ComponentType.FIRMWARE.value,
    "file": ComponentType.FILE.value,
    "operating-system": ComponentType.OPERATING_SYSTEM.value,
    "operatingsystem": ComponentType.OPERATING_SYSTEM.value,
    "os": ComponentType.OPERATING_SYSTEM.value,
    "machine-learning-model": ComponentType.MACHINE_LEARNING_MODEL.value,
    "machinelearningmodel": ComponentType.MACHINE_LEARNING_MODEL.value,
    "data": ComponentType.DATA.value,
    "cryptographic-asset": ComponentType.CRYPTOGRAPHIC_ASSET.value,
    "cryptographicasset": ComponentType.CRYPTOGRAPHIC_ASSET.value,
}


class Component(BaseModel):
    """A single software package, library, container or device in the SBOM."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))
    type: ComponentType = ComponentType.LIBRARY
    name: str
    version: str | None = None
    description: str | None = None
    purl: str | None = None
    cpe: str | None = None
    supplier: Supplier | None = None
    author: str | None = None
    publisher: str | None = None
    licenses: list[LicenseChoice] = Field(default_factory=list)
    hashes: list[Hash] = Field(default_factory=list)
    external_references: list[ExternalReference] = Field(
        default_factory=list,
        validation_alias=AliasChoices("external_references", "externalReferences", "externalRefs"),
    )
    properties: dict[str, str] = Field(default_factory=dict)
    scope: str | None = None  # one of: required, optional, excluded
    group: str | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _normalise_type(cls, value: object) -> object:
        """Accept SPDX purposes and loose spellings for the CycloneDX enum.

        Types SBOMBox does not model degrade to ``library`` rather than failing
        the component: losing an entry costs far more than mis-labelling it, and
        the original document is still available via :attr:`Sbom.raw_data`.
        """
        if isinstance(value, ComponentType):
            return value
        if isinstance(value, str):
            key = value.strip().lower().replace("_", "-")
            if not key:
                return ComponentType.LIBRARY.value
            if key in COMPONENT_TYPE_ALIASES:
                return COMPONENT_TYPE_ALIASES[key]
            known = {member.value for member in ComponentType}
            return key if key in known else ComponentType.LIBRARY.value
        return ComponentType.LIBRARY.value

    @field_validator("hashes", mode="before")
    @classmethod
    def _drop_exotic_hashes(cls, value: object) -> object:
        return drop_unknown_hash_algorithms(value)

    @field_validator("name", mode="before")
    @classmethod
    def _strip_name(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("version", "description", "purl", "cpe", "author", "publisher", "group", mode="before")
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            # SPDX's placeholders for "we don't know" carry no information and
            # would otherwise leak into purls, CPEs and version comparisons.
            if not stripped or stripped.upper() in _SPDX_PLACEHOLDERS:
                return None
            return stripped
        return value

    @field_validator("name", mode="after")
    @classmethod
    def _require_name(cls, value: str | None) -> str:
        if not value:
            raise ValueError("component name must not be empty")
        return value

    @field_validator("scope", mode="before")
    @classmethod
    def _normalise_scope(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower() or None
        return value

    @field_validator("properties", mode="before")
    @classmethod
    def _coerce_properties(cls, value: object) -> object:
        """Accept CycloneDX's ``[{"name": .., "value": ..}]`` array form."""
        if isinstance(value, list):
            coerced: dict[str, str] = {}
            for item in value:
                if isinstance(item, dict) and "name" in item:
                    coerced[str(item["name"])] = "" if item.get("value") is None else str(item["value"])
            return coerced
        if isinstance(value, dict):
            return {str(k): "" if v is None else str(v) for k, v in value.items()}
        return value

    @field_validator("licenses", mode="before")
    @classmethod
    def _coerce_licenses(cls, value: object) -> object:
        """Accept a bare license id or an SPDX expression string."""
        if value is None or isinstance(value, (list, dict)):
            return value
        if isinstance(value, str) and value.strip():
            return [{"expression": value.strip()}]
        return value

    def identity_key(self) -> str:
        """Return a stable deduplication key for this component.

        Uses the purl when available (it encodes type, namespace, name and
        version) and falls back to the CycloneDX coordinate triple.
        """
        if self.purl:
            return self.purl.lower()
        return "\x00".join(part.lower() for part in (self.group or "", self.name, self.version or "", self.type.value))

    def display_name(self) -> str:
        """Return a human-readable ``group/name@version`` label."""
        name = f"{self.group}/{self.name}" if self.group else self.name
        return f"{name}@{self.version}" if self.version else name
