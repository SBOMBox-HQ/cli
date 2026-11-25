"""Services declared in an SBOM (the CycloneDX ``services`` section).

A service is a remotely callable piece of software - an API, a database, a
queue.  It has no purl, so it never participates in vulnerability matching by
coordinates; it is kept in the model so a BOM round-trips without loss and so
trust-boundary information stays visible to the scoring engine.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from sbombox_core.model.common import (
    Contact,
    ExternalReference,
    Hash,
    LicenseChoice,
    Supplier,
    drop_unknown_hash_algorithms,
)

__all__ = ["Service", "ServiceData", "ServiceDataFlow"]


class ServiceDataFlow(StrEnum):
    """Direction of a data flow across a service boundary."""

    BIDIRECTIONAL = "bidirectional"
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


_FLOW_VALUES: frozenset[str] = frozenset(member.value for member in ServiceDataFlow)


class ServiceData(BaseModel):
    """A data classification flowing through a service."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    flow: ServiceDataFlow = ServiceDataFlow.UNKNOWN
    classification: str = ""
    name: str | None = None
    description: str | None = None

    @field_validator("flow", mode="before")
    @classmethod
    def _normalise_flow(cls, value: object) -> object:
        if isinstance(value, ServiceDataFlow):
            return value
        if isinstance(value, str):
            key = value.strip().lower().replace("-", "_").replace(" ", "_")
            return key if key in _FLOW_VALUES else ServiceDataFlow.UNKNOWN.value
        return ServiceDataFlow.UNKNOWN.value


class Service(BaseModel):
    """A service described by the SBOM."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))
    name: str
    version: str | None = None
    description: str | None = None
    endpoints: list[str] = Field(default_factory=list)
    authenticated: bool | None = None
    x_trust_boundary: bool | None = Field(
        default=None,
        validation_alias=AliasChoices("x_trust_boundary", "x-trust-boundary", "xTrustBoundary"),
    )
    data: list[ServiceData] = Field(default_factory=list)
    provider: Supplier | None = None
    group: str | None = None
    services: list[Service] = Field(default_factory=list)
    licenses: list[LicenseChoice] = Field(default_factory=list)
    external_references: list[ExternalReference] = Field(
        default_factory=list,
        validation_alias=AliasChoices("external_references", "externalReferences"),
    )
    properties: dict[str, str] = Field(default_factory=dict)
    hashes: list[Hash] = Field(default_factory=list)
    contacts: list[Contact] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("endpoints", mode="before")
    @classmethod
    def _coerce_endpoints(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    @field_validator("authenticated", "x_trust_boundary", mode="before")
    @classmethod
    def _coerce_bool(cls, value: object) -> object:
        """XML hands us ``"true"``/``"false"`` strings."""
        if isinstance(value, str):
            text = value.strip().lower()
            if text in {"true", "1", "yes"}:
                return True
            if text in {"false", "0", "no", ""}:
                return False
        return value

    @field_validator("data", mode="before")
    @classmethod
    def _coerce_data(cls, value: object) -> object:
        if isinstance(value, dict):
            return [value]
        return value

    @field_validator("hashes", mode="before")
    @classmethod
    def _drop_exotic_hashes(cls, value: object) -> object:
        return drop_unknown_hash_algorithms(value)

    @field_validator("properties", mode="before")
    @classmethod
    def _coerce_properties(cls, value: object) -> object:
        if isinstance(value, list):
            return {
                str(item["name"]): "" if item.get("value") is None else str(item["value"])
                for item in value
                if isinstance(item, dict) and "name" in item
            }
        if isinstance(value, dict):
            return {str(k): "" if v is None else str(v) for k, v in value.items()}
        return value


# ``Service.services`` is a self-reference; Pydantic needs the model complete.
Service.model_rebuild()
