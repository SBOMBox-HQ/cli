"""VEX (Vulnerability Exploitability eXchange) statements.

A VEX statement asserts *whether a known vulnerability actually affects a given
product*, which is what turns a noisy SBOM into something a security team can
act on.  The status vocabulary follows CSAF/OpenVEX.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

__all__ = ["VexJustification", "VexStatement", "VexStatus"]


class VexStatus(StrEnum):
    """The four canonical VEX product statuses."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


#: Statuses that mean the product is *actually* vulnerable.
EXPLOITABLE_STATUSES: frozenset[VexStatus] = frozenset({VexStatus.AFFECTED})

_STATUS_ALIASES: dict[str, str] = {
    "not_affected": VexStatus.NOT_AFFECTED.value,
    "not-affected": VexStatus.NOT_AFFECTED.value,
    "notaffected": VexStatus.NOT_AFFECTED.value,
    "unaffected": VexStatus.NOT_AFFECTED.value,
    "affected": VexStatus.AFFECTED.value,
    "vulnerable": VexStatus.AFFECTED.value,
    "known_affected": VexStatus.AFFECTED.value,
    "fixed": VexStatus.FIXED.value,
    "resolved": VexStatus.FIXED.value,
    "remediated": VexStatus.FIXED.value,
    "under_investigation": VexStatus.UNDER_INVESTIGATION.value,
    "under-investigation": VexStatus.UNDER_INVESTIGATION.value,
    "investigating": VexStatus.UNDER_INVESTIGATION.value,
    "unknown": VexStatus.UNDER_INVESTIGATION.value,
}


class VexJustification(StrEnum):
    """Why a product is not affected (OpenVEX justification vocabulary)."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VexStatement(BaseModel):
    """A single assertion about a vulnerability's applicability."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str | None = Field(default=None, validation_alias=AliasChoices("id", "statementId"))  # noqa: A003
    vulnerability_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("vulnerability_id", "vulnerabilityId", "vulnerability", "name"),
    )
    status: VexStatus
    justification: str | None = None
    response: list[str] = Field(default_factory=list)
    details: str | None = Field(
        default=None,
        validation_alias=AliasChoices("details", "action_statement", "impact_statement"),
    )
    timestamp: datetime | None = None
    products: list[str] = Field(default_factory=list)

    @field_validator("status", mode="before")
    @classmethod
    def _normalise_status(cls, value: object) -> object:
        if isinstance(value, VexStatus):
            return value
        if isinstance(value, str):
            key = value.strip().lower().replace("-", "_").replace(" ", "_")
            return _STATUS_ALIASES.get(key, key)
        return value

    @field_validator("justification", "details", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("justification", mode="after")
    @classmethod
    def _lowercase_justification(cls, value: str | None) -> str | None:
        """Store justifications in the canonical snake_case OpenVEX spelling."""
        if value is None:
            return None
        return value.strip().lower().replace("-", "_").replace(" ", "_")

    @field_validator("response", mode="before")
    @classmethod
    def _coerce_response(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            return [value.strip()] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return value

    @field_validator("products", mode="before")
    @classmethod
    def _coerce_products(cls, value: object) -> object:
        """Accept OpenVEX ``products`` objects as well as bare refs."""
        if value is None:
            return []
        if isinstance(value, (str, dict)):
            value = [value]
        if not isinstance(value, list):
            return value
        coerced: list[str] = []
        for item in value:
            if isinstance(item, str):
                coerced.append(item.strip())
            elif isinstance(item, dict):
                ref = item.get("@id") or item.get("id") or item.get("subcomponents")
                if isinstance(ref, str):
                    coerced.append(ref.strip())
        return [entry for entry in coerced if entry]

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: object) -> object:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            if text.endswith(("Z", "z")):
                text = f"{text[:-1]}+00:00"
            try:
                return datetime.fromisoformat(text)
            except ValueError:
                return None
        return value

    @property
    def is_exploitable(self) -> bool:
        """Return ``True`` when this statement says the product is vulnerable."""
        return self.status in EXPLOITABLE_STATUSES
