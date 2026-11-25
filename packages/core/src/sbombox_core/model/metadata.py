"""Document-level metadata: who produced the SBOM, when, and about what."""

from __future__ import annotations

from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from sbombox_core.model.common import Contact, Hash, Supplier, drop_unknown_hash_algorithms
from sbombox_core.model.component import Component

__all__ = ["Metadata", "Tool", "split_name_email"]


def split_name_email(raw: str) -> dict[str, str | None]:
    """Split ``"Jane Doe <jane@example.com>"`` into a contact mapping.

    SPDX creator strings look like ``Person: Jane Doe (jane@example.com)``;
    both forms are handled so provenance survives normalisation.
    """
    text = raw.strip()
    for prefix in ("Person:", "person:", "Organization:", "organization:"):
        if text.startswith(prefix):
            text = text[len(prefix) :].strip()
            break

    email: str | None = None
    for opener, closer in (("<", ">"), ("(", ")")):
        if opener in text and text.rstrip().endswith(closer):
            head, _, tail = text.partition(opener)
            candidate = tail.rstrip(closer).strip()
            if "@" in candidate or opener == "<":
                text = head.strip()
                email = candidate or None
                break

    return {"name": text or None, "email": email}


class Tool(BaseModel):
    """A tool (or service) that took part in producing the SBOM."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    vendor: str | None = None
    name: str | None = None
    version: str | None = None
    hashes: list[Hash] = Field(default_factory=list)
    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))

    @field_validator("vendor", "name", "version", mode="before")
    @classmethod
    def _strip(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("hashes", mode="before")
    @classmethod
    def _drop_exotic_hashes(cls, value: object) -> object:
        return drop_unknown_hash_algorithms(value)

    def display_name(self) -> str:
        """Return ``vendor/name@version`` with the missing parts omitted."""
        parts = [p for p in (self.vendor, self.name) if p]
        label = "/".join(parts) if parts else "unknown"
        return f"{label}@{self.version}" if self.version else label


class Metadata(BaseModel):
    """Provenance information attached to the SBOM as a whole.

    ``manufacture`` and ``supplier`` both use the :class:`Supplier` shape, which
    matches CycloneDX's ``organizationalEntity``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    timestamp: datetime | None = None
    tools: list[Tool] = Field(default_factory=list)
    authors: list[Contact] = Field(default_factory=list)
    component: Component | None = None
    manufacture: Supplier | None = None
    supplier: Supplier | None = None
    properties: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: object) -> object:
        """Accept ISO-8601 strings, including the ``Z`` suffix and epoch ints."""
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value))
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            # ``fromisoformat`` only learned to accept ``Z`` in Python 3.11.
            if text.endswith(("Z", "z")):
                text = f"{text[:-1]}+00:00"
            try:
                return datetime.fromisoformat(text)
            except ValueError:
                # Unparseable provenance must not sink the whole document;
                # semantic validation reports the missing timestamp instead.
                return None
        return value

    @field_validator("tools", mode="before")
    @classmethod
    def _coerce_tools(cls, value: object) -> object:
        """Accept a plain string, a list of strings, or CycloneDX 1.5's object.

        CycloneDX 1.5 moved tools into
        ``{"components": [...], "services": [...]}``; both shapes collapse to a
        flat tool list so downstream consumers see one representation.
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [{"name": value}]
        if isinstance(value, dict):
            if "components" in value or "services" in value:
                tools: list[object] = []
                for entry in value.get("components") or []:
                    if isinstance(entry, dict):
                        tools.append(
                            {
                                "vendor": entry.get("group"),
                                "name": entry.get("name"),
                                "version": entry.get("version"),
                                "hashes": entry.get("hashes") or [],
                                "bom-ref": entry.get("bom-ref"),
                            }
                        )
                for entry in value.get("services") or []:
                    if isinstance(entry, dict):
                        provider = entry.get("provider")
                        tools.append(
                            {
                                "vendor": provider.get("name") if isinstance(provider, dict) else None,
                                "name": entry.get("name"),
                                "version": entry.get("version"),
                                "bom-ref": entry.get("bom-ref"),
                            }
                        )
                return tools
            return [value]
        if isinstance(value, list):
            coerced: list[object] = []
            for item in value:
                if isinstance(item, str):
                    coerced.append({"name": item})
                elif isinstance(item, dict):
                    coerced.append(item)
            return coerced
        return value

    @field_validator("authors", mode="before")
    @classmethod
    def _coerce_authors(cls, value: object) -> object:
        """Accept bare strings (``"Jane <jane@x.com>"``) as well as objects."""
        if value is None:
            return []
        if isinstance(value, (str, dict)):
            value = [value]
        if not isinstance(value, list):
            return value

        coerced: list[object] = []
        for item in value:
            if isinstance(item, str):
                coerced.append(split_name_email(item))
            elif isinstance(item, dict):
                coerced.append(item)
        return coerced

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
