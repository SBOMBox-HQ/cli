"""Shared value objects used by both the CycloneDX and SPDX mappings.

Everything in here is deliberately small and dumb: a digest, a license, a
supplier, an external reference.  Keeping them in one module means the parsers
and the writers agree on a single representation.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from sbombox_core.util.hashes import normalize_algorithm

__all__ = [
    "Contact",
    "ExternalReference",
    "Hash",
    "HashAlgorithm",
    "License",
    "LicenseChoice",
    "Property",
    "Supplier",
    "drop_unknown_hash_algorithms",
]


class HashAlgorithm(StrEnum):
    """Digest algorithms recognised by SBOMBox.

    The five canonical algorithms required by the validation ruleset are listed
    first; the remaining members cover the extra values permitted by CycloneDX
    1.5+ and SPDX so real-world documents parse without loss.
    """

    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
    BLAKE2B_256 = "BLAKE2b-256"
    BLAKE2B_384 = "BLAKE2b-384"
    BLAKE2B_512 = "BLAKE2b-512"
    BLAKE3 = "BLAKE3"


class Hash(BaseModel):
    """A cryptographic digest of an artifact."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    alg: HashAlgorithm = Field(validation_alias=AliasChoices("alg", "algorithm"))
    content: str = Field(validation_alias=AliasChoices("content", "value", "checksumValue", "hashValue"))

    @field_validator("alg", mode="before")
    @classmethod
    def _canonicalise_alg(cls, value: object) -> object:
        """Accept ``sha256``, ``SHA_256`` and ``SHA-256`` interchangeably."""
        if isinstance(value, str):
            return normalize_algorithm(value) or value
        return value

    @field_validator("content", mode="before")
    @classmethod
    def _strip_content(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value


def drop_unknown_hash_algorithms(value: object) -> object:
    """Remove digest records whose algorithm :class:`HashAlgorithm` cannot hold.

    SPDX permits algorithms (MD2, MD4, MD6, SHA3-224, ...) that SBOMBox does not
    model.  Dropping the *digest* keeps the component; letting the value through
    would fail validation and cost the whole entry, which is far worse - a
    missing component means missing vulnerabilities.
    """
    if not isinstance(value, list):
        return value

    kept: list[object] = []
    for entry in value:
        if isinstance(entry, Hash):
            kept.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        alg = entry.get("alg") or entry.get("algorithm")
        if isinstance(alg, str) and normalize_algorithm(alg) is None:
            continue  # algorithm SBOMBox does not model
        kept.append(entry)
    return kept


class Contact(BaseModel):
    """A person or role that can be reached about a component."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str | None = None
    email: str | None = None
    phone: str | None = None
    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))


class Supplier(BaseModel):
    """The organization that supplied a component.

    Mirrors the CycloneDX ``organizationalEntity`` shape, which is also what
    SPDX ``Supplier`` / ``Originator`` strings are normalised into.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str | None = None
    url: list[str] = Field(default_factory=list)
    contact: list[Contact] = Field(default_factory=list)
    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))

    @field_validator("url", "contact", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        """Accept a single value where an array is expected.

        XML serialisations collapse a one-element list into a scalar, and SPDX
        supplier strings produce a lone contact.
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, dict):
            return [value]
        return value


class License(BaseModel):
    """A single license: either an SPDX ``id`` or a free-text ``name``.

    Per the SPDX/CycloneDX convention exactly one of :attr:`id` and
    :attr:`name` should be populated; ``id`` wins when both are present.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str | None = Field(default=None, validation_alias=AliasChoices("id", "licenseId", "identifier"))  # noqa: A003
    name: str | None = Field(default=None, validation_alias=AliasChoices("name", "licenseName"))
    url: str | None = None
    text: str | None = None
    acknowledgement: str | None = None
    bom_ref: str | None = Field(default=None, validation_alias=AliasChoices("bom-ref", "bomRef"))

    @field_validator("text", mode="before")
    @classmethod
    def _unwrap_text(cls, value: object) -> object:
        """CycloneDX nests the body in ``{"contentType": .., "content": ..}``."""
        if isinstance(value, dict):
            return value.get("content") or value.get("text") or value.get("encoding")
        return value


class LicenseChoice(BaseModel):
    """A license declaration: a structured :class:`License` *or* an expression.

    ``expression`` holds an SPDX expression such as ``MIT OR Apache-2.0``.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    license: License | None = None  # noqa: A003
    expression: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _wrap_bare_license(cls, data: object) -> object:
        """Accept the shapes producers emit instead of the spec's wrapper.

        ``"MIT"`` and ``{"id": "MIT"}`` both become ``{"license": {...}}``.
        """
        if isinstance(data, str):
            text = data.strip()
            if not text:
                return {}
            return {"expression": text}
        if isinstance(data, License):
            return {"license": data.model_dump(exclude_none=True)}
        if isinstance(data, dict):
            if "license" in data or "expression" in data:
                return data
            return {"license": data}
        return data


class ExternalReference(BaseModel):
    """A pointer to something outside the SBOM (VCS, docs, advisory, ...)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: str = Field(validation_alias=AliasChoices("type", "referenceType", "externalRefType"))
    url: str = Field(
        default="",
        validation_alias=AliasChoices("url", "locator", "externalRefLocator", "referenceLocator"),
    )
    comment: str | None = None
    hashes: list[Hash] = Field(default_factory=list)

    @field_validator("hashes", mode="before")
    @classmethod
    def _drop_exotic_hashes(cls, value: object) -> object:
        return drop_unknown_hash_algorithms(value)

    @field_validator("url", mode="before")
    @classmethod
    def _coerce_url(cls, value: object) -> object:
        """SPDX stores locators as single-element arrays."""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        if isinstance(value, (int, float)):
            return str(value)
        return value


class Property(BaseModel):
    """A name/value pair carrying producer-specific annotations."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str
    value: str = ""
