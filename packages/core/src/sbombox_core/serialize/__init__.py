"""SBOM serialisation - model to CycloneDX / SPDX output.

Converts an :class:`~sbombox_core.model.Sbom` back into a serialised document
(CycloneDX 1.6/1.7 JSON+XML, SPDX 2.3 JSON).

Usage::

    from sbombox_core.serialize import to_cyclonedx_json, to_spdx_json
    doc = to_cyclonedx_json(sbom, version="1.6")
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sbombox_core.model.sbom import Sbom

__all__ = [
    "to_cyclonedx_json",
    "to_spdx_json",
    "serialize_sbom",
]


def serialize_sbom(
    sbom: Sbom,
    fmt: str = "cyclonedx-1.6",
) -> str:
    """Serialise *sbom* to the requested format.

    Args:
        sbom: The SBOM to serialise.
        fmt: Output format - ``"cyclonedx-1.6"``, ``"cyclonedx-1.7"``,
            ``"spdx-2.3"``.

    Returns:
        The serialised document as a JSON string.
    """
    fmt_lower = fmt.lower().replace(" ", "")
    if fmt_lower.startswith("cyclonedx"):
        version = fmt_lower.split("-", 1)[1] if "-" in fmt_lower else "1.6"
        return json.dumps(to_cyclonedx_json(sbom, version=version), indent=2)
    if fmt_lower.startswith("spdx"):
        return json.dumps(to_spdx_json(sbom), indent=2)
    raise ValueError(f"Unsupported serialisation format: {fmt}")


def to_cyclonedx_json(sbom: Sbom, version: str = "1.6") -> dict[str, Any]:
    """Convert *sbom* to a CycloneDX JSON document.

    Args:
        sbom: The SBOM to convert.
        version: CycloneDX spec version (``"1.4"`` through ``"1.7"``).

    Returns:
        A dict ready for JSON serialisation.
    """
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "serialNumber": f"urn:uuid:{_generate_serial()}",
        "version": 1,
    }

    # Metadata
    meta: dict[str, Any] = {}
    if sbom.metadata:
        if sbom.metadata.timestamp:
            meta["timestamp"] = sbom.metadata.timestamp.isoformat()
        if sbom.metadata.component:
            meta["component"] = _component_to_cdx(sbom.metadata.component)
        if sbom.metadata.tools:
            meta["tools"] = [
                {"name": t.name, "version": t.version} if t.version else {"name": t.name}
                for t in sbom.metadata.tools
            ]
        if sbom.metadata.properties:
            meta["properties"] = [{"name": k, "value": v} for k, v in sorted(sbom.metadata.properties.items())]
    doc["metadata"] = meta

    # Components
    doc["components"] = [_component_to_cdx(c) for c in sbom.components]

    # Dependencies
    if sbom.dependencies:
        doc["dependencies"] = [
            {"ref": d.ref, "dependsOn": d.depends_on}
            for d in sbom.dependencies
        ]

    return doc


def to_spdx_json(sbom: Sbom) -> dict[str, Any]:
    """Convert *sbom* to an SPDX 2.3 JSON document.

    Args:
        sbom: The SBOM to convert.

    Returns:
        A dict ready for JSON serialisation.
    """
    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": _doc_name(sbom),
        "documentNamespace": f"https://sbombox.io/spdx/{_generate_serial()}",
        "creationInfo": {
            "created": (sbom.metadata.timestamp or datetime.now(UTC)).isoformat(),
            "creators": ["Tool: sbombox-core"],
        },
        "packages": [],
        "relationships": [],
    }

    for component in sbom.components:
        pkg = _component_to_spdx(component)
        doc["packages"].append(pkg)

    # Relationships from dependency graph
    for dep in sbom.dependencies:
        for target in dep.depends_on:
            doc["relationships"].append({
                "spdxElementId": _spdx_ref(dep.ref),
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": _spdx_ref(target),
            })

    return doc


# --------------------------------------------------------- helpers


def _component_to_cdx(component: Any) -> dict[str, Any]:
    """Convert a Component model to CycloneDX JSON shape."""
    obj: dict[str, Any] = {
        "type": component.type.value if component.type else "library",
        "name": component.name,
    }
    if component.bom_ref:
        obj["bom-ref"] = component.bom_ref
    if component.version:
        obj["version"] = component.version
    if component.purl:
        obj["purl"] = component.purl
    if component.cpe:
        obj["cpe"] = component.cpe
    if component.description:
        obj["description"] = component.description
    if component.supplier and component.supplier.name:
        obj["supplier"] = {"name": component.supplier.name}
    if component.licenses:
        obj["licenses"] = []
        for lc in component.licenses:
            if lc.expression:
                obj["licenses"].append({"expression": lc.expression})
            elif lc.license:
                lic: dict[str, Any] = {}
                if lc.license.id:
                    lic["license"] = {"id": lc.license.id}
                elif lc.license.name:
                    lic["license"] = {"name": lc.license.name}
                if lic:
                    obj["licenses"].append(lic)
    if component.hashes:
        obj["hashes"] = [
            {"alg": h.alg.value if hasattr(h.alg, "value") else str(h.alg), "content": h.content}
            for h in component.hashes
        ]
    if component.scope:
        obj["scope"] = component.scope
    if component.group:
        obj["group"] = component.group
    return obj


def _component_to_spdx(component: Any) -> dict[str, Any]:
    """Convert a Component model to SPDX 2.3 JSON package shape."""
    pkg: dict[str, Any] = {
        "SPDXID": _spdx_ref(component.bom_ref or component.name),
        "name": component.name,
        "downloadLocation": "NOASSERTION",
    }
    if component.version:
        pkg["versionInfo"] = component.version
    if component.supplier and component.supplier.name:
        pkg["supplier"] = f"Organization: {component.supplier.name}"
    else:
        pkg["supplier"] = "NOASSERTION"
    if component.licenses:
        expr_parts = []
        for lc in component.licenses:
            if lc.expression:
                expr_parts.append(lc.expression)
            elif lc.license and lc.license.id:
                expr_parts.append(lc.license.id)
        pkg["licenseConcluded"] = " AND ".join(expr_parts) if expr_parts else "NOASSERTION"
    else:
        pkg["licenseConcluded"] = "NOASSERTION"
    if component.hashes:
        pkg["checksums"] = [
            {"algorithm": _spdx_hash_alg(h.alg), "checksumValue": h.content}
            for h in component.hashes
        ]
    if component.purl:
        pkg["externalRefs"] = [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": component.purl}
        ]
    return pkg


def _spdx_ref(ref: str) -> str:
    """Ensure a ref is a valid SPDXID (starts with SPDXRef-)."""
    if ref.startswith("SPDXRef-"):
        return ref
    safe = ref.replace(" ", "-").replace("/", "-").replace(":", "-")
    return f"SPDXRef-{safe}"


def _spdx_hash_alg(alg: Any) -> str:
    """Map a hash algorithm to SPDX checksum algorithm name."""
    val = alg.value if hasattr(alg, "value") else str(alg)
    mapping = {
        "SHA-256": "SHA256",
        "SHA-384": "SHA384",
        "SHA-512": "SHA512",
        "SHA-1": "SHA1",
        "MD5": "MD5",
    }
    return mapping.get(val, val)


def _doc_name(sbom: Sbom) -> str:
    """Derive a document name from the SBOM metadata."""
    if sbom.metadata and sbom.metadata.component:
        return sbom.metadata.component.name
    return "sbombox-sbom"


def _generate_serial() -> str:
    """Generate a UUID for the serial number."""
    import uuid as _uuid

    _uuid7 = getattr(_uuid, "uuid7", None) or _uuid.uuid4
    return str(_uuid7())
