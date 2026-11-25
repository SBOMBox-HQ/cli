"""Registry enrichment adapters.

Fetches additional metadata for components from public registries:
    - PyPI
    - npm
    - crates.io
    - Maven Central
    - deps.dev
    - ecosyste.ms

All network calls are opt-in via ``httpx``.

Usage::

    from sbombox_core.enrich import enrich_component
    enriched = enrich_component(component, registry="pypi")
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sbombox_core.model.common import Hash, LicenseChoice, Supplier
from sbombox_core.model.component import Component
from sbombox_core.util.purl import parse_purl

__all__ = ["enrich_component", "enrich_sbom", "ADAPTERS"]

_log = logging.getLogger(__name__)


def enrich_component(
    component: Component,
    registry: str | None = None,
    client: Any = None,
) -> Component:
    """Enrich a component with data from a public registry.

    Args:
        component: The component to enrich.
        registry: Registry to query (auto-detected from purl if ``None``).
        client: An ``httpx.Client`` instance (created if ``None``).

    Returns:
        The component with additional metadata filled in.
    """
    if not component.purl:
        return component

    parsed = parse_purl(component.purl)
    if parsed is None:
        return component

    if registry is None:
        registry = _detect_registry(parsed.type)

    adapter = ADAPTERS.get(registry)
    if adapter is None:
        return component

    return adapter(component, parsed, client=client)


def enrich_sbom(
    sbom: Any,
    client: Any = None,
) -> Any:
    """Enrich all components in an SBOM.

    Args:
        sbom: The SBOM to enrich.
        client: An ``httpx.Client`` instance.

    Returns:
        The SBOM with enriched components.
    """
    for component in sbom.components:
        enrich_component(component, client=client)
    return sbom


# --------------------------------------------------------- registry adapters


def _detect_registry(purl_type: str) -> str | None:
    """Detect the registry from a purl type."""
    mapping = {
        "pypi": "pypi",
        "npm": "npm",
        "cargo": "crates",
        "maven": "maven",
        "gem": "rubygems",
        "nuget": "nuget",
        "golang": "go",
    }
    return mapping.get(purl_type)


def _get_client(client: Any) -> tuple[httpx.Client, bool]:
    """Return an httpx.Client and whether we created it (so caller can close)."""
    if client is not None:
        return client, False
    return httpx.Client(timeout=10.0), True


def _enrich_pypi(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from PyPI."""
    c, owned = _get_client(client)
    try:
        url = f"https://pypi.org/pypi/{parsed.name}/{parsed.version}/json"
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("PyPI returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()
        info = data.get("info", {})

        if not component.description and info.get("summary"):
            component.description = info["summary"]

        if component.supplier is None:
            author = info.get("author") or info.get("author_email")
            if author:
                component.supplier = Supplier(name=author)

        if not component.licenses and info.get("license"):
            component.licenses = [LicenseChoice(expression=info["license"])]

        if not component.hashes:
            for f in data.get("urls", []):
                digest = f.get("digests", {}).get("sha256")
                if digest:
                    component.hashes.append(Hash(alg="SHA-256", content=digest))
    except Exception as exc:
        _log.warning("PyPI enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


def _enrich_npm(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from npm."""
    c, owned = _get_client(client)
    try:
        url = f"https://registry.npmjs.org/{parsed.name}/{parsed.version}"
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("npm returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()

        if not component.description and data.get("description"):
            component.description = data["description"]

        if component.supplier is None:
            author = data.get("author")
            if isinstance(author, dict) and author.get("name"):
                component.supplier = Supplier(name=author["name"])
            elif isinstance(author, str):
                component.supplier = Supplier(name=author)

        if not component.licenses and data.get("license"):
            lic = data["license"]
            if isinstance(lic, str):
                component.licenses = [LicenseChoice(expression=lic)]
            elif isinstance(lic, dict) and lic.get("type"):
                component.licenses = [LicenseChoice(expression=lic["type"])]

        if not component.hashes:
            dist = data.get("dist", {})
            if dist.get("shasum"):
                component.hashes.append(Hash(alg="SHA-1", content=dist["shasum"]))
    except Exception as exc:
        _log.warning("npm enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


def _enrich_crates(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from crates.io."""
    c, owned = _get_client(client)
    try:
        url = f"https://crates.io/api/v1/crates/{parsed.name}/{parsed.version}"
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("crates.io returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()
        crate = data.get("crate", {})
        version = data.get("version", {})

        if not component.description and crate.get("description"):
            component.description = crate["description"]

        if not component.licenses and version.get("license"):
            component.licenses = [LicenseChoice(expression=version["license"])]

        if component.supplier is None:
            publisher = version.get("published_by", {})
            name = None
            if isinstance(publisher, dict):
                name = publisher.get("name") or publisher.get("login")
            if not name:
                name = crate.get("created_by")
            if name:
                component.supplier = Supplier(name=name)
    except Exception as exc:
        _log.warning("crates.io enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


def _enrich_maven(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from Maven Central."""
    c, owned = _get_client(client)
    try:
        group = parsed.namespace
        artifact = parsed.name
        version = parsed.version
        url = (
            "https://search.maven.org/solrsearch/select"
            f"?q=g:{group}+AND+a:{artifact}+AND+v:{version}&rows=1&wt=json"
        )
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("Maven returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()
        docs = data.get("response", {}).get("docs", [])
        if docs:
            doc = docs[0]
            if not component.description and doc.get("description"):
                component.description = doc["description"]
    except Exception as exc:
        _log.warning("Maven enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


def _enrich_deps_dev(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from deps.dev."""
    c, owned = _get_client(client)
    try:
        system_map = {
            "pypi": "pypi",
            "npm": "npm",
            "cargo": "cargo",
            "maven": "maven",
        }
        system = system_map.get(parsed.type, parsed.type)
        name = parsed.name
        if parsed.namespace:
            name = f"{parsed.namespace}:{name}" if parsed.type == "maven" else f"{parsed.namespace}/{name}"
        url = f"https://api.deps.dev/v3alpha/systems/{system}/packages/{name}/versions/{parsed.version}"
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("deps.dev returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()

        if not component.licenses and data.get("license"):
            lic = data["license"]
            if isinstance(lic, str):
                component.licenses = [LicenseChoice(expression=lic)]
            elif isinstance(lic, list) and lic:
                component.licenses = [LicenseChoice(expression=" AND ".join(lic))]
    except Exception as exc:
        _log.warning("deps.dev enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


def _enrich_ecosystems(component: Component, parsed: Any, client: Any = None) -> Component:
    """Enrich from ecosyste.ms."""
    c, owned = _get_client(client)
    try:
        registry_map = {
            "pypi": "pypi",
            "npm": "npm",
            "cargo": "crates.io",
            "maven": "repo1.maven.org",
        }
        registry = registry_map.get(parsed.type, parsed.type)
        url = f"https://packages.ecosyste.ms/api/v1/registries/{registry}/packages/{parsed.name}"
        resp = c.get(url)
        if resp.status_code != 200:
            _log.warning("ecosyste.ms returned %s for %s", resp.status_code, url)
            return component
        data = resp.json()

        if not component.description and data.get("description"):
            component.description = data["description"]

        if not component.licenses and data.get("licenses"):
            lics = data["licenses"]
            if isinstance(lics, list) and lics:
                component.licenses = [LicenseChoice(expression=lics[0])]
            elif isinstance(lics, str):
                component.licenses = [LicenseChoice(expression=lics)]

        if component.supplier is None and data.get("maintainers"):
            maintainers = data["maintainers"]
            if isinstance(maintainers, list) and maintainers:
                first = maintainers[0]
                name = first.get("name") if isinstance(first, dict) else str(first)
                if name:
                    component.supplier = Supplier(name=name)
    except Exception as exc:
        _log.warning("ecosyste.ms enrichment failed for %s: %s", component.name, exc)
    finally:
        if owned:
            c.close()
    return component


ADAPTERS: dict[str, Any] = {
    "pypi": _enrich_pypi,
    "npm": _enrich_npm,
    "crates": _enrich_crates,
    "maven": _enrich_maven,
    "deps_dev": _enrich_deps_dev,
    "ecosystems": _enrich_ecosystems,
}
