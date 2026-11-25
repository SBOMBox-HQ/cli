"""Utilities for working with Package URLs (purls).

A purl is a URL string used to identify a software package in a
technology-agnostic way: ``pkg:npm/express@4.18.2``.  The helpers here wrap
``packageurl-python`` so the rest of the library never has to deal with the
raw exception types.
"""

from __future__ import annotations

from packageurl import PackageURL

__all__ = [
    "PURL_ECOSYSTEMS",
    "parse_purl",
    "purl_to_ecosystem",
    "validate_purl",
]

#: Mapping from purl ``type`` to the canonical ecosystem name used across
#: SBOMBox (and by the major advisory databases such as OSV / GHSA).
PURL_ECOSYSTEMS: dict[str, str] = {
    "alpm": "Alpm",
    "apk": "Alpine",
    "bitbucket": "Bitbucket",
    "bitnami": "Bitnami",
    "cargo": "crates.io",
    "cocoapods": "CocoaPods",
    "composer": "Packagist",
    "conan": "ConanCenter",
    "conda": "conda-forge",
    "cpan": "CPAN",
    "cran": "CRAN",
    "deb": "Debian",
    "docker": "Docker",
    "gem": "RubyGems",
    "generic": "Generic",
    "github": "GitHub",
    "gitea": "Gitea",
    "gitlab": "GitLab",
    "golang": "Go",
    "go": "Go",
    "hackage": "Hackage",
    "hex": "Hex",
    "huggingface": "HuggingFace",
    "luarocks": "LuaRocks",
    "maven": "Maven",
    "mlflow": "MLflow",
    "npm": "npm",
    "nuget": "NuGet",
    "oci": "OCI",
    "pub": "Pub",
    "pypi": "PyPI",
    "qpkg": "QNX",
    "rpm": "Red Hat",
    "swid": "SWID",
    "swift": "SwiftPM",
    "yocto": "Yocto",
}


def parse_purl(purl_str: str) -> PackageURL | None:
    """Parse *purl_str* into a :class:`~packageurl.PackageURL`.

    Returns ``None`` when the value is empty or malformed instead of raising,
    which keeps callers free of try/except blocks when scanning thousands of
    components.
    """
    if not purl_str or not isinstance(purl_str, str):
        return None

    candidate = purl_str.strip()
    if not candidate:
        return None

    # Some producers emit the bare coordinates without the ``pkg:`` scheme.
    if not candidate.startswith("pkg:"):
        candidate = f"pkg:{candidate}"

    try:
        return PackageURL.from_string(candidate)
    except ValueError:
        return None


def validate_purl(purl_str: str) -> bool:
    """Return ``True`` when *purl_str* is a syntactically valid purl."""
    return parse_purl(purl_str) is not None


def purl_to_ecosystem(purl_str: str) -> str:
    """Map a purl (or bare purl type) to its ecosystem name.

    Accepts either a full purl (``pkg:npm/express@4.0.0``) or just the type
    (``npm``).  Unknown types are returned verbatim so no information is lost.
    """
    if not purl_str:
        return ""

    candidate = purl_str.strip()
    if candidate.startswith("pkg:") or "/" in candidate:
        parsed = parse_purl(candidate)
        purl_type = parsed.type if parsed is not None else candidate.split("/", 1)[0].removeprefix("pkg:")
    else:
        purl_type = candidate

    purl_type = purl_type.lower().strip()
    return PURL_ECOSYSTEMS.get(purl_type, purl_type)
