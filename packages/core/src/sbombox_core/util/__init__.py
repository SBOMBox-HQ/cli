"""Small, dependency-light helpers shared across ``sbombox_core``.

The submodules are pure functions over strings and bytes - no I/O, no network,
no global state - which makes them safe to call from parsers, validators and
the scoring engine alike.
"""

from __future__ import annotations

from sbombox_core.util.hashes import (
    EXPECTED_LENGTHS,
    SUPPORTED_ALGORITHMS,
    compute_hash,
    compute_sha256,
    compute_sha512,
    normalize_algorithm,
    validate_hash,
)
from sbombox_core.util.licenses import (
    SPDX_NOASSERTION,
    SPDX_NONE,
    extract_license_ids,
    is_valid_spdx_license,
    normalize_license_expression,
)
from sbombox_core.util.purl import PURL_ECOSYSTEMS, parse_purl, purl_to_ecosystem, validate_purl

__all__ = [
    "EXPECTED_LENGTHS",
    "PURL_ECOSYSTEMS",
    "SPDX_NOASSERTION",
    "SPDX_NONE",
    "SUPPORTED_ALGORITHMS",
    "compute_hash",
    "compute_sha256",
    "compute_sha512",
    "extract_license_ids",
    "is_valid_spdx_license",
    "normalize_algorithm",
    "normalize_license_expression",
    "parse_purl",
    "purl_to_ecosystem",
    "validate_hash",
    "validate_purl",
]
