"""Hash algorithm helpers: validation and computation.

Digests appear in SBOMs as ``(algorithm, hex-digest)`` pairs.  Producers are
inconsistent about algorithm spelling (``SHA256`` vs ``SHA-256`` vs
``sha_256``), so everything funnels through :func:`normalize_algorithm` first.
"""

from __future__ import annotations

import hashlib
import re

__all__ = [
    "EXPECTED_LENGTHS",
    "SUPPORTED_ALGORITHMS",
    "compute_hash",
    "compute_sha256",
    "compute_sha512",
    "normalize_algorithm",
    "validate_hash",
]

#: Canonical algorithm name -> expected hex-digest length.
#:
#: The five entries required by the SBOMBox validation ruleset come first; the
#: remaining algorithms are the extra values permitted by CycloneDX and SPDX so
#: real-world documents do not fail validation spuriously.
EXPECTED_LENGTHS: dict[str, int] = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}

#: Canonical algorithm name -> :mod:`hashlib` algorithm name.
_HASHLIB_NAMES: dict[str, str] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
    "BLAKE2b-256": "blake2b",
    "BLAKE2b-384": "blake2b",
    "BLAKE2b-512": "blake2b",
}

#: Algorithms SBOMBox understands, keyed by their canonical spelling.
SUPPORTED_ALGORITHMS: tuple[str, ...] = tuple(EXPECTED_LENGTHS)

# ``sha256``, ``SHA-256``, ``sha_256`` and ``SHA 256`` all collapse to the same
# key once punctuation/case is removed.
_CANONICAL_LOOKUP: dict[str, str] = {re.sub(r"[-_\s]", "", name).lower(): name for name in EXPECTED_LENGTHS}

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")


def normalize_algorithm(alg: str) -> str | None:
    """Return the canonical spelling of *alg*, or ``None`` when unknown.

    >>> normalize_algorithm("sha256")
    'SHA-256'
    >>> normalize_algorithm("SHA_1")
    'SHA-1'
    >>> normalize_algorithm("ROT-13") is None
    True
    """
    if not alg:
        return None
    return _CANONICAL_LOOKUP.get(re.sub(r"[-_\s]", "", str(alg)).lower())


def validate_hash(alg: str, value: str) -> bool:
    """Return ``True`` when *value* is a well-formed digest for *alg*.

    The check covers both the digest length and the hexadecimal character set.
    Unknown algorithms return ``False`` - a digest we cannot interpret cannot be
    trusted to be well-formed.
    """
    canonical = normalize_algorithm(alg)
    if canonical is None:
        return False
    if not value or not isinstance(value, str):
        return False

    digest = value.strip().lower()
    if digest.startswith(("0x", "sha256:", "sha512:", "sha1:", "md5:")):
        # ``sha256:<hex>`` style digests are emitted by some OCI tooling.
        digest = digest.split(":", 1)[1]

    if not _HEX_ONLY.match(digest):
        return False
    return len(digest) == EXPECTED_LENGTHS[canonical]


def compute_hash(data: bytes, alg: str = "SHA-256") -> str:
    """Return the hex digest of *data* for *alg*."""
    canonical = normalize_algorithm(alg)
    if canonical is None:
        raise ValueError(f"Unsupported hash algorithm: {alg!r}")

    hashlib_name = _HASHLIB_NAMES[canonical]
    if hashlib_name == "blake2b":
        # EXPECTED_LENGTHS counts hex characters; blake2b wants raw bytes.
        digest_size = EXPECTED_LENGTHS[canonical] // 2
        return hashlib.blake2b(data, digest_size=digest_size).hexdigest()

    return hashlib.new(hashlib_name, data).hexdigest()


def compute_sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def compute_sha512(data: bytes) -> str:
    """Return the SHA-512 hex digest of *data*."""
    return hashlib.sha512(data).hexdigest()
