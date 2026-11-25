"""Tests for :mod:`sbombox_core.util`.

These helpers are the shared vocabulary of the whole package: the parser uses
them to normalise digests, the validator uses them to judge purls and licenses,
and the scoring engine will use them to decide whether an SBOM is trustworthy.
The behaviour worth pinning down is therefore the *tolerance* - what sloppy
input is accepted, and what is refused.
"""

from __future__ import annotations

import hashlib

import pytest
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
    extract_license_ids,
    is_valid_spdx_license,
    normalize_license_expression,
)
from sbombox_core.util.purl import PURL_ECOSYSTEMS, parse_purl, purl_to_ecosystem, validate_purl

# --------------------------------------------------------------------------- #
# purls
# --------------------------------------------------------------------------- #

VALID_PURLS = [
    "pkg:npm/express@4.18.2",
    "pkg:pypi/requests@2.31.0",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1",
    "pkg:golang/github.com/gorilla/mux@v1.8.0",
    "pkg:cargo/serde@1.0.0",
    "pkg:nuget/Newtonsoft.Json@13.0.1",
    "pkg:generic/acme-app@1.0.0",
    "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
    "pkg:docker/library/nginx@sha256%3Aabcdef",
]

INVALID_PURLS = [
    "",
    "   ",
    "pkg:not-a-purl",
    "pkg:npm",
    "not a purl at all",
    "http://example.com/pkg:npm/express@4.18.2",
]


@pytest.mark.parametrize("purl", VALID_PURLS)
def test_a_well_formed_purl_is_accepted(purl: str) -> None:
    assert validate_purl(purl)
    assert parse_purl(purl) is not None


@pytest.mark.parametrize("purl", INVALID_PURLS)
def test_a_malformed_purl_is_refused_without_raising(purl: str) -> None:
    """Validators scan thousands of these; an exception per bad purl is unusable."""
    assert not validate_purl(purl)
    assert parse_purl(purl) is None


def test_parse_purl_exposes_the_coordinates() -> None:
    parsed = parse_purl("pkg:npm/@scope/pkg@1.2.3")
    assert parsed is not None
    assert parsed.type == "npm"
    # The purl spec keeps the ``@`` on an npm scope; it is percent-encoded
    # (``%40``) in the string form rather than dropped.
    assert parsed.namespace == "@scope"
    assert parsed.name == "pkg"
    assert parsed.version == "1.2.3"
    assert parsed.qualifiers == {}
    assert str(parsed) == "pkg:npm/%40scope/pkg@1.2.3"


def test_a_purl_without_the_scheme_is_still_understood() -> None:
    """Some producers emit bare coordinates; rejecting them loses real data."""
    parsed = parse_purl("npm/express@4.18.2")
    assert parsed is not None
    assert parsed.type == "npm"


def test_parse_purl_rejects_a_non_string() -> None:
    assert parse_purl(None) is None  # type: ignore[arg-type]
    assert parse_purl(42) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("purl", "ecosystem"),
    [
        ("pkg:npm/express@4.18.2", "npm"),
        ("pkg:pypi/requests@2.31.0", "PyPI"),
        ("pkg:maven/a/b@1", "Maven"),
        ("pkg:cargo/serde@1", "crates.io"),
        ("pkg:golang/x/y@v1", "Go"),
        ("pkg:gem/rails@7", "RubyGems"),
        ("pkg:nuget/N@1", "NuGet"),
        ("pkg:composer/vendor/pkg@1", "Packagist"),
        ("pkg:apk/alpine/curl@1", "Alpine"),
        ("pkg:deb/debian/curl@1", "Debian"),
    ],
)
def test_purl_to_ecosystem_uses_the_advisory_database_names(purl: str, ecosystem: str) -> None:
    """OSV and GHSA key on these exact spellings, so they cannot be invented."""
    assert purl_to_ecosystem(purl) == ecosystem


def test_purl_to_ecosystem_accepts_a_bare_type() -> None:
    assert purl_to_ecosystem("npm") == "npm"
    assert purl_to_ecosystem("pypi") == "PyPI"


def test_an_unknown_ecosystem_is_returned_verbatim() -> None:
    """A new purl type must degrade to its own name, not to a blank string."""
    assert purl_to_ecosystem("pkg:brandnew/thing@1") == "brandnew"
    assert purl_to_ecosystem("") == ""


def test_the_ecosystem_map_is_lowercase_keyed() -> None:
    """purl types are case-insensitive, so the lookup table must be too."""
    assert all(key == key.lower() for key in PURL_ECOSYSTEMS)


# --------------------------------------------------------------------------- #
# licenses
# --------------------------------------------------------------------------- #

VALID_LICENSES = [
    "MIT",
    "Apache-2.0",
    "GPL-3.0-only",
    "BSD-3-Clause",
    "MPL-2.0",
    "CC0-1.0",
    "NOASSERTION",
    "NONE",
    "LicenseRef-Acme-Internal",
    "MIT OR Apache-2.0",
    "Apache-2.0 AND MIT",
    "(MIT OR Apache-2.0)",
]

INVALID_LICENSES = [
    "",
    "   ",
    "Totally-Not-A-License",
    "MIT OR",
    "Apache 2",
    "(MIT",
]


@pytest.mark.parametrize("license_id", VALID_LICENSES)
def test_known_spdx_licenses_are_recognised(license_id: str) -> None:
    assert is_valid_spdx_license(license_id)


@pytest.mark.parametrize("license_id", INVALID_LICENSES)
def test_unknown_spdx_licenses_are_rejected(license_id: str) -> None:
    assert not is_valid_spdx_license(license_id)


def test_license_matching_is_case_insensitive() -> None:
    """The SPDX specification recommends comparing identifiers without case."""
    assert is_valid_spdx_license("mit")
    assert is_valid_spdx_license("apache-2.0")


def test_a_user_defined_license_ref_is_valid() -> None:
    """``LicenseRef-*`` is how SPDX expresses "proprietary, but declared"."""
    assert is_valid_spdx_license("LicenseRef-Some-Vendor-EULA")


def test_normalize_license_expression_canonicalises_identifiers() -> None:
    assert normalize_license_expression("apache-2.0") == "Apache-2.0"


def test_normalize_license_expression_upper_cases_operators() -> None:
    assert normalize_license_expression("mit or apache-2.0") == "MIT OR Apache-2.0"


def test_normalize_license_expression_preserves_reserved_values() -> None:
    assert normalize_license_expression("noassertion") == "NOASSERTION"
    assert normalize_license_expression("none") == "NONE"


def test_normalize_license_expression_never_loses_data() -> None:
    """An unparseable expression is returned intact: tidying must not truncate."""
    assert normalize_license_expression("  Bogus-1.0  ") == "Bogus-1.0"
    assert normalize_license_expression("") == ""


def test_extract_license_ids_splits_an_expression() -> None:
    assert extract_license_ids("MIT OR Apache-2.0") == ["MIT", "Apache-2.0"]


def test_extract_license_ids_removes_operators_and_parentheses() -> None:
    assert extract_license_ids("(MIT AND Apache-2.0) OR BSD-3-Clause") == ["MIT", "Apache-2.0", "BSD-3-Clause"]


def test_extract_license_ids_deduplicates_but_keeps_order() -> None:
    assert extract_license_ids("MIT OR Apache-2.0 OR MIT") == ["MIT", "Apache-2.0"]


def test_extract_license_ids_handles_the_reserved_values() -> None:
    assert extract_license_ids("NOASSERTION") == ["NOASSERTION"]
    assert extract_license_ids("") == []


def test_extract_license_ids_keeps_unknown_identifiers() -> None:
    """A proprietary ``LicenseRef-`` is still a license the user must see."""
    assert extract_license_ids("LicenseRef-Acme AND MIT") == ["LicenseRef-Acme", "MIT"]


# --------------------------------------------------------------------------- #
# hashes
# --------------------------------------------------------------------------- #


def test_expected_lengths_cover_the_required_algorithms() -> None:
    """The five the ruleset depends on must be present with the right widths."""
    for algorithm, length in {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128}.items():
        assert EXPECTED_LENGTHS[algorithm] == length


def test_supported_algorithms_matches_the_length_table() -> None:
    assert set(SUPPORTED_ALGORITHMS) == set(EXPECTED_LENGTHS)


@pytest.mark.parametrize("algorithm", list(EXPECTED_LENGTHS))
def test_a_correctly_sized_digest_is_accepted(algorithm: str) -> None:
    assert validate_hash(algorithm, "a" * EXPECTED_LENGTHS[algorithm])


@pytest.mark.parametrize("algorithm", list(EXPECTED_LENGTHS))
def test_a_wrongly_sized_digest_is_rejected(algorithm: str) -> None:
    assert not validate_hash(algorithm, "a" * (EXPECTED_LENGTHS[algorithm] - 1))
    assert not validate_hash(algorithm, "a" * (EXPECTED_LENGTHS[algorithm] + 1))


def test_a_non_hexadecimal_digest_is_rejected() -> None:
    """Right length, wrong alphabet - a truncated base64 digest looks like this."""
    assert not validate_hash("SHA-1", "z" * 40)


def test_an_unknown_algorithm_is_rejected() -> None:
    """A digest we cannot interpret cannot be trusted to be well-formed."""
    assert not validate_hash("ROT-13", "a" * 32)
    assert not validate_hash("", "a" * 32)


def test_an_empty_digest_is_rejected() -> None:
    assert not validate_hash("SHA-256", "")


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        ("sha256", "SHA-256"),
        ("SHA-256", "SHA-256"),
        ("SHA_256", "SHA-256"),
        ("SHA 256", "SHA-256"),
        ("sha1", "SHA-1"),
        ("md5", "MD5"),
        ("SHA512", "SHA-512"),
    ],
)
def test_algorithm_spellings_are_normalised(spelling: str, canonical: str) -> None:
    """SPDX says ``SHA256``, CycloneDX says ``SHA-256``; both must compare equal."""
    assert normalize_algorithm(spelling) == canonical


def test_an_unknown_algorithm_normalises_to_none() -> None:
    assert normalize_algorithm("ROT-13") is None
    assert normalize_algorithm("") is None


def test_a_prefixed_digest_is_accepted() -> None:
    """OCI tooling emits ``sha256:<hex>``; stripping the prefix is harmless."""
    assert validate_hash("SHA-256", f"sha256:{'a' * 64}")


def test_compute_sha256_matches_hashlib() -> None:
    data = b"sbombox"
    assert compute_sha256(data) == hashlib.sha256(data).hexdigest()


def test_compute_sha512_matches_hashlib() -> None:
    data = b"sbombox"
    assert compute_sha512(data) == hashlib.sha512(data).hexdigest()


def test_compute_hash_is_case_and_spelling_insensitive() -> None:
    data = b"sbombox"
    assert compute_hash(data, "sha256") == compute_hash(data, "SHA-256") == hashlib.sha256(data).hexdigest()


def test_compute_hash_rejects_an_unknown_algorithm() -> None:
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        compute_hash(b"x", "ROT-13")


def test_computed_digests_pass_their_own_validation() -> None:
    """Round-tripping is the point: what we compute, we must accept."""
    data = b"sbombox-core"
    assert validate_hash("SHA-256", compute_sha256(data))
    assert validate_hash("SHA-512", compute_sha512(data))
