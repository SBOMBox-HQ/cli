"""Tests for the package's public surface - :func:`sbombox_core.load`.

``load()`` is the one function most callers ever touch, and its job is to accept
whatever the caller happens to be holding: a ``Path``, a filename string, raw
bytes, or the document itself as text.  The interesting cases are therefore the
ambiguous ones - a string that could be a path or a document - and the failures,
which have to name the actual problem rather than a generic "could not parse".
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import sbombox_core
from sbombox_core import (
    MalformedDocumentError,
    Sbom,
    SbomParseError,
    UnsupportedFormatError,
    load,
    validate_sbom,
)

from tests.fixtures import CDX_JSON, CDX_XML, CDX_YAML, DOCUMENTS, SPDX_JSON, SPDX_TAG_VALUE

if TYPE_CHECKING:
    # pytest resolves fixtures by parameter *name*, so the annotations on the
    # fixture signatures below are never evaluated and ``Path`` stays typing-only.
    from pathlib import Path

CDX_TEXT = json.dumps(CDX_JSON)
SPDX_TEXT = json.dumps(SPDX_JSON)


# --------------------------------------------------------------------------- #
# the advertised surface
# --------------------------------------------------------------------------- #


def test_version_matches_the_distribution_metadata() -> None:
    """A hard-coded ``__version__`` drifts; this is the tripwire."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("sbombox-core")
    except PackageNotFoundError:
        pytest.skip("sbombox-core is not installed; running from a source tree")
    assert sbombox_core.__version__ == installed


@pytest.mark.parametrize("name", sbombox_core.__all__)
def test_everything_in_all_is_importable(name: str) -> None:
    """``__all__`` is a promise; a name listed but missing breaks ``import *``."""
    assert hasattr(sbombox_core, name), name


def test_the_documented_entry_points_are_exported() -> None:
    for name in ("load", "parse_sbom", "validate_sbom", "Sbom", "Component", "__version__"):
        assert name in sbombox_core.__all__, name


# --------------------------------------------------------------------------- #
# every accepted input form
# --------------------------------------------------------------------------- #


@pytest.fixture
def tree(tmp_path: Path) -> dict[str, Path]:
    """A directory holding the same SBOM under several names and encodings."""
    paths = {
        "json": tmp_path / "bom.json",
        "xml": tmp_path / "bom.xml",
        "yaml": tmp_path / "bom.yaml",
        "spdx": tmp_path / "bom.spdx",
        "extensionless": tmp_path / "bom",
    }
    paths["json"].write_text(CDX_TEXT, encoding="utf-8")
    paths["xml"].write_bytes(CDX_XML)
    paths["yaml"].write_text(CDX_YAML, encoding="utf-8")
    paths["spdx"].write_text(SPDX_TAG_VALUE, encoding="utf-8")
    paths["extensionless"].write_text(SPDX_TEXT, encoding="utf-8")
    return paths


def test_load_accepts_a_path_object(tree: dict[str, Path]) -> None:
    sbom = load(tree["json"])
    assert isinstance(sbom, Sbom)
    assert sbom.format.value == "cyclonedx"
    assert sbom.summary()["components"] == 2


def test_load_accepts_a_path_string(tree: dict[str, Path]) -> None:
    assert load(str(tree["json"])).summary()["components"] == 2


@pytest.mark.parametrize("key", ["xml", "yaml", "spdx", "extensionless"])
def test_load_reads_every_serialisation_from_disk(tree: dict[str, Path], key: str) -> None:
    """Format comes from the content, so the extension is a hint at most."""
    sbom = load(tree[key])
    assert sbom.components or sbom.metadata.component is not None


def test_load_accepts_json_text() -> None:
    assert load(CDX_TEXT).summary()["components"] == 2


def test_load_accepts_xml_bytes() -> None:
    assert load(CDX_XML).format.value == "cyclonedx"


def test_load_accepts_a_bytearray() -> None:
    """Mutable buffers arrive from network and file APIs alike."""
    assert load(bytearray(DOCUMENTS["spdx-rdf"])).format.value == "spdx"


def test_load_accepts_yaml_text() -> None:
    assert load(CDX_YAML).spec_version == "1.4"


def test_load_accepts_tag_value_text() -> None:
    assert load(SPDX_TAG_VALUE).format.value == "spdx"


def test_a_relative_path_is_resolved_against_the_cwd(tree: dict[str, Path], monkeypatch) -> None:
    monkeypatch.chdir(tree["json"].parent)
    assert load("bom.json").summary()["components"] == 2


# --------------------------------------------------------------------------- #
# format hints
# --------------------------------------------------------------------------- #


def test_a_string_format_hint_is_honoured() -> None:
    assert load(SPDX_TEXT, format="spdx").format.value == "spdx"


def test_an_enum_format_hint_is_honoured() -> None:
    assert load(CDX_XML, format=sbombox_core.SbomFormat.CYCLONEDX).format.value == "cyclonedx"


def test_a_hint_cannot_contradict_the_content() -> None:
    """The hint says how to parse, not what the bytes are allowed to contain."""
    with pytest.raises(SbomParseError):
        load(SPDX_TEXT, format="cyclonedx")


# --------------------------------------------------------------------------- #
# path-versus-document disambiguation
# --------------------------------------------------------------------------- #


def test_a_path_that_does_not_exist_says_it_could_not_be_read(tree: dict[str, Path]) -> None:
    """The useful message is "no such file", not "cannot detect SBOM format"."""
    with pytest.raises(SbomParseError, match="(?i)read|open|exist"):
        load(str(tree["json"].parent / "absent.json"))


def test_an_extensionless_path_that_does_not_exist_is_still_a_path(tree: dict[str, Path]) -> None:
    """A dotted or nested name is a path even before the file exists."""
    with pytest.raises(SbomParseError, match="(?i)read|open|exist"):
        load(str(tree["json"].parent / "absent"))


def test_a_dotted_relative_name_is_treated_as_a_path(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SbomParseError, match="(?i)read|open|exist"):
        load("./missing/bom")


def test_a_document_starting_with_a_brace_is_never_a_path() -> None:
    assert load(CDX_TEXT).format.value == "cyclonedx"


def test_a_document_starting_with_an_angle_bracket_is_never_a_path() -> None:
    assert load(CDX_XML.decode()).format.value == "cyclonedx"


def test_a_very_long_string_is_a_document_not_a_filename() -> None:
    """No real path is 4 KB of JSON; treating it as one would just fail oddly."""
    with pytest.raises(UnsupportedFormatError):
        load("x" * 8192)


def test_a_multiline_string_is_a_document_not_a_path() -> None:
    with pytest.raises(UnsupportedFormatError):
        load("bom.json\nbom.xml")


# --------------------------------------------------------------------------- #
# failures
# --------------------------------------------------------------------------- #


def test_a_document_that_is_not_an_sbom_is_unsupported() -> None:
    with pytest.raises(UnsupportedFormatError):
        load('{"hello": "world"}')


def test_truncated_json_is_malformed_not_unsupported() -> None:
    with pytest.raises(MalformedDocumentError):
        load('{"bomFormat": "CycloneDX",')


def test_broken_xml_is_malformed_not_unsupported() -> None:
    with pytest.raises(MalformedDocumentError):
        load(b"<bom><components>")


def test_an_empty_string_is_a_parse_error() -> None:
    with pytest.raises(SbomParseError):
        load("")


def test_an_unknown_format_hint_is_unsupported() -> None:
    with pytest.raises(UnsupportedFormatError):
        load(CDX_TEXT, format="csaf")


def test_a_wrong_argument_type_is_a_type_error() -> None:
    """``42`` is neither a path nor a document; guessing would hide the bug."""
    with pytest.raises(TypeError):
        load(42)


def test_every_parse_failure_is_catchable_as_one_base_class() -> None:
    """Callers want one ``except``, not a taxonomy lesson."""
    for bad in ['{"hello": "world"}', '{"bomFormat": "CycloneDX",', "", b"<bom>"]:
        with pytest.raises(SbomParseError):
            load(bad)


def test_a_directory_is_rejected_clearly(tmp_path: Path) -> None:
    with pytest.raises(SbomParseError):
        load(tmp_path)


# --------------------------------------------------------------------------- #
# the documented end-to-end flow
# --------------------------------------------------------------------------- #


def test_load_then_validate_is_the_documented_two_liner() -> None:
    """The module docstring promises this pairing works; keep it true."""
    result = validate_sbom(load(CDX_TEXT))
    assert result.valid
    assert result.issues, "the fixture has a dangling dependency ref"


@pytest.mark.parametrize("name", list(DOCUMENTS))
def test_load_handles_every_fixture(name: str) -> None:
    assert isinstance(load(DOCUMENTS[name]), Sbom)
