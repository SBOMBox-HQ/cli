"""Container image SBOMs: BuildKit attestation first, then syft."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sbombox_core.generate.image import generate_image, plan_image_generators
from sbombox_core.serialize import serialize_sbom

DIGEST = "sha256:" + "d" * 64

SPDX = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "image",
    "dataLicense": "CC0-1.0",
    "documentNamespace": "https://example.com/sbom/1",
    "creationInfo": {"created": "2026-11-16T00:00:00Z", "creators": ["Tool: buildkit"]},
    "packages": [
        {
            "SPDXID": "SPDXRef-musl",
            "name": "musl",
            "versionInfo": "1.2.5-r0",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:apk/alpine/musl@1.2.5-r0",
                }
            ],
        }
    ],
}

SYFT_CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "metadata": {"component": {"type": "container", "name": "alpine", "version": "sha256:" + "e" * 64}},
    "components": [
        {"type": "library", "name": "busybox", "version": "1.36.1-r29", "purl": "pkg:apk/alpine/busybox@1.36.1-r29"}
    ],
}


def _available(*commands: str):
    return lambda c: c in commands


def _fake(sbom_json: object | None, calls: list[list[str]], syft_fails: bytes | None = None):
    """subprocess.run stand-in for docker buildx and syft."""

    def run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "buildx", "imagetools"]:
            if "--format" in cmd:
                return MagicMock(stdout=json.dumps(sbom_json).encode())
            text = f"Name: x\nMediaType: application/vnd.oci.image.index.v1+json\nDigest: {DIGEST}\n"
            return MagicMock(stdout=text.encode())
        if cmd[0] == "syft":
            if syft_fails is not None:
                raise subprocess.CalledProcessError(1, cmd, stderr=syft_fails)
            assert kwargs["env"]["SYFT_FILE_METADATA_SELECTION"] == "none"
            Path(cmd[cmd.index("-o") + 1].split("=", 1)[1]).write_text(json.dumps(SYFT_CDX))
            return MagicMock(returncode=0)
        raise AssertionError(f"unexpected command {cmd}")

    return run


def _generate(ref: str, sbom_json: object | None, tools=("docker", "syft"), **kw):
    calls: list[list[str]] = []
    run = _fake(sbom_json, calls, kw.pop("syft_fails", None))
    with (
        patch("sbombox_core.generate.image.subprocess.run", side_effect=run),
        patch("sbombox_core.generate.image._is_available", side_effect=_available(*tools)),
    ):
        result = generate_image(ref, **kw)
    return result, calls


def test_buildkit_attestation_is_used_first() -> None:
    result, calls = _generate("ghcr.io/acme/api:1.4.0", {"SPDX": SPDX})
    assert result.generator == "BuildKit SBOM attestation"
    assert not any(c[0] == "syft" for c in calls)
    root = result.sbom.metadata.component
    assert (root.type, root.name, root.version) == ("container", "ghcr.io/acme/api", "1.4.0")
    assert root.hashes[0].content == "d" * 64
    assert result.sbom.metadata.properties["sbombox:image:digest"] == DIGEST
    assert [c.name for c in result.sbom.components] == ["musl"]


def test_multi_platform_attestation_picks_the_platform() -> None:
    arm = json.loads(json.dumps(SPDX))
    arm["packages"][0]["name"] = "musl-arm"
    data = {"linux/amd64": {"SPDX": SPDX}, "linux/arm64": {"SPDX": arm}}
    assert [c.name for c in _generate("alpine:3.20", data)[0].sbom.components] == ["musl"]
    picked = _generate("alpine:3.20", data, platform="linux/arm64")[0]
    assert [c.name for c in picked.sbom.components] == ["musl-arm"]


def test_missing_platform_falls_back_to_syft_with_that_platform() -> None:
    result, calls = _generate("alpine:3.20", {"linux/amd64": {"SPDX": SPDX}}, platform="linux/s390x")
    assert result.generator == "syft"
    syft = next(c for c in calls if c[0] == "syft")
    assert syft[syft.index("--platform") + 1] == "linux/s390x"


def test_no_attestation_uses_syft() -> None:
    result, calls = _generate("alpine:3.20", None)
    assert result.generator == "syft"
    syft = next(c for c in calls if c[0] == "syft")
    assert syft[:2] == ["syft", "alpine:3.20"] and syft[3].startswith("cyclonedx-json@1.6=")
    root = result.sbom.metadata.component
    assert (root.type, root.name, root.version) == ("container", "alpine", "3.20")


def test_syft_alone_works_without_docker() -> None:
    result, calls = _generate("ghcr.io/acme/api@" + DIGEST, None, tools=("syft",))
    assert [c[0] for c in calls] == ["syft"]
    root = result.sbom.metadata.component
    assert root.version == DIGEST and root.hashes[0].content == "d" * 64


def test_registry_refusal_is_explained() -> None:
    with pytest.raises(RuntimeError, match="docker login"):
        refusal = b"GET ...: UNAUTHORIZED: authentication required"
        _generate("private.example/app:1", None, tools=("syft",), syft_fails=refusal)


def test_no_tools_says_how_to_install() -> None:
    with pytest.raises(RuntimeError, match="install.sh"):
        _generate("alpine:3.20", None, tools=())


def test_option_like_refs_are_refused() -> None:
    with pytest.raises(RuntimeError, match="Not an image reference"):
        generate_image("--help")


def test_generator_env_is_filtered_to_image_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SBOMBOX_GENERATOR", "npm-sbom")
    assert plan_image_generators() == ["buildx-attestation", "syft"]
    monkeypatch.setenv("SBOMBOX_GENERATOR", "npm-sbom,syft")
    assert plan_image_generators() == ["syft"]


def test_image_metadata_is_serialised() -> None:
    result, _ = _generate("ghcr.io/acme/api:1.4.0", {"SPDX": SPDX})
    doc = json.loads(serialize_sbom(result.sbom, "cyclonedx-1.6"))
    assert doc["metadata"]["component"]["type"] == "container"
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["sbombox:image:digest"] == DIGEST
    assert props["sbombox:image:ref"] == "ghcr.io/acme/api:1.4.0"
    assert props["sbombox:image:source"] == "buildx-attestation"


def test_unknown_registry_is_explained() -> None:
    stderr = (
        b"ERROR could not determine source: errors occurred attempting to resolve 'nope.example/x:1':\n"
        b"  - oci-registry: Get \"https://nope.example/v2/\": dial tcp: lookup nope.example: no such host"
    )
    with pytest.raises(RuntimeError, match="registry could not be reached"):
        _generate("nope.example/x:1", None, tools=("syft",), syft_fails=stderr)
