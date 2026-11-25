"""SBOMs for container images.

Two sources, tried in order:

1. ``buildx-attestation``: the SBOM BuildKit attached when the image was built
   with ``docker buildx build --sbom=true`` (an SPDX document). It describes
   exactly what the build put in the image, so it is preferred when present.
   Read with ``docker buildx imagetools inspect REF --format '{{ json .SBOM }}'``.
2. ``syft``: scans the image's layers (OS packages and language packages).
   Registry credentials come from Docker's own config (``docker login``, or
   ``DOCKER_CONFIG``).

``SBOMBOX_GENERATOR`` can force the order (``syft`` or
``buildx-attestation``); names that cannot read images are ignored here, so a
value meant for source scans does not break image scans.

Usage::

    from sbombox_core.generate.image import generate_image
    result = generate_image("ghcr.io/acme/api:1.4.0")
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sbombox_core.generate import GENERATOR_ENV, GenerationResult, _cyclonedx_version, _is_available
from sbombox_core.model.common import Hash
from sbombox_core.model.component import Component, ComponentType

if TYPE_CHECKING:
    from sbombox_core.model.sbom import Sbom

__all__ = ["IMAGE_GENERATORS", "generate_image", "plan_image_generators"]

#: Image-capable generators, best first.
IMAGE_GENERATORS: tuple[str, ...] = ("buildx-attestation", "syft")
#: Platform picked from a multi-platform image when none is given.
DEFAULT_PLATFORM = "linux/amd64"

_DIGEST = re.compile(r"^Digest:\s+(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


def plan_image_generators() -> list[str]:
    """Order in which image generators are tried (``SBOMBOX_GENERATOR`` aware)."""
    forced = [n.strip() for n in os.environ.get(GENERATOR_ENV, "").split(",") if n.strip()]
    chosen = [n for n in forced if n in IMAGE_GENERATORS]
    return chosen or list(IMAGE_GENERATORS)


def generate_image(ref: str, fmt: str = "cyclonedx-1.6", platform: str | None = None) -> GenerationResult:
    """Generate an SBOM for the container image ``ref``.

    Args:
        ref: Image reference, e.g. ``alpine:3.20`` or ``ghcr.io/acme/api@sha256:...``.
        fmt: Requested output format; only the CycloneDX version matters here,
            the caller serialises the result.
        platform: For multi-platform images, e.g. ``linux/arm64``. Default
            ``linux/amd64``.

    Raises:
        RuntimeError: when no generator could produce an SBOM. The message
            lists why each one failed.
    """
    ref = ref.strip()
    if not ref or ref.startswith("-"):
        raise RuntimeError(f"Not an image reference: {ref!r}")

    errors: list[str] = []
    for name in plan_image_generators():
        try:
            if name == "buildx-attestation":
                sbom = _from_attestation(ref, platform)
                if sbom is None:
                    continue  # no attestation on this image: not an error
            else:
                sbom = _from_syft(ref, fmt, platform)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        _describe_image(sbom, ref, _digest(ref), source=name)
        return GenerationResult(sbom=sbom, generator=_LABELS[name], ecosystems=["container"])

    if errors:
        raise RuntimeError("; ".join(errors))
    raise RuntimeError(
        "No SBOM generator for container images found. syft is installed by "
        "curl -fsSL https://sbombox.com/install.sh | sh"
    )


_LABELS = {"buildx-attestation": "BuildKit SBOM attestation", "syft": "syft"}


# --------------------------------------------------------------- sources


def _from_attestation(ref: str, platform: str | None) -> Sbom | None:
    """The image's BuildKit SBOM attestation, or ``None`` if it has none."""
    if not _is_available("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{ json .SBOM }}"],
            capture_output=True,
            check=True,
            timeout=120,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        # buildx missing, image unreachable or no permission: let syft try,
        # and let syft's error (which names the cause) reach the user.
        return None
    document = _pick_platform(_json_or_none(proc.stdout), platform)
    if not document:
        return None
    from sbombox_core import load

    sbom = load(json.dumps(document))
    return sbom if sbom.components else None


def _pick_platform(data: Any, platform: str | None) -> dict[str, Any] | None:
    """The SPDX document from ``.SBOM``, single- or multi-platform."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("SPDX"), dict):
        single: dict[str, Any] = data["SPDX"]
        return single
    per_platform = {k: v for k, v in data.items() if isinstance(v, dict) and isinstance(v.get("SPDX"), dict)}
    if not per_platform:
        return None
    if platform:
        if platform not in per_platform:
            # Never substitute another platform's SBOM; let syft scan the one asked for.
            raise RuntimeError(
                f"The image has no SBOM attestation for {platform}; it has: {', '.join(sorted(per_platform))}."
            )
        key = platform
    else:
        key = DEFAULT_PLATFORM if DEFAULT_PLATFORM in per_platform else sorted(per_platform)[0]
    document: dict[str, Any] = per_platform[key]["SPDX"]
    return document


def _from_syft(ref: str, fmt: str, platform: str | None) -> Sbom:
    if not _is_available("syft"):
        raise RuntimeError(
            "syft is not installed. Install it with: curl -fsSL https://sbombox.com/install.sh | sh"
        )
    with tempfile.TemporaryDirectory(prefix="sbombox-image-") as tmp:
        out = Path(tmp) / "image.cdx.json"
        args = ["syft", ref, "-o", f"cyclonedx-json@{_cyclonedx_version(fmt)}={out}"]
        if platform:
            args += ["--platform", platform]
        # By default syft also lists every file it hashed as a component (77
        # of 92 entries for alpine:3.20). Files have no version or purl, so
        # they bury the packages and drag the score down. Respect an explicit
        # setting from the user.
        env = {**os.environ}
        env.setdefault("SYFT_FILE_METADATA_SELECTION", "none")
        try:
            subprocess.run(args, capture_output=True, check=True, timeout=900, env=env)
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or b"").decode(errors="replace").strip()
            raise RuntimeError(f"syft could not read {ref}: {_explain(stderr) or exc}") from exc
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError(f"syft could not read {ref}: {exc}") from exc
        if not out.is_file() or out.stat().st_size == 0:
            raise RuntimeError(f"syft produced no output for {ref}.")
        from sbombox_core import load

        return load(out)


def _explain(stderr: str) -> str:
    lowered = stderr.lower()
    if "unauthorized" in lowered or "authentication required" in lowered or "denied" in lowered:
        return "the registry refused access. Run `docker login <registry>` (or set DOCKER_CONFIG) and try again."
    if "no such host" in lowered:
        return "the registry could not be reached. Check the registry name in the image reference, and the network."
    if "not found" in lowered or "manifest unknown" in lowered or "could not determine source" in lowered:
        return (
            "the image was not found locally or in its registry. Check the name and tag, "
            "and that the image has been pushed (or pulled, for a local image)."
        )
    return stderr


# --------------------------------------------------------------- metadata


def _digest(ref: str) -> str | None:
    """The image's manifest digest: from the reference, else from the registry."""
    if "@sha256:" in ref:
        return ref.split("@", 1)[1]
    if not _is_available("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref], capture_output=True, check=True, timeout=120
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    text = proc.stdout.decode(errors="replace") if isinstance(proc.stdout, bytes) else ""
    match = _DIGEST.search(text)
    return match.group(1) if match else None


def _split_ref(ref: str) -> tuple[str, str | None]:
    """``(name, tag)`` from an image reference; a digest-only ref has no tag."""
    name = ref.split("@", 1)[0]
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:  # a colon after the last slash is a tag, not a registry port
        return name[:colon], name[colon + 1 :]
    return name, None


def _describe_image(sbom: Sbom, ref: str, digest: str | None, source: str) -> None:
    """Make the root component the image: type container, name, tag, digest."""
    name, tag = _split_ref(ref)
    root = sbom.metadata.component
    if root is None:
        root = Component(name=name)
        sbom.metadata.component = root
    root.type = ComponentType.CONTAINER
    root.name = name
    if tag:
        root.version = tag
    elif digest:
        root.version = digest
    if digest and not any(h.content == digest.split(":", 1)[1] for h in root.hashes):
        root.hashes = [*root.hashes, Hash(alg="SHA-256", content=digest.split(":", 1)[1])]
    sbom.metadata.properties["sbombox:image:ref"] = ref
    sbom.metadata.properties["sbombox:image:source"] = source
    if digest:
        sbom.metadata.properties["sbombox:image:digest"] = digest


def _json_or_none(raw: bytes | str | None) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None
