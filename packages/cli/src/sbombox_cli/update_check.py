"""Update notices, driven by the server's version policy.

The SBOMBox API publishes the current and minimum supported CLI versions at
``GET /v1/meta/cli`` (see ``sbombox_api.core.cli_version``). The CLI checks at
most once a day, caches the answer in ``~/.sbombox/version-check.json``, and
prints a notice on stderr when a newer version is available. In GitHub
Actions the notice is a workflow warning, so it shows on the run summary.

The notice is advisory. Enforcement is server-side: the API answers CLIs older
than the minimum with ``426 Upgrade Required`` whatever this check does.
``SBOMBOX_NO_UPDATE_CHECK=1`` only silences the notice (air-gapped machines,
tests); it cannot get an outdated CLI past the server.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx

from sbombox_cli import __version__

_CACHE_FILE = Path.home() / ".sbombox" / "version-check.json"
_CACHE_SECONDS = 24 * 60 * 60
_TIMEOUT = 2.0


def parse_version(value: Optional[str]) -> Optional[Tuple[int, ...]]:
    """``"1.2.3"`` -> ``(1, 2, 3)``; ``None`` if unparseable."""
    if not value:
        return None
    parts = value.strip().lstrip("v").split("+")[0].split(".")[:3]
    try:
        numbers = tuple(int(part) for part in parts)
    except ValueError:
        return None
    return numbers + (0,) * (3 - len(numbers))


def fetch_policy(api_url: str) -> Optional[Dict[str, Any]]:
    """The server's CLI policy, or ``None`` if it cannot be reached."""
    try:
        resp = httpx.get(
            f"{api_url.rstrip('/')}/v1/meta/cli",
            headers={"User-Agent": f"sbombox-cli/{__version__}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _cached_policy(api_url: str) -> Optional[Dict[str, Any]]:
    try:
        cached = json.loads(_CACHE_FILE.read_text())
        if cached.get("api_url") == api_url and time.time() - cached.get("checked_at", 0) < _CACHE_SECONDS:
            policy = cached.get("policy")
            return policy if isinstance(policy, dict) else None
    except (OSError, ValueError):
        pass
    policy = fetch_policy(api_url)
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Failures are cached too, so an offline machine is not slowed every run.
        _CACHE_FILE.write_text(json.dumps({"api_url": api_url, "checked_at": time.time(), "policy": policy}))
    except OSError:
        pass
    return policy


def update_notice(policy: Optional[Dict[str, Any]], current: str = __version__) -> Optional[str]:
    """The message to show for ``policy``, or ``None`` when up to date."""
    if not policy:
        return None
    mine = parse_version(current)
    latest = policy.get("latest_version")
    minimum = policy.get("min_supported_version")
    if mine is None:
        return None
    if minimum and parse_version(minimum) and mine < parse_version(minimum):  # type: ignore[operator]
        return (
            f"sbombox {current} is no longer supported (minimum {minimum}); the API will refuse it. "
            "Run `sbombox upgrade`."
        )
    if latest and parse_version(latest) and mine < parse_version(latest):  # type: ignore[operator]
        return f"sbombox {latest} is available (you have {current}). Run `sbombox upgrade`."
    return None


def check_for_updates(api_url: str) -> None:
    """Print an update notice on stderr if one applies. Never raises."""
    if os.environ.get("SBOMBOX_NO_UPDATE_CHECK"):
        return
    try:
        message = update_notice(_cached_policy(api_url))
    except Exception:  # noqa: BLE001 - a notice must never break a command
        return
    if not message:
        return
    import typer

    if os.environ.get("GITHUB_ACTIONS"):
        typer.echo(f"::warning title=SBOMBox CLI update::{message}", err=True)
    else:
        typer.echo(message, err=True)
