"""Keyless CI authentication.

A pipeline should not need a stored SBOMBox secret. When no ``SBOMBOX_TOKEN``
is set and the CLI runs inside a CI system that can mint an OIDC identity
token, :func:`exchange_ci_token` fetches that token and swaps it at
``POST /v1/auth/oidc/exchange`` for a 15-minute token that can only upload
SBOMs to one project. The server verifies the identity token against the
project's trust rules (``sbombox ci trust``) and records the verified claims
on every SBOM uploaded with the resulting token.

Where the identity token comes from:

* **GitHub Actions** - requested from the runner, which only works when the
  workflow grants ``permissions: id-token: write``.
* **GitLab CI and anything else** - read from ``SBOMBOX_ID_TOKEN`` (GitLab:
  declare it under ``id_tokens:`` with ``aud: sbombox-api``).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

#: Audience the SBOMBox API accepts by default (``OIDC_AUDIENCE`` server-side).
DEFAULT_AUDIENCE = "sbombox-api"
_TIMEOUT = 15.0


class CiAuthError(Exception):
    """The CI identity could not be obtained or was rejected."""

    def __init__(self, message: str, exit_code: int = 5) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _audience() -> str:
    return os.environ.get("SBOMBOX_OIDC_AUDIENCE") or DEFAULT_AUDIENCE


def _github_id_token(audience: str) -> str | None:
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        return None
    try:
        resp = httpx.get(
            url,
            params={"audience": audience},
            headers={"Authorization": f"bearer {bearer}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        value = resp.json().get("value")
    except (httpx.HTTPError, ValueError) as exc:
        raise CiAuthError(f"GitHub did not issue an OIDC token: {exc}") from exc
    return str(value) if value else None


def ci_identity_token() -> str | None:
    """Return the CI-issued OIDC identity token, or ``None`` if none is available."""
    explicit = os.environ.get("SBOMBOX_ID_TOKEN")
    if explicit:
        return explicit
    return _github_id_token(_audience())


def ci_identity_available() -> bool:
    """Whether this environment can produce a CI identity token at all."""
    return bool(
        os.environ.get("SBOMBOX_ID_TOKEN")
        or (os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
    )


def missing_identity_hint() -> str:
    """A one-line fix for the most common reason no identity is available."""
    if os.environ.get("GITHUB_ACTIONS"):
        return "Add `permissions: id-token: write` to the job, or set SBOMBOX_TOKEN."
    if os.environ.get("GITLAB_CI"):
        return "Declare `id_tokens: SBOMBOX_ID_TOKEN: aud: sbombox-api` on the job, or set SBOMBOX_TOKEN."
    return "Set SBOMBOX_TOKEN, or run `sbombox login`."


def exchange_ci_token(api_url: str, project: str, *, user_agent: str = "") -> dict[str, Any]:
    """Exchange the CI identity token for a short-lived, project-scoped token.

    Returns the server response (``access_token``, ``expires_in``,
    ``provenance``). Raises :class:`CiAuthError` with an actionable message.
    """
    id_token = ci_identity_token()
    if not id_token:
        raise CiAuthError(f"No CI identity token available. {missing_identity_hint()}")
    body: dict[str, Any] = {"token": id_token, "project": project}
    instance_url = os.environ.get("CI_SERVER_URL")
    if os.environ.get("GITLAB_CI") and instance_url and "gitlab.com" not in instance_url:
        body["instance_url"] = instance_url
    headers = {"Accept": "application/json"}
    if user_agent:
        headers["User-Agent"] = user_agent
    try:
        resp = httpx.post(
            f"{api_url.rstrip('/')}/v1/auth/oidc/exchange", json=body, headers=headers, timeout=_TIMEOUT
        )
    except httpx.RequestError as exc:
        raise CiAuthError(f"Could not reach SBOMBox: {exc}") from exc
    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail") or resp.text
        except ValueError:
            detail = resp.text
        hint = ""
        if resp.status_code == 426:
            raise CiAuthError(str(detail), exit_code=6)
        if resp.status_code == 403:
            hint = " Run `sbombox ci trust` once to allow this repository to upload."
        raise CiAuthError(f"SBOMBox refused the CI identity ({resp.status_code}): {detail}.{hint}")
    data: dict[str, Any] = resp.json()
    return data
