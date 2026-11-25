"""HTTP API client for the SBOMBox backend.

Uses ``httpx`` with automatic retries and structured error handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from sbombox_cli.config import CliConfig

# Exit codes -----------------------------------------------------------------

EXIT_OK = 0
EXIT_POLICY_FAIL = 1
EXIT_USAGE = 2
EXIT_NETWORK = 3
EXIT_GENERATION = 4
EXIT_AUTH = 5
EXIT_UPGRADE = 6

_MAX_RETRIES = 3
_BACKOFF_FACTOR = 0.5


def user_agent() -> str:
    """``sbombox-cli/<version> (<ci>)`` - lets the server's audit log tell CLI
    and CI traffic apart, and shows which CI systems people actually use."""
    from sbombox_cli import __version__
    from sbombox_cli.ci_detect import detect_ci

    return f"sbombox-cli/{__version__} ({detect_ci().ci_name})"


def _problem_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    return str(body.get("detail") or "") if isinstance(body, dict) else ""


class ApiError(Exception):
    """Raised when an API request fails."""

    def __init__(self, message: str, exit_code: int = EXIT_NETWORK) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class ApiClient:
    """Thin wrapper around ``httpx.Client`` with auth + retry logic."""

    def __init__(self, config: CliConfig) -> None:
        self._config = config
        self._client = self._build_client()

    # -- lifecycle ------------------------------------------------------------

    def _build_client(self) -> httpx.Client:
        """Create an ``httpx.Client`` with auth headers and retry transport."""
        headers: Dict[str, str] = {"Accept": "application/json", "User-Agent": user_agent()}
        if self._config.token:
            headers["Authorization"] = f"Bearer {self._config.token}"

        transport = httpx.HTTPTransport(retries=_MAX_RETRIES)
        return httpx.Client(
            base_url=self._config.api_url,
            headers=headers,
            transport=transport,
            timeout=30.0,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> ApiClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- helpers --------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Execute an HTTP request and return parsed JSON.

        Raises
        ------
        ApiError
            On network failures or non-2xx responses.
        """
        try:
            resp = self._client.request(method, path, json=json, params=params)
            resp.raise_for_status()
            if resp.status_code == 204:
                return None
            return resp.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 426:
                raise ApiError(_problem_detail(exc.response) or "This CLI version is no longer supported. "
                               "Run `sbombox upgrade`.", exit_code=EXIT_UPGRADE) from exc
            if status in (401, 403):
                raise ApiError(f"Authentication failed: {exc}", exit_code=EXIT_AUTH) from exc
            detail = ""
            try:
                body = exc.response.json()
                detail = body.get("detail") or body.get("title") or ""
            except ValueError:
                pass
            message = f"API error {status}" + (f": {detail}" if detail else f": {exc}")
            raise ApiError(message, exit_code=EXIT_NETWORK) from exc
        except httpx.RequestError as exc:
            raise ApiError(f"Network error: {exc}", exit_code=EXIT_NETWORK) from exc

    # -- public API -----------------------------------------------------------

    def upload_sbom(
        self,
        project_id: str,
        sbom_path: Path,
        *,
        branch: str = "main",
        version_label: str = "",
        sbom_format: str | None = None,
        ci: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Upload an SBOM document to a project.

        SBOMs are nested under their project (``/v1/sboms/projects/<id>/sboms/``)
        and sent as JSON so the server can hash and store the exact bytes.
        """
        payload: Dict[str, Any] = {
            "content": sbom_path.read_text(encoding="utf-8"),
            "branch": branch,
        }
        if version_label:
            payload["version_label"] = version_label
        if sbom_format:
            payload["format"] = sbom_format
        if ci:
            payload["ci"] = ci
        return self._request("POST", f"/v1/sboms/projects/{project_id}/sboms/", json=payload)

    def get_project(self, project_id: str) -> Dict[str, Any]:
        """Retrieve project metadata."""
        return self._request("GET", f"/v1/projects/{project_id}/")

    def list_projects(self, *, limit: int = 50) -> List[Dict[str, Any]]:
        """List projects across every organization visible to the token."""
        orgs = self._request("GET", "/v1/orgs/")
        projects: List[Dict[str, Any]] = []
        for org in orgs.get("results") or []:
            data = self._request(
                "GET", f"/v1/orgs/{org['slug']}/projects/", params={"limit": limit}
            )
            projects.extend(data.get("results") or [])
            if len(projects) >= limit:
                break
        return projects[:limit]

    def latest_sbom(self, project_id: str) -> Dict[str, Any]:
        """Return the most recent SBOM for a project, or an empty dict."""
        listing = self._request("GET", f"/v1/sboms/projects/{project_id}/sboms/")
        results = listing.get("results") if isinstance(listing, dict) else listing
        return (results or [{}])[0]

    def get_score(self, project_id: str, sbom_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve the latest score run for a project's SBOM."""
        if not sbom_id:
            sbom_id = self.latest_sbom(project_id).get("id")
            if not sbom_id:
                return {}
        data = self._request(
            "GET", f"/v1/sboms/projects/{project_id}/sboms/{sbom_id}/scores/"
        )
        results = data.get("results") if isinstance(data, dict) else data
        return (results or [{}])[0]

    def get_vulnerabilities(
        self,
        project_id: str,
        *,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vulnerability findings for a project."""
        params: Dict[str, Any] = {}
        if severity:
            params["severity"] = severity
        data = self._request(
            "GET", f"/v1/vulns/projects/{project_id}/vulnerabilities/", params=params
        )
        results = data.get("results") if isinstance(data, dict) else data
        return results or []

    def get_trust_rules(self, project_id: str) -> Dict[str, Any]:
        """Return the project's CI (OIDC) trust rules."""
        data = self._request("GET", f"/v1/projects/{project_id}/trust-rules/")
        rules = data.get("trust_rules") if isinstance(data, dict) else None
        return rules if isinstance(rules, dict) else {}

    def set_trust_rules(self, project_id: str, trust_rules: Dict[str, Any]) -> Dict[str, Any]:
        """Replace the project's CI trust rules (project admin only)."""
        return self._request(
            "PATCH", f"/v1/projects/{project_id}/trust-rules/", json={"trust_rules": trust_rules}
        )

    def whoami(self) -> Dict[str, Any]:
        """Return information about the authenticated user."""
        return self._request("GET", "/v1/me/")
