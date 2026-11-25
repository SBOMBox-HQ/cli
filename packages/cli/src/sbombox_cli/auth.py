"""OAuth device-flow authentication for the SBOMBox CLI.

Supports token storage via OS keyring with a fallback to a ``0600`` file
at ``~/.sbombox/token.json``.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

_KEYRING_SERVICE = "sbombox-cli"
_KEYRING_USERNAME = "sbombox-user"
#: Public OAuth client registered for the device-code grant. The server grants
#: this client's full scope set when ``scope`` is omitted.
_CLIENT_ID = "sbombox-cli"
_TOKEN_DIR = Path.home() / ".sbombox"
_TOKEN_FILE = _TOKEN_DIR / "token.json"

_POLL_INTERVAL = 5  # seconds
_DEFAULT_TIMEOUT = 30.0


# -- token storage ------------------------------------------------------------


def _save_token_to_keyring(token: str) -> bool:
    """Attempt to store token in OS keyring. Return True on success."""
    try:
        import keyring as kr

        kr.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, token)
        return True
    except Exception:
        return False


def _load_token_from_keyring() -> Optional[str]:
    """Retrieve token from OS keyring. Return None on failure."""
    try:
        import keyring as kr

        return kr.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
    except Exception:
        return None


def _delete_token_from_keyring() -> bool:
    """Remove token from OS keyring. Return True on success."""
    try:
        import keyring as kr

        kr.delete_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        return True
    except Exception:
        return False


def _save_token_to_file(token: str) -> None:
    """Store token in ``~/.sbombox/token.json`` with 0600 permissions."""
    _TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"token": token})
    _TOKEN_FILE.write_text(payload, encoding="utf-8")
    _TOKEN_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _load_token_from_file() -> Optional[str]:
    """Load token from file fallback. Return None if missing."""
    if not _TOKEN_FILE.is_file():
        return None
    try:
        data = json.loads(_TOKEN_FILE.read_text(encoding="utf-8"))
        return data.get("token")
    except (json.JSONDecodeError, OSError):
        return None


def _delete_token_file() -> None:
    """Remove the token file if it exists."""
    if _TOKEN_FILE.is_file():
        _TOKEN_FILE.unlink()


# -- public API ---------------------------------------------------------------


def store_token(token: str) -> None:
    """Persist token - keyring first, file fallback."""
    if not _save_token_to_keyring(token):
        _save_token_to_file(token)


def load_token() -> Optional[str]:
    """Load token - keyring first, file fallback."""
    tok = _load_token_from_keyring()
    if tok:
        return tok
    return _load_token_from_file()


def clear_token() -> None:
    """Remove stored token from both keyring and file."""
    _delete_token_from_keyring()
    _delete_token_file()


def device_flow(api_url: str) -> str:
    """Execute the OAuth device-authorization flow.

    Parameters
    ----------
    api_url:
        Base URL of the SBOMBox API (e.g. ``https://api.sbombox.com``).

    Returns
    -------
    str
        The access token on success.

    Raises
    ------
    SystemExit
        If the flow fails or is aborted.
    """
    import typer

    # Step 1: request device + user codes ------------------------------------
    try:
        resp = httpx.post(
            f"{api_url}/oauth/device-authorization",
            json={"client_id": _CLIENT_ID},
            timeout=_DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
    except httpx.RequestError as exc:
        typer.echo(f"Error: could not reach auth endpoint: {exc}", err=True)
        raise typer.Exit(code=5) from exc
    except httpx.HTTPStatusError as exc:
        typer.echo(f"Error: auth endpoint returned {exc.response.status_code}", err=True)
        raise typer.Exit(code=5) from exc

    user_code: str = data["user_code"]
    verification_uri: str = data["verification_uri"]
    device_code: str = data["device_code"]
    interval: int = data.get("interval", _POLL_INTERVAL)
    expires_in: int = data.get("expires_in", 900)

    # Step 2: display instructions -------------------------------------------
    typer.echo(f"\nOpen this URL in your browser:\n\n  {verification_uri}\n")
    typer.echo(f"Enter code: {user_code}\n")
    typer.echo("Waiting for authorization…")

    # Step 3: poll for token -------------------------------------------------
    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        time.sleep(interval)
        try:
            token_resp = httpx.post(
                f"{api_url}/oauth/token",
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    # Public clients identify themselves in the body: there is no
                    # secret to put in an HTTP Basic header.
                    "client_id": _CLIENT_ID,
                },
                timeout=_DEFAULT_TIMEOUT,
            )
        except httpx.RequestError:
            continue

        if token_resp.status_code == 200:
            token_data = token_resp.json()
            access_token: str = token_data["access_token"]
            store_token(access_token)
            typer.echo("\nAuthorization successful!")
            return access_token

        # Handle slow_down / authorization_pending
        if token_resp.status_code == 400:
            err = token_resp.json().get("error", "")
            if err == "slow_down":
                interval += 5
            elif err == "authorization_pending":
                continue
            else:
                typer.echo(f"\nAuth error: {err}", err=True)
                raise typer.Exit(code=5)
        else:
            typer.echo(f"\nUnexpected auth response: {token_resp.status_code}", err=True)
            raise typer.Exit(code=5)

    typer.echo("\nTimed out waiting for authorization.", err=True)
    raise typer.Exit(code=5)
