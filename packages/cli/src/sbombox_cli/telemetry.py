"""Anonymous usage telemetry, so we can see which commands are used and fail.

What is sent, per command run: the command name (e.g. ``score``), whether it
succeeded, its exit code and duration, the CLI version, the OS, the CI provider
if any, and a random installation ID kept in ``~/.sbombox/telemetry.json``.
Never file names or paths, project or repository names, account details,
tokens, or anything from an SBOM.

The first time the CLI runs in an interactive terminal it asks once whether to
share this, and remembers the answer. It never asks when not in a terminal
(CI, pipes), so scripts cannot hang. Turn it off with any of:

* answering "n" to that question, or ``sbombox config --telemetry off`` later
  (for this user, on this machine; ``--telemetry status`` shows the setting);
* ``sbombox --no-telemetry <command>`` for one run;
* ``SBOMBOX_NO_TELEMETRY=1`` or ``DO_NOT_TRACK=1`` in the environment (CI);
* ``telemetry: false`` in a repository's ``.sbombox.yml``.

It never slows a command noticeably or breaks one. Events are queued in
``~/.sbombox/telemetry-queue.jsonl`` and sent in one batch at most once an
hour (at once on a fresh machine, such as a CI runner), with a short timeout.
If the API cannot be reached, sending pauses for a day and the queue is capped.
Events go to the configured API (``SBOMBOX_API_URL`` / ``api_url``), so a
self-hosted install keeps them in-house.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from sbombox_cli import __version__

STATE_DIR = Path.home() / ".sbombox"
_STATE_FILE = "telemetry.json"
_QUEUE_FILE = "telemetry-queue.jsonl"
_FLUSH_EVERY_SECONDS = 60 * 60
_BACKOFF_SECONDS = 24 * 60 * 60
_MAX_QUEUE = 200
_MAX_BATCH = 50
_TIMEOUT = 1.5
_FALSE = {"", "0", "false", "no", "off"}

QUESTION = (
    "Help improve sbombox by sharing anonymous usage data? It covers the command run, whether it "
    "succeeded, how long it took, the CLI version and OS; never file names, project names or SBOM content. "
    "Change it any time with `sbombox config --telemetry on|off`. Details: https://sbombox.com/privacy#tools\n"
    "Share usage data?"
)

#: Commands that never prompt or record: managing the setting itself.
_SILENT_COMMANDS = {"config"}


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() not in _FALSE


def _state_path() -> Path:
    return STATE_DIR / _STATE_FILE


def _queue_path() -> Path:
    return STATE_DIR / _QUEUE_FILE


def read_state() -> Dict[str, Any]:
    try:
        data = json.loads(_state_path().read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(state: Dict[str, Any]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        _state_path().write_text(json.dumps(state))
    except OSError:
        pass


def set_enabled(enabled: bool) -> None:
    """The per-user switch: the first-run answer, or ``sbombox config --telemetry on|off``."""
    state = read_state()
    state["enabled"] = enabled
    state["notice_shown"] = True
    write_state(state)
    if not enabled:
        try:
            _queue_path().unlink()
        except OSError:
            pass


def disabled_reason(repo_config: Optional[Dict[str, Any]] = None, flag: bool = False) -> Optional[str]:
    """Why telemetry is off, or ``None`` when it is on."""
    if flag:
        return "--no-telemetry was passed"
    if _truthy(os.environ.get("SBOMBOX_NO_TELEMETRY")):
        return "SBOMBOX_NO_TELEMETRY is set"
    if _truthy(os.environ.get("DO_NOT_TRACK")):
        return "DO_NOT_TRACK is set"
    if repo_config and repo_config.get("telemetry") is False:
        return "telemetry: false in .sbombox.yml"
    if read_state().get("enabled") is False:
        return "turned off with `sbombox config --telemetry off`"
    return None


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def ask_once(command: Optional[str], repo_config: Optional[Dict[str, Any]] = None, flag: bool = False) -> None:
    """On the first interactive run, ask whether to share usage data and remember the answer.

    Skipped when telemetry is already off, when the question was answered (or the
    setting changed) before, outside a terminal, and for ``sbombox config``.
    """
    try:
        if not command or command in _SILENT_COMMANDS or not _interactive():
            return
        if disabled_reason(repo_config, flag):
            return
        state = read_state()
        if state.get("notice_shown") or "enabled" in state:
            return
        import typer

        answer = typer.confirm(QUESTION, default=True, err=True)
        set_enabled(answer)
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - never block a command over this
        # No answer recorded: the question comes back next time.
        return


def ci_provider() -> str:
    """The CI system running this command, from its environment; empty on a workstation."""
    env = os.environ
    for var, name in (
        ("GITHUB_ACTIONS", "github-actions"),
        ("GITLAB_CI", "gitlab-ci"),
        ("CIRCLECI", "circleci"),
        ("BUILDKITE", "buildkite"),
        ("TF_BUILD", "azure-pipelines"),
        ("BITBUCKET_BUILD_NUMBER", "bitbucket"),
        ("JENKINS_URL", "jenkins"),
    ):
        if env.get(var):
            return name
    return "other" if env.get("CI") else ""


def _os_name() -> str:
    return platform.system().lower()[:16] or "unknown"


def build_event(command: str, exit_code: int, duration_seconds: float) -> Dict[str, Any]:
    """The event for one command run. Only the fields documented above."""
    return {
        "event": "command.completed" if exit_code == 0 else "command.failed",
        "cli_version": __version__,
        "os": _os_name(),
        "ci": ci_provider(),
        "properties": {
            "command": command[:100],
            "exit_code": exit_code,
            "success": exit_code == 0,
            "duration_ms": int(max(duration_seconds, 0) * 1000),
        },
    }


def _read_queue() -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    try:
        lines = _queue_path().read_text().splitlines()
    except OSError:
        return events
    for line in lines[-_MAX_QUEUE:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            events.append(item)
    return events


def _write_queue(events: List[Dict[str, Any]]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        _queue_path().write_text("".join(json.dumps(e) + "\n" for e in events[-_MAX_QUEUE:]))
    except OSError:
        pass


def _send(api_url: str, events: List[Dict[str, Any]]) -> bool:
    try:
        resp = httpx.post(
            f"{api_url.rstrip('/')}/v1/telemetry/events/",
            json={"events": events},
            headers={"User-Agent": f"sbombox-cli/{__version__}"},
            timeout=_TIMEOUT,
        )
    except httpx.HTTPError:
        return False
    # 4xx means the server will never accept these events: drop them rather than retry forever.
    return resp.status_code < 500


def record(command: Optional[str], exit_code: int, duration_seconds: float, api_url: str,
           repo_config: Optional[Dict[str, Any]] = None, flag: bool = False, now: Optional[float] = None) -> None:
    """Queue one command run and send the queue when due. Never raises or prints."""
    try:
        if not command or command in _SILENT_COMMANDS or disabled_reason(repo_config, flag):
            return
        now = time.time() if now is None else now
        state = read_state()
        changed = False
        if not state.get("anonymous_id"):
            state["anonymous_id"] = str(uuid.uuid4())
            changed = True

        event = {**build_event(command, exit_code, duration_seconds), "anonymous_id": state["anonymous_id"]}
        queue = _read_queue() + [event]

        due = now >= float(state.get("next_send_at", 0)) and (
            now - float(state.get("last_sent_at", 0)) >= _FLUSH_EVERY_SECONDS or not state.get("last_sent_at")
        )
        if due:
            batch, rest = queue[:_MAX_BATCH], queue[_MAX_BATCH:]
            if _send(api_url, batch):
                queue = rest
                state["last_sent_at"] = now
                state.pop("next_send_at", None)
            else:
                state["next_send_at"] = now + _BACKOFF_SECONDS
            changed = True
        _write_queue(queue)
        if changed:
            write_state(state)
    except Exception:  # noqa: BLE001 - telemetry must never break a command
        return
