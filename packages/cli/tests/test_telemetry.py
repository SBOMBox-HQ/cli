"""Anonymous usage telemetry (sbombox_cli.telemetry): switches, payload, batching, failure tolerance."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import httpx
import pytest

from sbombox_cli import main as cli_main
from sbombox_cli import telemetry

API = "https://api.example.test"
# The server's validation (sbombox_api.telemetry.serializers), mirrored so a drift fails here.
SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(telemetry, "STATE_DIR", tmp_path / ".sbombox")
    for var in ("SBOMBOX_NO_TELEMETRY", "DO_NOT_TRACK", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def posts(monkeypatch):
    sent: list[dict] = []
    status = {"code": 204, "error": None}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        if status["error"]:
            raise status["error"]
        sent.append({"url": url, "body": json, "headers": headers, "timeout": timeout})
        return httpx.Response(status["code"])

    monkeypatch.setattr(telemetry.httpx, "post", fake_post)
    return sent, status


def queued() -> list[dict]:
    path = telemetry.STATE_DIR / "telemetry-queue.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class TestSwitches:
    def test_on_by_default(self):
        assert telemetry.disabled_reason() is None

    @pytest.mark.parametrize("var", ["SBOMBOX_NO_TELEMETRY", "DO_NOT_TRACK"])
    @pytest.mark.parametrize("value", ["1", "true", "yes"])
    def test_env_vars_turn_it_off(self, monkeypatch, var, value):
        monkeypatch.setenv(var, value)
        assert telemetry.disabled_reason()

    @pytest.mark.parametrize("value", ["", "0", "false"])
    def test_falsy_env_values_leave_it_on(self, monkeypatch, value):
        monkeypatch.setenv("DO_NOT_TRACK", value)
        assert telemetry.disabled_reason() is None

    def test_flag_repo_config_and_user_setting(self):
        assert "--no-telemetry" in telemetry.disabled_reason(flag=True)
        assert ".sbombox.yml" in telemetry.disabled_reason({"telemetry": False})
        telemetry.set_enabled(False)
        assert "config --telemetry off" in telemetry.disabled_reason()
        telemetry.set_enabled(True)
        assert telemetry.disabled_reason() is None

    def test_off_sends_and_stores_nothing(self, monkeypatch, posts):
        monkeypatch.setenv("SBOMBOX_NO_TELEMETRY", "1")
        telemetry.record("score", 0, 0.5, API)
        assert posts[0] == [] and queued() == []
        assert not (telemetry.STATE_DIR / "telemetry.json").exists()


class TestPayload:
    def test_only_documented_fields_in_server_format(self, monkeypatch, posts):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        telemetry.record("score", 2, 1.234, API)
        sent, _ = posts
        assert sent[0]["url"] == f"{API}/v1/telemetry/events/"
        assert sent[0]["timeout"] <= 2
        (event,) = sent[0]["body"]["events"]
        assert set(event) == {"event", "cli_version", "os", "ci", "properties", "anonymous_id"}
        assert event["event"] == "command.failed" and event["ci"] == "github-actions"
        assert event["properties"] == {"command": "score", "exit_code": 2, "success": False, "duration_ms": 1234}
        assert all(SLUG.match(event[f]) for f in ("event", "os", "ci"))
        assert all(KEY.match(k) for k in event["properties"])
        assert re.fullmatch(r"[0-9a-f-]{36}", event["anonymous_id"])

    def test_install_id_is_stable(self, posts):
        telemetry.record("score", 0, 0.1, API, now=1000)
        telemetry.record("list", 0, 0.1, API, now=1000 + 7200)
        ids = {e["anonymous_id"] for call in posts[0] for e in call["body"]["events"]}
        assert len(ids) == 1


class TestBatching:
    def test_sends_at_once_then_hourly_in_one_batch(self, posts):
        sent, _ = posts
        telemetry.record("score", 0, 0.1, API, now=1000)  # fresh machine (e.g. CI): sent now
        telemetry.record("list", 0, 0.1, API, now=1600)  # within the hour: queued
        telemetry.record("fix", 0, 0.1, API, now=1900)
        assert len(sent) == 1 and len(queued()) == 2
        telemetry.record("push", 0, 0.1, API, now=1000 + 3600)
        assert len(sent) == 2
        assert [e["properties"]["command"] for e in sent[1]["body"]["events"]] == ["list", "fix", "push"]
        assert queued() == []

    def test_unreachable_api_backs_off_for_a_day_and_keeps_events(self, posts):
        sent, status = posts
        status["error"] = httpx.ConnectError("offline")
        telemetry.record("score", 0, 0.1, API, now=1000)
        status["error"] = None
        telemetry.record("list", 0, 0.1, API, now=1000 + 7200)  # still backing off: no attempt
        assert sent == [] and len(queued()) == 2
        telemetry.record("fix", 0, 0.1, API, now=1000 + 86_400)
        assert len(sent[0]["body"]["events"]) == 3

    def test_rejected_events_are_dropped_not_retried(self, posts):
        _, status = posts
        status["code"] = 400
        telemetry.record("score", 0, 0.1, API, now=1000)
        assert queued() == []

    def test_queue_is_capped(self, posts):
        sent, status = posts
        status["error"] = httpx.ConnectError("offline")
        for i in range(250):
            telemetry.record("score", 0, 0.1, API, now=1000 + i)
        assert len(queued()) == 200

    def test_never_raises(self, posts):
        _, status = posts
        status["error"] = RuntimeError("boom")
        telemetry.record("score", 0, 0.1, API)  # no exception


class TestQuestion:
    def _tty(self, monkeypatch, value: bool):
        monkeypatch.setattr(telemetry, "_interactive", lambda: value)

    def test_not_asked_outside_a_terminal(self, monkeypatch):
        self._tty(monkeypatch, False)
        monkeypatch.setattr("typer.confirm", lambda *a, **k: pytest.fail("prompted"))
        telemetry.ask_once("score")
        assert telemetry.read_state() == {}

    @pytest.mark.parametrize("answer", [True, False])
    def test_asked_once_and_remembered(self, monkeypatch, answer):
        self._tty(monkeypatch, True)
        calls = []
        monkeypatch.setattr("typer.confirm", lambda *a, **k: calls.append(1) or answer)
        telemetry.ask_once("score")
        telemetry.ask_once("list")
        assert calls == [1]
        assert telemetry.read_state()["enabled"] is answer
        assert (telemetry.disabled_reason() is None) is answer

    def test_not_asked_when_already_off_or_for_config(self, monkeypatch):
        self._tty(monkeypatch, True)
        monkeypatch.setattr("typer.confirm", lambda *a, **k: pytest.fail("prompted"))
        telemetry.ask_once("config")
        telemetry.ask_once("score", flag=True)
        monkeypatch.setenv("DO_NOT_TRACK", "1")
        telemetry.ask_once("score")


class TestEntryPoint:
    def test_run_records_command_exit_code_and_flag(self, monkeypatch, tmp_path):
        recorded = []
        monkeypatch.setattr(telemetry, "record", lambda *a, **k: recorded.append(a))
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["sbombox", "--no-telemetry", "list", "missing.json"])
        with pytest.raises(SystemExit) as exc:
            cli_main.run()
        command, exit_code, _duration, _api, _repo, flag = recorded[0]
        assert (command, exit_code, flag) == ("list", exc.value.code, True)
        assert exit_code != 0

    def test_config_switch(self, monkeypatch, tmp_path):
        from typer.testing import CliRunner

        monkeypatch.chdir(tmp_path)
        runner = CliRunner(env={"COLUMNS": "200"})
        assert "off" in runner.invoke(cli_main.app, ["config", "--telemetry", "off"]).output
        assert telemetry.read_state()["enabled"] is False
        result = runner.invoke(cli_main.app, ["config", "--telemetry", "status"])
        assert "off (turned off" in result.output
        assert runner.invoke(cli_main.app, ["config", "--telemetry", "maybe"]).exit_code == 2
