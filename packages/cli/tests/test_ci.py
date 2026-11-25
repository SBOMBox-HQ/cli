"""CI detection, keyless auth and repository trust for the CLI."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from sbombox_cli import ci_auth
from sbombox_cli.ci_detect import detect_ci, forge_of, repository_slug
from sbombox_cli.commands.ci import build_rule, merge_rule
from sbombox_cli.main import app
from typer.testing import CliRunner

_CI_VARS = (
    "GITHUB_ACTIONS", "GITLAB_CI", "BITBUCKET_PIPELINE", "JENKINS_URL", "CIRCLECI", "TF_BUILD",
    "SBOMBOX_TOKEN", "SBOMBOX_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in _CI_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    # No saved login from the developer's machine.
    monkeypatch.setattr("sbombox_cli.auth.load_token", lambda: None)


def _github_env(monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
    env = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "acme/api",
        "GITHUB_RUN_ID": "42",
        "GITHUB_REF_NAME": "7/merge",
        "GITHUB_HEAD_REF": "feature/x",
        "GITHUB_SHA": "0123abc",
        "GITHUB_EVENT_NAME": "pull_request",
        **extra,
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)


class TestDetect:
    def test_pull_request_uses_head_branch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _github_env(monkeypatch)
        ctx = detect_ci()
        assert ctx.branch == "feature/x"
        assert ctx.run_url == "https://github.com/acme/api/actions/runs/42"
        assert ctx.as_metadata()["event"] == "pull_request"

    def test_push_uses_ref_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _github_env(monkeypatch, GITHUB_REF_NAME="main", GITHUB_HEAD_REF="")
        assert detect_ci().branch == "main"

    @pytest.mark.parametrize(
        ("url", "slug", "forge"),
        [
            ("https://github.com/acme/api.git", "acme/api", "github"),
            ("git@github.com:acme/api.git", "acme/api", "github"),
            ("https://gitlab.com/group/sub/proj", "group/sub/proj", "gitlab"),
            ("ssh://git@example.org/team/repo.git", "team/repo", None),
        ],
    )
    def test_remote_parsing(self, url: str, slug: str, forge: str | None) -> None:
        assert repository_slug(url) == slug
        assert forge_of(url) == forge


class TestTrustRules:
    def test_github_rule(self) -> None:
        assert build_rule("github", "acme/api", "main") == {
            "provider": "github", "repository": "acme/api", "ref_patterns": ["refs/heads/main"],
        }

    def test_gitlab_rule_uses_project_path(self) -> None:
        assert build_rule("gitlab", "group/proj") == {"provider": "gitlab", "project_path": "group/proj"}

    def test_merge_keeps_existing_and_is_idempotent(self) -> None:
        existing = {"identities": [{"provider": "github", "repository": "acme/web"}], "note": "keep"}
        rule = build_rule("github", "acme/api")
        merged, changed = merge_rule(existing, rule)
        assert changed and merged["note"] == "keep" and len(merged["identities"]) == 2
        _again, changed_again = merge_rule(merged, rule)
        assert not changed_again


class TestCiAuth:
    def test_github_token_requested_with_audience(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://runner/token?x=1")
        monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-secret")
        seen: dict[str, Any] = {}

        def fake_get(url: str, **kwargs: Any) -> httpx.Response:
            seen.update(url=url, **kwargs)
            return httpx.Response(200, json={"value": "id-token"}, request=httpx.Request("GET", url))

        monkeypatch.setattr(ci_auth.httpx, "get", fake_get)
        assert ci_auth.ci_identity_token() == "id-token"
        assert seen["params"] == {"audience": "sbombox-api"}
        assert seen["headers"]["Authorization"] == "bearer runner-secret"

    def test_missing_permission_hint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        with pytest.raises(ci_auth.CiAuthError, match="id-token: write"):
            ci_auth.exchange_ci_token("https://api", "proj")

    def test_refusal_points_at_trust(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SBOMBOX_ID_TOKEN", "id-token")
        monkeypatch.setattr(
            ci_auth.httpx, "post",
            lambda url, **kw: httpx.Response(403, json={"detail": "no rule"}, request=httpx.Request("POST", url)),
        )
        with pytest.raises(ci_auth.CiAuthError, match="sbombox ci trust"):
            ci_auth.exchange_ci_token("https://api", "proj")


class TestPush:
    def test_keyless_push_in_ci(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        _github_env(monkeypatch)
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        monkeypatch.setattr(
            ci_auth, "exchange_ci_token",
            lambda api_url, project, user_agent="": {
                "access_token": "short-lived",
                "provenance": {"project_id": "uuid-1", "repository": "acme/api", "provider": "github"},
            },
        )
        calls: dict[str, Any] = {}

        def fake_upload(self: Any, project_id: str, path: Path, **kwargs: Any) -> dict[str, Any]:
            calls.update(project_id=project_id, token=self._config.token, **kwargs)
            return {"id": "sbom-1", "provenance_level": "P2", "branch": kwargs["branch"]}

        monkeypatch.setattr("sbombox_cli.api_client.ApiClient.upload_sbom", fake_upload)
        result = CliRunner().invoke(app, ["push", str(sbom), "--project", "acme/api", "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout.strip().splitlines()[-1])["provenance_level"] == "P2"
        assert calls["project_id"] == "uuid-1"  # slug resolved to the UUID by the exchange
        assert calls["token"] == "short-lived"
        assert calls["branch"] == "feature/x"
        assert calls["ci"]["commit"] == "0123abc"

    def test_no_credentials_outside_ci(self, tmp_path: Path) -> None:
        sbom = tmp_path / "sbom.json"
        sbom.write_text("{}")
        result = CliRunner().invoke(app, ["push", str(sbom), "--project", "p"])
        assert result.exit_code == 5


def test_unknown_compliance_profile_is_an_error(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    result = CliRunner().invoke(app, ["compliance", str(sbom), "--profile", "cra-2099"])
    assert result.exit_code == 2
    assert "cra-readiness" in result.output


def test_short_compliance_alias_resolves_to_current_ruleset(tmp_path: Path) -> None:
    """Aliases are explicit (documented in PROFILE_ALIASES), not a silent fallback."""
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))
    result = CliRunner().invoke(app, ["compliance", str(sbom), "--profile", "cisa", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "CISA SBOM Minimum Elements" in result.output
