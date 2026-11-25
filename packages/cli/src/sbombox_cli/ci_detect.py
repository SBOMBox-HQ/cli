"""CI and VCS environment auto-detection.

Inspects well-known environment variables to determine whether the CLI is
running inside a CI pipeline and, if so, which one.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class CiContext:
    """Snapshot of the detected CI/VCS environment."""

    ci_name: str  # e.g. "github-actions", "gitlab-ci", … or "local"
    build_id: str | None = None
    repo_url: str | None = None
    branch: str | None = None
    commit: str | None = None
    run_url: str | None = None
    actor: str | None = None
    event: str | None = None
    workflow: str | None = None

    @property
    def is_ci(self) -> bool:
        """Whether a CI system (rather than a developer machine) was detected."""
        return self.ci_name != "local"

    def as_metadata(self) -> dict[str, str]:
        """The non-empty fields, as sent with an upload for the audit trail.

        This is *client-reported* context. The server only treats CI identity
        as verified when it comes from an OIDC-exchanged token.
        """
        fields = {
            "ci_name": self.ci_name,
            "build_id": self.build_id,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "commit": self.commit,
            "run_url": self.run_url,
            "actor": self.actor,
            "event": self.event,
            "workflow": self.workflow,
        }
        return {key: value for key, value in fields.items() if value}


# -- per-CI detectors ---------------------------------------------------------


def _github_actions() -> dict[str, str | None] | None:
    if not os.environ.get("GITHUB_ACTIONS"):
        return None
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID")
    return {
        "ci_name": "github-actions",
        "build_id": run_id,
        "repo_url": f"{server}/{repository}",
        # On pull requests GITHUB_REF_NAME is "<n>/merge"; the head branch is
        # what people mean by "the branch".
        "branch": os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME"),
        "commit": os.environ.get("GITHUB_SHA"),
        "run_url": f"{server}/{repository}/actions/runs/{run_id}" if run_id and repository else None,
        "actor": os.environ.get("GITHUB_ACTOR"),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "workflow": os.environ.get("GITHUB_WORKFLOW_REF") or os.environ.get("GITHUB_WORKFLOW"),
    }


def _gitlab_ci() -> dict[str, str | None] | None:
    if not os.environ.get("GITLAB_CI"):
        return None
    return {
        "ci_name": "gitlab-ci",
        "build_id": os.environ.get("CI_JOB_ID"),
        "repo_url": os.environ.get("CI_REPOSITORY_URL"),
        "branch": os.environ.get("CI_COMMIT_BRANCH")
        or os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
        or os.environ.get("CI_COMMIT_TAG"),
        "commit": os.environ.get("CI_COMMIT_SHA"),
        "run_url": os.environ.get("CI_JOB_URL"),
        "actor": os.environ.get("GITLAB_USER_LOGIN"),
        "event": os.environ.get("CI_PIPELINE_SOURCE"),
        "workflow": os.environ.get("CI_CONFIG_PATH"),
    }


def _bitbucket_pipelines() -> dict[str, str | None] | None:
    if not os.environ.get("BITBUCKET_PIPELINE"):
        return None
    return {
        "ci_name": "bitbucket-pipelines",
        "build_id": os.environ.get("BITBUCKET_BUILD_NUMBER"),
        "repo_url": f"https://bitbucket.org/{os.environ.get('BITBUCKET_REPO_FULL_NAME', '')}",
        "branch": os.environ.get("BITBUCKET_BRANCH"),
        "commit": os.environ.get("BITBUCKET_COMMIT"),
    }


def _jenkins() -> dict[str, str | None] | None:
    if not os.environ.get("JENKINS_URL"):
        return None
    return {
        "ci_name": "jenkins",
        "build_id": os.environ.get("BUILD_NUMBER"),
        "repo_url": os.environ.get("GIT_URL"),
        "branch": os.environ.get("GIT_BRANCH"),
        "commit": os.environ.get("GIT_COMMIT"),
    }


def _circleci() -> dict[str, str | None] | None:
    if not os.environ.get("CIRCLECI"):
        return None
    return {
        "ci_name": "circleci",
        "build_id": os.environ.get("CIRCLE_BUILD_NUM"),
        "repo_url": os.environ.get("CIRCLE_REPOSITORY_URL"),
        "branch": os.environ.get("CIRCLE_BRANCH"),
        "commit": os.environ.get("CIRCLE_SHA1"),
    }


def _azure_pipelines() -> dict[str, str | None] | None:
    if not os.environ.get("TF_BUILD"):
        return None
    return {
        "ci_name": "azure-pipelines",
        "build_id": os.environ.get("BUILD_BUILDID"),
        "repo_url": os.environ.get("BUILD_REPOSITORY_URI"),
        "branch": os.environ.get("BUILD_SOURCEBRANCH"),
        "commit": os.environ.get("BUILD_SOURCEVERSION"),
    }


_DETECTORS: list[Callable[[], dict[str, str | None] | None]] = [
    _github_actions,
    _gitlab_ci,
    _bitbucket_pipelines,
    _jenkins,
    _circleci,
    _azure_pipelines,
]


_FIELDS = frozenset(CiContext.__dataclass_fields__)


# -- git fallback helpers -----------------------------------------------------


def _git_output(*args: str) -> str | None:
    """Run a git command and return stripped stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


# -- public API ---------------------------------------------------------------


def detect_ci() -> CiContext:
    """Detect the current CI environment.

    Returns a :class:`CiContext` with information about the CI system and the
    current VCS state.  When no CI system is detected, ``ci_name`` is
    ``"local"`` and git information is filled in on a best-effort basis.
    """
    for detector in _DETECTORS:
        result = detector()
        if result is not None:
            fields = {key: value for key, value in result.items() if key in _FIELDS}
            return CiContext(ci_name=str(fields.pop("ci_name")), **fields)

    # Local / unknown - fall back to git ------------------------------------
    return CiContext(
        ci_name="local",
        build_id=None,
        repo_url=_git_output("remote", "get-url", "origin"),
        branch=_git_output("rev-parse", "--abbrev-ref", "HEAD"),
        commit=_git_output("rev-parse", "HEAD"),
    )


def repository_slug(repo_url: str | None) -> str | None:
    """``owner/name`` (or ``group/sub/project``) from an https or ssh remote URL."""
    if not repo_url:
        return None
    url = repo_url.strip()
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@") and ":" in url:
        return url.split(":", 1)[1].strip("/") or None
    if "://" in url:
        path = url.split("://", 1)[1].split("/", 1)
        if len(path) == 2:
            return path[1].strip("/") or None
    return None


def forge_of(repo_url: str | None) -> str | None:
    """``"github"`` / ``"gitlab"`` for well-known hosts, else ``None``."""
    if not repo_url:
        return None
    lowered = repo_url.lower()
    if "github.com" in lowered:
        return "github"
    if "gitlab" in lowered:
        return "gitlab"
    return None
