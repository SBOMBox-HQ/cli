"""``sbombox ci`` - connect a repository's CI to a project, without secrets."""
from __future__ import annotations

from typing import Any

import typer
from rich.console import Console

console = Console()

app = typer.Typer(help="Let CI pipelines upload without stored credentials (OIDC).", no_args_is_help=True)


def build_rule(provider: str, repository: str, branch: str | None = None) -> dict[str, Any]:
    """The trust rule allowing ``repository``'s pipelines (optionally one branch) to upload."""
    rule: dict[str, Any] = {"provider": provider}
    rule["repository" if provider == "github" else "project_path"] = repository
    if branch:
        rule["ref_patterns"] = [f"refs/heads/{branch}"]
    return rule


def merge_rule(trust_rules: dict[str, Any], rule: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Add ``rule`` under ``identities``; returns ``(rules, changed)``. Existing rules are kept."""
    identities: list[dict[str, Any]] = list(trust_rules.get("identities") or [])
    if rule in identities:
        return trust_rules, False
    merged = dict(trust_rules)
    merged["identities"] = [*identities, rule]
    return merged, True


def trust_repository(
    project_id: str, *, repo: str | None = None, provider: str | None = None, branch: str | None = None
) -> dict[str, Any]:
    """Allow ``repo`` (default: this checkout's origin) to upload to ``project_id``."""
    from sbombox_cli.api_client import ApiClient
    from sbombox_cli.ci_detect import detect_ci, forge_of, repository_slug
    from sbombox_cli.config import load_config

    ctx = detect_ci()
    repository = repo or repository_slug(ctx.repo_url)
    forge = provider or forge_of(ctx.repo_url) or "github"
    if not repository:
        console.print("[red]Could not tell which repository this is.[/red] Pass --repo owner/name.")
        raise typer.Exit(code=2)
    rule = build_rule(forge, repository, branch)
    with ApiClient(load_config()) as client:
        merged, changed = merge_rule(client.get_trust_rules(project_id), rule)
        if changed:
            client.set_trust_rules(project_id, merged)
    scope = f"branch {branch}" if branch else "any branch"
    verb = "Trusted" if changed else "Already trusted"
    console.print(f"[green]{verb}:[/green] {forge} {repository} ({scope}) can upload SBOMs to this project.")
    return rule


@app.command("trust", help="Allow a repository's pipelines to upload to the project.")
def trust(
    repo: str = typer.Option(None, "--repo", help="Repository as owner/name (GitHub) or group/project (GitLab). Default: the git origin."),
    provider: str = typer.Option(None, "--provider", help="github or gitlab. Default: inferred from the origin URL."),
    branch: str = typer.Option(None, "--branch", help="Allow uploads from this branch only. Default: any branch."),
    project: str = typer.Option(None, "--project", "-p", help="Project UUID (overrides config)."),
) -> None:
    """Let a repository's pipelines upload SBOMs with no stored token.

    Run once, logged in as a project admin. The pipeline then proves who it
    is with the OIDC token its CI issues; SBOMBox checks it against this rule
    and records the verified repository, commit and run on every SBOM.
    """
    from sbombox_cli.api_client import ApiError
    from sbombox_cli.config import load_config

    config = load_config()
    project_id = project or (str(config.project_id) if config.project_id else None)
    if not project_id:
        console.print("[red]No project selected.[/red] Run `sbombox projects use` or pass --project.")
        raise typer.Exit(code=2)
    try:
        trust_repository(project_id, repo=repo, provider=provider, branch=branch)
    except ApiError as exc:
        console.print(f"[red]Could not update trust rules:[/red] {exc}")
        raise typer.Exit(code=exc.exit_code) from exc


@app.command("show", help="List the repositories allowed to upload to the project.")
def show(project: str = typer.Option(None, "--project", "-p", help="Project UUID (overrides config).")) -> None:
    """List the repositories allowed to upload to this project."""
    from sbombox_cli.api_client import ApiClient, ApiError
    from sbombox_cli.config import load_config

    config = load_config()
    project_id = project or (str(config.project_id) if config.project_id else None)
    if not project_id:
        console.print("[red]No project selected.[/red] Run `sbombox projects use` or pass --project.")
        raise typer.Exit(code=2)
    try:
        with ApiClient(config) as client:
            rules = client.get_trust_rules(project_id).get("identities") or []
    except ApiError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=exc.exit_code) from exc
    if not rules:
        console.print("No repositories trusted yet. Run `sbombox ci trust` in the repository.")
        return
    for rule in rules:
        repo = rule.get("repository") or rule.get("project_path") or rule.get("repository_owner", "?")
        refs = ", ".join(rule.get("ref_patterns") or []) or "any branch"
        console.print(f"- {rule.get('provider', '?')} {repo} ({refs})")
