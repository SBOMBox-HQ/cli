"""``sbombox init`` - set a repository up for SBOMBox in one command.

1. Pick the project (``--project``, ``.sbombox.yml``, or a choice from your projects).
2. Trust this repository's CI to upload keylessly (``sbombox ci trust``).
3. Write the CI workflow (GitHub) or print the snippet to include (GitLab).

Then commit and push. No tokens or secrets to create.
"""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(help="Initialize SBOMBox in a repository.")
console = Console()

GITHUB_WORKFLOW = """\
# SBOMBox: generate, score and upload an SBOM on every push.
# Keyless: no secrets needed. The job's OIDC identity is checked against the
# repositories you trusted with `sbombox ci trust`.
name: SBOM
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  id-token: write  # lets the job prove its identity to SBOMBox

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sbombox-hq/action@v1
        with:
          project: {project}
"""

GITLAB_SNIPPET = """\
include:
  - remote: 'https://raw.githubusercontent.com/sbombox-hq/action/v1/gitlab/sbombox-component.yml'

variables:
  SBOMBOX_PROJECT: "{project}"
"""


def _pick_project(explicit: str | None) -> str | None:
    from sbombox_cli.api_client import ApiClient, ApiError
    from sbombox_cli.config import load_config

    config = load_config()
    if explicit or config.project_id:
        return explicit or str(config.project_id)
    if not config.token:
        return None
    try:
        with ApiClient(config) as client:
            projects = client.list_projects()
    except ApiError:
        return None
    if not projects:
        return None
    if len(projects) == 1:
        return str(projects[0]["id"])
    for index, project in enumerate(projects, start=1):
        console.print(f"  {index}. {project.get('name')} ({project.get('slug')})")
    choice = typer.prompt("Which project should this repository upload to?", type=int, default=1)
    if not 1 <= choice <= len(projects):
        raise typer.BadParameter(f"Choose 1-{len(projects)}.")
    return str(projects[choice - 1]["id"])


def _write_project_config(directory: Path, project_id: str) -> None:
    path = directory / ".sbombox.yml"
    if path.exists():
        return
    from sbombox_cli.commands.config_cmd import TEMPLATE

    path.write_text(TEMPLATE.replace('project_id: ""', f'project_id: "{project_id}"'))
    console.print("[green]Created[/green] .sbombox.yml")


@app.command()
def init(
    directory: Path = typer.Option(".", "--dir", help="Repository directory."),
    project: str = typer.Option(None, "--project", "-p", help="Project UUID. Default: .sbombox.yml, or choose from your projects."),
    no_trust: bool = typer.Option(False, "--no-trust", help="Do not change the project's CI trust rules (e.g. if you are not a project admin)."),
) -> None:
    """Pick a project, trust this repository's CI, and write the workflow."""
    from sbombox_cli.ci_detect import _git_output, forge_of, repository_slug

    repo_url = _git_output("-C", str(directory), "remote", "get-url", "origin")
    forge = forge_of(repo_url) or ("github" if (directory / ".github").is_dir() else None)
    if (directory / ".gitlab-ci.yml").exists():
        forge = forge or "gitlab"
    console.print(f"Repository: [bold]{repository_slug(repo_url) or directory.resolve().name}[/bold]"
                  f" ({forge or 'no CI detected'})")

    project_id = _pick_project(project)
    if not project_id:
        console.print("[red]No project.[/red] Run `sbombox login` first, or pass --project <uuid>.")
        raise typer.Exit(code=2)
    _write_project_config(directory, project_id)

    if not no_trust and forge:
        from sbombox_cli.api_client import ApiError
        from sbombox_cli.commands.ci import trust_repository

        try:
            trust_repository(project_id, repo=repository_slug(repo_url), provider=forge)
        except (ApiError, typer.Exit) as exc:
            console.print(f"[yellow]Could not trust the repository yet[/yellow] ({exc}). "
                          "A project admin can run `sbombox ci trust` later.")

    if forge == "gitlab":
        console.print("\nAdd this to [bold].gitlab-ci.yml[/bold]:\n")
        console.print(GITLAB_SNIPPET.format(project=project_id), markup=False, highlight=False)
    else:
        workflow = directory / ".github" / "workflows" / "sbombox.yml"
        if workflow.exists():
            console.print(f"[yellow]Kept existing[/yellow] {workflow.relative_to(directory)}")
        else:
            workflow.parent.mkdir(parents=True, exist_ok=True)
            workflow.write_text(GITHUB_WORKFLOW.format(project=project_id))
            console.print(f"[green]Created[/green] {workflow.relative_to(directory)}")

    console.print("\n[bold]Done.[/bold] Commit and push - every push now gets a scored, audited SBOM.")
