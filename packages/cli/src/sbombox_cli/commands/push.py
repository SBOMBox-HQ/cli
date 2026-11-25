"""Upload SBOMs to the API."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

app = typer.Typer(help="Upload SBOMs.")
console = Console(stderr=True)


def upload(
    sbom_path: Path,
    *,
    project: str | None = None,
    branch: str | None = None,
    version: str = "",
) -> dict[str, Any]:
    """Upload ``sbom_path`` and return the API response.

    Credentials, in order: ``SBOMBOX_TOKEN`` / ``.sbombox.yml`` / ``sbombox
    login``; otherwise, inside CI, a keyless OIDC exchange. Branch and commit
    default to what the CI system (or local git) reports, so uploads from
    feature branches and tags are labelled correctly without any flags.
    """
    from sbombox_cli.api_client import EXIT_AUTH, EXIT_USAGE, ApiClient, ApiError, user_agent
    from sbombox_cli.ci_detect import detect_ci
    from sbombox_cli.config import load_config

    config = load_config()
    project_id = project or (str(config.project_id) if config.project_id else None)
    if not project_id:
        console.print("[red]No project specified.[/red] Use --project, SBOMBOX_PROJECT, or `sbombox projects use`.")
        raise typer.Exit(code=EXIT_USAGE)

    ctx = detect_ci()
    if not config.token and ctx.is_ci:
        from sbombox_cli.ci_auth import CiAuthError, exchange_ci_token

        try:
            grant = exchange_ci_token(config.api_url, project_id, user_agent=user_agent())
        except CiAuthError as exc:
            console.print(f"[red]Authentication failed:[/red] {exc}")
            raise typer.Exit(code=exc.exit_code or EXIT_AUTH) from exc
        config.token = grant["access_token"]
        provenance = grant.get("provenance") or {}
        # The exchange accepts a slug; uploads are addressed by UUID.
        project_id = provenance.get("project_id") or project_id
        console.print(
            f"Authenticated keylessly as [bold]{provenance.get('repository') or ctx.repo_url}[/bold]"
            f" ({provenance.get('provider', ctx.ci_name)} OIDC)"
        )
    elif not config.token:
        console.print("[red]Not logged in.[/red] Run `sbombox login`, or set SBOMBOX_TOKEN.")
        raise typer.Exit(code=EXIT_AUTH)

    with ApiClient(config) as client:
        try:
            return client.upload_sbom(
                project_id,
                sbom_path,
                branch=branch or ctx.branch or "main",
                version_label=version,
                ci=ctx.as_metadata(),
            )
        except ApiError as exc:
            console.print(f"[red]Upload failed:[/red] {exc}")
            raise typer.Exit(code=exc.exit_code) from exc


@app.command()
def push(
    sbom_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Path to the SBOM file."),
    project: str = typer.Option(None, "--project", "-p", help="Project UUID or org/project slug. Default: the active project."),
    branch: str = typer.Option(None, "--branch", "-b", help="Branch label. Default: the branch reported by CI or git."),
    version: str = typer.Option("", "--version", "-v", help="Release or version label, e.g. v1.4.0."),
    as_json: bool = typer.Option(False, "--json", help="Print the API response as JSON on stdout (messages go to stderr)."),
) -> None:
    """Upload an SBOM to the SBOMBox API."""
    result = upload(sbom_path, project=project, branch=branch, version=version)
    if as_json:
        typer.echo(json.dumps(result, default=str))
        return
    console.print(
        f"[green]SBOM uploaded:[/green] {result.get('id', 'ok')}"
        f" (branch {result.get('branch', branch or '?')}, provenance {result.get('provenance_level', '?')})"
    )
