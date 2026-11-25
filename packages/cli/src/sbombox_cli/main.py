"""Entry point for the ``sbombox`` CLI."""
from __future__ import annotations
import typer
from sbombox_cli import __version__

app = typer.Typer(
    name="sbombox",
    help="Generate, assess and publish software bills of materials (SBOMs).",
    epilog="Documentation: https://sbombox.com/docs/cli",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

SETUP = "Set up"
ASSESS = "Create and assess SBOMs"
PUBLISH = "Publish"
CONFIGURE = "Configure"

_UPDATE_CHECK_REGISTERED = False


def version_callback(value: bool) -> None:
    """Print the CLI version and exit."""
    if value:
        typer.echo(f"sbombox {__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=version_callback, is_eager=True,
        help="Show the sbombox version and exit.",
    ),
) -> None:
    """Generate, assess and publish software bills of materials (SBOMs)."""
    # Advisory update notice, at most one network check a day, printed when the
    # command finishes so it never interleaves with command output.
    import atexit

    from sbombox_cli.config import load_config
    from sbombox_cli.update_check import check_for_updates

    try:
        api_url = load_config().api_url
    except Exception:  # noqa: BLE001 - a broken config is reported by the command itself
        return
    global _UPDATE_CHECK_REGISTERED
    if not _UPDATE_CHECK_REGISTERED:
        _UPDATE_CHECK_REGISTERED = True
        atexit.register(check_for_updates, api_url)

# Register commands
from sbombox_cli.commands.login import login, logout, whoami
from sbombox_cli.commands.generate import generate
from sbombox_cli.commands.score import score
from sbombox_cli.commands.compliance import compliance
from sbombox_cli.commands.list import list_components
from sbombox_cli.commands.fix import fix
from sbombox_cli.commands.share import share
from sbombox_cli.commands.config_cmd import config_cmd
from sbombox_cli.commands.init import init
from sbombox_cli.commands.push import push
from sbombox_cli.commands.status import status

app.command("login", rich_help_panel=SETUP, help="Sign in to SBOMBox in your browser.")(login)
app.command("logout", rich_help_panel=SETUP, help="Sign out and delete stored credentials.")(logout)
app.command("whoami", rich_help_panel=SETUP, help="Show the account you are signed in as.")(whoami)
app.command("init", rich_help_panel=SETUP, help="Set up a repository: choose a project, trust its CI, write the workflow.")(init)

from sbombox_cli.commands import projects as projects_mod
projects_app = typer.Typer(help="List projects or choose the active one.", no_args_is_help=True)
projects_app.command("list", help="List the projects you can access.")(projects_mod.list_projects)
projects_app.command("use", help="Set the active project in .sbombox.yml.")(projects_mod.use)
app.add_typer(projects_app, name="projects", rich_help_panel=SETUP)

from sbombox_cli.commands.ci import app as ci_app
app.add_typer(ci_app, name="ci", rich_help_panel=SETUP)

from sbombox_cli.commands.check import check
app.command("generate", rich_help_panel=ASSESS, help="Generate an SBOM for a project directory.")(generate)
app.command("check", rich_help_panel=ASSESS, help="Generate and score an SBOM locally without uploading (for pre-commit).")(check)
app.command("score", rich_help_panel=ASSESS, help="Score an SBOM's quality from 0 to 10.")(score)
app.command("compliance", rich_help_panel=ASSESS, help="Check an SBOM against a compliance ruleset.")(compliance)
app.command("list", rich_help_panel=ASSESS, help="List the components in an SBOM.")(list_components)
app.command("fix", rich_help_panel=ASSESS, help="Repair common SBOM defects automatically.")(fix)
app.command("share", rich_help_panel=ASSESS, help="Write a report with aggregate scores only, safe to share.")(share)

app.command("push", rich_help_panel=PUBLISH, help="Upload an SBOM to SBOMBox.")(push)
app.command("status", rich_help_panel=PUBLISH, help="Show the active project's latest SBOM, score and vulnerabilities.")(status)

from sbombox_cli.commands.upgrade import upgrade
app.command("upgrade", rich_help_panel=CONFIGURE, help="Upgrade to the current version published by SBOMBox.")(upgrade)
app.command("config", rich_help_panel=CONFIGURE, help="Print the default .sbombox.yml, or write it with --init.")(config_cmd)

if __name__ == "__main__":  # pragma: no cover
    app()
