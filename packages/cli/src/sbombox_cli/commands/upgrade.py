"""``sbombox upgrade`` - install the version the server says is current."""
from __future__ import annotations

import shutil
import subprocess

import typer
from rich.console import Console

console = Console()


def upgrade() -> None:
    """Upgrade the CLI to the current version published by SBOMBox."""
    from sbombox_cli import __version__
    from sbombox_cli.config import load_config
    from sbombox_cli.update_check import fetch_policy, parse_version

    policy = fetch_policy(load_config().api_url)
    if not policy or not policy.get("latest_version"):
        console.print("[red]Could not reach SBOMBox to find the current version.[/red]")
        raise typer.Exit(code=3)
    latest = str(policy["latest_version"])
    current, target = parse_version(__version__), parse_version(latest)
    if current and target and current >= target:
        console.print(f"sbombox {__version__} is up to date.")
        return

    console.print(f"Upgrading sbombox {__version__} -> {latest}")
    uv = shutil.which("uv")
    if uv and _installed_with_uv(uv):
        result = subprocess.run([uv, "tool", "install", "--force", "--python", ">=3.12", f"sbombox=={latest}"])
        if result.returncode != 0:
            raise typer.Exit(code=4)
        console.print(f"[green]Upgraded to sbombox {latest}.[/green]")
        return
    if shutil.which("pipx"):
        console.print(f"Run: pipx install --force sbombox=={latest}")
    else:
        console.print(f"Run: {policy.get('install_command') or 'curl -fsSL https://sbombox.com/install.sh | sh'}")
    raise typer.Exit(code=2)


def _installed_with_uv(uv: str) -> bool:
    try:
        listing = subprocess.run([uv, "tool", "list"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return any(line.startswith("sbombox ") for line in listing.splitlines())
