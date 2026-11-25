"""Project management commands."""
from __future__ import annotations
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage projects.")
console = Console()

@app.command(name="list")
def list_projects() -> None:
    """List all projects."""
    from sbombox_cli.config import load_config
    from sbombox_cli.api_client import ApiClient
    config = load_config()
    client = ApiClient(config)
    try:
        projects = client.list_projects()
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=getattr(exc, "exit_code", 3))
    table = Table(title="Projects")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Slug")
    for p in projects:
        table.add_row(str(p.get("id", "")), p.get("name", ""), p.get("slug", ""))
    console.print(table)

@app.command()
def use(project_id: str = typer.Argument(..., help="Project UUID to set as active.")) -> None:
    """Set the active project."""
    from pathlib import Path
    config_path = Path(".sbombox.yml")
    if config_path.exists():
        content = config_path.read_text()
        import re
        if re.search(r"^project_id:", content, re.MULTILINE):
            content = re.sub(r"^project_id:.*$", f'project_id: "{project_id}"', content, flags=re.MULTILINE)
        else:
            content += f'\nproject_id: "{project_id}"\n'
        config_path.write_text(content)
    else:
        config_path.write_text(f'project_id: "{project_id}"\n')
    console.print(f"[green]Active project set to {project_id}[/green]")
