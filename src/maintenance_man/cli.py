import typer
from rich.console import Console
from rich.table import Table

from maintenance_man import __version__
from maintenance_man.config import load_config

app = typer.Typer(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    rich_markup_mode="markdown",
)


def _version_callback(value: bool) -> None:
    if value:
        print(f"mm {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Config-driven CLI for routine software project maintenance."""


@app.command()
def scan(
    project: str | None = typer.Argument(
        None, help="Project name to scan. Scans all if omitted."
    ),
) -> None:
    """Scan projects for vulnerabilities and available updates."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)


@app.command()
def update(
    project: str = typer.Argument(..., help="Project name to update."),
) -> None:
    """Apply updates from scan results to a project."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)


@app.command()
def deploy(
    project: str = typer.Argument(..., help="Project name to deploy."),
) -> None:
    """Deploy a project."""
    typer.echo("Not implemented.")
    raise typer.Exit(code=1)


@app.command(name="list")
def list_projects() -> None:
    """List all configured projects."""
    config = load_config()

    if not config.projects:
        typer.echo("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    console = Console()
    table = Table(title="Configured Projects")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Package Manager")

    for name, project in sorted(config.projects.items()):
        table.add_row(name, str(project.path), project.package_manager)

    console.print(table)
