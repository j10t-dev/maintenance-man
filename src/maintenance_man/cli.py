import sys

import cyclopts
from rich.console import Console
from rich.table import Table

from maintenance_man import __version__
from maintenance_man.config import load_config

app = cyclopts.App(
    name="mm",
    help="Config-driven CLI for routine software project maintenance.",
    version=__version__,
    version_flags=["--version", "-v"],
)


@app.command
def scan(
    project: str | None = None,
) -> None:
    """Scan projects for vulnerabilities and available updates.

    Parameters
    ----------
    project: str | None
        Project name to scan. Scans all if omitted.
    """
    print("Not implemented.")
    sys.exit(1)


@app.command
def update(
    project: str,
) -> None:
    """Apply updates from scan results to a project.

    Parameters
    ----------
    project: str
        Project name to update.
    """
    print("Not implemented.")
    sys.exit(1)


@app.command
def deploy(
    project: str,
) -> None:
    """Deploy a project.

    Parameters
    ----------
    project: str
        Project name to deploy.
    """
    print("Not implemented.")
    sys.exit(1)


@app.command(name="list")
def list_projects() -> None:
    """List all configured projects."""
    config = load_config()

    if not config.projects:
        print("No projects configured. Edit ~/.mm/config.toml to add projects.")
        return

    console = Console()
    table = Table(title="Configured Projects")
    table.add_column("Name", style="bold")
    table.add_column("Path")
    table.add_column("Package Manager")

    for name, project in sorted(config.projects.items()):
        table.add_row(name, str(project.path), project.package_manager)

    console.print(table)


def main() -> None:
    app()
