import typer

from maintenance_man import __version__

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
