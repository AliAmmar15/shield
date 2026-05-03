"""
Shield AI — CLI entry point.

Defines the root Typer application and registers all command groups:
  - scan     : Run static analysis on a local path
  - auth     : Authenticate with the Shield API (Phase 2)
  - config   : Manage local CLI configuration (Phase 2)
  - pr       : GitHub PR integration utilities (Phase 3)

Local-only mode is fully supported without an API connection.
"""

import typer

from shield.commands import auth, config, scan

app = typer.Typer(
    name="shield",
    help="[bold green]Shield AI[/bold green] — AI-native AppSec scanner for developers.",
    rich_markup_mode="rich",
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_show_locals=False,
)

# Register command groups
app.add_typer(scan.app, name="scan", help="Run security scans on a local path.")
app.add_typer(auth.app, name="auth", help="Authenticate with the Shield API.")
app.add_typer(config.app, name="config", help="Manage Shield CLI configuration.")


def main() -> None:
    """Invoke the Shield CLI application."""
    app()


if __name__ == "__main__":
    main()
