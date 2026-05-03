"""
config command group — local CLI configuration management (Phase 2).

Stubs only in Phase 0.
"""

import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command("show")
def show() -> None:
    """Display current Shield CLI configuration. [dim](Available in Phase 2)[/dim]"""
    console.print("[yellow]⚠ Config management is not yet available. Coming in Phase 2.[/yellow]")
    raise typer.Exit(code=0)


@app.command("set")
def set_value(
    key: str = typer.Argument(help="Config key to set."),
    value: str = typer.Argument(help="Value to assign."),
) -> None:
    """Set a configuration value. [dim](Available in Phase 2)[/dim]"""
    console.print("[yellow]⚠ Config management is not yet available. Coming in Phase 2.[/yellow]")
    raise typer.Exit(code=0)
