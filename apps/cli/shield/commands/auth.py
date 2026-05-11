"""
auth command group — Clerk-based authentication (Phase 2).

Stubs only in Phase 0. No API calls until Phase 2.
"""

import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command("login")
def login() -> None:
    """Authenticate with the Velonus API using Clerk. [dim](Available in Phase 2)[/dim]"""
    console.print("[yellow]⚠ Auth is not yet available. Coming in Phase 2.[/yellow]")
    raise typer.Exit(code=0)


@app.command("logout")
def logout() -> None:
    """Clear stored Velonus API credentials. [dim](Available in Phase 2)[/dim]"""
    console.print("[yellow]⚠ Auth is not yet available. Coming in Phase 2.[/yellow]")
    raise typer.Exit(code=0)


@app.command("status")
def status() -> None:
    """Show current authentication status. [dim](Available in Phase 2)[/dim]"""
    console.print("[yellow]⚠ Auth is not yet available. Coming in Phase 2.[/yellow]")
    raise typer.Exit(code=0)
