"""
scan command — core entry point for local security analysis.

Runs the scanner pipeline on a given path and renders findings
to the terminal using Rich. No API calls in Phase 0.

Phase 0 pipeline:
  1. SecretsDetector (trufflehog v3 or entropy fallback)
  2. NormalizedFinding conversion (normalizer_stub)
  3. Severity filter + terminal/json/sarif output

Usage:
    shield scan ./myproject
    shield scan ./myproject --format json
    shield scan ./myproject --severity high
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from shield.core.output import Severity
from shield.formatters.sarif import to_sarif, write_sarif
from shield.formatters.terminal import render_findings_table
from shield.normalizer_stub import NormalizedFinding, get_stub_findings

# allow_interspersed_args=True lets users place options after the path argument:
#   shield scan ./project --sarif   (instead of requiring: shield scan --sarif ./project)
# Click groups disable interspersed args by default; we opt back in here.
app = typer.Typer(context_settings={"allow_interspersed_args": True})
console = Console()


class OutputFormat(str, Enum):
    """Supported output formats for scan results."""

    terminal = "terminal"
    json = "json"
    sarif = "sarif"


def _resolve_target(path: str) -> Path:
    """Resolve and validate the scan target path.

    Args:
        path: Raw string path provided by the user.

    Returns:
        Resolved absolute Path object.

    Raises:
        typer.BadParameter: If the path does not exist.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise typer.BadParameter(f"Path does not exist: {resolved}")
    return resolved


def _output_json(findings: list[NormalizedFinding]) -> None:
    """Serialize findings to JSON and print to stdout.

    Args:
        findings: List of normalized findings to serialize.
    """
    import json
    from dataclasses import asdict

    console.print_json(json.dumps([asdict(f) for f in findings], default=str))


@app.callback(invoke_without_command=True)
def scan(
    path: Annotated[
        str,
        typer.Argument(help="Path to the project or file to scan."),
    ] = ".",
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format: terminal, json, sarif."),
    ] = OutputFormat.terminal,
    min_severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to display: critical, high, medium, low, info.",
        ),
    ] = "info",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show verbose output including skipped files."),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option(
            "--sarif",
            help="Write findings to a SARIF file (default: shield-results.sarif).",
        ),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output path for the SARIF file. Implies --sarif when set.",
        ),
    ] = None,
) -> None:
    """Run a security scan on the given path.

    Phase 0 pipeline: secrets detection only (trufflehog v3 or entropy fallback).
    Phase 1 will add: Bandit, Semgrep, pip-audit, parallel execution.
    """
    target = _resolve_target(path)

    if verbose:
        console.print(f"[dim]Resolved target: {target}[/dim]")

    console.print(f"\n[bold green]Shield AI[/bold green] — scanning [cyan]{target}[/cyan]\n")

    findings: list[NormalizedFinding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,  # clears the spinner line after completion
    ) as progress:
        task = progress.add_task("[yellow]Detecting secrets...[/yellow]", total=None)

        # Phase 0: secrets detection only.
        # get_stub_findings() calls run_secrets_scan() → SecretsDetector.scan().
        # trufflehog is used if installed; entropy fallback runs otherwise.
        findings = get_stub_findings(target)

        progress.update(task, description="[green]Scan complete.[/green]")

    # Filter by minimum severity
    sev_order = ["info", "low", "medium", "high", "critical"]
    min_idx = sev_order.index(min_severity.lower()) if min_severity.lower() in sev_order else 0
    filtered = [f for f in findings if sev_order.index(f.severity.value.lower()) >= min_idx]

    if output_format == OutputFormat.terminal:
        render_findings_table(filtered, target=str(target), console=console)
    elif output_format == OutputFormat.json:
        _output_json(filtered)
    elif output_format == OutputFormat.sarif:
        # --format sarif: print SARIF JSON to stdout (for piping / CI consumption)
        import json as _json

        console.print_json(_json.dumps(to_sarif(filtered, str(target))))

    # --sarif flag (or -o path): write SARIF to a file in addition to terminal output
    write_sarif_file = sarif or output is not None
    if write_sarif_file:
        sarif_path = output if output is not None else Path("shield-results.sarif")
        write_sarif(filtered, sarif_path, scan_path=str(target))
        console.print(
            f"\n[dim]SARIF report written to[/dim] [cyan]{sarif_path}[/cyan]"
        )

    # Exit code 1 if any HIGH or CRITICAL findings (for CI gate integration)
    high_or_critical = [f for f in filtered if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if high_or_critical:
        raise typer.Exit(code=1)
