"""
scan command — core entry point for local security analysis.

Runs the scanner pipeline on a given path and renders findings
to the terminal using Rich.

Phase 1 pipeline (parallel execution):
  Stage 1: SecretsDetector (synchronous — always first)
  Stage 2: BanditRunner + SemgrepRunner + PipAuditRunner + SafetyRunner
           (concurrent via asyncio.to_thread — all four run simultaneously)
  Post:    FindingNormalizer → DeduplicationFilter → severity sort

Usage:
    velonus scan ./myproject
    velonus scan ./myproject --format json
    velonus scan ./myproject --severity high
    velonus scan ./myproject --verbose
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from scanner.pipeline import DEFAULT_EXCLUDE_PATTERNS, ScanPipeline

from shield.core.output import Severity
from shield.formatters.sarif import to_sarif, write_sarif
from shield.formatters.terminal import render_findings_table

if TYPE_CHECKING:
    from normalizer.models import NormalizedFinding

# allow_interspersed_args=True lets users place options after the path argument:
#   velonus scan ./project --sarif   (instead of requiring: velonus scan --sarif ./project)
# Click groups disable interspersed args by default; we opt back in here.
app = typer.Typer(context_settings={"allow_interspersed_args": True})
console = Console()

# Separate stderr console for status/spinner output.
# Used when --format json is active so that progress messages don't
# corrupt the JSON written to stdout by _output_json().
_stderr_console = Console(stderr=True)


def _tool_on_path(name: str) -> bool:
    """Return True if a binary is findable on PATH."""
    import shutil

    return shutil.which(name) is not None


def _prompted_marker() -> Path:
    """Return the path to the one-time prompt sentinel file.

    After the user has answered the optional-tools prompts (regardless of
    their answers), we write this file so the prompt never fires again.
    Location: ~/.velonus/.prompted_tools
    """
    return Path.home() / ".velonus" / ".prompted_tools"


def _prompt_optional_tools() -> None:
    """Prompt the user to install optional scanner tools on first use.

    Only runs:
      1. When stdin is a TTY (not in CI, not when piping output).
      2. Only ONCE — a sentinel file is written after the first run so
         subsequent scans skip this entirely.

    Prompts per missing tool:
      - semgrep    → pip-installable, offered auto-install
      - trufflehog → Go binary, shows install link only
    """
    if not sys.stdin.isatty():
        # Non-interactive environment (CI, pipe, script) — skip all prompts.
        return

    marker = _prompted_marker()
    if marker.exists():
        # Already asked. Never ask again.
        return

    missing: list[str] = []
    if not _tool_on_path("semgrep"):
        missing.append("semgrep")
    if not _tool_on_path("trufflehog"):
        missing.append("trufflehog")

    if not missing:
        # All optional tools present — write the marker so we never check again.
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        return

    console.print()
    console.print(
        "[bold yellow]Optional tools not installed[/bold yellow] — "
        "installing them improves scan coverage:\n"
    )

    for tool in missing:
        if tool == "semgrep":
            console.print(
                "  [cyan]semgrep[/cyan]  Pattern-based static analysis (~200 MB). "
                "Detects injection, hardcoded secrets, insecure patterns."
            )
        elif tool == "trufflehog":
            console.print(
                "  [cyan]trufflehog[/cyan]  High-accuracy secret scanning (Go binary). "
                "Detects 700+ credential types with verified entropy checks."
            )

    console.print()

    # --- semgrep (pip-installable — can auto-install) ---
    if "semgrep" in missing:
        if typer.confirm("  Install semgrep now? (~200 MB)", default=False):
            console.print("\n  [dim]Running: pip install semgrep ...[/dim]")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "semgrep"],
                capture_output=False,  # stream pip output directly to terminal
            )
            if result.returncode == 0:
                console.print("  [green]✓ semgrep installed.[/green]\n")
            else:
                console.print(
                    "  [red]semgrep install failed.[/red] "
                    "Run manually: [bold]pip install semgrep[/bold]\n"
                )
        else:
            console.print("  Skipped. Install later with: [bold]pip install semgrep[/bold]\n")

    # --- trufflehog (Go binary — cannot pip install, show link) ---
    if "trufflehog" in missing:
        if typer.confirm("  Show trufflehog install instructions?", default=True):
            console.print(
                "\n  [bold]trufflehog install options:[/bold]\n"
                "    macOS/Linux:  [cyan]curl -sSfL https://raw.githubusercontent.com/"
                "trufflesecurity/trufflehog/main/scripts/install.sh | sh[/cyan]\n"
                "    Windows:      Download from [cyan]https://github.com/trufflesecurity/"
                "trufflehog/releases[/cyan]\n"
                "    Homebrew:     [cyan]brew install trufflesecurity/trufflehog/trufflehog[/cyan]\n"
                "\n"
                "  [dim]Until installed, Velonus uses its built-in entropy-based "
                "secret scanner as a fallback.[/dim]\n"
            )
        else:
            console.print(
                "  Skipped. Install later from: "
                "[cyan]https://github.com/trufflesecurity/trufflehog/releases[/cyan]\n"
            )

    # Persist that we've asked — never prompt again regardless of answers.
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()


def _load_config_excludes() -> list[str]:
    """Read exclusion patterns from ~/.velonus/config.toml if it exists.

    Expected TOML structure::

        [scan]
        exclude = ["tests/", "conftest.py", "mydir/"]

    Returns an empty list when the file is missing, malformed, or has no
    ``[scan] exclude`` key.
    """
    import tomllib

    config_path = Path.home() / ".velonus" / "config.toml"
    if not config_path.exists():
        return []
    try:
        with config_path.open("rb") as fh:
            data = tomllib.load(fh)
        raw = data.get("scan", {}).get("exclude", [])
        if isinstance(raw, list):
            return [str(p) for p in raw]
    except Exception:  # noqa: BLE001 — malformed TOML silently ignored
        pass
    return []


class OutputFormat(StrEnum):
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


def _json_default(obj: object) -> str:
    """Custom JSON serializer for types not handled natively by json.dumps.

    - datetime → ISO 8601 string with T separator (e.g. "2026-05-11T12:34:56.789")
    - Everything else → str() fallback (covers any unexpected types)

    StrEnum values (Severity, Confidence) are NOT routed here because StrEnum
    inherits from str, so json.dumps already treats them as plain strings.
    """
    from datetime import datetime

    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _output_json(findings: list[NormalizedFinding]) -> None:
    """Serialize findings to JSON and write directly to sys.stdout.

    Writes to sys.stdout (not the Rich console) so the output is always
    clean and pipeable:
        velonus scan ./ --format json | python -m json.tool

    Args:
        findings: List of normalized findings to serialize.
    """
    import json
    import sys
    from dataclasses import asdict

    payload = json.dumps(
        [asdict(f) for f in findings],
        indent=2,
        default=_json_default,
    )
    sys.stdout.write(payload + "\n")


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
        typer.Option("--verbose", "-v", help="Show verbose output including per-tool timing."),
    ] = False,
    sarif: Annotated[
        bool,
        typer.Option(
            "--sarif",
            help="Write findings to a SARIF file (default: velonus-results.sarif).",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output path for the SARIF file. Implies --sarif when set.",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help=(
                "Glob pattern to exclude from results. Repeatable. "
                "e.g. --exclude migrations/ --exclude */generated_*.py"
            ),
        ),
    ] = None,
) -> None:
    """Run a security scan on the given path.

    Phase 1 pipeline: secrets + Bandit + Semgrep + pip-audit + Safety.
    Secrets run first (synchronous); all other tools run in parallel.
    """
    target = _resolve_target(path)

    # Build exclusion pattern list: defaults + config file + CLI flags.
    # Config file patterns are additive on top of the defaults.
    # CLI --exclude patterns are further additive on top of both.
    exclude_patterns: list[str] = list(DEFAULT_EXCLUDE_PATTERNS)
    exclude_patterns.extend(_load_config_excludes())
    if exclude:
        exclude_patterns.extend(exclude)

    # Route all UI output to stderr when JSON format is active so that stdout
    # contains only the JSON array — making it safely pipeable to jq / json.tool.
    ui_console = _stderr_console if output_format == OutputFormat.json else console

    # Prompt to install optional tools (semgrep, trufflehog) on first use.
    # Only runs in interactive TTY sessions — silently skipped in CI/pipes.
    if output_format == OutputFormat.terminal:
        _prompt_optional_tools()

    if verbose:
        ui_console.print(f"[dim]Resolved target: {target}[/dim]")

    if output_format != OutputFormat.json:
        console.print(f"\n[bold green]Velonus[/bold green] — scanning [cyan]{target}[/cyan]\n")

    findings: list[NormalizedFinding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=ui_console,
        transient=True,  # clears the spinner line after completion
    ) as progress:
        task = progress.add_task(
            "[yellow]Running security scan (secrets → bandit + semgrep + pip-audit + safety)...[/yellow]",
            total=None,
        )

        # Phase 1: full parallel pipeline.
        # ScanPipeline.run() is async; asyncio.run() bridges to this sync CLI context.
        # verbose=True passes per-detector timing to the pipeline logger.
        pipeline = ScanPipeline(exclude=exclude_patterns)
        findings = asyncio.run(pipeline.run(target, verbose=verbose))

        progress.update(task, description="[green]Scan complete.[/green]")

    # Filter by minimum severity — applied before all output formats
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
        sarif_path = output if output is not None else Path("velonus-results.sarif")
        write_sarif(filtered, sarif_path, scan_path=str(target))
        console.print(f"\n[dim]SARIF report written to[/dim] [cyan]{sarif_path}[/cyan]")

    # Exit code 1 if any HIGH or CRITICAL findings (for CI gate integration)
    high_or_critical = [f for f in filtered if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    if high_or_critical:
        raise typer.Exit(code=1)
