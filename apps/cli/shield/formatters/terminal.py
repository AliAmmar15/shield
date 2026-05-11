"""
terminal.py — Rich terminal findings table renderer.

Renders a NormalizedFinding list as a formatted Rich Table with:
  - Severity badge (colored + emoji)
  - Tool name
  - File path (relative, shortened if long)
  - Line number
  - Rule ID
  - Message (truncated to 80 chars for readability)

If no findings are present, prints a green success panel instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shield.core.output import SEVERITY_BADGES, SEVERITY_COLORS, Severity

if TYPE_CHECKING:
    from normalizer.models import NormalizedFinding


def _truncate(text: str, max_len: int = 80) -> str:
    """Truncate a string to max_len characters, appending ellipsis if needed.

    Args:
        text: Input string.
        max_len: Maximum allowed character length.

    Returns:
        Truncated string with '…' appended if it exceeded max_len.
    """
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _shorten_path(file_path: str, target: str) -> str:
    """Return a path relative to the scan target for compact display.

    Args:
        file_path: Absolute or relative file path from the finding.
        target: The root scan target path.

    Returns:
        Relative path string, or original if relativization fails.
    """
    try:
        return str(Path(file_path).relative_to(target))
    except ValueError:
        return file_path


def _build_table() -> Table:
    """Construct an empty Rich Table with Velonus's standard column layout.

    Returns:
        Configured Rich Table instance ready for row insertion.
    """
    table = Table(
        title="[bold]Velonus — Scan Results[/bold]",
        show_header=True,
        header_style="bold white",
        border_style="grey50",
        show_lines=False,
        expand=True,
    )
    table.add_column("Severity", width=14, no_wrap=True)
    table.add_column("Tool", style="dim cyan", width=10, no_wrap=True)
    table.add_column("File", style="white", min_width=20, max_width=45)
    table.add_column("Line", style="dim", width=6, justify="right")
    table.add_column("Rule", style="dim magenta", width=22, no_wrap=True)
    table.add_column("Message", style="white", min_width=30)
    return table


def render_findings_table(
    findings: list[NormalizedFinding],
    target: str,
    console: Console | None = None,
) -> None:
    """Render a list of normalized findings as a Rich terminal table.

    Prints a colored table row for each finding, sorted by severity
    (CRITICAL first). If the findings list is empty, prints a success
    panel instead.

    Args:
        findings: List of NormalizedFinding instances to display.
        target: The root scan target path (used for shortening file paths).
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    _console = console or Console()

    if not findings:
        _console.print(
            Panel(
                "[bold green]✓ No findings detected.[/bold green]\n"
                "[dim]Shield scanned your project and found no issues.[/dim]",
                title="[bold green]Clean Scan[/bold green]",
                border_style="green",
                padding=(1, 4),
            )
        )
        _print_summary(findings, _console)
        return

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

    table = _build_table()

    for finding in sorted_findings:
        color = SEVERITY_COLORS[finding.severity]
        badge = SEVERITY_BADGES[finding.severity]

        severity_cell = Text()
        severity_cell.append(f"{badge} ")
        severity_cell.append(finding.severity.value, style=color)

        table.add_row(
            severity_cell,
            finding.tool,
            _shorten_path(finding.file, target),
            str(finding.line_start),
            finding.rule_id,
            _truncate(finding.message),
        )

    _console.print(table)
    _print_summary(sorted_findings, _console)


def _print_summary(findings: list[NormalizedFinding], console: Console) -> None:
    """Print a one-line severity summary below the findings table.

    Args:
        findings: All findings that were displayed.
        console: Rich Console instance.
    """
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    total = len(findings)
    if total == 0:
        console.print("[dim]Scan complete. 0 findings.[/dim]\n")
        return

    parts: list[str] = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts[sev]
        if n:
            c = SEVERITY_COLORS[sev]
            parts.append(f"[{c}]{n} {sev.value}[/{c}]")

    summary = "  ".join(parts)
    console.print(
        f"\n[bold]Total:[/bold] {total} finding{'s' if total != 1 else ''}  —  {summary}\n"
    )
