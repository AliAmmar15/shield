"""
output.py — Core severity definitions and Rich color mappings.

Defines the canonical Severity and Confidence enums used across the
entire CLI. Color scheme:
    CRITICAL → bold red
    HIGH     → dark_orange
    MEDIUM   → yellow
    LOW      → steel_blue1
    INFO     → grey70

These colors are used consistently in all terminal output (tables,
inline messages, progress indicators).
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Normalized severity levels across all scanner tools.

    Values map directly to the NormalizedFinding.severity field.
    Always use this enum — never raw strings — for severity comparisons.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    """Confidence level for a finding — reflects tool certainty, not severity."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Canonical Rich markup color per severity level.
# Used in tables, panels, and inline messages.
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "steel_blue1",
    Severity.INFO: "grey70",
}

# Emoji badge per severity for compact display in terminal tables.
SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def severity_markup(severity: Severity, text: str | None = None) -> str:
    """Return a Rich markup string for the given severity.

    Args:
        severity: The severity level to style.
        text: Optional override text. Defaults to the severity value itself.

    Returns:
        Rich markup string, e.g. '[bold red]CRITICAL[/bold red]'
    """
    color = SEVERITY_COLORS[severity]
    label = text if text is not None else severity.value
    return f"[{color}]{label}[/{color}]"


def severity_badge(severity: Severity) -> str:
    """Return the emoji badge + colored label for a severity level.

    Args:
        severity: The severity level.

    Returns:
        String combining emoji and Rich-colored severity name.
    """
    badge = SEVERITY_BADGES[severity]
    return f"{badge} {severity_markup(severity)}"
