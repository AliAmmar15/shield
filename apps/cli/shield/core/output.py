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

Note: Severity and Confidence are the canonical definitions from
packages/normalizer/models.py. They are re-exported here so that all
existing CLI code (formatters, commands) can continue to import from
shield.core.output without any changes.
"""

from __future__ import annotations

# Re-export canonical enums from the normalizer package.
# This keeps Severity and Confidence as the single source of truth in
# packages/normalizer/models.py while preserving backward compatibility
# for all existing imports in the CLI (e.g. `from shield.core.output import Severity`).
from normalizer.models import (  # noqa: PLC0414
    Confidence as Confidence,
)
from normalizer.models import (
    Severity as Severity,
)

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
