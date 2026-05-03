"""
normalizer_stub.py — Phase 0 stub for the finding pipeline.

Returns an empty finding list. In Phase 1 this module is replaced
by a real import from packages/normalizer via the uv workspace.

The NormalizedFinding dataclass defined here is the canonical shape
used by all CLI formatters. It must stay in sync with the spec in
.github/copilot-instructions.md → DATA MODELS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from shield.core.output import Confidence, Severity


@dataclass
class NormalizedFinding:
    """Canonical finding shape shared by all scanner tools and formatters.

    Fields are a strict subset of the full NormalizedFinding spec.
    AI-enrichment fields (exploitability_score, ai_priority, etc.)
    are added in Phase 2 when the AI engine is wired in.
    """

    id: str                           # deterministic: hash(tool+file+line+rule_id)
    tool: str                         # "bandit" | "semgrep" | "secrets" | "pip-audit"
    rule_id: str
    cwe: list[str]                    # e.g. ["CWE-89"]
    owasp: list[str]                  # e.g. ["A03:2021"]
    severity: Severity
    confidence: Confidence
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    message: str
    fix_available: bool = False
    suppressed: bool = False
    first_seen: datetime = field(default_factory=datetime.utcnow)
    # AI fields — populated in Phase 2
    exploitability_score: float | None = None
    ai_priority: int | None = None
    ai_explanation: str | None = None
    ai_remediation: str | None = None
    false_positive: bool = False


def get_stub_findings(target: Path) -> list[NormalizedFinding]:
    """Return stub findings for Phase 0.

    In Phase 0, the real scanner pipeline is not yet wired in.
    This function returns an empty list so the CLI renders correctly.
    Replace this with the real pipeline call in Phase 1.

    Args:
        target: The resolved scan target path (unused in stub).

    Returns:
        Empty list of NormalizedFinding.
    """
    # Phase 0 — no real tool execution yet.
    # Returning empty list intentionally. See Phase 1 tasks in copilot-instructions.md.
    _ = target  # will be used in Phase 1
    return []
