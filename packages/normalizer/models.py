"""models.py — Canonical data models for the Velonus scanner pipeline.

NormalizedFinding is the single source-of-truth shape shared by:
  - All scanner detectors (via RawFinding → NormalizedFinding conversion)
  - The CLI formatters (terminal, JSON, SARIF)
  - The API layer (Phase 2 — stored in PostgreSQL as findings)
  - The AI engine (Phase 2 — prioritization, scoring, remediation)

Severity and Confidence enums are defined here (not in apps/cli) so that
packages/normalizer, packages/scanner/pipeline.py, and packages/ai-engine
can all use them without importing from the CLI package.

apps/cli/shield/core/output.py re-exports Severity and Confidence from here
for backward compatibility with all existing CLI code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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


@dataclass
class NormalizedFinding:
    """Canonical finding shape shared by all scanner tools and formatters.

    All scanner detectors produce RawFinding objects which are converted to
    NormalizedFinding by FindingNormalizer (packages/normalizer/normalizer.py).

    The ``id`` field is a deterministic SHA-256 fingerprint derived from
    ``tool + file + line + rule_id`` (first 16 hex chars). This enables
    cross-scan deduplication: the same vulnerability found in two different
    scans will have the same id.

    Fields follow the spec in .github/copilot-instructions.md → DATA MODELS.
    """

    id: str  # deterministic: sha256(tool+file+line+rule_id)[:16]
    tool: str  # "bandit"|"semgrep"|"secrets"|"pip-audit"|"safety"
    rule_id: str
    cwe: list[str]  # e.g. ["CWE-89"]
    owasp: list[str]  # e.g. ["A03:2021"]
    severity: Severity  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: Confidence  # HIGH | MEDIUM | LOW
    file: str
    line_start: int
    line_end: int
    code_snippet: str
    message: str
    fix_available: bool = False
    suppressed: bool = False
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # AI fields — populated in Phase 2 when ai-engine is wired in
    exploitability_score: float | None = None
    ai_priority: int | None = None
    ai_explanation: str | None = None
    ai_remediation: str | None = None
    false_positive: bool = False
