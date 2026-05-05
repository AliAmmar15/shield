"""
normalizer_stub.py — Phase 0 scanner entry point and finding normalization.

Responsibilities in Phase 0:
  - Defines the canonical NormalizedFinding dataclass (shared by all formatters)
  - Defines _RawFindingLike Protocol (structural type for RawFinding from scanner pkg)
  - Provides run_secrets_scan() which calls SecretsDetector and converts results
  - get_stub_findings() delegates to run_secrets_scan() — replaces the empty stub

In Phase 1, this module is replaced by a real import from packages/normalizer
(full normalization, deduplication, CWE mapping, fingerprint hashing).

The NormalizedFinding dataclass must stay in sync with the spec in
.github/copilot-instructions.md → DATA MODELS.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from shield.core.output import Confidence, Severity

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol — structural type for RawFinding from packages/scanner
# ---------------------------------------------------------------------------


class _RawFindingLike(Protocol):
    """Structural interface matching scanner.detectors.secrets.RawFinding.

    Defined here so normalizer_stub.py can type-check conversions without
    a hard import-time dependency on shield-scanner. The Protocol is satisfied
    by any object that has the listed attributes with compatible types.
    """

    tool: str
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    code_snippet: str
    metadata: dict[str, Any]


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
    """Run Phase 0 scanner — secrets detection only.

    Delegates to run_secrets_scan(). Provides trufflehog if installed,
    entropy-based fallback if not. Returns empty list if shield-scanner
    package is not installed.

    Will be replaced by the full parallel pipeline in Phase 1.

    Args:
        target: The resolved scan target path.

    Returns:
        List of NormalizedFinding from the secrets detector.
    """
    return run_secrets_scan(target)


# ---------------------------------------------------------------------------
# Secrets scan integration
# ---------------------------------------------------------------------------

# Severity string → Severity enum mapping used during normalization.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def run_secrets_scan(target: Path) -> list[NormalizedFinding]:
    """Run the secrets detector and return normalized findings.

    Imports SecretsDetector from packages/scanner at call time (lazy import).
    If shield-scanner is not installed, logs a warning and returns [] so the
    CLI still works — just without detection.

    CWE mapping for secrets: CWE-798 (Use of Hard-coded Credentials).
    OWASP mapping: A07:2021 (Identification and Authentication Failures).

    Args:
        target: Resolved absolute path to scan (file or directory).

    Returns:
        List of NormalizedFinding converted from RawFinding results.
    """
    try:
        # Lazy import — shield-scanner must be installed separately.
        # Run: pip install -e packages/scanner
        # In Phase 1, this becomes a uv workspace source dependency.
        from scanner.detectors.secrets import SecretsDetector  # noqa: PGH003
    except ImportError:
        logger.warning(
            "shield-scanner package not installed — secret detection disabled. "
            "Run: pip install -e packages/scanner"
        )
        return []

    detector = SecretsDetector()
    raw_findings: list[_RawFindingLike] = detector.scan(target)
    return [_raw_to_normalized(f) for f in raw_findings]


def _raw_to_normalized(raw: _RawFindingLike) -> NormalizedFinding:
    """Convert a RawFinding (from scanner package) to a NormalizedFinding.

    Applies:
      - Deterministic ID: SHA-256(tool:file:line:rule_id)[:16]
      - Severity: maps string → Severity enum (defaults to HIGH on unknown)
      - CWE-798 and A07:2021 hardcoded for secrets (Phase 1 will generalize)
      - Confidence: HIGH for all secrets in Phase 0

    Args:
        raw: Any object satisfying the _RawFindingLike Protocol.

    Returns:
        Fully populated NormalizedFinding instance.
    """
    finding_id = hashlib.sha256(
        f"{raw.tool}:{raw.file}:{raw.line}:{raw.rule_id}".encode()
    ).hexdigest()[:16]

    severity = _SEVERITY_MAP.get(raw.severity.upper(), Severity.HIGH)

    return NormalizedFinding(
        id=finding_id,
        tool=raw.tool,
        rule_id=raw.rule_id,
        cwe=["CWE-798"],      # Use of Hard-coded Credentials
        owasp=["A07:2021"],   # Identification and Authentication Failures
        severity=severity,
        confidence=Confidence.HIGH,
        file=raw.file,
        line_start=raw.line,
        line_end=raw.line,
        code_snippet=raw.code_snippet,
        message=raw.message,
    )
