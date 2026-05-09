"""
normalizer_stub.py — Phase 0 scanner entry point and finding normalization.

Phase 1 update: NormalizedFinding is now defined in packages/normalizer/models.py
and re-exported here for backward compatibility. All existing imports of
NormalizedFinding from this module continue to work unchanged.

The secrets-only scan path (run_secrets_scan / get_stub_findings) is retained
for backward compatibility. In Phase 1 the CLI scan command uses ScanPipeline
directly; get_stub_findings is no longer called from scan.py.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, Protocol

# Phase 1: NormalizedFinding is the canonical definition from packages/normalizer.
# Re-exported here so any existing code that imports from normalizer_stub continues
# to work without modification.
from normalizer.models import Confidence, NormalizedFinding, Severity  # noqa: F401

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol — structural type for RawFinding from packages/scanner
# ---------------------------------------------------------------------------


class _RawFindingLike(Protocol):
    """Structural interface matching scanner.detectors.secrets.RawFinding."""

    tool: str
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    code_snippet: str
    metadata: dict[str, Any]


def get_stub_findings(target: Path) -> list[NormalizedFinding]:
    """Run secrets-only scan (Phase 0 fallback).

    Retained for backward compatibility. Phase 1 CLI scan.py uses ScanPipeline.

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
    raw_findings = detector.scan(target)  # list[RawFinding] — compatible at runtime
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
        cwe=["CWE-798"],  # Use of Hard-coded Credentials
        owasp=["A07:2021"],  # Identification and Authentication Failures
        severity=severity,
        confidence=Confidence.HIGH,
        file=raw.file,
        line_start=raw.line,
        line_end=raw.line,
        code_snippet=raw.code_snippet,
        message=raw.message,
    )
