"""normalizer.py — Finding normalization for the Shield AI scanner pipeline.

FindingNormalizer converts RawFinding objects (produced by scanner detectors)
into NormalizedFinding objects (the canonical shape used by all downstream
consumers: CLI formatters, API, AI engine).

Normalization responsibilities:
  - Deterministic ID generation: SHA-256(tool+file+line+rule_id)[:16]
  - Severity string → Severity enum mapping
  - Confidence string → Confidence enum mapping (with per-tool defaults)
  - CWE list: extracted from detector metadata (with tool-specific fallbacks)
  - OWASP list: extracted from detector metadata (with tool-specific fallbacks)
  - line_end: from metadata["line_end"] when available; defaults to line_start

Tool-specific CWE/OWASP fallbacks (applied when metadata is absent):
  - secrets:   CWE-798, A07:2021 (hard-coded credentials)
  - bandit:    cwe from metadata["cwe"] (pre-computed in BanditRunner._parse_entry)
  - semgrep:   cwe+owasp from metadata["cwe"]/["owasp"] (SemgrepRunner._parse_entry)
  - pip-audit: CWE-1035, A06:2021 (vulnerable third-party component)
  - safety:    CWE-1035, A06:2021 (vulnerable third-party component)

This module uses a structural Protocol (_RawFindingLike) to avoid a hard
import-time dependency on packages/scanner. Any object with the listed
attributes satisfies the protocol at runtime (duck typing).
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

from normalizer.models import Confidence, NormalizedFinding, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol — structural type for RawFinding from packages/scanner
# ---------------------------------------------------------------------------


class _RawFindingLike(Protocol):
    """Structural interface matching scanner.detectors.secrets.RawFinding.

    Defined here so FindingNormalizer can accept RawFinding objects from any
    scanner detector without a hard import-time dependency on packages/scanner.
    Any object with these attributes satisfies this Protocol.
    """

    tool: str
    rule_id: str
    file: str
    line: int
    severity: str
    message: str
    code_snippet: str
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Severity / Confidence string → enum mappings
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}

# ---------------------------------------------------------------------------
# Tool-specific fallbacks for CWE and OWASP
# ---------------------------------------------------------------------------

# Applied only when the detector's metadata dict does not supply cwe/owasp.
# Bandit and Semgrep pre-populate their metadata, so these entries cover
# tools whose output has no CWE/OWASP data embedded.
_TOOL_CWE_DEFAULTS: dict[str, list[str]] = {
    "secrets": ["CWE-798"],  # Use of Hard-coded Credentials
    "pip-audit": ["CWE-1035"],  # Vulnerable Third Party Component
    "safety": ["CWE-1035"],  # Vulnerable Third Party Component
}

_TOOL_OWASP_DEFAULTS: dict[str, list[str]] = {
    "secrets": ["A07:2021"],  # Identification and Authentication Failures
    "pip-audit": ["A06:2021"],  # Vulnerable and Outdated Components
    "safety": ["A06:2021"],  # Vulnerable and Outdated Components
}


# ---------------------------------------------------------------------------
# FindingNormalizer
# ---------------------------------------------------------------------------


class FindingNormalizer:
    """Converts RawFinding objects to NormalizedFinding objects.

    Stateless — safe to instantiate once and reuse across scans.

    Usage::

        normalizer = FindingNormalizer()
        normalized = normalizer.normalize_all(raw_findings)
    """

    def normalize(self, raw: _RawFindingLike) -> NormalizedFinding:
        """Convert a single RawFinding to a NormalizedFinding.

        Args:
            raw: Any object satisfying the _RawFindingLike Protocol.

        Returns:
            Fully populated NormalizedFinding instance.
        """
        finding_id = hashlib.sha256(
            f"{raw.tool}:{raw.file}:{raw.line}:{raw.rule_id}".encode()
        ).hexdigest()[:16]

        severity = _SEVERITY_MAP.get(raw.severity.upper(), Severity.HIGH)

        # Confidence: prefer metadata["confidence"], default MEDIUM
        raw_confidence: str = str(raw.metadata.get("confidence", "MEDIUM")).upper()
        confidence = _CONFIDENCE_MAP.get(raw_confidence, Confidence.MEDIUM)

        # CWE: prefer metadata["cwe"] if non-empty, else tool-specific default
        cwe_meta: list[str] = list(raw.metadata.get("cwe") or [])
        cwe = cwe_meta if cwe_meta else list(_TOOL_CWE_DEFAULTS.get(raw.tool, []))

        # OWASP: prefer metadata["owasp"] if non-empty, else tool-specific default
        owasp_meta: list[str] = list(raw.metadata.get("owasp") or [])
        owasp = owasp_meta if owasp_meta else list(_TOOL_OWASP_DEFAULTS.get(raw.tool, []))

        # line_end: prefer metadata["line_end"] when detector supplies it (e.g. semgrep)
        line_end: int = int(raw.metadata.get("line_end", raw.line))

        return NormalizedFinding(
            id=finding_id,
            tool=raw.tool,
            rule_id=raw.rule_id,
            cwe=cwe,
            owasp=owasp,
            severity=severity,
            confidence=confidence,
            file=raw.file,
            line_start=raw.line,
            line_end=line_end,
            code_snippet=raw.code_snippet,
            message=raw.message,
        )

    def normalize_all(self, raw_findings: Sequence[_RawFindingLike]) -> list[NormalizedFinding]:
        """Convert a list of RawFinding objects to NormalizedFinding objects.

        Uses Sequence (covariant) rather than list (invariant) so callers can
        pass ``list[RawFinding]`` without an explicit cast.

        Silently skips individual findings that fail normalization to avoid
        one bad result crashing the entire pipeline.

        Args:
            raw_findings: Sequence of objects satisfying _RawFindingLike Protocol.

        Returns:
            List of successfully normalized NormalizedFinding objects.
        """
        normalized: list[NormalizedFinding] = []
        for raw in raw_findings:
            try:
                normalized.append(self.normalize(raw))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping finding that failed normalization: %s", exc)
        return normalized
