"""semgrep.py — Semgrep static analysis runner for the Velonus scanner pipeline.

Semgrep is a fast, pattern-based static analysis tool that matches code against
human-readable YAML rules. This module uses the ``p/python`` ruleset, which
covers OWASP Top 10 vulnerabilities and common Python security anti-patterns.

PIPELINE ORDER: SemgrepRunner runs third — after SecretsDetector (priority 0)
and BanditRunner (priority 1), before PipAuditRunner (priority 3).
See PIPELINE_PRIORITY = 2.

Subprocess invocation::

    semgrep scan --config p/python --json --quiet --metrics=off <target>

    --config p/python  Python security ruleset (downloaded + cached on first run)
    --json             Machine-readable JSON output (required for parsing)
    --quiet            Suppress progress and informational output to stderr
    --metrics=off      Disable anonymous usage telemetry

Exit code behaviour (semgrep spec):
    0  — no findings detected
    1  — findings detected (NOT an error — normal operation, output is valid JSON)
    2+ — real error (bad arguments, semgrep internal crash)

Semgrep is expected to be installed in the same virtual environment as Shield.
If not found on PATH, a warning is logged and [] is returned so the pipeline
continues with the remaining detectors (pip-audit).

CWE and OWASP data comes directly from Semgrep rule metadata — no static map
required. Both are extracted and normalised from the ``extra.metadata`` block
of each result. Semgrep carries these verbatim from the rule YAML::

    # In a Semgrep rule YAML:
    metadata:
      cwe:
        - "CWE-89: Improper Neutralisation of Special Elements in SQL Commands"
      owasp:
        - "A03:2021 - Injection"

We extract just the canonical identifiers: ["CWE-89"] and ["A03:2021"].
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

# RawFinding is the canonical pre-normalisation shape shared by all detectors.
# Phase 1 task: move RawFinding to packages/normalizer/models.py so detectors
# don't need to import from each other. For now, import from secrets (same pkg).
from scanner.detectors.secrets import RawFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline metadata
# ---------------------------------------------------------------------------

# PIPELINE ORDER: Semgrep runs after BanditRunner (priority 1) and before
# PipAuditRunner (priority 3). Lower number = earlier execution.
PIPELINE_PRIORITY: int = 2

# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

# Maps Semgrep severity strings → our canonical severity strings.
# Semgrep rulesets emit ERROR, WARNING, and INFO only.
# CRITICAL is reserved for AI-scored exploitability (Phase 2 — not here).
_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # Some community rulesets use lowercase severity values
    "error": "HIGH",
    "warning": "MEDIUM",
    "info": "LOW",
}

# Regex to extract the canonical CWE identifier from a verbose description.
# Semgrep rule metadata often contains the full text, e.g.:
#   "CWE-78: Improper Neutralization of Special Elements..."
# We capture just: "CWE-78"
_CWE_EXTRACT_RE: re.Pattern[str] = re.compile(r"(CWE-\d+)", re.IGNORECASE)

# Regex to extract the OWASP category code from a full description string.
# Semgrep rule metadata often contains, e.g.:
#   "A03:2021 - Injection"
# We capture just: "A03:2021"
_OWASP_EXTRACT_RE: re.Pattern[str] = re.compile(r"(A\d{2}:\d{4})")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class SemgrepRunner:
    """Semgrep static analysis runner.

    Wraps the ``semgrep`` CLI as a subprocess, parses JSON output, and returns
    findings in the canonical RawFinding shape.

    Uses the ``p/python`` ruleset which covers common Python security issues
    including injection flaws, insecure deserialization, XXE, OWASP Top 10,
    and Python-specific anti-patterns (e.g. ``eval``, ``pickle``, weak hashes).

    PIPELINE ORDER: Always runs after SecretsDetector (PIPELINE_PRIORITY=0)
    and BanditRunner (PIPELINE_PRIORITY=1), before PipAuditRunner (PIPELINE_PRIORITY=3).
    See PIPELINE_PRIORITY = 2.

    Usage::

        runner = SemgrepRunner()
        findings = runner.scan(Path("./my-project"))
        # returns list[RawFinding] — empty if semgrep not installed or no issues
    """

    # Semgrep ruleset to use. p/python is the official Python security registry.
    # This is configurable here for unit testing and future Phase 2 config support.
    _RULESET: str = "p/python"

    def scan(self, target: Path) -> list[RawFinding]:
        """Run semgrep on target and return findings as RawFinding instances.

        Invokes ``semgrep scan --config p/python --json --quiet --metrics=off <target>``.

        Semgrep exits with code 1 when findings are present. This is NOT treated
        as an error — the JSON output is still fully valid and parsed normally.
        Exit code 2+ indicates a real error (bad arguments, semgrep crash).

        Args:
            target: Resolved absolute path (file or directory) to scan.

        Returns:
            List of RawFinding. Empty list if semgrep is not installed or there
            are no findings.
        """
        if not self._semgrep_available():
            logger.warning(
                "semgrep not found on PATH — skipping Semgrep analysis. "
                "Install with: pip install semgrep"
            )
            return []

        return self._run_semgrep(target)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _semgrep_available(self) -> bool:
        """Check whether semgrep is installed and accessible on PATH.

        Uses ``semgrep --version`` as a lightweight probe. The output is
        discarded; we only care about whether the binary exists.

        Returns:
            True if semgrep is found on PATH, False otherwise.
        """
        try:
            subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return True
        except FileNotFoundError:
            return False

    def _run_semgrep(self, target: Path) -> list[RawFinding]:
        """Execute the semgrep subprocess and parse its JSON output.

        Args:
            target: Resolved absolute path to scan.

        Returns:
            Parsed list of RawFinding. Returns [] on subprocess or JSON error.
        """
        cmd: list[str] = [
            "semgrep",
            "scan",
            "--config",
            self._RULESET,
            "--json",  # machine-readable JSON output
            "--quiet",  # suppress progress output to stderr
            "--metrics=off",  # disable anonymous telemetry reporting
            str(target),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # semgrep exits 1 on findings — handled below
                timeout=180,  # generous timeout; rule download + large repos
            )
        except subprocess.TimeoutExpired:
            logger.error("semgrep scan timed out after 180 seconds on: %s", target)
            return []
        except OSError as exc:
            logger.error("semgrep subprocess failed to start: %s", exc)
            return []

        # Exit code 2+ = real error (bad arguments, semgrep internal crash).
        if result.returncode >= 2:
            logger.error(
                "semgrep exited with error code %d. stderr: %s",
                result.returncode,
                result.stderr[:500],
            )
            return []

        # Exit code 0 = clean scan, exit code 1 = findings — both produce JSON.
        if not result.stdout.strip():
            logger.debug("semgrep returned no output for target: %s", target)
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, json_output: str) -> list[RawFinding]:
        """Parse semgrep's JSON stdout into a list of RawFinding.

        Semgrep JSON structure (abbreviated)::

            {
              "results": [
                {
                  "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                  "path": "/abs/path/to/file.py",
                  "start": {"line": 10, "col": 1},
                  "end": {"line": 10, "col": 50},
                  "extra": {
                    "severity": "ERROR",
                    "message": "Dangerous use of subprocess...",
                    "lines": "subprocess.call(cmd, shell=True)",
                    "metadata": {
                      "cwe": ["CWE-78: Improper Neutralization..."],
                      "owasp": ["A03:2021 - Injection"],
                      "confidence": "HIGH"
                    }
                  }
                }
              ],
              "errors": []
            }

        Args:
            json_output: Raw JSON string from semgrep's stdout.

        Returns:
            List of RawFinding. Silently skips individual malformed entries
            to avoid one bad result blocking the rest of the scan.
        """
        try:
            data: dict[str, Any] = json.loads(json_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse semgrep JSON output: %s", exc)
            return []

        results: list[dict[str, Any]] = data.get("results", [])
        findings: list[RawFinding] = []

        for entry in results:
            finding = self._parse_entry(entry)
            if finding is not None:
                findings.append(finding)

        logger.debug("semgrep: parsed %d findings from %d results", len(findings), len(results))
        return findings

    def _parse_entry(self, entry: dict[str, Any]) -> RawFinding | None:
        """Convert a single semgrep result dict into a RawFinding.

        Required fields: ``check_id``, ``path``, ``start.line``.
        Missing or malformed required fields cause this entry to be skipped
        with a warning (rather than crashing the whole scan).

        CWE and OWASP come from ``extra.metadata`` — extracted via regex so we
        get clean identifiers regardless of how verbose the rule author was.

        Args:
            entry: One element from semgrep's ``results`` array.

        Returns:
            RawFinding on success, or None if required fields are missing.
        """
        try:
            check_id: str = str(entry["check_id"])
            path: str = str(entry["path"])
            start_line: int = int(entry["start"]["line"])
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "Skipping malformed semgrep result entry (missing required field): %s", exc
            )
            return None

        extra: dict[str, Any] = entry.get("extra", {})
        metadata: dict[str, Any] = extra.get("metadata", {})

        # Severity: semgrep uses ERROR / WARNING / INFO — map to our canonical set
        raw_severity: str = str(extra.get("severity", "INFO"))
        severity: str = _SEVERITY_MAP.get(raw_severity, "LOW")

        message: str = str(extra.get("message", "")).strip()
        # ``lines`` is the actual source code line(s) that matched the rule
        lines: str = str(extra.get("lines", "")).strip()
        end_line: int = int(entry.get("end", {}).get("line", start_line))

        # CWE and OWASP extracted from rule metadata (present in well-maintained rules)
        cwe_list: list[str] = _extract_cwe(metadata.get("cwe", []))
        owasp_list: list[str] = _extract_owasp(metadata.get("owasp", []))

        # Confidence from rule metadata; default MEDIUM if absent or unrecognised
        raw_confidence: str = str(metadata.get("confidence", "MEDIUM")).upper()
        confidence: str = (
            raw_confidence if raw_confidence in ("HIGH", "MEDIUM", "LOW") else "MEDIUM"
        )

        # Use the last segment of the dotted check_id as a human-readable label
        # e.g. "python.lang.security.audit.exec-used" → "exec-used"
        rule_short: str = check_id.split(".")[-1] if "." in check_id else check_id

        # Compose a human-readable message that includes the short rule name
        composed_message: str = f"[{rule_short}] {message}" if message else f"[{rule_short}]"

        return RawFinding(
            tool="semgrep",
            rule_id=check_id,
            file=path,
            line=start_line,
            severity=severity,
            message=composed_message,
            code_snippet=lines,
            metadata={
                "confidence": confidence,
                "cwe": cwe_list,
                "owasp": owasp_list,
                # Preserve end line for SARIF region reporting
                "line_end": end_line,
                # Record which ruleset produced this finding for provenance
                "ruleset": self._RULESET,
            },
        )


# ---------------------------------------------------------------------------
# Metadata extraction helpers
# ---------------------------------------------------------------------------


def _extract_cwe(raw: Any) -> list[str]:
    """Extract canonical CWE identifiers from semgrep rule metadata.

    Semgrep metadata may contain CWE as:
      - A list of verbose strings: ``["CWE-78: Improper Neutralization..."]``
      - A single string: ``"CWE-78"``
      - An empty list or None

    Args:
        raw: The value of ``extra.metadata.cwe`` from semgrep JSON.

    Returns:
        Deduplicated list of clean CWE identifiers, e.g. ``["CWE-78"]``.
    """
    if not raw:
        return []

    items: list[Any] = raw if isinstance(raw, list) else [raw]
    seen: set[str] = set()
    result: list[str] = []

    for item in items:
        for match in _CWE_EXTRACT_RE.findall(str(item)):
            # Normalise to uppercase, e.g. "cwe-78" → "CWE-78"
            normalised = match.upper()
            if normalised not in seen:
                seen.add(normalised)
                result.append(normalised)

    return result


def _extract_owasp(raw: Any) -> list[str]:
    """Extract canonical OWASP category codes from semgrep rule metadata.

    Semgrep metadata may contain OWASP as:
      - A list of verbose strings: ``["A03:2021 - Injection"]``
      - A single string: ``"A03:2021"``
      - An empty list or None

    Args:
        raw: The value of ``extra.metadata.owasp`` from semgrep JSON.

    Returns:
        Deduplicated list of clean OWASP codes, e.g. ``["A03:2021"]``.
    """
    if not raw:
        return []

    items: list[Any] = raw if isinstance(raw, list) else [raw]
    seen: set[str] = set()
    result: list[str] = []

    for item in items:
        for match in _OWASP_EXTRACT_RE.findall(str(item)):
            if match not in seen:
                seen.add(match)
                result.append(match)

    return result
