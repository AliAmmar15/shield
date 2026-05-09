"""safety.py — Safety dependency vulnerability runner for the Shield AI scanner pipeline.

Safety checks Python packages against a curated database of known security
vulnerabilities. It is maintained by pyup.io and covers the same PyPI ecosystem
as pip-audit, but draws from a different advisory database (Safety DB / OSV).

Running both pip-audit (PIPELINE_PRIORITY=3) and Safety (PIPELINE_PRIORITY=4)
gives broader vulnerability coverage — each tool may surface advisories the
other misses. The deduplication layer in Phase 1 handles overlapping CVEs.

This module wraps the ``safety check`` CLI as a subprocess, parses its JSON
output (both v1 and v2 formats), and returns findings in the canonical
RawFinding shape shared across all detectors.

PIPELINE ORDER: SafetyRunner runs last in the pipeline — after SecretsDetector
(priority 0), BanditRunner (priority 1), SemgrepRunner (priority 2), and
PipAuditRunner (priority 3). See PIPELINE_PRIORITY = 4.

Subprocess invocation (requirements file)::

    safety check --json -r <requirements_file>

    --json               Machine-readable JSON output (required for parsing)
    -r <requirements>    Audit a specific requirements file

Subprocess invocation (environment fallback — no requirements file found)::

    safety check --json

    Audits all packages currently installed in the active Python environment.

Auto-detection logic (in order of preference):
  1. requirements.txt in target directory
  2. requirements-dev.txt in target directory
  3. requirements/base.txt in target directory
  4. requirements/prod.txt in target directory
  5. requirements/production.txt in target directory
  6. Fallback: scan currently installed environment (no ``-r`` flag)

Exit code behaviour (safety spec):
    0   — no vulnerabilities found (output may be empty or valid JSON)
    1   — vulnerabilities found in older safety versions (< 2.0)
    64  — vulnerabilities found in safety >= 2.0 (NOT an error — valid JSON)
    other — real error (bad arguments, network failure, DB access issue)

Safety JSON output formats:

  Format A — safety >= 2.0 (dict wrapper)::

      {
        "vulnerabilities": [
          {
            "vulnerability_id": "51457",
            "package_name": "requests",
            "analyzed_version": "2.25.1",
            "advisory": "Requests 2.x...",
            "CVE": "CVE-2023-32681",
            "fixed_versions": ["2.31.0"],
            "severity": {
              "cvss_v3": {
                "base_score": 6.1,
                "base_severity": "MEDIUM"
              }
            }
          }
        ],
        "meta": { "safety_version": "2.4.0" }
      }

  Format B — safety < 2.0 (list of lists)::

      [
        ["requests", "<2.31.0", "2.25.1", "Advisory text...", "44715"]
      ]

      Fields: [package_name, affected_spec, installed_version, advisory, vuln_id]
      No CVSS data available in this format — defaults to MEDIUM severity.

Severity mapping (CVSS v3 base score when available):
    CVSS >= 9.0   → CRITICAL
    CVSS >= 7.0   → HIGH
    CVSS >= 4.0   → MEDIUM
    CVSS >= 0.1   → LOW
    No CVSS data  → MEDIUM (safe default — known vulnerability, unknown severity)

CWE mapping: All safety findings map to CWE-1035 (Using Components with Known
Vulnerabilities). OWASP category: A06:2021 (Vulnerable and Outdated Components).
These match pip-audit for consistency; the deduplication layer handles overlap.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

# RawFinding is the canonical pre-normalization shape shared by all detectors.
# Phase 1 task: move RawFinding to packages/normalizer/models.py so detectors
# don't need to import from each other. For now, import from secrets (same pkg).
from scanner.detectors.secrets import RawFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline metadata
# ---------------------------------------------------------------------------

# PIPELINE ORDER: SafetyRunner runs last in the pipeline.
# Lower number = earlier execution. 4 = after secrets(0), bandit(1),
# semgrep(2), pip-audit(3).
PIPELINE_PRIORITY: int = 4

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CWE assigned to all safety findings.
# CWE-1035: Using Components with Known Vulnerabilities
_CWE: list[str] = ["CWE-1035"]

# OWASP Top 10 2021 category for all safety findings.
# A06:2021 — Vulnerable and Outdated Components
_OWASP: list[str] = ["A06:2021"]

# Requirements file names to probe, in priority order.
# Safety is faster with an explicit requirements file vs. full env scan.
_REQUIREMENTS_CANDIDATES: list[str] = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "requirements/production.txt",
]

# CVSS v3 score thresholds for severity mapping.
_CVSS_CRITICAL: float = 9.0
_CVSS_HIGH: float = 7.0
_CVSS_MEDIUM: float = 4.0

# Exit codes that indicate vulnerabilities were found — these are NOT errors.
# safety < 2.0 uses exit code 1; safety >= 2.0 uses exit code 64.
_VULN_EXIT_CODES: frozenset[int] = frozenset({1, 64})


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class SafetyRunner:
    """Safety dependency vulnerability runner.

    Wraps the ``safety check`` CLI as a subprocess, parses JSON output (both
    v1 list-of-lists and v2 dict formats), and returns findings in the
    canonical RawFinding shape.

    Scans requirements files found in the target directory, or falls back to
    auditing the currently installed environment when no requirements files
    are present.

    PIPELINE ORDER: Always runs last in the pipeline (PIPELINE_PRIORITY=4),
    after SecretsDetector, BanditRunner, SemgrepRunner, and PipAuditRunner.

    Usage::

        runner = SafetyRunner()
        findings = runner.scan(Path("./my-project"))
        # returns list[RawFinding] — empty if safety not installed or no CVEs
    """

    def scan(self, target: Path) -> list[RawFinding]:
        """Run safety check on target and return findings as RawFinding instances.

        Probes for requirements files in the target directory. If found, passes
        them to safety via ``-r``. Falls back to scanning the installed
        environment when no requirements files are detected.

        Args:
            target: Resolved absolute path (directory) to scan.

        Returns:
            List of RawFinding. Empty list if safety is not installed or there
            are no known vulnerabilities.
        """
        if not self._safety_available():
            logger.warning(
                "safety not found on PATH — skipping Safety analysis. "
                "Install with: uv add safety --dev"
            )
            return []

        req_file = self._find_requirements(target)
        return self._run_safety(target, req_file)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safety_available(self) -> bool:
        """Check whether safety is installed and accessible on PATH.

        Uses ``safety --version`` as a lightweight probe. The output is
        discarded; we only care about whether the binary exists.

        Returns:
            True if safety is found on PATH, False otherwise.
        """
        try:
            subprocess.run(
                ["safety", "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return True
        except FileNotFoundError:
            return False

    def _find_requirements(self, target: Path) -> Path | None:
        """Probe target directory for a requirements file to pass to safety.

        Checks _REQUIREMENTS_CANDIDATES in order and returns the first match.
        Returns None if none are found (triggers environment-wide scan fallback).

        Args:
            target: Directory to search.

        Returns:
            Path to requirements file, or None if not found.
        """
        for candidate in _REQUIREMENTS_CANDIDATES:
            req_path = target / candidate
            if req_path.is_file():
                logger.debug("safety: using requirements file: %s", req_path)
                return req_path

        logger.debug(
            "safety: no requirements file found in %s — will scan installed environment", target
        )
        return None

    def _run_safety(self, target: Path, req_file: Path | None) -> list[RawFinding]:
        """Execute the safety check subprocess and parse its JSON output.

        Args:
            target: Resolved absolute path to the scan root (used for file
                    attribution in RawFinding.file when no specific file is known).
            req_file: Path to a requirements file, or None to scan the
                      installed environment without ``-r``.

        Returns:
            Parsed list of RawFinding. Returns [] on subprocess or JSON error.
        """
        cmd: list[str] = ["safety", "check", "--json"]

        if req_file is not None:
            cmd.extend(["-r", str(req_file)])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # exit codes 1 and 64 indicate vulns — handled below
                timeout=120,  # network calls to Safety DB can be slow
                cwd=str(target),  # run in target directory for context
            )
        except subprocess.TimeoutExpired:
            logger.error("safety scan timed out after 120 seconds")
            return []
        except OSError as exc:
            logger.error("safety subprocess failed to start: %s", exc)
            return []

        # Exit code 0 = no vulnerabilities.
        # Exit code 1 (safety < 2.0) or 64 (safety >= 2.0) = vulnerabilities found.
        # Both produce valid JSON output. Any other exit code is a real error.
        if result.returncode not in {0} | _VULN_EXIT_CODES:
            logger.error(
                "safety exited with error code %d. stderr: %s",
                result.returncode,
                result.stderr[:500],
            )
            return []

        if not result.stdout.strip():
            logger.debug("safety returned no output")
            return []

        # Determine the attribution path for RawFinding.file.
        attribution_path = str(req_file) if req_file is not None else str(target)
        return self._parse_output(result.stdout, attribution_path)

    def _parse_output(self, json_output: str, attribution_path: str) -> list[RawFinding]:
        """Parse safety's JSON stdout into a list of RawFinding.

        Handles two output formats automatically:

        - **Format A** (safety >= 2.0): dict with a ``"vulnerabilities"`` key
          containing a list of vulnerability dicts.
        - **Format B** (safety < 2.0): list of 5-element lists:
          ``[package_name, affected_spec, installed_version, advisory, vuln_id]``

        Args:
            json_output: Raw JSON string from safety's stdout.
            attribution_path: Path to attribute findings to (requirements file
                              or target directory).

        Returns:
            List of RawFinding. One RawFinding per vulnerability.
            Returns [] on JSON decode failure or unrecognised format.
        """
        try:
            data: Any = json.loads(json_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse safety JSON output: %s", exc)
            return []

        # Format A: safety >= 2.0 outputs a dict with a "vulnerabilities" key.
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
            if not isinstance(vulns, list):
                logger.error("safety v2 JSON: 'vulnerabilities' is not a list")
                return []
            findings: list[RawFinding] = []
            for entry in vulns:
                finding = self._parse_entry_v2(entry, attribution_path)
                if finding is not None:
                    findings.append(finding)
            logger.debug("safety (v2 format): parsed %d findings", len(findings))
            return findings

        # Format B: safety < 2.0 outputs a list of 5-element lists.
        if isinstance(data, list):
            findings = []
            for entry in data:
                finding = self._parse_entry_v1(entry, attribution_path)
                if finding is not None:
                    findings.append(finding)
            logger.debug("safety (v1 format): parsed %d findings", len(findings))
            return findings

        logger.error(
            "safety JSON output is neither a dict nor a list: %s", type(data).__name__
        )
        return []

    def _parse_entry_v2(
        self, entry: Any, attribution_path: str
    ) -> RawFinding | None:
        """Convert a single safety v2 vulnerability dict into a RawFinding.

        Expected structure::

            {
              "vulnerability_id": "51457",
              "package_name": "requests",
              "analyzed_version": "2.25.1",
              "advisory": "Requests 2.x before 2.31.0...",
              "CVE": "CVE-2023-32681",
              "fixed_versions": ["2.31.0"],
              "severity": {
                "cvss_v3": {"base_score": 6.1, "base_severity": "MEDIUM"}
              }
            }

        Required fields: ``vulnerability_id``, ``package_name``,
        ``analyzed_version``. Missing required fields cause the entry to be
        skipped with a warning.

        Args:
            entry: One element from the ``"vulnerabilities"`` list.
            attribution_path: Path to attribute the finding to.

        Returns:
            RawFinding on success, or None if required fields are missing.
        """
        if not isinstance(entry, dict):
            logger.warning("safety v2: skipping non-dict vulnerability entry")
            return None

        try:
            vuln_id: str = str(entry["vulnerability_id"])
            package_name: str = str(entry["package_name"])
            installed_version: str = str(entry["analyzed_version"])
        except (KeyError, TypeError) as exc:
            logger.warning("safety v2: skipping malformed entry: %s", exc)
            return None

        advisory: str = str(entry.get("advisory", "")).strip()
        cve: str = str(entry.get("CVE", "")).strip()
        fix_versions: list[str] = [str(v) for v in entry.get("fixed_versions", [])]

        # Extract CVSS v3 base score from the nested severity dict.
        cvss_score: float | None = _extract_cvss_v2(entry.get("severity"))
        severity: str = _cvss_to_severity(cvss_score)

        # Build a human-readable message. Prefer the CVE alias for recognisability.
        display_id = cve if cve and cve != "None" else vuln_id
        if fix_versions:
            fix_hint = f" Fix: upgrade to {', '.join(fix_versions)}."
        else:
            fix_hint = " No fix version available yet."
        message = (
            f"[{display_id}] {package_name}=={installed_version} "
            f"has a known vulnerability.{fix_hint}"
        )
        if advisory:
            truncated = advisory[:200] + "..." if len(advisory) > 200 else advisory
            message = f"{message} {truncated}"

        return RawFinding(
            tool="safety",
            rule_id=vuln_id,
            file=attribution_path,
            line=0,  # No line number — dependency vulnerabilities are file-level
            severity=severity,
            message=message,
            code_snippet="",  # No code snippet — this is a dependency finding
            metadata={
                "package_name": package_name,
                "package_version": installed_version,
                "cve": cve,
                "fix_versions": fix_versions,
                "cvss_score": cvss_score,
                "cwe": _CWE,
                "owasp": _OWASP,
                # fix_available drives the UI badge in the terminal formatter
                "fix_available": bool(fix_versions),
            },
        )

    def _parse_entry_v1(
        self, entry: Any, attribution_path: str
    ) -> RawFinding | None:
        """Convert a single safety v1 list entry into a RawFinding.

        Safety v1 format: 5-element list::

            [package_name, affected_spec, installed_version, advisory, vuln_id]

        No CVSS data is available in this format. Severity defaults to MEDIUM
        (safe default — known vulnerability, unknown severity).

        Args:
            entry: One element from the safety v1 output list.
            attribution_path: Path to attribute the finding to.

        Returns:
            RawFinding on success, or None if the entry is malformed.
        """
        if not isinstance(entry, list) or len(entry) < 5:
            logger.warning(
                "safety v1: skipping malformed entry (expected list of ≥5 elements): %r",
                entry,
            )
            return None

        try:
            package_name: str = str(entry[0])
            # entry[1] = affected version spec (e.g. "<2.31.0,>=2.0.0")
            installed_version: str = str(entry[2])
            advisory: str = str(entry[3]).strip()
            vuln_id: str = str(entry[4])
        except (IndexError, TypeError) as exc:
            logger.warning("safety v1: skipping malformed entry: %s", exc)
            return None

        fix_hint = _extract_fix_hint_v1(str(entry[1]))
        fix_msg = f" Fix: {fix_hint}." if fix_hint else ""

        message = (
            f"[{vuln_id}] {package_name}=={installed_version} "
            f"has a known vulnerability.{fix_msg}"
        )
        if advisory:
            truncated = advisory[:200] + "..." if len(advisory) > 200 else advisory
            message = f"{message} {truncated}"

        return RawFinding(
            tool="safety",
            rule_id=vuln_id,
            file=attribution_path,
            line=0,  # No line number — dependency vulnerabilities are file-level
            severity="MEDIUM",  # v1 format has no CVSS data — default to MEDIUM
            message=message,
            code_snippet="",  # No code snippet — this is a dependency finding
            metadata={
                "package_name": package_name,
                "package_version": installed_version,
                "cve": None,
                "fix_versions": [],
                "cvss_score": None,
                "cwe": _CWE,
                "owasp": _OWASP,
                "fix_available": False,
            },
        )


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------


def _extract_cvss_v2(severity_field: Any) -> float | None:
    """Extract the CVSS v3 base score from a safety v2 severity dict.

    Safety v2 severity structure::

        {
          "cvss_v3": {
            "base_score": 7.5,
            "base_severity": "HIGH"
          }
        }

    The ``severity`` field may be None, a dict with ``cvss_v3``, or malformed.

    Args:
        severity_field: The ``severity`` value from a safety v2 vulnerability
                        entry. May be None, a dict, or any other type.

    Returns:
        CVSS v3 base score as a float, or None if not available or malformed.
    """
    if not severity_field or not isinstance(severity_field, dict):
        return None

    cvss_v3 = severity_field.get("cvss_v3")
    if not cvss_v3 or not isinstance(cvss_v3, dict):
        return None

    raw_score = cvss_v3.get("base_score")
    if raw_score is None:
        return None
    try:
        return float(raw_score)
    except (TypeError, ValueError):
        return None


def _cvss_to_severity(score: float | None) -> str:
    """Map a CVSS v3 base score to our canonical severity string.

    Thresholds follow CVSS v3.1 qualitative severity ratings:
        9.0–10.0  → CRITICAL
        7.0–8.9   → HIGH
        4.0–6.9   → MEDIUM
        0.1–3.9   → LOW
        None      → MEDIUM (unknown severity, known vulnerability — safe default)

    Args:
        score: CVSS v3 base score (0.0–10.0), or None if not available.

    Returns:
        Canonical severity string.
    """
    if score is None:
        # Known vulnerability with no CVSS data — default to MEDIUM so it
        # gets triaged but doesn't drown out HIGH/CRITICAL findings.
        return "MEDIUM"
    if score >= _CVSS_CRITICAL:
        return "CRITICAL"
    if score >= _CVSS_HIGH:
        return "HIGH"
    if score >= _CVSS_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _extract_fix_hint_v1(affected_spec: str) -> str:
    """Extract a human-readable fix hint from a safety v1 affected version spec.

    Safety v1 provides the affected version spec as a pip-style constraint
    string (e.g. ``"!=5.1.0,<8.3.1"``). We extract the lower bound of a safe
    version from the spec when possible.

    This is best-effort — complex specs are returned as-is for clarity.

    Args:
        affected_spec: The affected version spec string from safety v1 output.

    Returns:
        A short hint string, or empty string if the spec is empty or trivially
        informative.
    """
    spec = affected_spec.strip()
    if not spec:
        return ""
    # Return the raw spec as the fix guidance — developers understand pip specs.
    return f"install a version outside {spec}"
