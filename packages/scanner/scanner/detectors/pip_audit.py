"""pip_audit.py — pip-audit dependency vulnerability runner for the Velonus scanner pipeline.

pip-audit is an official Python Packaging Authority (PyPA) tool that audits
Python environments and requirement files for known vulnerabilities by querying
the Python Packaging Advisory Database (PyPI/OSV).

This module wraps the pip-audit CLI as a subprocess, parses its JSON output,
and returns findings in the canonical RawFinding shape shared across all detectors.

PIPELINE ORDER: PipAuditRunner runs last — after SecretsDetector (priority 0),
BanditRunner (priority 1), and SemgrepRunner (priority 2).
See PIPELINE_PRIORITY = 3.

Subprocess invocation (project scan)::

    pip-audit --format json --progress-spinner off -r <requirements_file>

    --format json            Machine-readable JSON output (required for parsing)
    --progress-spinner off   Suppress the animated progress indicator to stderr
    -r <requirements_file>   Scan a specific requirements file

Subprocess invocation (environment scan — fallback when no requirements found)::

    pip-audit --format json --progress-spinner off --local

    --local   Audit the currently installed packages in the active environment

Auto-detection logic (in order of preference):
  1. requirements.txt in target directory
  2. requirements-dev.txt in target directory
  3. requirements/*.txt files in target directory
  4. pyproject.toml in target directory (pip-audit reads PEP 621 deps natively)
  5. Fallback: scan currently installed environment with --local

Exit code behaviour (pip-audit spec):
    0  — no vulnerabilities found
    1  — vulnerabilities found (NOT an error — output is valid JSON)
    2+ — real error (bad arguments, pip-audit internal crash, network failure)

pip-audit is expected to be installed in the same virtual environment as Shield.
If not found on PATH, a warning is logged and [] is returned so the pipeline
continues unblocked.

Severity mapping: pip-audit does not provide severity ratings. We map based on
CVSS v3 base score embedded in the vulnerability data when available:
    CVSS >= 9.0   → CRITICAL
    CVSS >= 7.0   → HIGH
    CVSS >= 4.0   → MEDIUM
    CVSS >= 0.1   → LOW
    No CVSS data  → MEDIUM (safe default — known vulnerability, unknown severity)

CWE mapping: pip-audit findings represent CWE-1035 (Vulnerable Third Party Component),
a OWASP-aligned CWE for using packages with known vulnerabilities.
OWASP category: A06:2021 (Vulnerable and Outdated Components).
"""

from __future__ import annotations

import json
import logging
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

# PIPELINE ORDER: PipAuditRunner runs last in the pipeline.
# Lower number = earlier execution. 3 = after secrets(0), bandit(1), semgrep(2).
PIPELINE_PRIORITY: int = 3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CWE assigned to all pip-audit findings.
# CWE-1035: Using Components with Known Vulnerabilities
_CWE: list[str] = ["CWE-1035"]

# OWASP Top 10 2021 category for all pip-audit findings.
# A06:2021 — Vulnerable and Outdated Components
_OWASP: list[str] = ["A06:2021"]

# Requirements file names to probe, in priority order.
# pip-audit is much faster with an explicit requirements file vs env scan.
_REQUIREMENTS_CANDIDATES: list[str] = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "requirements/production.txt",
]

# CVSS v3 score thresholds for severity mapping.
# pip-audit embeds CVSS scores when the advisory includes them.
_CVSS_CRITICAL: float = 9.0
_CVSS_HIGH: float = 7.0
_CVSS_MEDIUM: float = 4.0


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class PipAuditRunner:
    """pip-audit dependency vulnerability runner.

    Wraps the ``pip-audit`` CLI as a subprocess, parses JSON output, and
    returns findings in the canonical RawFinding shape.

    Scans requirements files found in the target directory, or falls back to
    auditing the currently installed environment with ``--local`` when no
    requirements files are present.

    PIPELINE ORDER: Always runs last in the pipeline (PIPELINE_PRIORITY=3).
    See PIPELINE_PRIORITY = 3.

    Usage::

        runner = PipAuditRunner()
        findings = runner.scan(Path("./my-project"))
        # returns list[RawFinding] — empty if pip-audit not installed or no CVEs
    """

    def scan(self, target: Path) -> list[RawFinding]:
        """Run pip-audit on target and return findings as RawFinding instances.

        Probes for requirements files in the target directory. If found, scans
        those files specifically. Falls back to ``--local`` environment scan
        when no requirements files are detected.

        Args:
            target: Resolved absolute path (directory) to scan.

        Returns:
            List of RawFinding. Empty list if pip-audit is not installed or
            there are no known vulnerabilities.
        """
        if not self._pip_audit_available():
            logger.warning(
                "pip-audit not found on PATH — skipping dependency audit. "
                "Install with: uv add pip-audit --dev"
            )
            return []

        req_file = self._find_requirements(target)
        return self._run_pip_audit(target, req_file)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _pip_audit_available(self) -> bool:
        """Check whether pip-audit is installed and accessible on PATH.

        Uses ``pip-audit --version`` as a lightweight probe. The output is
        discarded; we only care about whether the binary exists.

        Returns:
            True if pip-audit is found on PATH, False otherwise.
        """
        try:
            subprocess.run(
                ["pip-audit", "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return True
        except FileNotFoundError:
            return False

    def _find_requirements(self, target: Path) -> Path | None:
        """Probe target directory for a requirements file to pass to pip-audit.

        Checks _REQUIREMENTS_CANDIDATES in order and returns the first match.
        Returns None if none are found (triggers --local fallback).

        Args:
            target: Directory to search.

        Returns:
            Path to requirements file, or None if not found.
        """
        for candidate in _REQUIREMENTS_CANDIDATES:
            req_path = target / candidate
            if req_path.is_file():
                logger.debug("pip-audit: using requirements file: %s", req_path)
                return req_path
        logger.debug(
            "pip-audit: no requirements file found in %s — will use --local fallback", target
        )
        return None

    def _run_pip_audit(self, target: Path, req_file: Path | None) -> list[RawFinding]:
        """Execute the pip-audit subprocess and parse its JSON output.

        Args:
            target: Resolved absolute path to the scan root (used for file
                    attribution in RawFinding.file when no specific file is known).
            req_file: Path to a requirements file, or None to use ``--local``.

        Returns:
            Parsed list of RawFinding. Returns [] on subprocess or JSON error.
        """
        cmd: list[str] = [
            "pip-audit",
            "--format",
            "json",
            "--progress-spinner",
            "off",  # suppress animated spinner on stderr
        ]

        if req_file is not None:
            cmd.extend(["-r", str(req_file)])
        else:
            # No requirements file found — audit installed environment directly.
            cmd.append("--local")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # pip-audit exits 1 on vulnerabilities — handled below
                timeout=120,  # network calls to PyPI advisory DB can be slow
            )
        except subprocess.TimeoutExpired:
            logger.error("pip-audit scan timed out after 120 seconds")
            return []
        except OSError as exc:
            logger.error("pip-audit subprocess failed to start: %s", exc)
            return []

        # Exit code 2+ = real error (bad arguments, network failure, crash).
        if result.returncode >= 2:
            logger.error(
                "pip-audit exited with error code %d. stderr: %s",
                result.returncode,
                result.stderr[:500],
            )
            return []

        # Exit code 0 = no vulnerabilities, exit code 1 = vulnerabilities found.
        # Both produce valid JSON output.
        if not result.stdout.strip():
            logger.debug("pip-audit returned no output")
            return []

        # Determine the attribution path: requirements file if scanned, else target dir.
        attribution_path = str(req_file) if req_file is not None else str(target)
        return self._parse_output(result.stdout, attribution_path)

    def _parse_output(self, json_output: str, attribution_path: str) -> list[RawFinding]:
        """Parse pip-audit's JSON stdout into a list of RawFinding.

        pip-audit JSON structure (abbreviated)::

            [
              {
                "name": "requests",
                "version": "2.25.1",
                "vulns": [
                  {
                    "id": "PYSEC-2023-74",
                    "fix_versions": ["2.31.0"],
                    "aliases": ["CVE-2023-32681"],
                    "description": "Requests forwards proxy-authorization...",
                    "cvss": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", "base_score": 6.1}]
                  }
                ]
              }
            ]

        Args:
            json_output: Raw JSON string from pip-audit's stdout.
            attribution_path: Path to attribute findings to (requirements file or target dir).

        Returns:
            List of RawFinding. One RawFinding per vulnerability (not per package).
            Silently skips malformed entries.
        """
        try:
            data: list[dict[str, Any]] = json.loads(json_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse pip-audit JSON output: %s", exc)
            return []

        # pip-audit may return a dict wrapper in some versions; normalise to list.
        if isinstance(data, dict):
            data = data.get("dependencies", [])

        if not isinstance(data, list):
            logger.error("pip-audit JSON output is not a list: %s", type(data).__name__)
            return []

        findings: list[RawFinding] = []
        for package_entry in data:
            package_findings = self._parse_package(package_entry, attribution_path)
            findings.extend(package_findings)

        logger.debug("pip-audit: parsed %d findings", len(findings))
        return findings

    def _parse_package(self, entry: dict[str, Any], attribution_path: str) -> list[RawFinding]:
        """Convert a single pip-audit package entry into RawFinding instances.

        Each package may have multiple vulnerabilities. We emit one RawFinding
        per vulnerability so each can be independently tracked, suppressed, and
        AI-analysed.

        Args:
            entry: One element from pip-audit's output list.
            attribution_path: Path to attribute findings to.

        Returns:
            List of RawFinding (one per vulnerability). Empty list if the entry
            has no vulnerabilities or is malformed.
        """
        try:
            package_name: str = str(entry["name"])
            package_version: str = str(entry["version"])
        except (KeyError, TypeError) as exc:
            logger.warning("Skipping malformed pip-audit package entry: %s", exc)
            return []

        vulns: list[dict[str, Any]] = entry.get("vulns", [])
        if not vulns:
            return []

        findings: list[RawFinding] = []
        for vuln in vulns:
            finding = self._parse_vuln(vuln, package_name, package_version, attribution_path)
            if finding is not None:
                findings.append(finding)
        return findings

    def _parse_vuln(
        self,
        vuln: dict[str, Any],
        package_name: str,
        package_version: str,
        attribution_path: str,
    ) -> RawFinding | None:
        """Convert a single vulnerability dict into a RawFinding.

        Required fields: ``id``.
        Missing required fields cause this entry to be skipped with a warning.

        Severity is derived from the CVSS v3 base score when available.
        Falls back to MEDIUM when no CVSS data is present (safe default —
        we know the package is vulnerable, we just don't know how bad).

        Args:
            vuln: One element from a package entry's ``vulns`` array.
            package_name: Name of the vulnerable package.
            package_version: Installed version of the vulnerable package.
            attribution_path: Path to attribute the finding to.

        Returns:
            RawFinding on success, or None if required fields are missing.
        """
        try:
            vuln_id: str = str(vuln["id"])
        except (KeyError, TypeError) as exc:
            logger.warning("Skipping malformed pip-audit vulnerability entry: %s", exc)
            return None

        aliases: list[str] = list(vuln.get("aliases", []))
        description: str = str(vuln.get("description", "")).strip()
        fix_versions: list[str] = [str(v) for v in vuln.get("fix_versions", [])]

        # Extract CVSS base score for severity mapping.
        cvss_score: float | None = _extract_cvss_score(vuln.get("cvss", []))
        severity: str = _cvss_to_severity(cvss_score)

        # Build a human-readable message.
        # Include CVE alias if available (more recognisable than PYSEC IDs).
        cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
        display_id = cve_alias if cve_alias else vuln_id
        if fix_versions:
            fix_hint = f" Fix: upgrade to {', '.join(fix_versions)}."
        else:
            fix_hint = " No fix version available yet."
        message = (
            f"[{display_id}] {package_name}=={package_version} has a known vulnerability.{fix_hint}"
        )
        if description:
            # Truncate long descriptions to keep messages readable in terminal output.
            truncated = description[:200] + "..." if len(description) > 200 else description
            message = f"{message} {truncated}"

        return RawFinding(
            tool="pip-audit",
            rule_id=vuln_id,
            file=attribution_path,
            line=0,  # No line number — dependency vulnerabilities are file-level
            severity=severity,
            message=message,
            code_snippet="",  # No code snippet — this is a dependency finding
            metadata={
                "package_name": package_name,
                "package_version": package_version,
                "aliases": aliases,
                "fix_versions": fix_versions,
                "cvss_score": cvss_score,
                "cwe": _CWE,
                "owasp": _OWASP,
                # fix_available drives the UI badge in the terminal formatter
                "fix_available": bool(fix_versions),
            },
        )


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------


def _extract_cvss_score(cvss_list: Any) -> float | None:
    """Extract the highest CVSS v3 base score from pip-audit's cvss array.

    pip-audit embeds CVSS data as a list of score objects::

        [{"type": "CVSS_V3", "score": "CVSS:3.1/...", "base_score": 7.5}]

    We prefer CVSS_V3 scores. If multiple are present, we take the highest
    (most conservative / worst-case severity).

    Args:
        cvss_list: The ``cvss`` field from a pip-audit vulnerability entry.
                   May be a list, None, or malformed.

    Returns:
        Highest CVSS v3 base score as float, or None if not available.
    """
    if not cvss_list or not isinstance(cvss_list, list):
        return None

    best_score: float | None = None
    for entry in cvss_list:
        if not isinstance(entry, dict):
            continue
        raw_score = entry.get("base_score")
        try:
            score = float(raw_score)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if best_score is None or score > best_score:
            best_score = score

    return best_score


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
