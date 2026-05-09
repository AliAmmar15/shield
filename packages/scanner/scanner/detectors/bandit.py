"""bandit.py — Bandit static analysis runner for the Shield AI scanner pipeline.

Bandit is a Python AST-based security linter maintained by PyCQA. It detects
common security issues in Python code using a plugin-based test suite.

This module wraps the bandit CLI as a subprocess, parses its JSON output, and
returns findings in the canonical RawFinding shape shared across all detectors.

PIPELINE ORDER: BanditRunner runs second — after SecretsDetector (priority 0)
and before SemgrepRunner (priority 2) and PipAuditRunner (priority 3).
See PIPELINE_PRIORITY = 1.

Subprocess invocation::

    bandit -r <target> -f json -q

    -r        recursive scan of the target directory
    -f json   machine-readable JSON output (required for parsing)
    -q        suppress progress and informational output to stderr

Exit code behaviour (bandit spec):
    0  — no findings detected
    1  — findings detected (NOT an error — normal operation, output is valid JSON)
    2+ — real error (bad arguments, bandit internal crash)

Bandit is expected to be installed in the same virtual environment as Shield.
If not found on PATH, a warning is logged and [] is returned so the pipeline
continues with the remaining detectors (semgrep, pip-audit).
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

# PIPELINE ORDER: Bandit runs after SecretScanner (priority 0) and before
# SemgrepRunner (priority 2) and PipAuditRunner (priority 3).
PIPELINE_PRIORITY: int = 1

# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------

# Maps Bandit test IDs to CWE identifiers.
# Source: https://bandit.readthedocs.io/en/latest/plugins/
# Tests not listed here fall back to bandit's own `issue_cwe` field in the JSON.
_BANDIT_CWE_MAP: dict[str, list[str]] = {
    # Injection / exec
    "B102": ["CWE-78"],  # exec_used — OS command injection via exec()
    "B307": ["CWE-78"],  # eval — dangerous use of eval()
    "B601": ["CWE-78"],  # paramiko_calls — shell=True in paramiko
    "B602": ["CWE-78"],  # subprocess_popen_with_shell_equals_true
    "B603": ["CWE-78"],  # subprocess_without_shell_equals_true
    "B604": ["CWE-78"],  # any_other_function_with_shell_equals_true
    "B605": ["CWE-78"],  # start_process_with_a_shell
    "B606": ["CWE-78"],  # start_process_with_no_shell
    "B607": ["CWE-78"],  # start_process_with_partial_path
    "B609": ["CWE-78"],  # linux_commands_wildcard_injection
    "B608": ["CWE-89"],  # hardcoded_sql_expressions — SQL injection
    "B611": ["CWE-89"],  # django_rawsql_used — raw SQL in Django ORM
    # Hard-coded credentials
    "B105": ["CWE-259"],  # hardcoded_password_string
    "B106": ["CWE-259"],  # hardcoded_password_funcarg
    "B107": ["CWE-259"],  # hardcoded_password_default
    # Cryptography
    "B303": ["CWE-327"],  # use of MD5 or SHA1 (weak hash)
    "B304": ["CWE-327"],  # use of weak/broken cipher
    "B305": ["CWE-327"],  # ECB mode cipher
    "B324": ["CWE-327"],  # hashlib with insecure hash function
    "B502": ["CWE-326"],  # ssl_with_bad_version
    "B503": ["CWE-326"],  # ssl_with_bad_defaults
    "B504": ["CWE-295"],  # ssl_with_no_version
    "B505": ["CWE-326"],  # weak_cryptographic_key (RSA < 2048 bits, etc.)
    "B311": ["CWE-338"],  # random — non-cryptographic RNG used for security
    # Deserialization
    "B301": ["CWE-502"],  # pickle — insecure deserialization
    "B302": ["CWE-502"],  # marshal — insecure deserialization
    "B506": ["CWE-20"],  # yaml_load — arbitrary code execution
    # Template injection / XSS
    "B701": ["CWE-94"],  # jinja2_autoescape_false — XSS via template injection
    "B702": ["CWE-94"],  # use_of_mako_templates — XSS
    "B703": ["CWE-79"],  # django_mark_safe — XSS
    # Network / cleartext
    "B321": ["CWE-319"],  # ftp_lib
    "B401": ["CWE-319"],  # import_telnetlib
    "B402": ["CWE-319"],  # import_ftplib
    "B501": ["CWE-295"],  # request_with_no_cert_validation
    # File / permissions
    "B103": ["CWE-732"],  # setting_mask_422 — insecure file permissions
    "B108": ["CWE-377"],  # probable_insecure_usage_of_temp_file
    "B306": ["CWE-377"],  # mktemp_q — insecure temp file creation
    # Binding / interfaces
    "B104": ["CWE-605"],  # hardcoded_bind_all_interfaces — listens on 0.0.0.0
    # Error handling
    "B110": ["CWE-390"],  # try_except_pass — swallowed exceptions
    # Code execution / debug
    "B101": ["CWE-703"],  # assert_used — asserts removed in optimised bytecode
    "B201": ["CWE-94"],  # flask_debug_true — exposes interactive Werkzeug console
    # XML
    "B320": ["CWE-611"],  # xml — XXE via lxml/etree
    "B411": ["CWE-611"],  # import_xmlrpclib — XXE
    "B322": ["CWE-78"],  # input — Python 2 input() == eval()
}

# Maps bandit's severity string → our canonical severity string.
# Bandit uses HIGH / MEDIUM / LOW only (no CRITICAL / INFO).
_SEVERITY_MAP: dict[str, str] = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Maps bandit's confidence string → our canonical confidence string.
_CONFIDENCE_MAP: dict[str, str] = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class BanditRunner:
    """Bandit static analysis runner.

    Wraps the ``bandit`` CLI as a subprocess, parses JSON output, and returns
    findings in the canonical RawFinding shape.

    PIPELINE ORDER: Always runs after SecretsDetector (PIPELINE_PRIORITY=0)
    and before SemgrepRunner (PIPELINE_PRIORITY=2). See PIPELINE_PRIORITY = 1.

    Usage::

        runner = BanditRunner()
        findings = runner.scan(Path("./my-project"))
        # returns list[RawFinding] — empty if bandit not installed or no issues
    """

    def scan(self, target: Path) -> list[RawFinding]:
        """Run bandit on target and return findings as RawFinding instances.

        Invokes ``bandit -r <target> -f json -q``.

        Bandit exits with code 1 when findings are present. This is NOT treated
        as an error — the JSON output is still fully valid and is parsed normally.
        Exit code 2+ indicates a real error (bad arguments, bandit crash).

        Args:
            target: Resolved absolute path (file or directory) to scan.

        Returns:
            List of RawFinding. Empty list if bandit is not installed or there
            are no findings.
        """
        if not self._bandit_available():
            logger.warning(
                "bandit not found on PATH — skipping Bandit analysis. "
                "Install with: uv add bandit --dev"
            )
            return []

        return self._run_bandit(target)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _bandit_available(self) -> bool:
        """Check whether bandit is installed and accessible on PATH.

        Uses ``bandit --version`` as a lightweight probe. The output is
        discarded; we only care about whether the binary exists.

        Returns:
            True if bandit is found on PATH, False otherwise.
        """
        try:
            subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                check=False,
                timeout=10,
            )
            return True
        except FileNotFoundError:
            return False

    def _run_bandit(self, target: Path) -> list[RawFinding]:
        """Execute the bandit subprocess and parse its JSON output.

        Args:
            target: Resolved absolute path to scan.

        Returns:
            Parsed list of RawFinding. Returns [] on subprocess or JSON error.
        """
        cmd: list[str] = [
            "bandit",
            "-r",  # recursive scan
            str(target),
            "-f",
            "json",  # machine-readable JSON output
            "-q",  # suppress progress/info output to stderr
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,  # bandit exits 1 on findings — handled below
                timeout=120,  # generous timeout; large repos can be slow
            )
        except subprocess.TimeoutExpired:
            logger.error("bandit scan timed out after 120 seconds on: %s", target)
            return []
        except OSError as exc:
            logger.error("bandit subprocess failed to start: %s", exc)
            return []

        # Exit code 2+ = real error (bad args, internal bandit crash).
        if result.returncode >= 2:
            logger.error(
                "bandit exited with error code %d. stderr: %s",
                result.returncode,
                result.stderr[:500],
            )
            return []

        # Exit code 0 = clean scan, exit code 1 = findings — both produce JSON.
        if not result.stdout.strip():
            logger.debug("bandit returned no output for target: %s", target)
            return []

        return self._parse_output(result.stdout)

    def _parse_output(self, json_output: str) -> list[RawFinding]:
        """Parse bandit's JSON stdout into a list of RawFinding.

        Bandit JSON structure (abbreviated)::

            {
              "errors": [],
              "results": [
                {
                  "filename": "/abs/path/to/file.py",
                  "line_number": 42,
                  "issue_severity": "HIGH",
                  "issue_confidence": "MEDIUM",
                  "issue_text": "Use of exec detected.",
                  "code": "42  exec(user_input)\\n",
                  "test_id": "B102",
                  "test_name": "exec_used",
                  "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/..."},
                  "more_info": "https://bandit.readthedocs.io/..."
                }
              ]
            }

        Args:
            json_output: Raw JSON string from bandit's stdout.

        Returns:
            List of RawFinding. Silently skips individual malformed entries
            to avoid one bad result blocking the rest of the scan.
        """
        try:
            data: dict[str, Any] = json.loads(json_output)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse bandit JSON output: %s", exc)
            return []

        results: list[dict[str, Any]] = data.get("results", [])
        findings: list[RawFinding] = []

        for entry in results:
            finding = self._parse_entry(entry)
            if finding is not None:
                findings.append(finding)

        logger.debug("bandit: parsed %d findings from %d results", len(findings), len(results))
        return findings

    def _parse_entry(self, entry: dict[str, Any]) -> RawFinding | None:
        """Convert a single bandit result dict into a RawFinding.

        Required fields: ``test_id``, ``filename``, ``line_number``.
        Missing or malformed required fields cause this entry to be skipped
        with a warning (rather than crashing the whole scan).

        CWE resolution order:
          1. ``_BANDIT_CWE_MAP`` static table (curated, most reliable)
          2. bandit's own ``issue_cwe.id`` field in the JSON (fallback)
          3. Empty list (no CWE known)

        Args:
            entry: One element from bandit's ``results`` array.

        Returns:
            RawFinding on success, or None if required fields are missing.
        """
        try:
            test_id: str = str(entry["test_id"])
            filename: str = str(entry["filename"])
            line_number: int = int(entry["line_number"])
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "Skipping malformed bandit result entry (missing required field): %s", exc
            )
            return None

        issue_severity: str = str(entry.get("issue_severity", "LOW")).upper()
        issue_confidence: str = str(entry.get("issue_confidence", "LOW")).upper()
        issue_text: str = str(entry.get("issue_text", ""))
        test_name: str = str(entry.get("test_name", ""))
        # bandit's `code` field contains the flagged line(s) with line numbers
        code_snippet: str = str(entry.get("code", "")).strip()

        severity: str = _SEVERITY_MAP.get(issue_severity, "LOW")
        confidence: str = _CONFIDENCE_MAP.get(issue_confidence, "LOW")

        # CWE resolution: static map first, then bandit's own field
        cwe_list: list[str] = list(_BANDIT_CWE_MAP.get(test_id, []))
        if not cwe_list:
            raw_cwe: dict[str, Any] = entry.get("issue_cwe", {})
            if isinstance(raw_cwe, dict):
                cwe_id = raw_cwe.get("id")
                if cwe_id is not None:
                    cwe_list = [f"CWE-{cwe_id}"]

        # Human-readable message: include test name for traceability
        if test_name:
            message = f"[{test_id}] {test_name}: {issue_text}"
        else:
            message = f"[{test_id}] {issue_text}"

        return RawFinding(
            tool="bandit",
            rule_id=test_id,
            file=filename,
            line=line_number,
            severity=severity,
            message=message,
            code_snippet=code_snippet,
            metadata={
                "test_name": test_name,
                "confidence": confidence,
                "cwe": cwe_list,
                # Link to bandit docs for the specific test
                "more_info": str(entry.get("more_info", "")),
            },
        )
