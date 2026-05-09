"""test_safety.py — Unit tests for the Shield Safety runner.

Tests cover:
  - SafetyRunner.scan() returns [] when safety is not on PATH
  - SafetyRunner.scan() finds requirements files and passes them to _run_safety
  - SafetyRunner.scan() falls back to env scan when no requirements file found
  - _safety_available() returns True/False correctly
  - _find_requirements() returns first matching candidate, or None
  - _run_safety() handles exit code 0 (no vulns), 1 (vulns — safety <2.0),
    64 (vulns — safety >=2.0), and error codes (other values)
  - _run_safety() handles TimeoutExpired and OSError gracefully
  - _run_safety() handles empty stdout
  - _run_safety() passes -r <file> when req_file is set, omits it when not
  - _parse_output() correctly parses v2 dict format (safety >= 2.0)
  - _parse_output() correctly parses v1 list-of-lists format (safety < 2.0)
  - _parse_output() returns [] on malformed JSON
  - _parse_output() returns [] when dict has non-list "vulnerabilities"
  - _parse_output() returns [] for unrecognised root type
  - _parse_entry_v2() maps CVSS score to correct severity
  - _parse_entry_v2() defaults to MEDIUM when severity is null
  - _parse_entry_v2() uses CVE alias in message when available
  - _parse_entry_v2() includes fix version hint in message
  - _parse_entry_v2() returns None for missing required fields
  - _parse_entry_v2() returns None for non-dict entry
  - _parse_entry_v1() defaults to MEDIUM (no CVSS in v1 format)
  - _parse_entry_v1() returns None for entries with < 5 elements
  - _parse_entry_v1() returns None for non-list entries
  - _extract_cvss_v2() returns correct score from nested severity dict
  - _extract_cvss_v2() returns None for None/empty/malformed input
  - _cvss_to_severity() maps correctly across all thresholds
  - PIPELINE_PRIORITY == 4
  - _CWE == ["CWE-1035"] and _OWASP == ["A06:2021"]
  - _REQUIREMENTS_CANDIDATES contains expected file names
  - _VULN_EXIT_CODES contains 1 and 64
  - RawFinding shape: tool="safety", cwe=["CWE-1035"], owasp=["A06:2021"],
    line=0, code_snippet=""

All tests are fully self-contained — no network calls, no safety binary required.
subprocess.run is mocked throughout.
"""

# ruff: noqa: I001
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup — mirrors the pattern in test_bandit.py / test_pip_audit.py
# ---------------------------------------------------------------------------
_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

# ---------------------------------------------------------------------------
# Imports (after path setup)
# ---------------------------------------------------------------------------
from scanner.detectors.safety import (  # noqa: E402
    PIPELINE_PRIORITY,
    SafetyRunner,
    _CWE,
    _OWASP,
    _REQUIREMENTS_CANDIDATES,
    _VULN_EXIT_CODES,
    _cvss_to_severity,
    _extract_cvss_v2,
    _extract_fix_hint_v1,
)

# ---------------------------------------------------------------------------
# Fixtures — realistic safety JSON payloads
# ---------------------------------------------------------------------------

# Format A (safety >= 2.0): dict with "vulnerabilities" key.
# Two packages: requests (CVSS 6.1 → MEDIUM) and pillow (no CVSS → MEDIUM).
_SAFETY_V2_JSON_TWO_VULNS: str = json.dumps(
    {
        "vulnerabilities": [
            {
                "vulnerability_id": "51457",
                "package_name": "requests",
                "analyzed_version": "2.25.1",
                "advisory": (
                    "Requests forwards proxy-authorization headers to "
                    "destination servers when a redirect occurs."
                ),
                "CVE": "CVE-2023-32681",
                "fixed_versions": ["2.31.0"],
                "severity": {
                    "cvss_v3": {
                        "base_score": 6.1,
                        "base_severity": "MEDIUM",
                    }
                },
            },
            {
                "vulnerability_id": "44715",
                "package_name": "pillow",
                "analyzed_version": "8.2.0",
                "advisory": "Pillow 8.3.x contains a security fix.",
                "CVE": None,
                "fixed_versions": ["8.3.1"],
                "severity": None,  # no CVSS → defaults to MEDIUM
            },
        ],
        "ignored_vulnerabilities": [],
        "meta": {"safety_version": "2.4.0"},
    }
)

# Format A — CRITICAL severity (CVSS >= 9.0).
_SAFETY_V2_JSON_CRITICAL: str = json.dumps(
    {
        "vulnerabilities": [
            {
                "vulnerability_id": "99999",
                "package_name": "vuln-pkg",
                "analyzed_version": "1.0.0",
                "advisory": "Remote code execution vulnerability.",
                "CVE": "CVE-2024-12345",
                "fixed_versions": ["2.0.0"],
                "severity": {"cvss_v3": {"base_score": 9.8, "base_severity": "CRITICAL"}},
            }
        ],
        "meta": {},
    }
)

# Format A — HIGH severity (7.0 <= CVSS < 9.0).
_SAFETY_V2_JSON_HIGH: str = json.dumps(
    {
        "vulnerabilities": [
            {
                "vulnerability_id": "88888",
                "package_name": "django",
                "analyzed_version": "3.0.0",
                "advisory": "SQL injection via crafted JSON.",
                "CVE": "CVE-2021-35042",
                "fixed_versions": ["3.2.14"],
                "severity": {"cvss_v3": {"base_score": 7.5, "base_severity": "HIGH"}},
            }
        ],
        "meta": {},
    }
)

# Format A — LOW severity (CVSS < 4.0).
_SAFETY_V2_JSON_LOW: str = json.dumps(
    {
        "vulnerabilities": [
            {
                "vulnerability_id": "77777",
                "package_name": "somelib",
                "analyzed_version": "1.0.0",
                "advisory": "Minor info disclosure.",
                "CVE": "",
                "fixed_versions": [],
                "severity": {"cvss_v3": {"base_score": 2.5, "base_severity": "LOW"}},
            }
        ],
        "meta": {},
    }
)

# Format A — empty vulnerabilities list (no findings).
_SAFETY_V2_JSON_EMPTY: str = json.dumps(
    {"vulnerabilities": [], "ignored_vulnerabilities": [], "meta": {}}
)

# Format A — missing required field (vulnerability_id).
_SAFETY_V2_JSON_MISSING_ID: str = json.dumps(
    {
        "vulnerabilities": [
            {
                # vulnerability_id intentionally omitted
                "package_name": "badlib",
                "analyzed_version": "0.1.0",
                "advisory": "No id field.",
                "CVE": "CVE-2024-0001",
                "fixed_versions": [],
                "severity": None,
            }
        ],
        "meta": {},
    }
)

# Format A — non-dict entry in vulnerabilities list (should be skipped).
_SAFETY_V2_JSON_NON_DICT_ENTRY: str = json.dumps(
    {"vulnerabilities": ["not-a-dict", None, 42], "meta": {}}
)

# Format B (safety < 2.0): list of 5-element lists.
_SAFETY_V1_JSON_TWO_VULNS: str = json.dumps(
    [
        [
            "django",
            "<2.2.24,>=2.2.0",
            "2.2.12",
            "Django 2.2.x before 2.2.24 allows SQL injection.",
            "35518",
        ],
        [
            "requests",
            "<2.31.0",
            "2.25.1",
            "Requests forwards auth headers.",
            "44715",
        ],
    ]
)

# Format B — entry with fewer than 5 elements (should be skipped).
_SAFETY_V1_JSON_SHORT_ENTRY: str = json.dumps(
    [
        ["only", "three", "fields"],  # too short
        ["django", "<2.2.24,>=2.2.0", "2.2.12", "SQL injection.", "35518"],
    ]
)

# Format B — non-list entry in outer list (should be skipped).
_SAFETY_V1_JSON_NON_LIST_ENTRY: str = json.dumps(
    [
        {"this": "is a dict, not a list"},
        ["django", "<2.2.24,>=2.2.0", "2.2.12", "SQL injection.", "35518"],
    ]
)


def _make_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    """Build a mock subprocess.CompletedProcess object."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ---------------------------------------------------------------------------
# Tests: module-level constants
# ---------------------------------------------------------------------------


class TestModuleConstants:
    def test_pipeline_priority(self) -> None:
        """SafetyRunner must run after PipAuditRunner (priority 3)."""
        assert PIPELINE_PRIORITY == 4

    def test_cwe_constant(self) -> None:
        """All safety findings map to CWE-1035."""
        assert _CWE == ["CWE-1035"]

    def test_owasp_constant(self) -> None:
        """All safety findings map to A06:2021."""
        assert _OWASP == ["A06:2021"]

    def test_requirements_candidates_not_empty(self) -> None:
        """Requirements candidate list must contain at least one entry."""
        assert len(_REQUIREMENTS_CANDIDATES) > 0

    def test_requirements_candidates_includes_requirements_txt(self) -> None:
        assert "requirements.txt" in _REQUIREMENTS_CANDIDATES

    def test_requirements_candidates_includes_requirements_dev_txt(self) -> None:
        assert "requirements-dev.txt" in _REQUIREMENTS_CANDIDATES

    def test_vuln_exit_codes_contains_1(self) -> None:
        """Exit code 1 (safety < 2.0 vulns found) must not be treated as error."""
        assert 1 in _VULN_EXIT_CODES

    def test_vuln_exit_codes_contains_64(self) -> None:
        """Exit code 64 (safety >= 2.0 vulns found) must not be treated as error."""
        assert 64 in _VULN_EXIT_CODES


# ---------------------------------------------------------------------------
# Tests: _safety_available()
# ---------------------------------------------------------------------------


class TestSafetyAvailable:
    def test_returns_true_when_safety_found(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0)):
            assert runner._safety_available() is True

    def test_returns_false_when_not_found(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert runner._safety_available() is False

    def test_calls_safety_version(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0)) as mock_run:
            runner._safety_available()
        args = mock_run.call_args[0][0]
        assert args[0] == "safety"
        assert "--version" in args


# ---------------------------------------------------------------------------
# Tests: _find_requirements()
# ---------------------------------------------------------------------------


class TestFindRequirements:
    def test_returns_requirements_txt_when_present(self) -> None:
        runner = SafetyRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.25.1\n")
            result = runner._find_requirements(Path(tmpdir))
        assert result is not None
        assert result.name == "requirements.txt"

    def test_returns_requirements_dev_when_no_requirements_txt(self) -> None:
        runner = SafetyRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            dev = Path(tmpdir) / "requirements-dev.txt"
            dev.write_text("pytest==7.0.0\n")
            result = runner._find_requirements(Path(tmpdir))
        assert result is not None
        assert result.name == "requirements-dev.txt"

    def test_requirements_txt_takes_priority_over_dev(self) -> None:
        runner = SafetyRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text("requests==2.25.1\n")
            (Path(tmpdir) / "requirements-dev.txt").write_text("pytest==7.0.0\n")
            result = runner._find_requirements(Path(tmpdir))
        assert result is not None
        assert result.name == "requirements.txt"

    def test_returns_none_when_no_candidates_present(self) -> None:
        runner = SafetyRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner._find_requirements(Path(tmpdir))
        assert result is None


# ---------------------------------------------------------------------------
# Tests: scan() dispatch
# ---------------------------------------------------------------------------


class TestScanDispatch:
    def test_returns_empty_when_safety_not_available(self) -> None:
        runner = SafetyRunner()
        with patch.object(runner, "_safety_available", return_value=False):
            result = runner.scan(Path("/fake/path"))
        assert result == []

    def test_calls_run_safety_with_req_file_when_found(self) -> None:
        runner = SafetyRunner()
        fake_req = Path("/fake/requirements.txt")
        with (
            patch.object(runner, "_safety_available", return_value=True),
            patch.object(runner, "_find_requirements", return_value=fake_req),
            patch.object(runner, "_run_safety", return_value=[]) as mock_run,
        ):
            runner.scan(Path("/fake/path"))
        mock_run.assert_called_once_with(Path("/fake/path"), fake_req)

    def test_calls_run_safety_with_none_when_no_req_file(self) -> None:
        runner = SafetyRunner()
        with (
            patch.object(runner, "_safety_available", return_value=True),
            patch.object(runner, "_find_requirements", return_value=None),
            patch.object(runner, "_run_safety", return_value=[]) as mock_run,
        ):
            runner.scan(Path("/fake/path"))
        mock_run.assert_called_once_with(Path("/fake/path"), None)


# ---------------------------------------------------------------------------
# Tests: _run_safety()
# ---------------------------------------------------------------------------


class TestRunSafety:
    def test_exit_code_0_no_output_returns_empty(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0, stdout="")):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_exit_code_1_parsed_as_vulns(self) -> None:
        """safety < 2.0 uses exit code 1 to indicate vulnerabilities found."""
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(1, stdout=_SAFETY_V1_JSON_TWO_VULNS)):
            result = runner._run_safety(Path("/fake"), None)
        assert len(result) == 2

    def test_exit_code_64_parsed_as_vulns(self) -> None:
        """safety >= 2.0 uses exit code 64 to indicate vulnerabilities found."""
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(64, stdout=_SAFETY_V2_JSON_TWO_VULNS)):
            result = runner._run_safety(Path("/fake"), None)
        assert len(result) == 2

    def test_exit_code_2_returns_empty(self) -> None:
        """Exit codes other than 0, 1, 64 are real errors — return []."""
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(2, stderr="fatal error")):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_exit_code_255_returns_empty(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(255, stderr="crash")):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_timeout_returns_empty(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("safety", 120)):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_oserror_returns_empty(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_empty_stdout_returns_empty(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0, stdout="   ")):
            result = runner._run_safety(Path("/fake"), None)
        assert result == []

    def test_cmd_includes_r_flag_when_req_file_provided(self) -> None:
        runner = SafetyRunner()
        req_file = Path("/fake/requirements.txt")
        with patch("subprocess.run", return_value=_make_proc(0, stdout="[]")) as mock_run:
            runner._run_safety(Path("/fake"), req_file)
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert str(req_file) in cmd

    def test_cmd_omits_r_flag_when_no_req_file(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0, stdout="[]")) as mock_run:
            runner._run_safety(Path("/fake"), None)
        cmd = mock_run.call_args[0][0]
        assert "-r" not in cmd

    def test_cmd_includes_json_flag(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0, stdout="[]")) as mock_run:
            runner._run_safety(Path("/fake"), None)
        cmd = mock_run.call_args[0][0]
        assert "--json" in cmd

    def test_cmd_includes_check_subcommand(self) -> None:
        runner = SafetyRunner()
        with patch("subprocess.run", return_value=_make_proc(0, stdout="[]")) as mock_run:
            runner._run_safety(Path("/fake"), None)
        cmd = mock_run.call_args[0][0]
        assert "check" in cmd

    def test_attribution_path_uses_req_file_when_provided(self) -> None:
        runner = SafetyRunner()
        req_file = Path("/fake/requirements.txt")
        with patch("subprocess.run", return_value=_make_proc(64, stdout=_SAFETY_V2_JSON_CRITICAL)):
            result = runner._run_safety(Path("/fake"), req_file)
        assert len(result) == 1
        assert result[0].file == str(req_file)

    def test_attribution_path_uses_target_when_no_req_file(self) -> None:
        runner = SafetyRunner()
        target = Path("/fake/project")
        with patch("subprocess.run", return_value=_make_proc(64, stdout=_SAFETY_V2_JSON_CRITICAL)):
            result = runner._run_safety(target, None)
        assert len(result) == 1
        assert result[0].file == str(target)


# ---------------------------------------------------------------------------
# Tests: _parse_output()
# ---------------------------------------------------------------------------


class TestParseOutput:
    def _runner(self) -> SafetyRunner:
        return SafetyRunner()

    def test_v2_two_vulns(self) -> None:
        runner = self._runner()
        findings = runner._parse_output(_SAFETY_V2_JSON_TWO_VULNS, "/fake/req.txt")
        assert len(findings) == 2

    def test_v2_empty_vulnerabilities_list(self) -> None:
        runner = self._runner()
        findings = runner._parse_output(_SAFETY_V2_JSON_EMPTY, "/fake/req.txt")
        assert findings == []

    def test_v1_two_vulns(self) -> None:
        runner = self._runner()
        findings = runner._parse_output(_SAFETY_V1_JSON_TWO_VULNS, "/fake/req.txt")
        assert len(findings) == 2

    def test_malformed_json_returns_empty(self) -> None:
        runner = self._runner()
        findings = runner._parse_output("NOT VALID JSON {{{", "/fake/req.txt")
        assert findings == []

    def test_dict_with_non_list_vulnerabilities_returns_empty(self) -> None:
        runner = self._runner()
        bad = json.dumps({"vulnerabilities": "not-a-list"})
        findings = runner._parse_output(bad, "/fake/req.txt")
        assert findings == []

    def test_unrecognised_root_type_returns_empty(self) -> None:
        """A JSON number / string at root is neither dict nor list."""
        runner = self._runner()
        findings = runner._parse_output(json.dumps(42), "/fake/req.txt")
        assert findings == []

    def test_v2_missing_id_skips_entry(self) -> None:
        runner = self._runner()
        findings = runner._parse_output(_SAFETY_V2_JSON_MISSING_ID, "/fake/req.txt")
        assert findings == []

    def test_v2_non_dict_entries_skipped(self) -> None:
        runner = self._runner()
        findings = runner._parse_output(_SAFETY_V2_JSON_NON_DICT_ENTRY, "/fake/req.txt")
        assert findings == []

    def test_v1_short_entry_skipped(self) -> None:
        runner = self._runner()
        # Only the full 5-element entry should be parsed; the 3-element one is skipped.
        findings = runner._parse_output(_SAFETY_V1_JSON_SHORT_ENTRY, "/fake/req.txt")
        assert len(findings) == 1

    def test_v1_non_list_entry_skipped(self) -> None:
        runner = self._runner()
        # Only the list entry (django) should be parsed; the dict entry is skipped.
        findings = runner._parse_output(_SAFETY_V1_JSON_NON_LIST_ENTRY, "/fake/req.txt")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Tests: _parse_entry_v2()
# ---------------------------------------------------------------------------


class TestParseEntryV2:
    def _runner(self) -> SafetyRunner:
        return SafetyRunner()

    def _make_entry(self, **overrides: object) -> dict:
        base: dict = {
            "vulnerability_id": "51457",
            "package_name": "requests",
            "analyzed_version": "2.25.1",
            "advisory": "Some advisory text.",
            "CVE": "CVE-2023-32681",
            "fixed_versions": ["2.31.0"],
            "severity": {"cvss_v3": {"base_score": 6.1, "base_severity": "MEDIUM"}},
        }
        base.update(overrides)
        return base

    def test_returns_raw_finding_on_valid_entry(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None

    def test_tool_is_safety(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.tool == "safety"

    def test_rule_id_is_vulnerability_id(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.rule_id == "51457"

    def test_line_is_zero(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.line == 0

    def test_code_snippet_is_empty(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.code_snippet == ""

    def test_cwe_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.metadata["cwe"] == ["CWE-1035"]

    def test_owasp_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.metadata["owasp"] == ["A06:2021"]

    def test_severity_medium_for_cvss_6_1(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake/req.txt")
        assert result is not None
        assert result.severity == "MEDIUM"

    def test_severity_critical_for_cvss_9_8(self) -> None:
        runner = self._runner()
        entry = self._make_entry(
            severity={"cvss_v3": {"base_score": 9.8, "base_severity": "CRITICAL"}}
        )
        result = runner._parse_entry_v2(entry, "/fake/req.txt")
        assert result is not None
        assert result.severity == "CRITICAL"

    def test_severity_high_for_cvss_7_5(self) -> None:
        runner = self._runner()
        entry = self._make_entry(severity={"cvss_v3": {"base_score": 7.5, "base_severity": "HIGH"}})
        result = runner._parse_entry_v2(entry, "/fake/req.txt")
        assert result is not None
        assert result.severity == "HIGH"

    def test_severity_low_for_cvss_2_5(self) -> None:
        runner = self._runner()
        entry = self._make_entry(severity={"cvss_v3": {"base_score": 2.5, "base_severity": "LOW"}})
        result = runner._parse_entry_v2(entry, "/fake/req.txt")
        assert result is not None
        assert result.severity == "LOW"

    def test_severity_medium_when_severity_is_null(self) -> None:
        """No CVSS data → safe default of MEDIUM."""
        runner = self._runner()
        entry = self._make_entry(severity=None)
        result = runner._parse_entry_v2(entry, "/fake/req.txt")
        assert result is not None
        assert result.severity == "MEDIUM"

    def test_cve_alias_used_in_message(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(CVE="CVE-2023-32681"), "/fake")
        assert result is not None
        assert "CVE-2023-32681" in result.message

    def test_vuln_id_used_when_no_cve(self) -> None:
        runner = self._runner()
        entry = self._make_entry(CVE=None)
        result = runner._parse_entry_v2(entry, "/fake")
        assert result is not None
        assert "51457" in result.message

    def test_empty_cve_string_falls_back_to_vuln_id(self) -> None:
        runner = self._runner()
        entry = self._make_entry(CVE="")
        result = runner._parse_entry_v2(entry, "/fake")
        assert result is not None
        assert "51457" in result.message

    def test_fix_version_in_message(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake")
        assert result is not None
        assert "2.31.0" in result.message

    def test_no_fix_version_message(self) -> None:
        runner = self._runner()
        entry = self._make_entry(fixed_versions=[])
        result = runner._parse_entry_v2(entry, "/fake")
        assert result is not None
        assert "No fix version available" in result.message

    def test_fix_available_true_when_fix_versions(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["fix_available"] is True

    def test_fix_available_false_when_no_fix_versions(self) -> None:
        runner = self._runner()
        entry = self._make_entry(fixed_versions=[])
        result = runner._parse_entry_v2(entry, "/fake")
        assert result is not None
        assert result.metadata["fix_available"] is False

    def test_package_name_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["package_name"] == "requests"

    def test_package_version_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v2(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["package_version"] == "2.25.1"

    def test_advisory_truncated_to_200_chars(self) -> None:
        runner = self._runner()
        long_advisory = "A" * 300
        entry = self._make_entry(advisory=long_advisory)
        result = runner._parse_entry_v2(entry, "/fake")
        assert result is not None
        # The message should contain the truncated advisory ending in "..."
        assert "..." in result.message

    def test_returns_none_when_vulnerability_id_missing(self) -> None:
        runner = self._runner()
        entry = {
            "package_name": "requests",
            "analyzed_version": "2.25.1",
            # vulnerability_id intentionally omitted
        }
        assert runner._parse_entry_v2(entry, "/fake") is None

    def test_returns_none_when_package_name_missing(self) -> None:
        runner = self._runner()
        entry = {
            "vulnerability_id": "51457",
            "analyzed_version": "2.25.1",
            # package_name intentionally omitted
        }
        assert runner._parse_entry_v2(entry, "/fake") is None

    def test_returns_none_when_analyzed_version_missing(self) -> None:
        runner = self._runner()
        entry = {
            "vulnerability_id": "51457",
            "package_name": "requests",
            # analyzed_version intentionally omitted
        }
        assert runner._parse_entry_v2(entry, "/fake") is None

    def test_returns_none_for_non_dict_input(self) -> None:
        runner = self._runner()
        assert runner._parse_entry_v2("not-a-dict", "/fake") is None
        assert runner._parse_entry_v2(None, "/fake") is None
        assert runner._parse_entry_v2(42, "/fake") is None


# ---------------------------------------------------------------------------
# Tests: _parse_entry_v1()
# ---------------------------------------------------------------------------


class TestParseEntryV1:
    def _runner(self) -> SafetyRunner:
        return SafetyRunner()

    def _make_entry(self, **overrides: object) -> list:
        base: list = [
            "django",  # [0] package name
            "<2.2.24,>=2.2.0",  # [1] affected spec
            "2.2.12",  # [2] installed version
            "Django 2.2.x before 2.2.24 allows SQL injection.",  # [3] advisory
            "35518",  # [4] vuln ID
        ]
        # Apply positional overrides by index if provided
        return base

    def test_returns_raw_finding_on_valid_entry(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake/req.txt")
        assert result is not None

    def test_tool_is_safety(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.tool == "safety"

    def test_rule_id_is_vuln_id(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.rule_id == "35518"

    def test_severity_defaults_to_medium(self) -> None:
        """v1 format has no CVSS data — must default to MEDIUM."""
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.severity == "MEDIUM"

    def test_line_is_zero(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.line == 0

    def test_code_snippet_is_empty(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.code_snippet == ""

    def test_cwe_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["cwe"] == ["CWE-1035"]

    def test_owasp_in_metadata(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["owasp"] == ["A06:2021"]

    def test_package_name_in_message(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert "django" in result.message

    def test_vuln_id_in_message(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert "35518" in result.message

    def test_advisory_included_in_message(self) -> None:
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert "SQL injection" in result.message

    def test_returns_none_for_short_list(self) -> None:
        runner = self._runner()
        assert runner._parse_entry_v1(["only", "three"], "/fake") is None
        assert runner._parse_entry_v1([], "/fake") is None

    def test_returns_none_for_non_list(self) -> None:
        runner = self._runner()
        assert runner._parse_entry_v1({"this": "is a dict"}, "/fake") is None
        assert runner._parse_entry_v1("a string", "/fake") is None
        assert runner._parse_entry_v1(None, "/fake") is None

    def test_fix_available_false_in_v1(self) -> None:
        """v1 format has no fix version data — fix_available must be False."""
        runner = self._runner()
        result = runner._parse_entry_v1(self._make_entry(), "/fake")
        assert result is not None
        assert result.metadata["fix_available"] is False


# ---------------------------------------------------------------------------
# Tests: _extract_cvss_v2()
# ---------------------------------------------------------------------------


class TestExtractCvssV2:
    def test_returns_score_from_nested_cvss_v3(self) -> None:
        severity = {"cvss_v3": {"base_score": 7.5, "base_severity": "HIGH"}}
        assert _extract_cvss_v2(severity) == 7.5

    def test_returns_none_for_none_input(self) -> None:
        assert _extract_cvss_v2(None) is None

    def test_returns_none_for_empty_dict(self) -> None:
        assert _extract_cvss_v2({}) is None

    def test_returns_none_when_cvss_v3_missing(self) -> None:
        assert _extract_cvss_v2({"cvss_v2": {"base_score": 5.0}}) is None

    def test_returns_none_when_cvss_v3_is_none(self) -> None:
        assert _extract_cvss_v2({"cvss_v3": None}) is None

    def test_returns_none_when_base_score_missing(self) -> None:
        assert _extract_cvss_v2({"cvss_v3": {"base_severity": "HIGH"}}) is None

    def test_returns_none_when_base_score_is_string(self) -> None:
        assert _extract_cvss_v2({"cvss_v3": {"base_score": "not-a-number"}}) is None

    def test_returns_none_for_non_dict_input(self) -> None:
        assert _extract_cvss_v2("string") is None
        assert _extract_cvss_v2(42) is None
        assert _extract_cvss_v2([]) is None

    def test_returns_float_for_integer_base_score(self) -> None:
        severity = {"cvss_v3": {"base_score": 9, "base_severity": "CRITICAL"}}
        result = _extract_cvss_v2(severity)
        assert result == 9.0
        assert isinstance(result, float)


# ---------------------------------------------------------------------------
# Tests: _cvss_to_severity()
# ---------------------------------------------------------------------------


class TestCvssToSeverity:
    def test_none_returns_medium(self) -> None:
        assert _cvss_to_severity(None) == "MEDIUM"

    def test_exactly_9_0_returns_critical(self) -> None:
        assert _cvss_to_severity(9.0) == "CRITICAL"

    def test_9_8_returns_critical(self) -> None:
        assert _cvss_to_severity(9.8) == "CRITICAL"

    def test_10_0_returns_critical(self) -> None:
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_8_9_returns_high(self) -> None:
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_exactly_7_0_returns_high(self) -> None:
        assert _cvss_to_severity(7.0) == "HIGH"

    def test_6_9_returns_medium(self) -> None:
        assert _cvss_to_severity(6.9) == "MEDIUM"

    def test_exactly_4_0_returns_medium(self) -> None:
        assert _cvss_to_severity(4.0) == "MEDIUM"

    def test_3_9_returns_low(self) -> None:
        assert _cvss_to_severity(3.9) == "LOW"

    def test_0_1_returns_low(self) -> None:
        assert _cvss_to_severity(0.1) == "LOW"

    def test_0_0_returns_low(self) -> None:
        assert _cvss_to_severity(0.0) == "LOW"


# ---------------------------------------------------------------------------
# Tests: _extract_fix_hint_v1()
# ---------------------------------------------------------------------------


class TestExtractFixHintV1:
    def test_returns_empty_for_empty_spec(self) -> None:
        assert _extract_fix_hint_v1("") == ""

    def test_returns_empty_for_whitespace_spec(self) -> None:
        assert _extract_fix_hint_v1("   ") == ""

    def test_returns_hint_string_for_valid_spec(self) -> None:
        result = _extract_fix_hint_v1("<2.31.0")
        assert result != ""
        assert "<2.31.0" in result

    def test_complex_spec_included_in_hint(self) -> None:
        result = _extract_fix_hint_v1("!=5.1.0,<8.3.1")
        assert "!=5.1.0,<8.3.1" in result


# ---------------------------------------------------------------------------
# Tests: end-to-end fixture round-trips
# ---------------------------------------------------------------------------


class TestEndToEndFixtures:
    def test_v2_two_vulns_shapes(self) -> None:
        """Full round-trip through _parse_output for v2 format."""
        runner = SafetyRunner()
        findings = runner._parse_output(_SAFETY_V2_JSON_TWO_VULNS, "/fake/req.txt")

        assert len(findings) == 2

        requests_finding = next(f for f in findings if f.metadata["package_name"] == "requests")
        assert requests_finding.tool == "safety"
        assert requests_finding.severity == "MEDIUM"  # CVSS 6.1
        assert requests_finding.rule_id == "51457"
        assert "CVE-2023-32681" in requests_finding.message
        assert requests_finding.metadata["cwe"] == ["CWE-1035"]
        assert requests_finding.metadata["owasp"] == ["A06:2021"]
        assert requests_finding.metadata["fix_available"] is True
        assert requests_finding.line == 0
        assert requests_finding.code_snippet == ""

        pillow_finding = next(f for f in findings if f.metadata["package_name"] == "pillow")
        assert pillow_finding.severity == "MEDIUM"  # no CVSS → default
        assert pillow_finding.metadata["fix_available"] is True

    def test_v1_two_vulns_shapes(self) -> None:
        """Full round-trip through _parse_output for v1 format."""
        runner = SafetyRunner()
        findings = runner._parse_output(_SAFETY_V1_JSON_TWO_VULNS, "/fake/req.txt")

        assert len(findings) == 2
        for f in findings:
            assert f.tool == "safety"
            assert f.severity == "MEDIUM"  # v1 always MEDIUM
            assert f.line == 0
            assert f.code_snippet == ""
            assert f.metadata["cwe"] == ["CWE-1035"]
            assert f.metadata["owasp"] == ["A06:2021"]
            assert f.metadata["fix_available"] is False

    def test_v2_critical_finding(self) -> None:
        runner = SafetyRunner()
        findings = runner._parse_output(_SAFETY_V2_JSON_CRITICAL, "/fake/req.txt")
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_v2_high_finding(self) -> None:
        runner = SafetyRunner()
        findings = runner._parse_output(_SAFETY_V2_JSON_HIGH, "/fake/req.txt")
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_v2_low_finding(self) -> None:
        runner = SafetyRunner()
        findings = runner._parse_output(_SAFETY_V2_JSON_LOW, "/fake/req.txt")
        assert len(findings) == 1
        assert findings[0].severity == "LOW"
