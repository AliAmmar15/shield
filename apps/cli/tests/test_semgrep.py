"""test_semgrep.py — Unit tests for the Shield Semgrep runner.

Tests cover:
  - SemgrepRunner.scan() returns [] when semgrep is not on PATH
  - SemgrepRunner.scan() delegates to _run_semgrep() when semgrep is available
  - _semgrep_available() returns True/False correctly
  - _run_semgrep() handles exit codes 0 (clean), 1 (findings), 2+ (error)
  - _run_semgrep() handles TimeoutExpired and OSError gracefully
  - _run_semgrep() handles empty stdout
  - _parse_output() correctly parses a realistic semgrep JSON fixture
  - _parse_output() returns [] on malformed JSON
  - _parse_entry() maps ERROR→HIGH, WARNING→MEDIUM, INFO→LOW severity
  - _parse_entry() extracts CWE and OWASP from metadata
  - _parse_entry() returns None for entries missing required fields
  - _parse_entry() uses last dotted segment as rule_short label
  - _parse_entry() stores end line and ruleset in metadata
  - _extract_cwe() handles list of verbose strings, single string, empty, None
  - _extract_owasp() handles list of verbose strings, single string, empty, None
  - RawFinding shape: tool="semgrep", correct rule_id, file, line, severity, message

All tests are self-contained — no network calls, no semgrep binary required.
subprocess.run is mocked throughout.
"""

# ruff: noqa: I001
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Path setup — mirrors the pattern in test_bandit.py
# ---------------------------------------------------------------------------
_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

# ---------------------------------------------------------------------------
# Imports (after path setup)
# ---------------------------------------------------------------------------
from scanner.detectors.semgrep import (  # noqa: E402
    PIPELINE_PRIORITY,
    SemgrepRunner,
    _CWE_EXTRACT_RE,
    _OWASP_EXTRACT_RE,
    _SEVERITY_MAP,
    _extract_cwe,
    _extract_owasp,
)
from scanner.detectors.secrets import RawFinding  # noqa: E402, TC002


# ---------------------------------------------------------------------------
# Fixtures — realistic semgrep JSON payloads
# ---------------------------------------------------------------------------

# A realistic semgrep JSON output with two findings covering two common rules.
_SEMGREP_JSON_TWO_FINDINGS: str = json.dumps(
    {
        "errors": [],
        "paths": {"scanned": ["/proj/app/runner.py", "/proj/app/db.py"]},
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use",
                "path": "/proj/app/runner.py",
                "start": {"line": 42, "col": 5},
                "end": {"line": 42, "col": 48},
                "extra": {
                    "severity": "ERROR",
                    "message": "Detected subprocess function with a dynamic argument and shell=True. This is dangerous because it allows an attacker to execute arbitrary OS commands.",
                    "lines": "    subprocess.call(user_input, shell=True)",
                    "metadata": {
                        "cwe": [
                            "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
                        ],
                        "owasp": ["A03:2021 - Injection"],
                        "confidence": "HIGH",
                        "category": "security",
                    },
                },
            },
            {
                "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
                "path": "/proj/app/db.py",
                "start": {"line": 17, "col": 9},
                "end": {"line": 17, "col": 55},
                "extra": {
                    "severity": "WARNING",
                    "message": "Detected possible formatted SQL query. Use parameterised queries instead.",
                    "lines": '        cursor.execute(f"SELECT * FROM {table}")',
                    "metadata": {
                        "cwe": [
                            "CWE-89: Improper Neutralization of Special Elements in SQL Commands"
                        ],
                        "owasp": ["A03:2021 - Injection"],
                        "confidence": "MEDIUM",
                        "category": "security",
                    },
                },
            },
        ],
        "version": "1.50.0",
    }
)

# A semgrep JSON with an INFO-severity finding (no metadata CWE/OWASP).
_SEMGREP_JSON_INFO_FINDING: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "check_id": "python.lang.maintainability.is-function-without-parentheses",
                "path": "/proj/app/utils.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 20},
                "extra": {
                    "severity": "INFO",
                    "message": "Did you mean to call this function?",
                    "lines": "    if os.path.exists:",
                    "metadata": {},
                },
            }
        ],
    }
)

# A semgrep JSON entry missing the required ``check_id`` field.
_SEMGREP_JSON_MISSING_CHECK_ID: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                # check_id intentionally omitted
                "path": "/proj/app/bad.py",
                "start": {"line": 5, "col": 1},
                "end": {"line": 5, "col": 10},
                "extra": {"severity": "ERROR", "message": "Missing check_id"},
            }
        ],
    }
)

# A semgrep JSON entry missing the ``start.line`` field.
_SEMGREP_JSON_MISSING_START_LINE: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "check_id": "python.lang.security.some-rule",
                "path": "/proj/app/bad.py",
                "start": {"col": 1},  # line key missing
                "end": {"line": 10, "col": 1},
                "extra": {"severity": "ERROR", "message": "Missing start.line"},
            }
        ],
    }
)

# A semgrep JSON with a finding that has CWE/OWASP as plain strings (not lists).
_SEMGREP_JSON_STRING_METADATA: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "check_id": "python.lang.security.audit.eval.eval-usage",
                "path": "/proj/app/eval_user.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 18},
                "extra": {
                    "severity": "ERROR",
"message": "# FIX: 移除eval，改用安全方式
"lines": "# FIX: 移除eval，改用安全方式
# user_input)",
                    "lines": "eval(user_input)",
                    "metadata": {
                        # Strings instead of lists — must be handled gracefully
                        "cwe": "CWE-94: Improper Control of Generation of Code",
                        "owasp": "A03:2021 - Injection",
                        "confidence": "HIGH",
                    },
                },
            }
        ],
    }
)

# A finding whose check_id has no dots (short rule name falls back to full id).
_SEMGREP_JSON_NO_DOTS_IN_RULE_ID: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "check_id": "hardcoded-secret",
                "path": "/proj/app/settings.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 30},
                "extra": {
                    "severity": "ERROR",
                    "message": "Hardcoded secret detected",
                    "lines": 'SECRET_KEY = "abc123"',
                    "metadata": {"confidence": "HIGH"},
                },
            }
        ],
    }
)


def _make_completed_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    """Build a mock CompletedProcess for use in patch targets."""
    proc: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
        args=["semgrep"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )
    return proc


# ===========================================================================
# Module-level constants
# ===========================================================================


class TestModuleConstants:
    """Sanity-checks on module-level constants."""

    def test_pipeline_priority_is_two(self) -> None:
        """SemgrepRunner must have PIPELINE_PRIORITY=2 (after secrets=0, bandit=1)."""
        assert PIPELINE_PRIORITY == 2

    def test_severity_map_covers_error_warning_info(self) -> None:
        """_SEVERITY_MAP must cover ERROR, WARNING, INFO (and lowercase variants)."""
        for key in ("ERROR", "WARNING", "INFO"):
            assert key in _SEVERITY_MAP

    def test_severity_map_covers_lowercase_variants(self) -> None:
        """_SEVERITY_MAP must cover lowercase variants emitted by some rulesets."""
        for key in ("error", "warning", "info"):
            assert key in _SEVERITY_MAP

    def test_severity_error_maps_to_high(self) -> None:
        assert _SEVERITY_MAP["ERROR"] == "HIGH"

    def test_severity_warning_maps_to_medium(self) -> None:
        assert _SEVERITY_MAP["WARNING"] == "MEDIUM"

    def test_severity_info_maps_to_low(self) -> None:
        assert _SEVERITY_MAP["INFO"] == "LOW"

    def test_cwe_regex_extracts_cwe_number(self) -> None:
        """_CWE_EXTRACT_RE must extract 'CWE-78' from a verbose description."""
        match = _CWE_EXTRACT_RE.search("CWE-78: Improper Neutralization of Special Elements")
        assert match is not None
        assert match.group(1).upper() == "CWE-78"

    def test_owasp_regex_extracts_owasp_code(self) -> None:
        """_OWASP_EXTRACT_RE must extract 'A03:2021' from a verbose description."""
        match = _OWASP_EXTRACT_RE.search("A03:2021 - Injection")
        assert match is not None
        assert match.group(1) == "A03:2021"


# ===========================================================================
# _extract_cwe() helper
# ===========================================================================


class TestExtractCwe:
    """Tests for the _extract_cwe() module-level helper."""

    def test_extracts_from_verbose_list(self) -> None:
        """Verbose CWE list → clean identifiers."""
        result = _extract_cwe(["CWE-78: Improper Neutralization of OS Commands"])
        assert result == ["CWE-78"]

    def test_extracts_from_multiple_verbose_entries(self) -> None:
        """Multiple CWEs in list → all extracted."""
        result = _extract_cwe(
            [
                "CWE-89: SQL Injection",
                "CWE-20: Improper Input Validation",
            ]
        )
        assert "CWE-89" in result
        assert "CWE-20" in result
        assert len(result) == 2

    def test_extracts_from_plain_string(self) -> None:
        """Plain 'CWE-78' string → ['CWE-78']."""
        result = _extract_cwe("CWE-78")
        assert result == ["CWE-78"]

    def test_deduplicates(self) -> None:
        """Duplicate CWE entries must be deduplicated."""
        result = _extract_cwe(["CWE-78: description one", "CWE-78: description two"])
        assert result == ["CWE-78"]

    def test_normalises_to_uppercase(self) -> None:
        """Lowercase 'cwe-78' must be normalised to 'CWE-78'."""
        result = _extract_cwe(["cwe-78: something"])
        assert result == ["CWE-78"]

    def test_returns_empty_for_empty_list(self) -> None:
        assert _extract_cwe([]) == []

    def test_returns_empty_for_none(self) -> None:
        assert _extract_cwe(None) == []

    def test_returns_empty_for_empty_string(self) -> None:
        assert _extract_cwe("") == []

    def test_ignores_entries_with_no_cwe_pattern(self) -> None:
        """Non-CWE strings must yield an empty list."""
        result = _extract_cwe(["No vulnerability here"])
        assert result == []


# ===========================================================================
# _extract_owasp() helper
# ===========================================================================


class TestExtractOwasp:
    """Tests for the _extract_owasp() module-level helper."""

    def test_extracts_from_verbose_list(self) -> None:
        """Verbose OWASP list → clean category codes."""
        result = _extract_owasp(["A03:2021 - Injection"])
        assert result == ["A03:2021"]

    def test_extracts_from_multiple_entries(self) -> None:
        """Multiple OWASP entries in list → all extracted."""
        result = _extract_owasp(["A01:2021 - Broken Access Control", "A03:2021 - Injection"])
        assert "A01:2021" in result
        assert "A03:2021" in result
        assert len(result) == 2

    def test_extracts_from_plain_string(self) -> None:
        """Plain 'A03:2021' string → ['A03:2021']."""
        result = _extract_owasp("A03:2021")
        assert result == ["A03:2021"]

    def test_deduplicates(self) -> None:
        """Duplicate OWASP entries must be deduplicated."""
        result = _extract_owasp(["A03:2021 - Injection", "A03:2021 - Injection (again)"])
        assert result == ["A03:2021"]

    def test_returns_empty_for_empty_list(self) -> None:
        assert _extract_owasp([]) == []

    def test_returns_empty_for_none(self) -> None:
        assert _extract_owasp(None) == []

    def test_returns_empty_for_empty_string(self) -> None:
        assert _extract_owasp("") == []

    def test_ignores_entries_with_no_owasp_pattern(self) -> None:
        """Non-OWASP strings must yield an empty list."""
        result = _extract_owasp(["No OWASP category here"])
        assert result == []


# ===========================================================================
# SemgrepRunner.scan() — top-level dispatch
# ===========================================================================


class TestSemgrepRunnerScan:
    """Tests for SemgrepRunner.scan() — the public entry point."""

    def test_returns_empty_list_when_semgrep_not_installed(self) -> None:
        """scan() must return [] and not raise when semgrep is missing from PATH."""
        runner = SemgrepRunner()
        with (
            patch.object(runner, "_semgrep_available", return_value=False),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner.scan(Path(tmp))
        assert result == []

    def test_delegates_to_run_semgrep_when_available(self) -> None:
        """scan() must call _run_semgrep() when semgrep is on PATH."""
        runner = SemgrepRunner()
        sentinel: list[RawFinding] = []
        with (
            patch.object(runner, "_semgrep_available", return_value=True),
            patch.object(runner, "_run_semgrep", return_value=sentinel) as mock_run,
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner.scan(Path(tmp))
        mock_run.assert_called_once()
        assert result is sentinel


# ===========================================================================
# SemgrepRunner._semgrep_available()
# ===========================================================================


class TestSemgrepAvailable:
    """Tests for _semgrep_available() — PATH probe."""

    def test_returns_true_when_semgrep_exits_successfully(self) -> None:
        """_semgrep_available() returns True when semgrep --version succeeds."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(returncode=0)
            assert runner._semgrep_available() is True

    def test_returns_false_when_semgrep_not_found(self) -> None:
        """_semgrep_available() returns False when FileNotFoundError is raised."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run", side_effect=FileNotFoundError):
            assert runner._semgrep_available() is False


# ===========================================================================
# SemgrepRunner._run_semgrep()
# ===========================================================================


class TestRunSemgrep:
    """Tests for _run_semgrep() — subprocess execution and error handling."""

    def test_returns_findings_on_exit_code_1(self) -> None:
        """Exit code 1 (findings present) must still parse and return findings."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=_SEMGREP_JSON_TWO_FINDINGS,
                returncode=1,  # semgrep normal "findings present" exit code
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_semgrep(Path(tmp))
        assert len(findings) == 2

    def test_returns_empty_list_on_exit_code_0(self) -> None:
        """Exit code 0 (clean scan) must return an empty list."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=json.dumps({"results": []}),
                returncode=0,
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_semgrep(Path(tmp))
        assert findings == []

    def test_returns_empty_list_on_exit_code_2(self) -> None:
        """Exit code 2+ (semgrep error) must return [] and not raise."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stderr="semgrep: error: invalid config",
                returncode=2,
            )
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_semgrep(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_exit_code_3(self) -> None:
        """Exit code 3 (also a semgrep error) must return []."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(returncode=3)
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_semgrep(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_timeout(self) -> None:
        """TimeoutExpired must be caught — returns [] without raising."""
        runner = SemgrepRunner()
        with (
            patch(
                "scanner.detectors.semgrep.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["semgrep"], timeout=180),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_semgrep(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_os_error(self) -> None:
        """OSError on subprocess start must be caught — returns []."""
        runner = SemgrepRunner()
        with (
            patch(
                "scanner.detectors.semgrep.subprocess.run",
                side_effect=OSError("Permission denied"),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_semgrep(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_empty_stdout(self) -> None:
        """Empty stdout must return [] without error."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(stdout="", returncode=0)
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_semgrep(Path(tmp))
        assert result == []

    def test_cmd_contains_expected_flags(self) -> None:
        """_run_semgrep() must invoke semgrep with --json, --quiet, --metrics=off."""
        runner = SemgrepRunner()
        with patch("scanner.detectors.semgrep.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=json.dumps({"results": []}), returncode=0
            )
            with tempfile.TemporaryDirectory() as tmp:
                runner._run_semgrep(Path(tmp))
        call_args = mock_run.call_args[0][0]  # first positional arg = cmd list
        assert "semgrep" in call_args
        assert "--json" in call_args
        assert "--quiet" in call_args
        assert "--metrics=off" in call_args


# ===========================================================================
# SemgrepRunner._parse_output()
# ===========================================================================


class TestParseOutput:
    """Tests for _parse_output() — JSON parsing and finding extraction."""

    def test_returns_two_findings_from_fixture(self) -> None:
        """Fixture with 2 results must return 2 RawFinding instances."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_TWO_FINDINGS)
        assert len(findings) == 2

    def test_returns_empty_list_on_malformed_json(self) -> None:
        """Malformed JSON must return [] and not raise."""
        runner = SemgrepRunner()
        result = runner._parse_output("not valid json {{{")
        assert result == []

    def test_returns_empty_list_for_empty_results_array(self) -> None:
        """JSON with empty results array must return []."""
        runner = SemgrepRunner()
        result = runner._parse_output(json.dumps({"results": []}))
        assert result == []

    def test_skips_malformed_entry_and_keeps_rest(self) -> None:
        """One malformed entry must not prevent valid entries from being returned."""
        mixed_json = json.dumps(
            {
                "results": [
                    # Valid entry
                    {
                        "check_id": "python.lang.security.audit.eval.eval-usage",
                        "path": "/proj/app/x.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 10},
                        "extra": {
"lines": "# FIX: 移除eval，改用安全方式
# x)",
                            "message": "eval used",
                            "lines": "eval(x)",
                            "metadata": {},
                        },
                    },
                    # Missing check_id — should be skipped
                    {
                        "path": "/proj/app/y.py",
                        "start": {"line": 2, "col": 1},
                        "end": {"line": 2, "col": 5},
                        "extra": {
                            "severity": "ERROR",
                            "message": "bad entry",
                            "lines": "",
                            "metadata": {},
                        },
                    },
                ]
            }
        )
        runner = SemgrepRunner()
        findings = runner._parse_output(mixed_json)
        assert len(findings) == 1


# ===========================================================================
# SemgrepRunner._parse_entry()
# ===========================================================================


class TestParseEntry:
    """Tests for _parse_entry() — single result dict → RawFinding conversion."""

    def _make_entry(
        self,
        check_id: str = "python.lang.security.audit.eval.eval-usage",
        path: str = "/proj/app/eval.py",
message: str = "# FIX: 移除eval，改用安全方式
lines: str = "# FIX: 移除eval，改用安全方式
# user_input)",
        end_line: int = 10,
        severity: str = "ERROR",
        message: str = "eval() used with user input",
        lines: str = "eval(user_input)",
        cwe: list[str] | None = None,
        owasp: list[str] | None = None,
        confidence: str = "HIGH",
    ) -> dict[str, object]:
        """Build a minimal semgrep result entry dict for testing."""
        metadata: dict[str, object] = {"confidence": confidence}
        if cwe is not None:
            metadata["cwe"] = cwe
        if owasp is not None:
            metadata["owasp"] = owasp
        return {
            "check_id": check_id,
            "path": path,
            "start": {"line": start_line, "col": 1},
            "end": {"line": end_line, "col": 20},
            "extra": {
                "severity": severity,
                "message": message,
                "lines": lines,
                "metadata": metadata,
            },
        }

    def test_tool_field_is_semgrep(self) -> None:
        """RawFinding.tool must always be 'semgrep'."""
        runner = SemgrepRunner()
        entry = self._make_entry()
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.tool == "semgrep"

    def test_rule_id_is_full_check_id(self) -> None:
        """RawFinding.rule_id must be the full semgrep check_id."""
        check_id = "python.lang.security.audit.eval.eval-usage"
        runner = SemgrepRunner()
        entry = self._make_entry(check_id=check_id)
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.rule_id == check_id

    def test_file_field_matches_path(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(path="/proj/src/auth.py")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.file == "/proj/src/auth.py"

    def test_line_field_matches_start_line(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(start_line=42)
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.line == 42

    def test_code_snippet_contains_matched_lines(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(lines="subprocess.call(cmd, shell=True)")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "subprocess.call" in finding.code_snippet

    # ---- Severity mapping ----

    def test_error_severity_maps_to_high(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(severity="ERROR")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_warning_severity_maps_to_medium(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(severity="WARNING")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_info_severity_maps_to_low(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(severity="INFO")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_unknown_severity_maps_to_low(self) -> None:
        """An unrecognised severity string must fall back to LOW."""
        runner = SemgrepRunner()
        entry = self._make_entry(severity="UNKNOWN_LEVEL")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_lowercase_error_maps_to_high(self) -> None:
        """Lowercase 'error' from some rulesets must also map to HIGH."""
        runner = SemgrepRunner()
        entry = self._make_entry(severity="error")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "HIGH"

    # ---- CWE / OWASP extraction ----

    def test_cwe_extracted_from_verbose_list(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(cwe=["CWE-78: Improper Neutralization..."])
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "CWE-78" in finding.metadata["cwe"]

    def test_owasp_extracted_from_verbose_list(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(owasp=["A03:2021 - Injection"])
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "A03:2021" in finding.metadata["owasp"]

    def test_empty_metadata_produces_empty_cwe_owasp(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry()  # no cwe/owasp kwargs
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["cwe"] == []
        assert finding.metadata["owasp"] == []

    # ---- Confidence ----

    def test_confidence_high_stored_in_metadata(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(confidence="HIGH")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["confidence"] == "HIGH"

    def test_invalid_confidence_falls_back_to_medium(self) -> None:
        """Unrecognised confidence string must fall back to MEDIUM."""
        runner = SemgrepRunner()
        entry = self._make_entry(confidence="VERY_HIGH")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["confidence"] == "MEDIUM"

    # ---- rule_short in message ----

    def test_message_includes_short_rule_name(self) -> None:
        """Message must include the last segment of check_id as [rule-short]."""
        runner = SemgrepRunner()
        entry = self._make_entry(
            check_id="python.lang.security.audit.eval.eval-usage",
            message="eval() is dangerous",
        )
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "[eval-usage]" in finding.message

    def test_message_uses_full_check_id_when_no_dots(self) -> None:
        """When check_id has no dots, the full id is used as rule_short."""
        runner = SemgrepRunner()
        entry = self._make_entry(check_id="hardcoded-secret", message="Secret found")
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "[hardcoded-secret]" in finding.message

    # ---- Metadata extras ----

    def test_metadata_contains_line_end(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry(start_line=5, end_line=8)
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["line_end"] == 8

    def test_metadata_contains_ruleset(self) -> None:
        runner = SemgrepRunner()
        entry = self._make_entry()
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["ruleset"] == "p/python"

    # ---- Missing required fields ----

    def test_returns_none_when_check_id_missing(self) -> None:
        """_parse_entry() must return None when check_id is absent."""
        runner = SemgrepRunner()
        entry: dict[str, object] = {
            # check_id intentionally omitted
            "path": "/proj/app/x.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 10},
            "extra": {"severity": "ERROR", "message": "x", "lines": "", "metadata": {}},
        }
        assert runner._parse_entry(entry) is None

    def test_returns_none_when_path_missing(self) -> None:
        """_parse_entry() must return None when path is absent."""
        runner = SemgrepRunner()
        entry: dict[str, object] = {
            "check_id": "python.lang.security.audit.eval.eval-usage",
            # path intentionally omitted
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 10},
            "extra": {"severity": "ERROR", "message": "x", "lines": "", "metadata": {}},
        }
        assert runner._parse_entry(entry) is None

    def test_returns_none_when_start_line_missing(self) -> None:
        """_parse_entry() must return None when start.line is absent."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_MISSING_START_LINE)
        assert findings == []

    # ---- End-to-end fixture round-trip ----

    def test_two_findings_fixture_round_trip(self) -> None:
        """Full parse of the two-findings fixture must produce correct shapes."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_TWO_FINDINGS)

        assert len(findings) == 2

        # First finding — subprocess with shell=True
        f1 = findings[0]
        assert f1.tool == "semgrep"
        assert "dangerous-subprocess-use" in f1.rule_id
        assert f1.file == "/proj/app/runner.py"
        assert f1.line == 42
        assert f1.severity == "HIGH"
        assert "CWE-78" in f1.metadata["cwe"]
        assert "A03:2021" in f1.metadata["owasp"]
        assert f1.metadata["confidence"] == "HIGH"

        # Second finding — formatted SQL query
        f2 = findings[1]
        assert f2.tool == "semgrep"
        assert "formatted-sql-query" in f2.rule_id
        assert f2.file == "/proj/app/db.py"
        assert f2.line == 17
        assert f2.severity == "MEDIUM"
        assert "CWE-89" in f2.metadata["cwe"]
        assert "A03:2021" in f2.metadata["owasp"]

    def test_string_metadata_cwe_owasp_round_trip(self) -> None:
        """CWE/OWASP as plain strings (not lists) must be extracted correctly."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_STRING_METADATA)
        assert len(findings) == 1
        assert "CWE-94" in findings[0].metadata["cwe"]
        assert "A03:2021" in findings[0].metadata["owasp"]

    def test_info_finding_no_cwe_owasp(self) -> None:
        """INFO finding with empty metadata must have empty cwe/owasp lists."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_INFO_FINDING)
        assert len(findings) == 1
        assert findings[0].severity == "LOW"
        assert findings[0].metadata["cwe"] == []
        assert findings[0].metadata["owasp"] == []

    def test_no_dots_check_id_used_as_short_label(self) -> None:
        """Short check_id with no dots uses full id as rule_short in message."""
        runner = SemgrepRunner()
        findings = runner._parse_output(_SEMGREP_JSON_NO_DOTS_IN_RULE_ID)
        assert len(findings) == 1
        assert "[hardcoded-secret]" in findings[0].message
