"""test_bandit.py — Unit tests for the Shield Bandit runner.

Tests cover:
  - BanditRunner.scan() returns [] when bandit is not on PATH
  - BanditRunner.scan() delegates to _run_bandit() when bandit is available
  - _parse_output() correctly parses a realistic bandit JSON fixture
  - _parse_entry() maps HIGH/MEDIUM/LOW severity and confidence correctly
  - _parse_entry() resolves CWE from the static map (B602 → CWE-78)
  - _parse_entry() falls back to bandit's own issue_cwe field for unknown IDs
  - _parse_entry() returns None for entries missing required fields
  - _run_bandit() returns [] and logs error on exit code 2+
  - _run_bandit() returns [] on subprocess timeout
  - _run_bandit() returns [] on empty stdout
  - _parse_output() returns [] on malformed JSON
  - RawFinding shape: tool="bandit", correct rule_id, file, line, severity, message

All tests are self-contained — no network calls, no bandit binary required.
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
# Path setup — mirrors the pattern in test_secrets.py
# ---------------------------------------------------------------------------
_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

# ---------------------------------------------------------------------------
# Imports (after path setup)
# ---------------------------------------------------------------------------
from scanner.detectors.bandit import (  # noqa: E402
    PIPELINE_PRIORITY,
    BanditRunner,
    _BANDIT_CWE_MAP,
    _CONFIDENCE_MAP,
    _SEVERITY_MAP,
)
from scanner.detectors.secrets import RawFinding  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A realistic bandit JSON output with two findings.
_BANDIT_JSON_TWO_FINDINGS: str = json.dumps(
    {
        "errors": [],
        "generated_at": "2026-05-05T12:00:00Z",
        "metrics": {},
        "results": [
            {
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "filename": "/proj/app/runner.py",
                "line_number": 42,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
                "code": "42 subprocess.Popen(cmd, shell=True)\n",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
            },
            {
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "filename": "/proj/app/config.py",
                "line_number": 7,
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password: 'hunter2'",
                "code": "7 PASSWORD = 'hunter2'\n",
                "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
            },
        ],
    }
)

# A bandit JSON with a test_id that is NOT in our static CWE map.
_BANDIT_JSON_UNKNOWN_TEST_ID: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                "test_id": "B999",
                "test_name": "hypothetical_future_test",
                "filename": "/proj/app/foo.py",
                "line_number": 1,
                "issue_severity": "LOW",
                "issue_confidence": "LOW",
                "issue_text": "Some hypothetical issue",
                "code": "1 foo()\n",
                "issue_cwe": {"id": 999, "link": "https://cwe.mitre.org/..."},
                "more_info": "",
            }
        ],
    }
)

# A bandit JSON entry missing the required `test_id` field.
_BANDIT_JSON_MISSING_REQUIRED: str = json.dumps(
    {
        "errors": [],
        "results": [
            {
                # test_id intentionally omitted
                "filename": "/proj/app/bad.py",
                "line_number": 5,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Missing test_id field",
                "code": "5 bad()\n",
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
        args=["bandit"],
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

    def test_pipeline_priority_is_one(self) -> None:
        """BanditRunner must have PIPELINE_PRIORITY=1 (after secrets=0)."""
        assert PIPELINE_PRIORITY == 1

    def test_severity_map_covers_all_bandit_levels(self) -> None:
        """_SEVERITY_MAP must cover HIGH, MEDIUM, LOW."""
        assert set(_SEVERITY_MAP.keys()) == {"HIGH", "MEDIUM", "LOW"}

    def test_confidence_map_covers_all_bandit_levels(self) -> None:
        """_CONFIDENCE_MAP must cover HIGH, MEDIUM, LOW."""
        assert set(_CONFIDENCE_MAP.keys()) == {"HIGH", "MEDIUM", "LOW"}

    def test_cwe_map_contains_required_test_ids(self) -> None:
        """The ten required CWE mappings from the spec must be present."""
        required = {"B101", "B102", "B103", "B104", "B105", "B106", "B107", "B108", "B110", "B201"}
        assert required.issubset(_BANDIT_CWE_MAP.keys())

    def test_b602_maps_to_cwe_78(self) -> None:
        """B602 (subprocess shell=True) must map to CWE-78 (OS Command Injection)."""
        assert "CWE-78" in _BANDIT_CWE_MAP["B602"]

    def test_b105_maps_to_cwe_259(self) -> None:
        """B105 (hardcoded_password_string) must map to CWE-259."""
        assert "CWE-259" in _BANDIT_CWE_MAP["B105"]

    def test_b201_maps_to_cwe_94(self) -> None:
        """B201 (flask_debug_true) must map to CWE-94."""
        assert "CWE-94" in _BANDIT_CWE_MAP["B201"]


# ===========================================================================
# BanditRunner.scan() — top-level dispatch
# ===========================================================================


class TestBanditRunnerScan:
    """Tests for BanditRunner.scan() — the public entry point."""

    def test_returns_empty_list_when_bandit_not_installed(self) -> None:
        """scan() must return [] and not raise when bandit is missing from PATH."""
        runner = BanditRunner()
        with (
            patch.object(runner, "_bandit_available", return_value=False),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner.scan(Path(tmp))
        assert result == []

    def test_delegates_to_run_bandit_when_available(self) -> None:
        """scan() must call _run_bandit() when bandit is on PATH."""
        runner = BanditRunner()
        sentinel: list[RawFinding] = []
        with (
            patch.object(runner, "_bandit_available", return_value=True),
            patch.object(runner, "_run_bandit", return_value=sentinel) as mock_run,
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner.scan(Path(tmp))
        mock_run.assert_called_once()
        assert result is sentinel


# ===========================================================================
# BanditRunner._bandit_available()
# ===========================================================================


class TestBanditAvailable:
    """Tests for _bandit_available() — PATH probe."""

    def test_returns_true_when_bandit_exits_successfully(self) -> None:
        """_bandit_available() returns True when bandit --version succeeds."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(returncode=0)
            assert runner._bandit_available() is True

    def test_returns_false_when_bandit_not_found(self) -> None:
        """_bandit_available() returns False when FileNotFoundError is raised."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run", side_effect=FileNotFoundError):
            assert runner._bandit_available() is False


# ===========================================================================
# BanditRunner._run_bandit()
# ===========================================================================


class TestRunBandit:
    """Tests for _run_bandit() — subprocess execution and error handling."""

    def test_returns_findings_on_exit_code_1(self) -> None:
        """Exit code 1 (findings present) must still parse and return findings."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=_BANDIT_JSON_TWO_FINDINGS,
                returncode=1,  # bandit normal "findings present" exit code
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_bandit(Path(tmp))
        assert len(findings) == 2

    def test_returns_findings_on_exit_code_0(self) -> None:
        """Exit code 0 (clean scan) must return an empty list."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=json.dumps({"results": []}),
                returncode=0,
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_bandit(Path(tmp))
        assert findings == []

    def test_returns_empty_list_on_exit_code_2(self) -> None:
        """Exit code 2+ (bandit error) must return [] and not raise."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stderr="bandit: error: ...",
                returncode=2,
            )
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_bandit(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_timeout(self) -> None:
        """TimeoutExpired must be caught — returns [] without raising."""
        runner = BanditRunner()
        with (
            patch(
                "scanner.detectors.bandit.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["bandit"], timeout=120),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_bandit(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_os_error(self) -> None:
        """OSError on subprocess start must be caught — returns []."""
        runner = BanditRunner()
        with (
            patch(
                "scanner.detectors.bandit.subprocess.run",
                side_effect=OSError("Permission denied"),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_bandit(Path(tmp))
        assert result == []

    def test_returns_empty_list_on_empty_stdout(self) -> None:
        """Empty stdout (e.g. bandit ran but produced nothing) returns []."""
        runner = BanditRunner()
        with patch("scanner.detectors.bandit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(stdout="   ", returncode=0)
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_bandit(Path(tmp))
        assert result == []


# ===========================================================================
# BanditRunner._parse_output()
# ===========================================================================


class TestParseOutput:
    """Tests for _parse_output() — JSON deserialization."""

    def test_parses_two_findings(self) -> None:
        """Two valid result entries → two RawFinding objects."""
        runner = BanditRunner()
        findings = runner._parse_output(_BANDIT_JSON_TWO_FINDINGS)
        assert len(findings) == 2

    def test_returns_empty_list_on_malformed_json(self) -> None:
        """Invalid JSON must not raise — returns [] with a logged error."""
        runner = BanditRunner()
        result = runner._parse_output("{not valid json")
        assert result == []

    def test_returns_empty_list_for_empty_results_array(self) -> None:
        """Empty results array → empty list."""
        runner = BanditRunner()
        result = runner._parse_output(json.dumps({"results": []}))
        assert result == []

    def test_skips_malformed_entry_keeps_valid_ones(self) -> None:
        """One malformed entry in results must not prevent valid entries from parsing."""
        runner = BanditRunner()
        mixed_json = json.dumps(
            {
                "results": [
                    # malformed — missing test_id and filename
                    {"line_number": 1},
                    # valid
                    {
                        "test_id": "B602",
                        "test_name": "subprocess_popen_with_shell_equals_true",
                        "filename": "/proj/app/runner.py",
                        "line_number": 10,
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_text": "shell=True",
                        "code": "10 subprocess.call(cmd, shell=True)\n",
                        "issue_cwe": {},
                        "more_info": "",
                    },
                ]
            }
        )
        findings = runner._parse_output(mixed_json)
        assert len(findings) == 1
        assert findings[0].rule_id == "B602"


# ===========================================================================
# BanditRunner._parse_entry()
# ===========================================================================


class TestParseEntry:
    """Tests for _parse_entry() — single result dict → RawFinding."""

    def _valid_entry(self) -> dict[str, object]:
        """Return a minimal valid bandit result entry."""
        return {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "filename": "/proj/app/runner.py",
            "line_number": 42,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "subprocess call with shell=True",
            "code": "42 subprocess.Popen(cmd, shell=True)\n",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/..."},
            "more_info": "https://bandit.readthedocs.io/...",
        }

    def test_returns_raw_finding_for_valid_entry(self) -> None:
        """A fully valid entry must produce a non-None RawFinding."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert isinstance(finding, RawFinding)

    def test_tool_is_bandit(self) -> None:
        """RawFinding.tool must always be 'bandit'."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert finding.tool == "bandit"

    def test_rule_id_is_test_id(self) -> None:
        """RawFinding.rule_id must equal the bandit test_id (e.g. 'B602')."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert finding.rule_id == "B602"

    def test_file_and_line_are_set_correctly(self) -> None:
        """RawFinding.file and .line must match filename and line_number."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert finding.file == "/proj/app/runner.py"
        assert finding.line == 42

    def test_severity_high_maps_correctly(self) -> None:
        """issue_severity=HIGH → severity='HIGH'."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_severity_medium_maps_correctly(self) -> None:
        """issue_severity=MEDIUM → severity='MEDIUM'."""
        runner = BanditRunner()
        entry = self._valid_entry()
        entry["issue_severity"] = "MEDIUM"
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_severity_low_maps_correctly(self) -> None:
        """issue_severity=LOW → severity='LOW'."""
        runner = BanditRunner()
        entry = self._valid_entry()
        entry["issue_severity"] = "LOW"
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_unknown_severity_defaults_to_low(self) -> None:
        """Unknown severity string must default to 'LOW' (safe fallback)."""
        runner = BanditRunner()
        entry = self._valid_entry()
        entry["issue_severity"] = "UNDEFINED"
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_confidence_stored_in_metadata(self) -> None:
        """Bandit confidence must be preserved in metadata['confidence']."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert finding.metadata["confidence"] == "HIGH"

    def test_cwe_from_static_map_for_b602(self) -> None:
        """B602 must resolve CWE-78 from the static map (not bandit's field)."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert "CWE-78" in finding.metadata["cwe"]

    def test_cwe_fallback_to_bandit_field_for_unknown_test_id(self) -> None:
        """Unknown test_id (not in static map) must fall back to issue_cwe.id."""
        runner = BanditRunner()
        entry: dict[str, object] = {
            "test_id": "B999",
            "test_name": "hypothetical_test",
            "filename": "/proj/foo.py",
            "line_number": 1,
            "issue_severity": "LOW",
            "issue_confidence": "LOW",
            "issue_text": "Hypothetical issue",
            "code": "1 foo()\n",
            "issue_cwe": {"id": 999, "link": ""},
            "more_info": "",
        }
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "CWE-999" in finding.metadata["cwe"]

    def test_cwe_empty_for_unknown_test_id_with_no_bandit_cwe(self) -> None:
        """If test_id unknown AND issue_cwe missing, cwe must be empty list."""
        runner = BanditRunner()
        entry: dict[str, object] = {
            "test_id": "B999",
            "test_name": "hypothetical_test",
            "filename": "/proj/foo.py",
            "line_number": 1,
            "issue_severity": "LOW",
            "issue_confidence": "LOW",
            "issue_text": "Hypothetical issue",
            "code": "1 foo()\n",
            "issue_cwe": {},  # no id key
            "more_info": "",
        }
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert finding.metadata["cwe"] == []

    def test_message_includes_test_id_and_test_name(self) -> None:
        """Message must include both the test_id and test_name for traceability."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert "B602" in finding.message
        assert "subprocess_popen_with_shell_equals_true" in finding.message

    def test_message_without_test_name_still_includes_test_id(self) -> None:
        """When test_name is absent the message still includes the test_id."""
        runner = BanditRunner()
        entry = self._valid_entry()
        entry["test_name"] = ""
        finding = runner._parse_entry(entry)
        assert finding is not None
        assert "B602" in finding.message

    def test_code_snippet_is_set(self) -> None:
        """RawFinding.code_snippet must contain bandit's code field."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert "subprocess.Popen" in finding.code_snippet

    def test_returns_none_for_missing_test_id(self) -> None:
        """Entry missing test_id must return None (not raise)."""
        runner = BanditRunner()
        entry = self._valid_entry()
        del entry["test_id"]  # type: ignore[misc]
        result = runner._parse_entry(entry)
        assert result is None

    def test_returns_none_for_missing_filename(self) -> None:
        """Entry missing filename must return None (not raise)."""
        runner = BanditRunner()
        entry = self._valid_entry()
        del entry["filename"]  # type: ignore[misc]
        result = runner._parse_entry(entry)
        assert result is None

    def test_returns_none_for_missing_line_number(self) -> None:
        """Entry missing line_number must return None (not raise)."""
        runner = BanditRunner()
        entry = self._valid_entry()
        del entry["line_number"]  # type: ignore[misc]
        result = runner._parse_entry(entry)
        assert result is None

    def test_more_info_stored_in_metadata(self) -> None:
        """more_info URL must be preserved in metadata for developer reference."""
        runner = BanditRunner()
        finding = runner._parse_entry(self._valid_entry())
        assert finding is not None
        assert "more_info" in finding.metadata


# ===========================================================================
# End-to-end: parse the two-finding fixture fully
# ===========================================================================


class TestEndToEndParsing:
    """End-to-end parse of the two-finding fixture — validates full data flow."""

    def setup_method(self) -> None:
        """Parse the standard fixture once; reuse across test methods."""
        runner = BanditRunner()
        self.findings = runner._parse_output(_BANDIT_JSON_TWO_FINDINGS)

    def test_finding_count(self) -> None:
        """Fixture has two results — both must parse successfully."""
        assert len(self.findings) == 2

    def test_first_finding_is_high_severity_b602(self) -> None:
        """First finding: B602, HIGH severity, file runner.py, line 42."""
        f = self.findings[0]
        assert f.tool == "bandit"
        assert f.rule_id == "B602"
        assert f.severity == "HIGH"
        assert f.file == "/proj/app/runner.py"
        assert f.line == 42
        assert "CWE-78" in f.metadata["cwe"]

    def test_second_finding_is_medium_severity_b105(self) -> None:
        """Second finding: B105, MEDIUM severity, file config.py, line 7."""
        f = self.findings[1]
        assert f.tool == "bandit"
        assert f.rule_id == "B105"
        assert f.severity == "MEDIUM"
        assert f.file == "/proj/app/config.py"
        assert f.line == 7
        assert "CWE-259" in f.metadata["cwe"]
