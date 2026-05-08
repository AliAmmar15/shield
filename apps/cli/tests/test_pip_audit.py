"""test_pip_audit.py — Unit tests for the Shield pip-audit runner.

Tests cover:
  - PipAuditRunner.scan() returns [] when pip-audit is not on PATH
  - PipAuditRunner.scan() finds requirements files and passes them to _run_pip_audit
  - PipAuditRunner.scan() falls back to --local when no requirements file found
  - _pip_audit_available() returns True/False correctly
  - _find_requirements() returns first matching candidate, or None
  - _run_pip_audit() handles exit codes 0 (clean), 1 (vulns), 2+ (error)
  - _run_pip_audit() handles TimeoutExpired and OSError gracefully
  - _run_pip_audit() handles empty stdout
  - _run_pip_audit() passes -r <file> when req_file is set, --local when not
  - _parse_output() correctly parses a realistic pip-audit JSON fixture
  - _parse_output() handles dict-wrapped JSON (some pip-audit versions)
  - _parse_output() returns [] on malformed JSON
  - _parse_package() skips malformed entries
  - _parse_package() returns [] for packages with no vulns
  - _parse_vuln() returns None when vuln id is missing
  - _parse_vuln() maps CVSS scores to correct severity
  - _parse_vuln() defaults to MEDIUM when no CVSS data
  - _parse_vuln() includes CVE alias in message when available
  - _parse_vuln() includes fix version hint in message
  - _parse_vuln() sets fix_available=True/False correctly
  - _extract_cvss_score() returns highest score from multi-entry list
  - _extract_cvss_score() returns None for empty/None/malformed input
  - _cvss_to_severity() maps correctly across all thresholds
  - RawFinding shape: tool="pip-audit", cwe=["CWE-1035"], owasp=["A06:2021"]

All tests are self-contained — no network calls, no pip-audit binary required.
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
# Path setup — mirrors the pattern in test_bandit.py / test_semgrep.py
# ---------------------------------------------------------------------------
_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_scanner_root = _repo_root / "packages" / "scanner"

if str(_scanner_root) not in sys.path:
    sys.path.insert(0, str(_scanner_root))

# ---------------------------------------------------------------------------
# Imports (after path setup)
# ---------------------------------------------------------------------------
from scanner.detectors.pip_audit import (  # noqa: E402
    PIPELINE_PRIORITY,
    PipAuditRunner,
    _CWE,
    _OWASP,
    _REQUIREMENTS_CANDIDATES,
    _cvss_to_severity,
    _extract_cvss_score,
)
# RawFinding used only at runtime via pip_audit internals; not needed directly in tests

# ---------------------------------------------------------------------------
# Fixtures — realistic pip-audit JSON payloads
# ---------------------------------------------------------------------------

# A realistic pip-audit JSON output with two vulnerable packages.
# requests has a known CVE with a CVSS score; aiohttp has a PYSEC ID only.
_PIP_AUDIT_JSON_TWO_VULNS: str = json.dumps(
    [
        {
            "name": "requests",
            "version": "2.25.1",
            "vulns": [
                {
                    "id": "PYSEC-2023-74",
                    "fix_versions": ["2.31.0"],
                    "aliases": ["CVE-2023-32681"],
                    "description": "Requests forwards proxy-authorization headers to destination servers when a redirect to a different origin occurs.",
                    "cvss": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
                            "base_score": 6.1,
                        }
                    ],
                }
            ],
        },
        {
            "name": "aiohttp",
            "version": "3.8.0",
            "vulns": [
                {
                    "id": "PYSEC-2024-15",
                    "fix_versions": ["3.9.0"],
                    "aliases": [],
                    "description": "CRLF injection in HTTP headers.",
                    "cvss": [],
                }
            ],
        },
    ]
)

# A pip-audit JSON with a CRITICAL CVSS score (>= 9.0).
_PIP_AUDIT_JSON_CRITICAL: str = json.dumps(
    [
        {
            "name": "pillow",
            "version": "8.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2021-1",
                    "fix_versions": ["9.0.0"],
                    "aliases": ["CVE-2021-27921"],
                    "description": "Buffer overflow vulnerability in Pillow.",
                    "cvss": [{"type": "CVSS_V3", "score": "CVSS:3.1/...", "base_score": 9.8}],
                }
            ],
        }
    ]
)

# A pip-audit JSON with a HIGH CVSS score (7.0 <= score < 9.0).
_PIP_AUDIT_JSON_HIGH: str = json.dumps(
    [
        {
            "name": "django",
            "version": "3.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2021-50",
                    "fix_versions": ["3.2.14"],
                    "aliases": ["CVE-2021-35042"],
                    "description": "SQL injection via crafted JSON.",
                    "cvss": [{"type": "CVSS_V3", "score": "CVSS:3.1/...", "base_score": 7.5}],
                }
            ],
        }
    ]
)

# A pip-audit JSON with a LOW CVSS score (< 4.0).
_PIP_AUDIT_JSON_LOW: str = json.dumps(
    [
        {
            "name": "somelib",
            "version": "1.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2023-99",
                    "fix_versions": ["1.1.0"],
                    "aliases": [],
                    "description": "Minor info disclosure.",
                    "cvss": [{"type": "CVSS_V3", "score": "CVSS:3.1/...", "base_score": 2.5}],
                }
            ],
        }
    ]
)

# A pip-audit JSON where the package has no vulns — should produce no findings.
_PIP_AUDIT_JSON_NO_VULNS: str = json.dumps([{"name": "httpx", "version": "0.24.0", "vulns": []}])

# A pip-audit JSON missing a required field in the vulnerability entry.
_PIP_AUDIT_JSON_MISSING_VULN_ID: str = json.dumps(
    [
        {
            "name": "badlib",
            "version": "0.1.0",
            "vulns": [
                {
                    # id intentionally omitted
                    "fix_versions": ["0.2.0"],
                    "aliases": [],
                    "description": "Missing id field.",
                    "cvss": [],
                }
            ],
        }
    ]
)

# A pip-audit JSON missing package name — entire package entry should be skipped.
_PIP_AUDIT_JSON_MISSING_PKG_NAME: str = json.dumps(
    [
        {
            # name intentionally omitted
            "version": "1.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2023-1",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "",
                    "cvss": [],
                }
            ],
        }
    ]
)

# pip-audit dict-wrapped format (some older versions emit {"dependencies": [...]}).
_PIP_AUDIT_JSON_DICT_WRAPPED: str = json.dumps(
    {
        "dependencies": [
            {
                "name": "urllib3",
                "version": "1.26.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-192",
                        "fix_versions": ["1.26.18"],
                        "aliases": ["CVE-2023-43804"],
                        "description": "urllib3 doesn't treat the Cookie HTTP header as sensitive.",
                        "cvss": [{"type": "CVSS_V3", "score": "CVSS:3.1/...", "base_score": 8.1}],
                    }
                ],
            }
        ]
    }
)


def _make_completed_process(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    """Build a mock CompletedProcess for use in patch targets."""
    return subprocess.CompletedProcess(
        args=["pip-audit"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


# ===========================================================================
# Module-level constants
# ===========================================================================


class TestModuleConstants:
    """Sanity-checks on module-level constants."""

    def test_pipeline_priority_is_three(self) -> None:
        """PipAuditRunner must have PIPELINE_PRIORITY=3 (last in pipeline)."""
        assert PIPELINE_PRIORITY == 3

    def test_cwe_is_cwe_1035(self) -> None:
        """All pip-audit findings must carry CWE-1035."""
        assert _CWE == ["CWE-1035"]

    def test_owasp_is_a06_2021(self) -> None:
        """All pip-audit findings must carry A06:2021."""
        assert _OWASP == ["A06:2021"]

    def test_requirements_candidates_contains_requirements_txt(self) -> None:
        """requirements.txt must be first in the candidates list."""
        assert _REQUIREMENTS_CANDIDATES[0] == "requirements.txt"

    def test_requirements_candidates_contains_dev(self) -> None:
        """requirements-dev.txt must be in candidates."""
        assert "requirements-dev.txt" in _REQUIREMENTS_CANDIDATES


# ===========================================================================
# _extract_cvss_score()
# ===========================================================================


class TestExtractCvssScore:
    """Tests for the _extract_cvss_score() module-level helper."""

    def test_returns_score_from_single_entry(self) -> None:
        cvss = [{"type": "CVSS_V3", "base_score": 7.5}]
        assert _extract_cvss_score(cvss) == 7.5

    def test_returns_highest_score_from_multiple_entries(self) -> None:
        cvss = [
            {"type": "CVSS_V3", "base_score": 6.1},
            {"type": "CVSS_V3", "base_score": 9.2},
        ]
        assert _extract_cvss_score(cvss) == 9.2

    def test_returns_none_for_empty_list(self) -> None:
        assert _extract_cvss_score([]) is None

    def test_returns_none_for_none_input(self) -> None:
        assert _extract_cvss_score(None) is None

    def test_returns_none_when_base_score_missing(self) -> None:
        cvss = [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}]  # no base_score key
        assert _extract_cvss_score(cvss) is None

    def test_returns_none_for_non_list_input(self) -> None:
        assert _extract_cvss_score("not-a-list") is None

    def test_skips_non_dict_entries(self) -> None:
        """Non-dict items in the CVSS list must be silently skipped."""
        cvss = ["not-a-dict", {"type": "CVSS_V3", "base_score": 5.0}]
        assert _extract_cvss_score(cvss) == 5.0

    def test_skips_non_numeric_base_score(self) -> None:
        cvss = [{"type": "CVSS_V3", "base_score": "not-a-number"}]
        assert _extract_cvss_score(cvss) is None

    def test_integer_base_score_accepted(self) -> None:
        """Integer base_score must be coerced to float."""
        cvss = [{"type": "CVSS_V3", "base_score": 8}]
        assert _extract_cvss_score(cvss) == 8.0


# ===========================================================================
# _cvss_to_severity()
# ===========================================================================


class TestCvssToSeverity:
    """Tests for the _cvss_to_severity() module-level helper."""

    def test_none_maps_to_medium(self) -> None:
        """No CVSS data → safe default of MEDIUM."""
        assert _cvss_to_severity(None) == "MEDIUM"

    def test_score_10_maps_to_critical(self) -> None:
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_score_9_0_maps_to_critical(self) -> None:
        assert _cvss_to_severity(9.0) == "CRITICAL"

    def test_score_8_9_maps_to_high(self) -> None:
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_score_7_0_maps_to_high(self) -> None:
        assert _cvss_to_severity(7.0) == "HIGH"

    def test_score_6_9_maps_to_medium(self) -> None:
        assert _cvss_to_severity(6.9) == "MEDIUM"

    def test_score_4_0_maps_to_medium(self) -> None:
        assert _cvss_to_severity(4.0) == "MEDIUM"

    def test_score_3_9_maps_to_low(self) -> None:
        assert _cvss_to_severity(3.9) == "LOW"

    def test_score_0_1_maps_to_low(self) -> None:
        assert _cvss_to_severity(0.1) == "LOW"

    def test_score_0_maps_to_low(self) -> None:
        assert _cvss_to_severity(0.0) == "LOW"


# ===========================================================================
# PipAuditRunner._pip_audit_available()
# ===========================================================================


class TestPipAuditAvailable:
    """Tests for _pip_audit_available() — PATH probe."""

    def test_returns_true_when_pip_audit_exits_successfully(self) -> None:
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(returncode=0)
            assert runner._pip_audit_available() is True

    def test_returns_false_when_pip_audit_not_found(self) -> None:
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run", side_effect=FileNotFoundError):
            assert runner._pip_audit_available() is False


# ===========================================================================
# PipAuditRunner._find_requirements()
# ===========================================================================


class TestFindRequirements:
    """Tests for _find_requirements() — requirements file probe."""

    def test_returns_requirements_txt_when_present(self) -> None:
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text("requests==2.25.1\n")
            result = runner._find_requirements(Path(tmp))
        assert result is not None
        assert result.name == "requirements.txt"

    def test_returns_requirements_dev_when_no_requirements_txt(self) -> None:
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements-dev.txt"
            req.write_text("pytest==7.0.0\n")
            result = runner._find_requirements(Path(tmp))
        assert result is not None
        assert result.name == "requirements-dev.txt"

    def test_returns_none_when_no_requirements_file_found(self) -> None:
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            result = runner._find_requirements(Path(tmp))
        assert result is None

    def test_requirements_txt_takes_priority_over_dev(self) -> None:
        """requirements.txt must be returned before requirements-dev.txt."""
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "requirements.txt").write_text("requests==2.25.1\n")
            (Path(tmp) / "requirements-dev.txt").write_text("pytest==7.0.0\n")
            result = runner._find_requirements(Path(tmp))
        assert result is not None
        assert result.name == "requirements.txt"


# ===========================================================================
# PipAuditRunner.scan() — top-level dispatch
# ===========================================================================


class TestPipAuditRunnerScan:
    """Tests for PipAuditRunner.scan() — the public entry point."""

    def test_returns_empty_list_when_pip_audit_not_installed(self) -> None:
        runner = PipAuditRunner()
        with (
            patch.object(runner, "_pip_audit_available", return_value=False),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner.scan(Path(tmp))
        assert result == []

    def test_calls_run_pip_audit_with_req_file_when_found(self) -> None:
        """scan() must pass the found requirements file to _run_pip_audit()."""
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text("requests==2.25.1\n")
            with (
                patch.object(runner, "_pip_audit_available", return_value=True),
                patch.object(runner, "_run_pip_audit", return_value=[]) as mock_run,
            ):
                runner.scan(Path(tmp))
        mock_run.assert_called_once_with(Path(tmp), req)

    def test_calls_run_pip_audit_with_none_when_no_req_file(self) -> None:
        """scan() must pass None as req_file when no requirements file is found."""
        runner = PipAuditRunner()
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(runner, "_pip_audit_available", return_value=True),
            patch.object(runner, "_run_pip_audit", return_value=[]) as mock_run,
        ):
            runner.scan(Path(tmp))
        mock_run.assert_called_once_with(Path(tmp), None)


# ===========================================================================
# PipAuditRunner._run_pip_audit()
# ===========================================================================


class TestRunPipAudit:
    """Tests for _run_pip_audit() — subprocess execution and error handling."""

    def test_returns_findings_on_exit_code_1(self) -> None:
        """Exit code 1 (vulnerabilities found) must still parse and return findings."""
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=_PIP_AUDIT_JSON_TWO_VULNS,
                returncode=1,
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_pip_audit(Path(tmp), None)
        assert len(findings) == 2

    def test_returns_empty_list_on_exit_code_0(self) -> None:
        """Exit code 0 (no vulnerabilities) must return an empty list."""
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stdout=_PIP_AUDIT_JSON_NO_VULNS,
                returncode=0,
            )
            with tempfile.TemporaryDirectory() as tmp:
                findings = runner._run_pip_audit(Path(tmp), None)
        assert findings == []

    def test_returns_empty_list_on_exit_code_2(self) -> None:
        """Exit code 2+ (error) must return [] and not raise."""
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(
                stderr="pip-audit: error: ...",
                returncode=2,
            )
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_pip_audit(Path(tmp), None)
        assert result == []

    def test_returns_empty_list_on_timeout(self) -> None:
        runner = PipAuditRunner()
        with (
            patch(
                "scanner.detectors.pip_audit.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["pip-audit"], timeout=120),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_pip_audit(Path(tmp), None)
        assert result == []

    def test_returns_empty_list_on_os_error(self) -> None:
        runner = PipAuditRunner()
        with (
            patch(
                "scanner.detectors.pip_audit.subprocess.run",
                side_effect=OSError("Permission denied"),
            ),
            tempfile.TemporaryDirectory() as tmp,
        ):
            result = runner._run_pip_audit(Path(tmp), None)
        assert result == []

    def test_returns_empty_list_on_empty_stdout(self) -> None:
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(stdout="", returncode=0)
            with tempfile.TemporaryDirectory() as tmp:
                result = runner._run_pip_audit(Path(tmp), None)
        assert result == []

    def test_cmd_uses_local_when_no_req_file(self) -> None:
        """--local flag must appear in cmd when req_file is None."""
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(stdout=json.dumps([]), returncode=0)
            with tempfile.TemporaryDirectory() as tmp:
                runner._run_pip_audit(Path(tmp), None)
        call_args: list[str] = mock_run.call_args[0][0]
        assert "--local" in call_args
        assert "-r" not in call_args

    def test_cmd_uses_r_flag_when_req_file_provided(self) -> None:
        """-r <file> must appear in cmd when req_file is given, not --local."""
        runner = PipAuditRunner()
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "requirements.txt"
            req.write_text("requests==2.25.1\n")
            with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
                mock_run.return_value = _make_completed_process(stdout=json.dumps([]), returncode=0)
                runner._run_pip_audit(Path(tmp), req)
            call_args_list: list[str] = mock_run.call_args[0][0]
        assert "-r" in call_args_list
        assert "--local" not in call_args_list
        # The requirements file path must follow -r
        r_idx = call_args_list.index("-r")
        assert call_args_list[r_idx + 1] == str(req)

    def test_cmd_always_has_format_json_and_no_spinner(self) -> None:
        runner = PipAuditRunner()
        with patch("scanner.detectors.pip_audit.subprocess.run") as mock_run:
            mock_run.return_value = _make_completed_process(stdout=json.dumps([]), returncode=0)
            with tempfile.TemporaryDirectory() as tmp:
                runner._run_pip_audit(Path(tmp), None)
        call_args_list = mock_run.call_args[0][0]
        assert "--format" in call_args_list
        assert "json" in call_args_list
        assert "--progress-spinner" in call_args_list
        assert "off" in call_args_list


# ===========================================================================
# PipAuditRunner._parse_output()
# ===========================================================================


class TestParseOutput:
    """Tests for _parse_output() — JSON parsing and finding extraction."""

    def test_returns_two_findings_from_fixture(self) -> None:
        """Fixture with 2 vulnerable packages (one vuln each) → 2 findings."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert len(findings) == 2

    def test_returns_empty_list_on_malformed_json(self) -> None:
        runner = PipAuditRunner()
        result = runner._parse_output("not valid json {{{", "/proj")
        assert result == []

    def test_returns_empty_list_for_package_with_no_vulns(self) -> None:
        runner = PipAuditRunner()
        result = runner._parse_output(_PIP_AUDIT_JSON_NO_VULNS, "/proj")
        assert result == []

    def test_handles_dict_wrapped_format(self) -> None:
        """pip-audit dict-wrapped format must be unwrapped correctly."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_DICT_WRAPPED, "/proj")
        assert len(findings) == 1
        assert findings[0].metadata["package_name"] == "urllib3"

    def test_skips_missing_package_name(self) -> None:
        """Package entries missing name must be skipped — no findings returned."""
        runner = PipAuditRunner()
        result = runner._parse_output(_PIP_AUDIT_JSON_MISSING_PKG_NAME, "/proj")
        assert result == []

    def test_skips_missing_vuln_id(self) -> None:
        """Vulnerability entries missing id must be skipped."""
        runner = PipAuditRunner()
        result = runner._parse_output(_PIP_AUDIT_JSON_MISSING_VULN_ID, "/proj")
        assert result == []


# ===========================================================================
# PipAuditRunner._parse_vuln() — via _parse_output
# ===========================================================================


class TestParseVuln:
    """Tests for _parse_vuln() behaviour exercised through _parse_output()."""

    def test_tool_field_is_pip_audit(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert all(f.tool == "pip-audit" for f in findings)

    def test_rule_id_is_vuln_id(self) -> None:
        """RawFinding.rule_id must be the PYSEC/CVE vulnerability id."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        rule_ids = {f.rule_id for f in findings}
        assert "PYSEC-2023-74" in rule_ids
        assert "PYSEC-2024-15" in rule_ids

    def test_cwe_is_cwe_1035(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert all(f.metadata["cwe"] == ["CWE-1035"] for f in findings)

    def test_owasp_is_a06_2021(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert all(f.metadata["owasp"] == ["A06:2021"] for f in findings)

    def test_severity_critical_for_cvss_9_8(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_CRITICAL, "/proj")
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_severity_high_for_cvss_7_5(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_HIGH, "/proj")
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_severity_medium_for_cvss_6_1(self) -> None:
        """CVSS 6.1 is in the MEDIUM range (4.0–6.9)."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        requests_finding = next(f for f in findings if "requests" in f.message)
        assert requests_finding.severity == "MEDIUM"

    def test_severity_medium_when_no_cvss(self) -> None:
        """No CVSS data → default to MEDIUM (safe default)."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        aiohttp_finding = next(f for f in findings if "aiohttp" in f.message)
        assert aiohttp_finding.severity == "MEDIUM"

    def test_severity_low_for_cvss_2_5(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_LOW, "/proj")
        assert len(findings) == 1
        assert findings[0].severity == "LOW"

    def test_message_contains_cve_alias_when_available(self) -> None:
        """CVE alias must appear in the message instead of PYSEC id."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        requests_finding = next(f for f in findings if "requests" in f.message)
        assert "CVE-2023-32681" in requests_finding.message
        # PYSEC id should NOT be the display id when CVE is available
        assert "PYSEC-2023-74" not in requests_finding.message.split("]")[0]

    def test_message_contains_pysec_id_when_no_cve_alias(self) -> None:
        """PYSEC id must appear in message when no CVE alias is available."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        aiohttp_finding = next(f for f in findings if "aiohttp" in f.message)
        assert "PYSEC-2024-15" in aiohttp_finding.message

    def test_message_contains_fix_version_hint(self) -> None:
        """Message must include a fix version hint when fix_versions is populated."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        requests_finding = next(f for f in findings if "requests" in f.message)
        assert "2.31.0" in requests_finding.message

    def test_message_contains_no_fix_hint_when_empty(self) -> None:
        """Message must state 'No fix version' when fix_versions is empty."""
        no_fix_json = json.dumps(
            [
                {
                    "name": "oldlib",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-99",
                            "fix_versions": [],
                            "aliases": [],
                            "description": "A bug.",
                            "cvss": [],
                        }
                    ],
                }
            ]
        )
        runner = PipAuditRunner()
        findings = runner._parse_output(no_fix_json, "/proj")
        assert len(findings) == 1
        assert "No fix version" in findings[0].message

    def test_fix_available_true_when_fix_versions_populated(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        requests_finding = next(f for f in findings if "requests" in f.message)
        assert requests_finding.metadata["fix_available"] is True

    def test_fix_available_false_when_no_fix_versions(self) -> None:
        no_fix_json = json.dumps(
            [
                {
                    "name": "oldlib",
                    "version": "1.0.0",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-99",
                            "fix_versions": [],
                            "aliases": [],
                            "description": "",
                            "cvss": [],
                        }
                    ],
                }
            ]
        )
        runner = PipAuditRunner()
        findings = runner._parse_output(no_fix_json, "/proj")
        assert findings[0].metadata["fix_available"] is False

    def test_package_metadata_stored_correctly(self) -> None:
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        requests_finding = next(f for f in findings if "requests" in f.message)
        assert requests_finding.metadata["package_name"] == "requests"
        assert requests_finding.metadata["package_version"] == "2.25.1"
        assert "2.31.0" in requests_finding.metadata["fix_versions"]
        assert requests_finding.metadata["cvss_score"] == 6.1

    def test_line_is_zero_for_all_findings(self) -> None:
        """pip-audit findings have no line number — must be 0."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert all(f.line == 0 for f in findings)

    def test_file_attribution_path_used(self) -> None:
        """RawFinding.file must equal the attribution_path passed to _parse_output."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj/requirements.txt")
        assert all(f.file == "/proj/requirements.txt" for f in findings)

    def test_code_snippet_is_empty(self) -> None:
        """pip-audit findings have no code snippet."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_TWO_VULNS, "/proj")
        assert all(f.code_snippet == "" for f in findings)

    def test_dict_wrapped_finding_has_correct_severity(self) -> None:
        """Dict-wrapped format finding must have correct CVSS-derived severity."""
        runner = PipAuditRunner()
        findings = runner._parse_output(_PIP_AUDIT_JSON_DICT_WRAPPED, "/proj")
        assert findings[0].severity == "HIGH"  # CVSS 8.1
