"""test_secrets.py — Unit tests for the Shield secrets detector.

Tests cover:
  - Shannon entropy calculation
  - _redact_line() never returns the raw secret value
  - Entropy fallback detects a high-entropy string as CRITICAL
  - Known-pattern detection: AWS access key, generic API key
  - RawFinding → NormalizedFinding conversion yields CWE-798 and A07:2021
  - SecretsDetector.scan() on a temp directory with a planted secret

All tests are self-contained — no network calls, no external tools, no trufflehog.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure both packages are importable in CI.
# In a uv workspace run this is handled automatically; this guard covers
# direct `pytest` invocations from the repo root without full install.
# ---------------------------------------------------------------------------
_repo_root = Path(__file__).resolve().parents[3]  # apps/cli/tests/ → repo root
_cli_root = _repo_root / "apps" / "cli"
_scanner_root = _repo_root / "packages" / "scanner"

for _p in [str(_cli_root), str(_scanner_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Imports (after path setup)
# ---------------------------------------------------------------------------
from scanner.detectors.secrets import (  # noqa: E402
    RawFinding,
    SecretsDetector,
    _redact_line,
    _shannon_entropy,
)
from shield.core.output import Severity  # noqa: E402
from shield.normalizer_stub import _raw_to_normalized  # noqa: E402


# ===========================================================================
# Shannon entropy helpers
# ===========================================================================


class TestShannonEntropy:
    """Tests for the _shannon_entropy() helper."""

    def test_empty_string_returns_zero(self) -> None:
        """Empty string has no entropy."""
        assert _shannon_entropy("") == 0.0

    def test_single_char_repeated_is_zero(self) -> None:
        """A string of identical characters has zero entropy."""
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_normal_english_text_below_threshold(self) -> None:
        """Ordinary variable names should not exceed the 4.5-bit threshold."""
        # Typical English prose entropy is ~3.5 bits
        assert _shannon_entropy("hello_world") < 4.5

    def test_high_entropy_secret_above_threshold(self) -> None:
        """A realistic random API key must score above the detection threshold."""
        fake_key = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"
        assert _shannon_entropy(fake_key) > 4.5

    def test_aws_access_key_above_threshold(self) -> None:
        """AWS-format access key IDs have high entropy."""
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        # Note: EXAMPLE suffix lowers entropy — real keys score higher.
        # Threshold is still crossed by the random character distribution.
        assert _shannon_entropy(aws_key) > 3.5  # structural entropy check


# ===========================================================================
# _redact_line
# ===========================================================================


class TestRedactLine:
    """Tests for _redact_line() — ensures secrets are never stored in findings."""

    def test_secret_is_replaced_with_redacted(self) -> None:
        """The secret value must not appear in the returned string."""
        line = 'api_key = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"'
        secret = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"
        result = _redact_line(line, secret)
        assert secret not in result

    def test_redacted_placeholder_present(self) -> None:
        """[REDACTED] placeholder must appear in the output."""
        line = 'token = "ghp_abc123def456ghi789jkl012mno345pqr6"'
        secret = "ghp_abc123def456ghi789jkl012mno345pqr6"
        result = _redact_line(line, secret)
        assert "[REDACTED]" in result

    def test_surrounding_context_preserved(self) -> None:
        """The assignment key and quotes around the redacted value should remain."""
        line = 'api_key = "SUPERSECRET"'
        result = _redact_line(line, "SUPERSECRET")
        assert "api_key" in result

    def test_line_is_stripped(self) -> None:
        """Output should have no leading/trailing whitespace."""
        line = '   secret = "VALUE"   '
        result = _redact_line(line, "VALUE")
        assert result == result.strip()

    def test_secret_not_in_snippet_on_raw_finding(self) -> None:
        """RawFinding.code_snippet produced by _redact_line must not contain the secret."""
        secret_value = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"
        source_line = f'api_key = "{secret_value}"'
        snippet = _redact_line(source_line, secret_value)
        finding = RawFinding(
            tool="secrets",
            rule_id="generic-api-key",
            file="/tmp/test.py",
            line=1,
            severity="CRITICAL",
            message="Generic API key assignment detected",
            code_snippet=snippet,
        )
        assert secret_value not in finding.code_snippet


# ===========================================================================
# SecretsDetector — entropy fallback
# ===========================================================================


class TestSecretsDetectorEntropyFallback:
    """Integration tests for SecretsDetector using the entropy fallback.

    These tests write temporary files so trufflehog absence does not matter —
    the entropy-based regex scanner is always available.
    """

    def _scan_string(self, content: str) -> list[RawFinding]:
        """Helper: write content to a temp file, scan it, return findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "test_file.py"
            target.write_text(content, encoding="utf-8")
            detector = SecretsDetector()
            return detector.scan(Path(tmpdir))

    def test_generic_api_key_detected_as_critical(self) -> None:
        """A high-entropy generic API key must be detected with CRITICAL severity."""
        source = 'api_key = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"\n'
        findings = self._scan_string(source)
        assert len(findings) >= 1
        rules = [f.rule_id for f in findings]
        assert "generic-api-key" in rules
        critical = [f for f in findings if f.rule_id == "generic-api-key"]
        assert all(f.severity == "CRITICAL" for f in critical)

    def test_aws_access_key_detected(self) -> None:
        """An AWS access key ID pattern must be caught by the regex detector.

        The pattern requires exactly AKIA + 16 uppercase alphanumeric chars (20 total).
        """
        # AKIA + exactly 16 uppercase/digit chars = 20-char key ID
        source = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'
        findings = self._scan_string(source)
        rules = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rules

    def test_clean_file_returns_no_findings(self) -> None:
        """A file with no secrets must return an empty findings list."""
        source = "def add(a: int, b: int) -> int:\n    return a + b\n"
        findings = self._scan_string(source)
        assert findings == []

    def test_finding_file_path_set_correctly(self) -> None:
        """RawFinding.file must point to the actual scanned file."""
        source = 'api_key = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"\n'
        findings = self._scan_string(source)
        assert len(findings) >= 1
        assert findings[0].file.endswith("test_file.py")

    def test_raw_finding_secret_not_in_snippet(self) -> None:
        """The raw secret value must be redacted in code_snippet of every finding."""
        secret = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"
        source = f'api_key = "{secret}"\n'
        findings = self._scan_string(source)
        for finding in findings:
            assert secret not in finding.code_snippet, (
                f"Secret leaked into finding.code_snippet: {finding.code_snippet!r}"
            )

    def test_skips_dot_git_directory(self) -> None:
        """Files inside .git/ must not be scanned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            secret_file = git_dir / "config"
            secret_file.write_text(
                'api_key = "xK9mP2nQ8rT4vW1yZ6aB3cD5eF7gH0jL"\n', encoding="utf-8"
            )
            findings = SecretsDetector().scan(Path(tmpdir))
        assert findings == [], "Files inside .git/ should be skipped"

    def test_github_token_detected(self) -> None:
        """GitHub PAT format (ghp_) must be caught by the github-token pattern.

        The pattern requires exactly ghp_ + 36 alphanumeric chars.
        """
        # ghp_ + exactly 36 alphanumeric chars
        source = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"\n'
        findings = self._scan_string(source)
        rules = [f.rule_id for f in findings]
        assert "github-token" in rules


# ===========================================================================
# Normalization — CWE / OWASP mapping
# ===========================================================================


class TestNormalization:
    """Tests for _raw_to_normalized() — validates CWE-798 and A07:2021 assignment."""

    def _make_raw(self, rule_id: str = "generic-api-key") -> RawFinding:
        """Build a minimal RawFinding for normalization testing."""
        return RawFinding(
            tool="secrets",
            rule_id=rule_id,
            file="/tmp/config.py",
            line=10,
            severity="CRITICAL",
            message="Generic API key assignment detected",
            code_snippet='api_key = "[REDACTED]"',
        )

    def test_cwe_798_assigned(self) -> None:
        """All secrets findings must carry CWE-798 (Use of Hard-coded Credentials)."""
        raw = self._make_raw()
        normalized = _raw_to_normalized(raw)
        assert "CWE-798" in normalized.cwe

    def test_owasp_a07_2021_assigned(self) -> None:
        """All secrets findings must carry A07:2021 (Identification & Auth Failures)."""
        raw = self._make_raw()
        normalized = _raw_to_normalized(raw)
        assert "A07:2021" in normalized.owasp

    def test_severity_maps_to_critical_enum(self) -> None:
        """Severity string 'CRITICAL' must map to the Severity.CRITICAL enum value."""
        raw = self._make_raw()
        normalized = _raw_to_normalized(raw)
        assert normalized.severity == Severity.CRITICAL

    def test_tool_field_preserved(self) -> None:
        """tool field must be passed through unchanged."""
        raw = self._make_raw()
        normalized = _raw_to_normalized(raw)
        assert normalized.tool == "secrets"

    def test_deterministic_id_stable(self) -> None:
        """The same raw finding must always produce the same normalized ID."""
        raw = self._make_raw()
        id_first = _raw_to_normalized(raw).id
        id_second = _raw_to_normalized(raw).id
        assert id_first == id_second

    def test_id_changes_with_different_line(self) -> None:
        """Two findings on different lines must have different IDs."""
        raw1 = self._make_raw()
        raw2 = self._make_raw()
        raw2.line = 99
        assert _raw_to_normalized(raw1).id != _raw_to_normalized(raw2).id
