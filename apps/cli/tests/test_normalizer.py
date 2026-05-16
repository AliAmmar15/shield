"""Unit tests for FindingNormalizer and DeduplicationFilter.

All tests use real dataclass instances — no mocking required.
The _RawFindingLike Protocol is satisfied by the SimpleRaw helper dataclass
defined below, which mirrors the fields any scanner detector produces.

Coverage targets:
  FindingNormalizer.normalize()     — id hashing, severity/confidence mapping,
                                      CWE/OWASP fallbacks, line_end, field passthrough
  FindingNormalizer.normalize_all() — list processing, error isolation
  DeduplicationFilter.deduplicate() — first-occurrence wins, order preservation,
                                      empty input, no-duplicate passthrough,
                                      cross-tool same-location highest-severity wins
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import pytest
from normalizer.deduplicator import DeduplicationFilter
from normalizer.models import Confidence, NormalizedFinding, Severity
from normalizer.normalizer import FindingNormalizer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class SimpleRaw:
    """Minimal concrete implementation of the _RawFindingLike Protocol.

    Used across all tests to create RawFinding-like objects without importing
    the scanner package (which would introduce an unnecessary test dependency).
    """

    tool: str = "bandit"
    rule_id: str = "B101"
    file: str = "app/main.py"
    line: int = 42
    severity: str = "HIGH"
    message: str = "Use of assert detected."
    code_snippet: str = "assert x == 1"
    metadata: dict[str, Any] = field(default_factory=dict)


def _expected_id(tool: str, file: str, line: int, rule_id: str) -> str:
    """Replicate the normalizer's deterministic ID hash for assertions."""
    return hashlib.sha256(f"{tool}:{file}:{line}:{rule_id}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# FindingNormalizer — id hashing
# ---------------------------------------------------------------------------


class TestNormalizerIdHashing:
    """The deterministic SHA-256 id is computed from tool+file+line+rule_id."""

    def test_id_is_16_hex_chars(self) -> None:
        raw = SimpleRaw()
        result = FindingNormalizer().normalize(raw)
        assert len(result.id) == 16
        assert all(c in "0123456789abcdef" for c in result.id)

    def test_id_matches_expected_hash(self) -> None:
        raw = SimpleRaw(tool="bandit", file="app/main.py", line=42, rule_id="B101")
        expected = _expected_id("bandit", "app/main.py", 42, "B101")
        assert FindingNormalizer().normalize(raw).id == expected

    def test_same_input_always_produces_same_id(self) -> None:
        raw = SimpleRaw()
        n = FindingNormalizer()
        assert n.normalize(raw).id == n.normalize(raw).id

    def test_different_line_produces_different_id(self) -> None:
        n = FindingNormalizer()
        id_a = n.normalize(SimpleRaw(line=10)).id
        id_b = n.normalize(SimpleRaw(line=11)).id
        assert id_a != id_b

    def test_different_tool_produces_different_id(self) -> None:
        n = FindingNormalizer()
        id_a = n.normalize(SimpleRaw(tool="bandit")).id
        id_b = n.normalize(SimpleRaw(tool="semgrep")).id
        assert id_a != id_b

    def test_different_file_produces_different_id(self) -> None:
        n = FindingNormalizer()
        id_a = n.normalize(SimpleRaw(file="a.py")).id
        id_b = n.normalize(SimpleRaw(file="b.py")).id
        assert id_a != id_b

    def test_different_rule_id_produces_different_id(self) -> None:
        n = FindingNormalizer()
        id_a = n.normalize(SimpleRaw(rule_id="B101")).id
        id_b = n.normalize(SimpleRaw(rule_id="B102")).id
        assert id_a != id_b


# ---------------------------------------------------------------------------
# FindingNormalizer — severity mapping
# ---------------------------------------------------------------------------


class TestNormalizerSeverityMapping:
    """Severity strings are mapped to Severity enum values."""

    @pytest.mark.parametrize(
        "raw_severity, expected",
        [
            ("CRITICAL", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("INFO", Severity.INFO),
        ],
    )
    def test_uppercase_severity_maps_correctly(self, raw_severity: str, expected: Severity) -> None:
        result = FindingNormalizer().normalize(SimpleRaw(severity=raw_severity))
        assert result.severity == expected

    @pytest.mark.parametrize(
        "raw_severity, expected",
        [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
        ],
    )
    def test_lowercase_severity_maps_correctly(self, raw_severity: str, expected: Severity) -> None:
        result = FindingNormalizer().normalize(SimpleRaw(severity=raw_severity))
        assert result.severity == expected

    def test_unknown_severity_defaults_to_high(self) -> None:
        """Unknown severity strings fall back to HIGH rather than crashing."""
        result = FindingNormalizer().normalize(SimpleRaw(severity="UNKNOWN"))
        assert result.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# FindingNormalizer — confidence mapping
# ---------------------------------------------------------------------------


class TestNormalizerConfidenceMapping:
    """Confidence from metadata is mapped to Confidence enum; default is MEDIUM."""

    @pytest.mark.parametrize(
        "raw_confidence, expected",
        [
            ("HIGH", Confidence.HIGH),
            ("MEDIUM", Confidence.MEDIUM),
            ("LOW", Confidence.LOW),
        ],
    )
    def test_confidence_from_metadata(self, raw_confidence: str, expected: Confidence) -> None:
        raw = SimpleRaw(metadata={"confidence": raw_confidence})
        assert FindingNormalizer().normalize(raw).confidence == expected

    def test_missing_confidence_defaults_to_medium(self) -> None:
        result = FindingNormalizer().normalize(SimpleRaw(metadata={}))
        assert result.confidence == Confidence.MEDIUM

    def test_lowercase_confidence_in_metadata(self) -> None:
        raw = SimpleRaw(metadata={"confidence": "high"})
        assert FindingNormalizer().normalize(raw).confidence == Confidence.HIGH


# ---------------------------------------------------------------------------
# FindingNormalizer — CWE / OWASP fallbacks
# ---------------------------------------------------------------------------


class TestNormalizerCweOwaspFallbacks:
    """Tool-specific CWE/OWASP defaults are applied when metadata is absent."""

    def test_secrets_tool_gets_cwe_798(self) -> None:
        raw = SimpleRaw(tool="secrets", metadata={})
        assert FindingNormalizer().normalize(raw).cwe == ["CWE-798"]

    def test_secrets_tool_gets_owasp_a07(self) -> None:
        raw = SimpleRaw(tool="secrets", metadata={})
        assert FindingNormalizer().normalize(raw).owasp == ["A07:2021"]

    def test_pip_audit_gets_cwe_1035(self) -> None:
        raw = SimpleRaw(tool="pip-audit", metadata={})
        assert FindingNormalizer().normalize(raw).cwe == ["CWE-1035"]

    def test_pip_audit_gets_owasp_a06(self) -> None:
        raw = SimpleRaw(tool="pip-audit", metadata={})
        assert FindingNormalizer().normalize(raw).owasp == ["A06:2021"]

    def test_safety_gets_cwe_1035(self) -> None:
        raw = SimpleRaw(tool="safety", metadata={})
        assert FindingNormalizer().normalize(raw).cwe == ["CWE-1035"]

    def test_safety_gets_owasp_a06(self) -> None:
        raw = SimpleRaw(tool="safety", metadata={})
        assert FindingNormalizer().normalize(raw).owasp == ["A06:2021"]

    def test_metadata_cwe_overrides_tool_default(self) -> None:
        """Explicit metadata CWE takes precedence over tool-level fallback."""
        raw = SimpleRaw(tool="secrets", metadata={"cwe": ["CWE-259"]})
        assert FindingNormalizer().normalize(raw).cwe == ["CWE-259"]

    def test_metadata_owasp_overrides_tool_default(self) -> None:
        raw = SimpleRaw(tool="secrets", metadata={"owasp": ["A02:2021"]})
        assert FindingNormalizer().normalize(raw).owasp == ["A02:2021"]

    def test_unknown_tool_produces_empty_cwe(self) -> None:
        """Tools without a default (e.g. bandit with no metadata) produce []."""
        raw = SimpleRaw(tool="bandit", metadata={})
        assert FindingNormalizer().normalize(raw).cwe == []

    def test_empty_metadata_cwe_falls_back_to_tool_default(self) -> None:
        """An empty list in metadata["cwe"] is treated as absent (falsy)."""
        raw = SimpleRaw(tool="safety", metadata={"cwe": []})
        assert FindingNormalizer().normalize(raw).cwe == ["CWE-1035"]


# ---------------------------------------------------------------------------
# FindingNormalizer — field passthrough + line_end
# ---------------------------------------------------------------------------


class TestNormalizerFieldPassthrough:
    """Non-derived fields are copied directly from the raw finding."""

    def test_tool_is_preserved(self) -> None:
        assert FindingNormalizer().normalize(SimpleRaw(tool="semgrep")).tool == "semgrep"

    def test_rule_id_is_preserved(self) -> None:
        assert FindingNormalizer().normalize(SimpleRaw(rule_id="B201")).rule_id == "B201"

    def test_file_is_preserved(self) -> None:
        assert FindingNormalizer().normalize(SimpleRaw(file="src/api.py")).file == "src/api.py"

    def test_line_start_equals_raw_line(self) -> None:
        assert FindingNormalizer().normalize(SimpleRaw(line=99)).line_start == 99

    def test_message_is_preserved(self) -> None:
        raw = SimpleRaw(message="Potential SQL injection")
        assert FindingNormalizer().normalize(raw).message == "Potential SQL injection"

    def test_code_snippet_is_preserved(self) -> None:
        raw = SimpleRaw(code_snippet="cursor.execute(query)")
        assert FindingNormalizer().normalize(raw).code_snippet == "cursor.execute(query)"

    def test_line_end_defaults_to_line_start_when_absent(self) -> None:
        raw = SimpleRaw(line=55, metadata={})
        result = FindingNormalizer().normalize(raw)
        assert result.line_end == 55

    def test_line_end_from_metadata_overrides_default(self) -> None:
        raw = SimpleRaw(line=55, metadata={"line_end": 60})
        result = FindingNormalizer().normalize(raw)
        assert result.line_end == 60

    def test_ai_fields_default_to_none(self) -> None:
        result = FindingNormalizer().normalize(SimpleRaw())
        assert result.exploitability_score is None
        assert result.ai_priority is None
        assert result.ai_explanation is None
        assert result.ai_remediation is None
        assert result.false_positive is False


# ---------------------------------------------------------------------------
# FindingNormalizer — normalize_all()
# ---------------------------------------------------------------------------


class TestNormalizerNormalizeAll:
    """normalize_all() processes a list and returns list[NormalizedFinding]."""

    def test_empty_list_returns_empty(self) -> None:
        assert FindingNormalizer().normalize_all([]) == []

    def test_single_item_returns_single_result(self) -> None:
        results = FindingNormalizer().normalize_all([SimpleRaw()])
        assert len(results) == 1
        assert isinstance(results[0], NormalizedFinding)

    def test_multiple_items_all_normalized(self) -> None:
        raws = [SimpleRaw(line=i) for i in range(5)]
        results = FindingNormalizer().normalize_all(raws)
        assert len(results) == 5

    def test_normalize_all_ids_are_unique_for_different_lines(self) -> None:
        raws = [SimpleRaw(line=i) for i in range(3)]
        results = FindingNormalizer().normalize_all(raws)
        ids = [r.id for r in results]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# DeduplicationFilter — core behaviour
# ---------------------------------------------------------------------------


class TestDeduplicationFilter:
    """DeduplicationFilter removes duplicate ids, preserving first occurrence."""

    def _make_finding(
        self,
        finding_id: str,
        tool: str = "bandit",
        line: int | None = None,
    ) -> NormalizedFinding:
        """Build a minimal NormalizedFinding with a pre-set id for testing.

        Each call uses a unique line derived from the finding_id hash so that
        pass-2 location dedup does not collapse unrelated findings.
        """
        # Use a stable but unique line per id so (file, line, cwe) keys differ.
        unique_line = line if line is not None else (hash(finding_id) % 9000 + 1000)
        f = FindingNormalizer().normalize(
            SimpleRaw(tool=tool, rule_id=finding_id, line=unique_line)
        )
        # Override the computed id so we can control the dedup key directly.
        object.__setattr__(f, "id", finding_id)
        return f

    def test_empty_list_returns_empty(self) -> None:
        assert DeduplicationFilter().deduplicate([]) == []

    def test_no_duplicates_returns_all(self) -> None:
        findings = [self._make_finding(f"id{i}") for i in range(4)]
        result = DeduplicationFilter().deduplicate(findings)
        assert len(result) == 4

    def test_exact_duplicate_ids_removed(self) -> None:
        f1 = self._make_finding("abc123")
        f2 = self._make_finding("abc123")  # same id → duplicate
        result = DeduplicationFilter().deduplicate([f1, f2])
        assert len(result) == 1

    def test_first_occurrence_wins_not_last(self) -> None:
        f1 = self._make_finding("abc123", tool="secrets")
        f2 = self._make_finding("abc123", tool="bandit")
        result = DeduplicationFilter().deduplicate([f1, f2])
        assert result[0].tool == "secrets"

    def test_different_ids_both_kept(self) -> None:
        f1 = self._make_finding("aaa")
        f2 = self._make_finding("bbb")
        result = DeduplicationFilter().deduplicate([f1, f2])
        assert len(result) == 2

    def test_order_of_non_duplicates_preserved(self) -> None:
        findings = [self._make_finding(f"id{i}") for i in range(5)]
        result = DeduplicationFilter().deduplicate(findings)
        assert [r.id for r in result] == [f"id{i}" for i in range(5)]

    def test_multiple_duplicates_only_first_kept(self) -> None:
        """Three findings with the same id → only the first survives."""
        findings = [self._make_finding("dup") for _ in range(3)]
        result = DeduplicationFilter().deduplicate(findings)
        assert len(result) == 1

    def test_mixed_duplicates_and_unique(self) -> None:
        """3 unique + 2 duplicates of one id → 4 total in output."""
        unique = [self._make_finding(f"u{i}") for i in range(3)]
        dupe_a = self._make_finding("dup")
        dupe_b = self._make_finding("dup")
        result = DeduplicationFilter().deduplicate(unique + [dupe_a, dupe_b])
        assert len(result) == 4
        assert sum(1 for r in result if r.id == "dup") == 1

    def test_single_finding_is_kept(self) -> None:
        f = self._make_finding("solo")
        assert DeduplicationFilter().deduplicate([f]) == [f]

    def test_cross_tool_same_location_highest_severity_wins(self) -> None:
        """Pass-2: bandit HIGH and semgrep MEDIUM on the same file+line+CWE → only HIGH survives."""
        n = FindingNormalizer()
        bandit_finding = n.normalize(
            SimpleRaw(
                tool="bandit",
                rule_id="B324",
                line=36,
                severity="HIGH",
                metadata={"cwe": ["CWE-327"]},
            )
        )
        semgrep_finding = n.normalize(
            SimpleRaw(
                tool="semgrep",
                rule_id="python.lang.security.weak-hash",
                line=36,
                severity="MEDIUM",
                metadata={"cwe": ["CWE-327"]},
            )
        )
        result = DeduplicationFilter().deduplicate([bandit_finding, semgrep_finding])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH
        assert result[0].tool == "bandit"
