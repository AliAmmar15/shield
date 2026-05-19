"""test_exclusion.py — Unit tests for the ScanPipeline path exclusion filter.

Covers:
  - _is_excluded() helper: directory patterns, file glob patterns, edge cases
  - ScanPipeline integration: default excludes strip test file findings
  - Zero-findings result when all findings are in excluded paths
  - --exclude CLI flag (additive on top of defaults)
  - Config file exclusion reader (_load_config_excludes)
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from scanner.pipeline import DEFAULT_EXCLUDE_PATTERNS, ScanPipeline, _is_excluded

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def project_root(tmp_path: Path) -> Path:
    """Return a temporary directory representing a project root."""
    return tmp_path


# ---------------------------------------------------------------------------
# _is_excluded — directory patterns (ending in '/')
# ---------------------------------------------------------------------------


class TestIsExcludedDirectoryPatterns:
    def test_tests_dir_match(self, project_root: Path) -> None:
        file = str(project_root / "tests" / "test_foo.py")
        assert _is_excluded(file, project_root, ["tests/"]) is True

    def test_tests_dir_nested(self, project_root: Path) -> None:
        file = str(project_root / "app" / "tests" / "test_foo.py")
        assert _is_excluded(file, project_root, ["tests/"]) is True

    def test_tests_dir_no_match_similar_name(self, project_root: Path) -> None:
        # "mytests/" should not match "tests/"
        file = str(project_root / "mytests" / "foo.py")
        assert _is_excluded(file, project_root, ["tests/"]) is False

    def test_test_wildcard_dir(self, project_root: Path) -> None:
        file = str(project_root / "test_utils" / "helper.py")
        assert _is_excluded(file, project_root, ["test_*/"]) is True

    def test_test_wildcard_dir_nested(self, project_root: Path) -> None:
        file = str(project_root / "src" / "test_helpers" / "mock.py")
        assert _is_excluded(file, project_root, ["test_*/"]) is True

    def test_test_wildcard_dir_no_match(self, project_root: Path) -> None:
        file = str(project_root / "utilities" / "helper.py")
        assert _is_excluded(file, project_root, ["test_*/"]) is False

    def test_filename_alone_not_matched_by_dir_pattern(self, project_root: Path) -> None:
        # A file named "tests.py" at the root should NOT be excluded by "tests/"
        file = str(project_root / "tests.py")
        assert _is_excluded(file, project_root, ["tests/"]) is False

    def test_migrations_custom_dir(self, project_root: Path) -> None:
        file = str(project_root / "migrations" / "0001_initial.py")
        assert _is_excluded(file, project_root, ["migrations/"]) is True


# ---------------------------------------------------------------------------
# _is_excluded — file glob patterns
# ---------------------------------------------------------------------------


class TestIsExcludedFileGlobPatterns:
    def test_conftest_root(self, project_root: Path) -> None:
        file = str(project_root / "conftest.py")
        assert _is_excluded(file, project_root, ["conftest.py"]) is True

    def test_conftest_nested(self, project_root: Path) -> None:
        file = str(project_root / "src" / "conftest.py")
        assert _is_excluded(file, project_root, ["conftest.py"]) is True

    def test_test_py_glob_subdir(self, project_root: Path) -> None:
        file = str(project_root / "app" / "test_views.py")
        assert _is_excluded(file, project_root, ["*/test_*.py"]) is True

    def test_test_py_glob_deep_nested(self, project_root: Path) -> None:
        file = str(project_root / "app" / "api" / "test_routes.py")
        assert _is_excluded(file, project_root, ["*/test_*.py"]) is True

    def test_test_py_glob_no_match_src_file(self, project_root: Path) -> None:
        file = str(project_root / "app" / "views.py")
        assert _is_excluded(file, project_root, ["*/test_*.py"]) is False

    def test_custom_generated_pattern(self, project_root: Path) -> None:
        file = str(project_root / "generated_models.py")
        assert _is_excluded(file, project_root, ["generated_*.py"]) is True

    def test_star_slash_pattern_no_match_root_level(self, project_root: Path) -> None:
        # "*/test_*.py" requires at least one directory prefix
        file = str(project_root / "test_standalone.py")
        # PurePath("test_standalone.py").match("*/test_*.py") is False in Python stdlib
        assert _is_excluded(file, project_root, ["*/test_*.py"]) is False


# ---------------------------------------------------------------------------
# _is_excluded — edge cases
# ---------------------------------------------------------------------------


class TestIsExcludedEdgeCases:
    def test_file_outside_target_not_excluded(self, project_root: Path) -> None:
        # Create a sibling directory to project_root (not a child of it)
        # so relative_to() raises ValueError → _is_excluded returns False.
        sibling_root = project_root.parent / "sibling_project"
        sibling_root.mkdir(exist_ok=True)
        file = str(sibling_root / "tests" / "foo.py")
        assert _is_excluded(file, project_root, ["tests/"]) is False

    def test_empty_patterns_never_excludes(self, project_root: Path) -> None:
        file = str(project_root / "tests" / "test_foo.py")
        assert _is_excluded(file, project_root, []) is False

    def test_multiple_patterns_first_match_wins(self, project_root: Path) -> None:
        file = str(project_root / "tests" / "conftest.py")
        assert _is_excluded(file, project_root, ["tests/", "conftest.py"]) is True

    def test_default_patterns_constant_not_empty(self) -> None:
        assert len(DEFAULT_EXCLUDE_PATTERNS) >= 4


# ---------------------------------------------------------------------------
# ScanPipeline — exclusion integration
# ---------------------------------------------------------------------------


def _make_raw(file: str, tool: str = "bandit") -> MagicMock:
    """Build a minimal RawFinding-like mock with the given file path."""
    raw = MagicMock()
    raw.file = file
    raw.tool = tool
    raw.rule_id = "B101"
    raw.line = 10
    raw.severity = "HIGH"
    raw.message = "Assert used"
    raw.code_snippet = ""
    raw.metadata = {}
    return raw


class TestScanPipelineExclusion:
    """Test that ScanPipeline filters findings before normalization."""

    def _run_pipeline_with_raws(
        self,
        project_root: Path,
        raw_findings: list[MagicMock],
        exclude: list[str] | None = None,
    ) -> list:
        """Run ScanPipeline with mocked detectors returning the given raw findings."""
        import asyncio

        # Patch all detectors to return the supplied raw findings list.
        # All findings come from Stage 1 (secrets) for simplicity.
        pipeline = ScanPipeline(exclude=exclude)

        async def _run() -> list:
            with (
                patch.object(pipeline._secrets, "scan", return_value=raw_findings),
                patch.object(pipeline._bandit, "scan", return_value=[]),
                patch.object(pipeline._semgrep, "scan", return_value=[]),
                patch.object(pipeline._pip_audit, "scan", return_value=[]),
                patch.object(pipeline._safety, "scan", return_value=[]),
            ):
                return await pipeline.run(project_root)

        return asyncio.run(_run())

    def test_default_excludes_remove_tests_dir(self, project_root: Path) -> None:
        raw = _make_raw(str(project_root / "tests" / "test_foo.py"))
        results = self._run_pipeline_with_raws(project_root, [raw])
        assert results == []

    def test_default_excludes_remove_conftest(self, project_root: Path) -> None:
        raw = _make_raw(str(project_root / "conftest.py"))
        results = self._run_pipeline_with_raws(project_root, [raw])
        assert results == []

    def test_default_excludes_remove_test_star_py(self, project_root: Path) -> None:
        raw = _make_raw(str(project_root / "src" / "test_views.py"))
        results = self._run_pipeline_with_raws(project_root, [raw])
        assert results == []

    def test_src_file_not_excluded_by_default(self, project_root: Path) -> None:
        # Create a minimal Python file so normalizer doesn't choke on snippet reads
        raw = _make_raw(str(project_root / "src" / "auth.py"))
        results = self._run_pipeline_with_raws(project_root, [raw])
        # The finding passes the exclusion filter (src/auth.py is not a test file)
        assert len(results) == 1

    def test_zero_findings_when_all_excluded(self, project_root: Path) -> None:
        raws = [
            _make_raw(str(project_root / "tests" / "test_a.py")),
            _make_raw(str(project_root / "tests" / "test_b.py")),
            _make_raw(str(project_root / "conftest.py")),
        ]
        results = self._run_pipeline_with_raws(project_root, raws)
        assert results == []

    def test_custom_exclude_migrations(self, project_root: Path) -> None:
        raw = _make_raw(str(project_root / "migrations" / "0001_initial.py"))
        results = self._run_pipeline_with_raws(project_root, [raw], exclude=["migrations/"])
        assert results == []

    def test_custom_exclude_additive(self, project_root: Path) -> None:
        # "migrations/" added on top of defaults; tests/ still excluded
        raw_test = _make_raw(str(project_root / "tests" / "test_foo.py"))
        raw_migration = _make_raw(str(project_root / "migrations" / "0001.py"))
        raw_src = _make_raw(str(project_root / "src" / "auth.py"))
        results = self._run_pipeline_with_raws(
            project_root,
            [raw_test, raw_migration, raw_src],
            exclude=DEFAULT_EXCLUDE_PATTERNS + ["migrations/"],
        )
        # Only src/auth.py passes
        assert len(results) == 1

    def test_empty_exclude_passes_all(self, project_root: Path) -> None:
        raw = _make_raw(str(project_root / "tests" / "test_foo.py"))
        results = self._run_pipeline_with_raws(project_root, [raw], exclude=[])
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Config file reader
# ---------------------------------------------------------------------------


class TestLoadConfigExcludes:
    """Tests for _load_config_excludes() reading ~/.velonus/config.toml."""

    def test_missing_config_returns_empty(self, tmp_path: Path) -> None:
        from shield.commands.scan import _load_config_excludes

        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_config_excludes()
        assert result == []

    def test_valid_config_returns_patterns(self, tmp_path: Path) -> None:
        from shield.commands.scan import _load_config_excludes

        config_dir = tmp_path / ".velonus"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text(
            textwrap.dedent("""\
                [scan]
                exclude = ["migrations/", "*/generated_*.py"]
            """),
            encoding="utf-8",
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_config_excludes()
        assert result == ["migrations/", "*/generated_*.py"]

    def test_malformed_toml_returns_empty(self, tmp_path: Path) -> None:
        from shield.commands.scan import _load_config_excludes

        config_dir = tmp_path / ".velonus"
        config_dir.mkdir()
        (config_dir / "config.toml").write_bytes(b"\xff\xfe invalid toml !!!")
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_config_excludes()
        assert result == []

    def test_config_without_scan_section_returns_empty(self, tmp_path: Path) -> None:
        from shield.commands.scan import _load_config_excludes

        config_dir = tmp_path / ".velonus"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text("[other]\nkey = 1\n", encoding="utf-8")
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_config_excludes()
        assert result == []

    def test_config_scan_section_without_exclude_returns_empty(self, tmp_path: Path) -> None:
        from shield.commands.scan import _load_config_excludes

        config_dir = tmp_path / ".velonus"
        config_dir.mkdir()
        (config_dir / "config.toml").write_text("[scan]\nother_key = true\n", encoding="utf-8")
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = _load_config_excludes()
        assert result == []
