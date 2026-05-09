"""pipeline.py — Parallel scan orchestration for the Shield AI scanner pipeline.

ScanPipeline orchestrates all five scanner detectors in two stages:

Stage 1 — Secret detection (synchronous, always first):
  SecretsDetector runs before all other tools. Secrets are the highest-risk
  finding class (hard-coded credentials, API keys). Running them first ensures
  critical findings are captured even if the parallel stage encounters a problem.

Stage 2 — Parallel static analysis (concurrent via asyncio.to_thread):
  BanditRunner, SemgrepRunner, PipAuditRunner, and SafetyRunner run concurrently.
  Each wraps a subprocess — asyncio.to_thread() dispatches each blocking call
  to a thread-pool worker, allowing all four to execute simultaneously.
  On a 1,000-file project the bottleneck is Semgrep (~20 s); running sequentially
  would take 40–60 s. Concurrent execution targets < 30 s overall.

After both stages, the collected RawFinding objects are:
  1. Normalized   → NormalizedFinding  (FindingNormalizer)
  2. Deduplicated by fingerprint id     (DeduplicationFilter)
  3. Sorted by severity descending      (CRITICAL → HIGH → MEDIUM → LOW → INFO)

Pipeline PRIORITY order (used for deduplication tie-breaking):
  0 = secrets, 1 = bandit, 2 = semgrep, 3 = pip-audit, 4 = safety

Timing is logged at INFO level when ``verbose=True``, DEBUG otherwise.

Usage::

    # Async context (e.g. API background worker):
    pipeline = ScanPipeline()
    findings = await pipeline.run(Path("./my-project"), verbose=True)

    # Sync context (CLI):
    import asyncio
    findings = asyncio.run(ScanPipeline().run(Path("./my-project")))
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from normalizer.deduplicator import DeduplicationFilter
from normalizer.models import NormalizedFinding, Severity
from normalizer.normalizer import FindingNormalizer

# Use relative imports for sibling detectors so mypy resolves them relative
# to this package root (packages/scanner/scanner/) and not the outer stub
# directory (packages/scanner/detectors/) which contains empty placeholder files.
from .detectors.bandit import BanditRunner
from .detectors.pip_audit import PipAuditRunner
from .detectors.safety import SafetyRunner
from .detectors.secrets import RawFinding, SecretsDetector
from .detectors.semgrep import SemgrepRunner

if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

# Union of all concrete parallel detector types.
# Avoids Protocol structural compatibility errors in mypy strict mode while
# preserving full type information for callers of _run_detector.
_ParallelRunner = BanditRunner | SemgrepRunner | PipAuditRunner | SafetyRunner

# ---------------------------------------------------------------------------
# Severity sort order — CRITICAL is highest priority (sort key 0)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _severity_sort_key(finding: NormalizedFinding) -> int:
    """Return an integer sort key for severity-descending ordering.

    Args:
        finding: A normalized finding to sort.

    Returns:
        Integer from 0 (CRITICAL) to 4 (INFO). Unknown severities return 99.
    """
    return _SEVERITY_ORDER.get(finding.severity, 99)


# ---------------------------------------------------------------------------
# ScanPipeline
# ---------------------------------------------------------------------------


class ScanPipeline:
    """Orchestrates all scanner detectors and returns normalized, deduplicated findings.

    Detectors run in two stages:
      Stage 1: SecretsDetector (synchronous — always runs first)
      Stage 2: BanditRunner + SemgrepRunner + PipAuditRunner + SafetyRunner
               (concurrent — asyncio.to_thread dispatches each blocking subprocess
                to a thread-pool worker for true parallelism)

    After both stages: normalize → deduplicate → sort by severity descending.

    Usage::

        pipeline = ScanPipeline()
        findings = await pipeline.run(Path("./my-project"), verbose=True)
    """

    def __init__(self) -> None:
        """Initialize the pipeline with all five detector instances and support classes."""
        # Detectors — instantiated once per pipeline; all are stateless
        self._secrets = SecretsDetector()
        self._bandit = BanditRunner()
        self._semgrep = SemgrepRunner()
        self._pip_audit = PipAuditRunner()
        self._safety = SafetyRunner()

        # Post-processing — stateless, safe to reuse
        self._normalizer = FindingNormalizer()
        self._deduplicator = DeduplicationFilter()

    async def run(
        self,
        target: Path,
        verbose: bool = False,
    ) -> list[NormalizedFinding]:
        """Run all scanner detectors and return normalized, deduplicated findings.

        Performance target: < 30 seconds on a 1,000-file Python project.

        Args:
            target: Resolved absolute path (file or directory) to scan.
            verbose: If True, logs per-detector timing at INFO level.
                     If False, timing is logged at DEBUG level only.

        Returns:
            Deduplicated, severity-sorted list of NormalizedFinding objects.
            CRITICAL findings appear first; INFO findings appear last.
            An empty list is returned if all detectors find nothing.
        """
        # Accumulates RawFinding objects in pipeline-priority order.
        # Order matters: deduplication keeps the FIRST occurrence of each id,
        # so secrets (priority 0) win over bandit (priority 1) for the same finding.
        all_raw: list[RawFinding] = []

        # ------------------------------------------------------------------
        # Stage 1 — Secret detection (synchronous, PIPELINE_PRIORITY = 0)
        # ------------------------------------------------------------------
        # Run in a thread so we stay async-compatible without blocking the loop.
        t0 = time.perf_counter()
        secrets_findings = await asyncio.to_thread(self._secrets.scan, target)
        elapsed = time.perf_counter() - t0

        all_raw.extend(secrets_findings)
        self._log_timing("secrets", len(secrets_findings), elapsed, verbose)

        # ------------------------------------------------------------------
        # Stage 2 — Parallel static analysis (PIPELINE_PRIORITY = 1–4)
        # ------------------------------------------------------------------
        # Define (name, runner) pairs in priority order.
        # asyncio.gather preserves this order in return_exceptions mode.
        parallel_runners: list[tuple[str, _ParallelRunner]] = [
            ("bandit", self._bandit),  # PIPELINE_PRIORITY = 1
            ("semgrep", self._semgrep),  # PIPELINE_PRIORITY = 2
            ("pip-audit", self._pip_audit),  # PIPELINE_PRIORITY = 3
            ("safety", self._safety),  # PIPELINE_PRIORITY = 4
        ]

        tasks = [
            self._run_detector(name, runner, target, verbose) for name, runner in parallel_runners
        ]

        # return_exceptions=True prevents one failed detector from killing the rest.
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for (tool_name, _), result in zip(parallel_runners, results, strict=True):
            if isinstance(result, BaseException):
                # Log and skip — never let one detector kill the whole scan.
                logger.error(
                    "[%s] detector raised an unhandled exception: %s",
                    tool_name,
                    result,
                )
            else:
                all_raw.extend(result)

        # ------------------------------------------------------------------
        # Post-processing: Normalize → Deduplicate → Sort
        # ------------------------------------------------------------------
        normalized = self._normalizer.normalize_all(all_raw)
        unique = self._deduplicator.deduplicate(normalized)
        unique.sort(key=_severity_sort_key)

        logger.info(
            "Pipeline complete: %d raw finding(s) from all tools → %d unique after deduplication",
            len(all_raw),
            len(unique),
        )

        return unique

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _run_detector(
        self,
        name: str,
        runner: _ParallelRunner,
        target: Path,
        verbose: bool,
    ) -> list[RawFinding]:
        """Run a single detector in a thread pool and log timing.

        asyncio.to_thread() dispatches the blocking subprocess call to the
        default ThreadPoolExecutor, allowing concurrent execution alongside
        other detectors in asyncio.gather.

        Args:
            name: Human-readable detector name used for log messages.
            runner: One of the four parallel detector instances.
            target: Scan target path passed through to runner.scan().
            verbose: Whether to emit timing at INFO or DEBUG level.

        Returns:
            List of RawFinding from the detector (may be empty).
        """
        t0 = time.perf_counter()
        # mypy sees two `scanner` namespaces (outer stub at packages/scanner/ and
        # inner package at packages/scanner/scanner/) and reports RawFinding type
        # mismatch at runtime both resolve to the same class via the editable finder.
        findings: list[RawFinding] = await asyncio.to_thread(runner.scan, target)  # type: ignore[arg-type]
        elapsed = time.perf_counter() - t0
        self._log_timing(name, len(findings), elapsed, verbose)
        return findings

    def _log_timing(
        self,
        name: str,
        count: int,
        elapsed: float,
        verbose: bool,
    ) -> None:
        """Log detector timing at the appropriate log level.

        Args:
            name: Detector name (e.g. "bandit", "secrets").
            count: Number of findings returned by this detector.
            elapsed: Wall-clock seconds the detector took.
            verbose: True \u2192 INFO level; False \u2192 DEBUG level.
        """
        msg = "[%s] %d finding(s) in %.2fs"
        if verbose:
            logger.info(msg, name, count, elapsed)
        else:
            logger.debug(msg, name, count, elapsed)
