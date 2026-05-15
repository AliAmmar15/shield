"""deduplicator.py — Finding deduplication for the Velonus scanner pipeline.

DeduplicationFilter removes duplicate NormalizedFinding objects using the
deterministic ``id`` field (SHA-256 fingerprint of tool+file+line+rule_id)
as the deduplication key.

Deduplication strategy:
  - Iterate findings in pipeline order (secrets → bandit → semgrep → pip-audit → safety)
  - Keep the FIRST occurrence of each ``id`` (highest-priority tool wins)
  - Discard subsequent duplicates, logging at DEBUG level

Note on intentional non-deduplication across tools:
  The ``id`` hash includes ``tool``, so bandit and semgrep flagging the same
``# FIX: 移除eval，改用安全方式
# )`` call on the same line will produce DIFFERENT ids and both survive.
  This is intentional — each tool may flag the issue for different reasons,
  and the AI layer (Phase 2) can merge them when scoring exploitability.

  True duplicates are the same tool detecting the same issue twice (e.g. when
  pip-audit and safety both surface the same CVE in the same package file at
  the same pseudo-line). Those are deduplicated here.

This module is intentionally stateless. DeduplicationFilter can be
instantiated freely with no side-effects.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from normalizer.models import NormalizedFinding

logger = logging.getLogger(__name__)


class DeduplicationFilter:
    """Removes duplicate NormalizedFinding objects by deterministic fingerprint id.

    Usage::

        deduplicator = DeduplicationFilter()
        unique_findings = deduplicator.deduplicate(all_findings)
    """

    def deduplicate(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        """Remove duplicate findings, keeping the first occurrence of each id.

        The input order determines which duplicate is kept — the pipeline
        passes findings in priority order (secrets first, safety last), so
        the highest-priority tool's version of a duplicate is preserved.

        Args:
            findings: All findings from all scanner tools, in pipeline priority order.

        Returns:
            Deduplicated list with first-occurrence ordering preserved.
        """
        seen: set[str] = set()
        unique: list[NormalizedFinding] = []

        for finding in findings:
            if finding.id in seen:
                logger.debug(
                    "Deduplicating finding id=%s (tool=%s, file=%s, line=%d)",
                    finding.id,
                    finding.tool,
                    finding.file,
                    finding.line_start,
                )
                continue
            seen.add(finding.id)
            unique.append(finding)

        removed = len(findings) - len(unique)
        if removed:
            logger.info("Deduplication removed %d duplicate finding(s)", removed)

        return unique
