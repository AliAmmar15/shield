"""
secrets.py — Secret detection for the Shield AI scanner pipeline.

PIPELINE ORDER: SecretScanner ALWAYS runs first. See pipeline.py for execution
order. Rationale: secrets are the highest-risk finding class and must be surfaced
before any other tool result can deprioritize them.

Detection strategy (in order of preference):
  1. trufflehog v3 subprocess wrapper  — best-in-class, verified credentials
  2. Entropy-based regex fallback       — runs automatically when trufflehog is missing

The fallback covers: AWS access/secret keys, OpenAI API keys, GitHub tokens,
hardcoded JWTs, PEM private keys, generic API keys, database connection strings.

Both paths return list[RawFinding] with identical shape.
The caller (normalizer) converts RawFinding → NormalizedFinding with deterministic
IDs, CWE-798/A07:2021 mappings, and deduplication.
"""

from __future__ import annotations

import json
import logging
import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline metadata
# ---------------------------------------------------------------------------

# PIPELINE ORDER: This constant is read by pipeline.py to enforce that secrets
# always run before Bandit/Semgrep/pip-audit. Lower number = earlier execution.
PIPELINE_PRIORITY: int = 0

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Shannon entropy threshold. Strings above this are treated as likely secrets.
# 4.5 bits is well above normal English text (~3.5) but below true random (~6.0).
_ENTROPY_THRESHOLD: float = 4.5

# Directories to skip during recursive file walking.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".eggs",
    }
)

# File extensions to skip — binary, compiled, lock, and media files.
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pyc",
        ".pyo",
        ".lock",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".svg",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".map",
    }
)

# Each entry: (rule_id, compiled_pattern, human_readable_message).
# Order matters — more specific patterns first to avoid duplicate matches.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "aws-access-key-id",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "AWS Access Key ID detected — rotate immediately via AWS IAM",
    ),
    (
        "aws-secret-access-key",
        re.compile(
            r"(?i)(?:aws.{0,20}secret|secret.{0,20}access)"
            r"\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
        ),
        "AWS Secret Access Key detected — rotate immediately via AWS IAM",
    ),
    (
        "openai-api-key",
        re.compile(r"\b(sk-[A-Za-z0-9]{48})\b"),
        "OpenAI API Key detected — revoke at platform.openai.com/account/api-keys",
    ),
    (
        "openai-api-key-project",
        re.compile(r"\b(sk-proj-[A-Za-z0-9\-_]{48,255})\b"),
        "OpenAI project-scoped API Key detected — revoke at platform.openai.com",
    ),
    (
        "github-token",
        re.compile(
            r"\b("
            r"ghp_[A-Za-z0-9]{36}"
            r"|gho_[A-Za-z0-9]{36}"
            r"|ghs_[A-Za-z0-9]{36}"
            r"|github_pat_[A-Za-z0-9_]{82}"
            r")\b"
        ),
        "GitHub Personal Access Token detected — revoke at github.com/settings/tokens",
    ),
    (
        "jwt-hardcoded",
        re.compile(r"\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b"),
        "Hardcoded JWT token found in source — never commit live tokens to version control",
    ),
    (
        "pem-private-key",
        re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----"),
        "PEM Private Key block detected — never commit private keys to version control",
    ),
    (
        "generic-api-key",
        re.compile(
            r"(?i)(?:api[_\-]?key|apikey|x-api-key)"
            r"\s*[=:]\s*[\"']([A-Za-z0-9\-_]{16,64})[\"']"
        ),
        "Generic API key assignment detected — verify this is not a live credential",
    ),
    (
        "db-connection-string",
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)"
            r"://[^\s\"'<>\r\n]{8,}"
        ),
        "Database connection string with embedded credentials detected",
    ),
]

# Catches `SECRET = "value"` / `api_key: "value"` assignments for entropy check.
_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)"
    r"(?:key|secret|token|password|passwd|pwd|credential|private[_\-]?key|auth)"
    r"\s*[=:]\s*[\"']([^\"']{8,})[\"']"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RawFinding:
    """Pre-normalization finding shape produced by each scanner tool.

    All detector wrappers return list[RawFinding]. The Phase 1 normalizer
    converts these to NormalizedFinding with deterministic IDs, CWE/OWASP
    mappings, and cross-scan deduplication.

    Note: severity is a plain string (not the Severity enum) so that
    packages/scanner has zero runtime dependency on apps/cli.
    """

    tool: str  # "secrets" | "bandit" | "semgrep" | "pip-audit"
    rule_id: str  # e.g. "aws-access-key-id", "trufflehog-aws"
    file: str  # absolute path string
    line: int  # 1-indexed line number
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    message: str  # human-readable description of the finding
    code_snippet: str  # redacted source line — never store plaintext secrets here
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits) for the given string.

    Typical ranges:
      0.0 – 2.4  — plain text, repeated characters, or short placeholders
      2.5 – 4.4  — moderate entropy (hex strings, short identifiers)
      4.5+       — high entropy (base64, random secrets, API keys)

    Args:
        data: Input string to measure.

    Returns:
        Entropy in bits as a float. Returns 0.0 for empty input.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact_line(line: str, secret: str) -> str:
    """Replace the secret value in a source line with [REDACTED].

    We never store plaintext credentials in RawFinding.code_snippet.
    Only enough context is retained to identify the file location.

    Args:
        line: The full source line containing the secret.
        secret: The detected secret value to redact.

    Returns:
        Stripped source line with the secret replaced by [REDACTED].
    """
    return line.replace(secret, "[REDACTED]").strip()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class SecretsDetector:
    """Secrets scanner — trufflehog v3 wrapper with entropy-based regex fallback.

    PIPELINE ORDER: Always instantiate and call scan() FIRST in the scanner
    pipeline (before Bandit, Semgrep, pip-audit). See PIPELINE_PRIORITY = 0.

    Usage::

        detector = SecretsDetector()
        findings = detector.scan(Path("./my-project"))
        # returns list[RawFinding], all with severity="CRITICAL"
    """

    def scan(self, target: Path) -> list[RawFinding]:
        """Run secrets detection on the given target path.

        Tries trufflehog first. Automatically falls back to the entropy-based
        regex scanner if trufflehog is not found on PATH.

        Args:
            target: Resolved absolute path (file or directory) to scan.

        Returns:
            List of RawFinding. All detected secrets use severity="CRITICAL".
        """
        if self._trufflehog_available():
            logger.debug("trufflehog available — using as primary secrets scanner")
            return self._trufflehog_scan(target)

        logger.warning(
            "trufflehog not found on PATH — falling back to entropy-based regex scanner. "
            "Install trufflehog v3 for higher accuracy: "
            "https://github.com/trufflesecurity/trufflehog#installation"
        )
        return self._entropy_scan(target)

    # ------------------------------------------------------------------
    # trufflehog path
    # ------------------------------------------------------------------

    def _trufflehog_available(self) -> bool:
        """Return True if trufflehog v3 is installed and accessible on PATH.

        Returns:
            True if `trufflehog --version` exits with code 0, False otherwise.
        """
        try:
            result = subprocess.run(
                ["trufflehog", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _trufflehog_scan(self, target: Path) -> list[RawFinding]:
        """Run trufflehog v3 filesystem scanner and parse NDJSON output.

        Command: ``trufflehog filesystem <path> --json --no-update``

        Falls back to entropy scan on timeout or unexpected failure.

        Args:
            target: Path to scan (file or directory).

        Returns:
            Parsed list of RawFinding from trufflehog NDJSON output.
        """
        try:
            result = subprocess.run(
                [
                    "trufflehog",
                    "filesystem",
                    str(target),
                    "--json",
                    "--no-update",
                ],
                capture_output=True,
                text=True,
                timeout=120,  # 2-minute cap — generous for large repos
            )
        except subprocess.TimeoutExpired:
            logger.warning("trufflehog timed out after 120s — falling back to entropy scanner")
            return self._entropy_scan(target)
        except FileNotFoundError:
            # Handles the edge case where trufflehog is removed between the
            # availability check and the actual scan run.
            logger.warning("trufflehog disappeared from PATH — falling back to entropy scanner")
            return self._entropy_scan(target)

        return self._parse_trufflehog_output(result.stdout)

    def _parse_trufflehog_output(self, stdout: str) -> list[RawFinding]:
        """Parse trufflehog v3 NDJSON output into RawFinding objects.

        trufflehog v3 emits one JSON object per line (NDJSON).
        Each line represents one detected secret.

        We redact the raw secret value before storing — only the first 4 chars
        are retained so developers can identify which key was leaked.

        Args:
            stdout: Raw stdout string from the trufflehog subprocess.

        Returns:
            List of RawFinding — one per trufflehog result line.
        """
        findings: list[RawFinding] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Non-JSON trufflehog output line (skipped): %.80s", line)
                continue

            # SourceMetadata structure:
            # {"Data": {"Filesystem": {"file": "/path", "line": 10}}}
            source_data: dict[str, Any] = (
                obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            )
            file_path = str(source_data.get("file", "unknown"))
            line_num = int(source_data.get("line", 1))

            detector_name = str(obj.get("DetectorName", "unknown"))
            verified = bool(obj.get("Verified", False))
            raw_value = str(obj.get("Raw", ""))

            # Retain only first 4 chars to help identify the key without exposing it.
            redacted = (raw_value[:4] + "****") if len(raw_value) > 4 else "****"

            findings.append(
                RawFinding(
                    tool="secrets",
                    rule_id=f"trufflehog-{detector_name.lower().replace(' ', '-')}",
                    file=file_path,
                    line=line_num,
                    severity="CRITICAL",
                    message=(
                        f"{'Verified' if verified else 'Potential'} secret detected "
                        f"[{detector_name}] — value starts: {redacted}"
                    ),
                    code_snippet=redacted,
                    metadata={
                        "detector": detector_name,
                        "verified": verified,
                        "decoder": str(obj.get("DecoderName", "")),
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Entropy-based fallback path
    # ------------------------------------------------------------------

    def _entropy_scan(self, target: Path) -> list[RawFinding]:
        """Entropy-based regex secret scanner — trufflehog fallback.

        Walks the target path recursively, skipping non-code directories and
        binary file extensions. For each source file, applies regex patterns
        for known secret types followed by Shannon entropy thresholding for
        generic high-entropy credential assignments.

        Args:
            target: File or directory to scan.

        Returns:
            List of RawFinding for all detected secrets in the target.
        """
        if target.is_file():
            return self._scan_file(target)

        findings: list[RawFinding] = []
        for file_path in self._iter_files(target):
            findings.extend(self._scan_file(file_path))
        return findings

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Yield scannable source files under root, skipping excluded paths.

        Skipped directories: .git, node_modules, __pycache__, .venv, venv,
                             .env, dist, build, .mypy_cache, .pytest_cache
        Skipped extensions: .pyc, .lock, binary/media formats (see _SKIP_EXTENSIONS)

        Args:
            root: Root directory to walk recursively.

        Yields:
            Path to each file that should be scanned for secrets.
        """
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            # Skip if any parent directory component is in the exclusion set.
            # relative_parts[-1] is the filename itself — only check parent dirs.
            if any(part in _SKIP_DIRS for part in relative_parts[:-1]):
                continue
            if path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            yield path

    def _scan_file(self, path: Path) -> list[RawFinding]:
        """Scan a single file for secrets using pattern matching and entropy.

        Pass 1: Apply each entry in _SECRET_PATTERNS (specific known formats).
        Pass 2: Check generic secret assignments for high Shannon entropy.
                Skips lines already flagged in Pass 1 to avoid duplicates.

        Skips files that cannot be read (binary encoding errors, permissions).

        Args:
            path: Absolute path to the file to scan.

        Returns:
            List of RawFinding for each secret found in the file.
        """
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            logger.debug("Skipping unreadable file %s: %s", path, exc)
            return []

        findings: list[RawFinding] = []
        lines = content.splitlines()
        flagged_lines: set[int] = set()  # prevents double-flagging the same line

        for line_num, line_text in enumerate(lines, start=1):
            # ----------------------------------------------------------
            # Pass 1: known secret patterns (regex-only, type-specific)
            # ----------------------------------------------------------
            for rule_id, pattern, message in _SECRET_PATTERNS:
                match = pattern.search(line_text)
                if not match:
                    continue

                # group(1) is the captured secret; group(0) is the full match
                secret_value = (
                    match.group(1)
                    if match.lastindex is not None and match.lastindex >= 1
                    else match.group(0)
                )

                # Filter out obvious placeholder strings ("your-api-key-here", "xxxx", etc.)
                # by requiring a minimum entropy. Real secrets are always > 2.5 bits.
                if _shannon_entropy(secret_value) < 2.5:
                    continue

                findings.append(
                    RawFinding(
                        tool="secrets",
                        rule_id=rule_id,
                        file=str(path),
                        line=line_num,
                        severity="CRITICAL",
                        message=message,
                        code_snippet=_redact_line(line_text, secret_value),
                        metadata={"entropy": round(_shannon_entropy(secret_value), 3)},
                    )
                )
                flagged_lines.add(line_num)

            # ----------------------------------------------------------
            # Pass 2: high-entropy generic assignments (unknown key types)
            # ----------------------------------------------------------
            if line_num in flagged_lines:
                # Already flagged by a specific pattern — skip entropy check
                continue

            assign_match = _ASSIGNMENT_PATTERN.search(line_text)
            if assign_match:
                candidate = assign_match.group(1)
                entropy = _shannon_entropy(candidate)
                if entropy >= _ENTROPY_THRESHOLD:
                    findings.append(
                        RawFinding(
                            tool="secrets",
                            rule_id="high-entropy-secret",
                            file=str(path),
                            line=line_num,
                            severity="CRITICAL",
                            message=(
                                f"High-entropy string in secret assignment "
                                f"(Shannon entropy={entropy:.2f}) — likely a hardcoded credential"
                            ),
                            code_snippet=_redact_line(line_text, candidate),
                            metadata={"entropy": round(entropy, 3)},
                        )
                    )
                    flagged_lines.add(line_num)

        return findings
