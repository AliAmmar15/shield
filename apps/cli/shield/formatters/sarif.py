"""sarif.py — SARIF 2.1.0 output formatter for Shield findings.

Produces output compatible with:
  - GitHub Code Scanning (via the `upload-sarif` action)
  - VS Code SARIF Viewer extension
  - Any SARIF-aware security tooling

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Usage:
    from shield.formatters.sarif import to_sarif, write_sarif

    sarif_doc = to_sarif(findings, scan_path="/path/to/project")
    write_sarif(findings, Path("shield-results.sarif"), scan_path="/path/to/project")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shield.core.output import Severity

if TYPE_CHECKING:
    from shield.normalizer_stub import NormalizedFinding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Version kept in sync with apps/cli/pyproject.toml [project] version
_SHIELD_VERSION = "0.1.0"

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"

# Maps our Severity enum to SARIF notification levels.
# SARIF spec §3.27.10: "error" | "warning" | "note" | "none"
_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def to_sarif(findings: list[NormalizedFinding], scan_path: str) -> dict[str, Any]:
    """Convert a list of NormalizedFindings to a SARIF 2.1.0 document.

    The returned dict is JSON-serialisable and suitable for:
    - Writing to a .sarif file and uploading to GitHub Code Scanning
    - Printing to stdout for toolchain piping

    Args:
        findings: Normalised findings produced by the scan pipeline.
        scan_path: Absolute (or resolvable) path to the root of the scanned
                   project. Used to compute relative artifact URIs so the
                   SARIF file is portable.

    Returns:
        A dict representing a valid SARIF 2.1.0 document.
    """
    scan_root = Path(scan_path).resolve()

    # Collect unique rule descriptors for tool.driver.rules.
    # De-duplicated so each rule_id appears exactly once even if it fires
    # on many files — required by the SARIF spec.
    rules = _collect_rules(findings)
    results = [_finding_to_result(f, scan_root) for f in findings]

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shield",
                        "version": _SHIELD_VERSION,
                        "informationUri": "https://github.com/AliAmmar15/shield",
                        # Each unique rule_id in the findings gets a descriptor entry
                        "rules": rules,
                    }
                },
                # Allows consuming tools to resolve relative URIs back to
                # absolute paths without encoding the machine path into every result.
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": _dir_uri(scan_root),
                        "description": {"text": "Root directory of the scanned project."},
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(
    findings: list[NormalizedFinding],
    output_path: Path,
    scan_path: str = ".",
) -> None:
    """Serialise findings to a SARIF 2.1.0 JSON file.

    Creates all intermediate parent directories automatically.

    Args:
        findings: Normalised findings produced by the scan pipeline.
        output_path: Destination path for the .sarif file. The filename
                     conventionally ends in .sarif but this is not enforced.
        scan_path: Absolute or relative path to the scan root, passed through
                   to :func:`to_sarif` for URI computation.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_doc = to_sarif(findings, scan_path)
    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_rules(findings: list[NormalizedFinding]) -> list[dict[str, Any]]:
    """Build the tool.driver.rules array from findings.

    Each unique rule_id produces exactly one ReportingDescriptor entry.
    The first finding for a given rule_id wins for description and severity
    metadata (all findings for the same rule should share these).

    Args:
        findings: Full list of normalised findings.

    Returns:
        List of SARIF ReportingDescriptor dicts.
    """
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.rule_id in seen:
            continue
        # Combine CWE + OWASP tags; add a generic "security" tag for tooling
        tags: list[str] = [*f.cwe, *f.owasp, "security"]
        seen[f.rule_id] = {
            "id": f.rule_id,
            # PascalCase name for display in IDEs / GitHub Security tab
            "name": _rule_id_to_name(f.rule_id),
            "shortDescription": {"text": f.message},
            "fullDescription": {"text": f.message},
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            },
            "properties": {
                "tags": tags,
                # GitHub Code Scanning uses problem.severity to colour findings
                "problem.severity": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                "precision": f.confidence.value.lower(),
            },
        }
    return list(seen.values())


def _finding_to_result(finding: NormalizedFinding, scan_root: Path) -> dict[str, Any]:
    """Convert a single NormalizedFinding to a SARIF Result object.

    Args:
        finding: The normalised finding to convert.
        scan_root: Resolved absolute path to the scan root, used to build
                   relative artifact URIs.

    Returns:
        A dict representing a SARIF Result (§3.27).
    """
    artifact_uri = _artifact_uri(finding.file, scan_root)
    level = _SEVERITY_TO_LEVEL.get(finding.severity, "warning")

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        # Consuming tool resolves this against originalUriBaseIds
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, finding.line_start),
                        "endLine": max(1, finding.line_end),
                        "snippet": {"text": finding.code_snippet},
                    },
                }
            }
        ],
        # Deterministic fingerprint — used by GitHub to de-duplicate findings
        # across PR scans so the same issue is not re-opened each time.
        "fingerprints": {
            "shieldFingerprint/v1": finding.id,
        },
        "properties": {
            "tags": [*finding.cwe, *finding.owasp],
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "tool": finding.tool,
        },
    }
    return result


def _artifact_uri(file_path: str, scan_root: Path) -> str:
    """Compute a relative URI for a file within the scan root.

    SARIF URIs use forward slashes regardless of the host OS.
    If the file is outside the scan root (e.g. a trufflehog virtual path),
    the raw posix path is returned so the result is still valid SARIF.

    Args:
        file_path: Absolute or relative file path string from the finding.
        scan_root: Resolved absolute path to the scan root.

    Returns:
        Relative POSIX URI string (e.g. ``"src/app/config.py"``).
    """
    try:
        resolved = Path(file_path).resolve()
        relative = resolved.relative_to(scan_root)
        return relative.as_posix()
    except ValueError:
        # File is outside the scan root — fall back to absolute posix path
        return Path(file_path).as_posix()


def _dir_uri(path: Path) -> str:
    """Return a file:// URI for a directory, ensuring a trailing slash.

    SARIF spec §3.14.14 requires directory URIs to end with ``/``.

    Args:
        path: Resolved absolute directory path.

    Returns:
        ``file://`` URI string ending with ``/``.
    """
    uri = path.as_uri()
    return uri if uri.endswith("/") else uri + "/"


def _rule_id_to_name(rule_id: str) -> str:
    """Convert a rule_id to a PascalCase display name for SARIF.

    Strips any tool-prefix segment (e.g. ``"secrets/generic-api-key"``
    becomes ``"GenericApiKey"``).

    Args:
        rule_id: The raw rule_id string from the finding.

    Returns:
        PascalCase name string.

    Examples:
        >>> _rule_id_to_name("generic-api-key")
        'GenericApiKey'
        >>> _rule_id_to_name("secrets/aws-access-key-id")
        'AwsAccessKeyId'
    """
    base = rule_id.split("/")[-1]
    return "".join(word.capitalize() for word in base.replace("-", "_").split("_"))
