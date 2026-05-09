# Shield AI

> AI-native security copilot for developers. Scans your codebase, cuts the noise, and generates real fixes — not just alerts.

---

## The Problem

Modern security tools generate hundreds of alerts. Most are noise. Developers ignore them. Real vulnerabilities slip through.

Shield is different. Instead of burying you in findings, it identifies real issues, scores actual exploitability, and gives you the fix — not just the warning.

---

## What It Does

- 🔍 **Secret Detection** — catches API keys, AWS credentials, tokens, and connection strings before they ship
- 🛡️ **Static Analysis** — aggregates Semgrep, Bandit, pip-audit, and Safety into one unified view
- 🤖 **AI Context Engine** — scores real exploitability, kills false positives, explains why findings matter
- 🔧 **AI Remediation** — generates secure code fixes with explanations, not just alerts
- 🔀 **GitHub PR Integration** — posts inline fix suggestions directly on pull requests, one click to accept

---

## Installation

**From source (development):**

```bash
git clone https://github.com/AliAmmar15/shield
cd shield

# Install uv if you don't have it
pip install uv

# Install all workspace packages
uv sync --all-extras --dev

# Activate the virtual environment
source .venv/bin/activate        # macOS/Linux
.venv\Scripts\Activate.ps1       # Windows PowerShell

# Install the CLI in editable mode
pip install -e apps/cli
pip install -e packages/scanner
pip install -e packages/normalizer
```

**Verify the install:**

```bash
shield --help
```

---

## Usage

### Scan a project

```bash
# Scan the current directory
shield scan ./

# Scan a specific path
shield scan ./src

# Only show HIGH and above
shield scan ./ --severity high

# Verbose output (shows per-tool timing)
shield scan ./ --verbose
```

### Output formats

```bash
# Default: rich terminal table
shield scan ./

# JSON (pipe-friendly)
shield scan ./ --format json

# Write a SARIF file (for GitHub Security tab)
shield scan ./ --sarif

# Write SARIF to a custom path
shield scan ./ -o results/shield.sarif
```

### Use in CI (GitHub Actions)

```yaml
- name: Shield security scan
  run: shield scan . --sarif -o shield-results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: shield-results.sarif
```

Shield exits with code `1` when CRITICAL or HIGH findings are detected — use this as a CI gate.

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: shield
        name: Shield security scan
        entry: shield scan
        language: system
        pass_filenames: false
        args: ["./", "--severity", "high"]
```

---

## Example Output

```
✓ Running secret detection...          [0.3s]
✓ Running Bandit...                    [2.1s]
✓ Running Semgrep...                   [4.2s]
✓ Running pip-audit...                 [1.8s]
✓ Running Safety...                    [1.2s]
──────────────────────────────────────────────
  3 CRITICAL  │  7 HIGH  │  12 MEDIUM  │  34 LOW

⚠ CRITICAL  Hardcoded AWS key detected
  → src/config.py:14
  CWE-798 · A07:2021
```

---

## Status

Shield is currently in active development. We are working through the following phases:

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | CLI foundation + secret detection | ✅ Complete |
| 1 | Full scanner pipeline + normalization | 🟡 In Progress |
| 2 | AI context + remediation engine | 🔵 Planned |
| 3 | GitHub PR integration | 🔵 Planned |
| 4 | Web dashboard | 🔵 Planned |
| 5 | Open source + GTM | 🔵 Planned |

### Phase 1 Progress (as of 2026-05-09)

The scanner pipeline and normalization layer are complete. `shield scan ./` runs 5 tools in parallel and returns normalized, deduplicated findings in a unified format:

- **Bandit** — Python AST static analysis (40 CWE mappings, B101–B413)
- **Semgrep** — Pattern-based analysis with OWASP Top 10 tagging
- **pip-audit** — Dependency CVE scanning with CVSS v3 severity scoring
- **Safety** — Vulnerability database cross-reference (v1 + v2 JSON formats)
- **Secret detection** — trufflehog v3 + entropy-based fallback

All findings are normalized to a unified `NormalizedFinding` schema with deterministic SHA-256 fingerprints, CWE tags, and OWASP Top 10 categories.

Remaining: JSON/SARIF output format validation against the new pipeline, and unit tests for `FindingNormalizer` and `DeduplicationFilter`.

---

## Tech Stack

- **CLI** — Python, Typer, Rich
- **API** — FastAPI, PostgreSQL, ARQ
- **AI** — Anthropic Claude (Sonnet for fixes, Haiku for triage)
- **Scanners** — Semgrep, Bandit, pip-audit, Safety
- **Dashboard** — Next.js, Tailwind, shadcn/ui
- **Auth** — Clerk
- **Infra** — Docker, Railway

---

## Target Users

- Python developers and AI startups
- Small SaaS teams without a dedicated security team
- Engineers who want security that fits into their workflow

---

## Contributing

Shield is currently in private development. Contribution guidelines will be published when the CLI core is open sourced after Phase 5.

---

## License

Private — All rights reserved until open source release.
