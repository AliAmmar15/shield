[![CI](https://github.com/AliAmmar15/Velonus/actions/workflows/ci.yml/badge.svg)](https://github.com/AliAmmar15/Velonus/actions)
[![PyPI](https://img.shields.io/pypi/v/velonus)](https://pypi.org/project/velonus)
[![Python](https://img.shields.io/pypi/pyversions/velonus)](https://pypi.org/project/velonus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Alpha](https://img.shields.io/badge/status-alpha-orange)]()

# Velonus

**Security scanning for Python developers that actually tells you how to fix things.**  
One command. Five scanners. Zero noise.

```bash
pip install velonus
velonus scan ./your-project
```

> Requires Python 3.10+

---

## Demo

```
$ velonus scan ./myapp

  Scanning with 5 tools...

  secrets    ████████████████████  0.3s
  bandit     ████████████████████  2.1s
  semgrep    ████████████████████  4.2s
  pip-audit  ████████████████████  1.8s
  safety     ████████████████████  1.2s

 ┌──────────────┬──────────────────────────────────────────┬──────────────────┬──────────┐
 │ Severity     │ Finding                                  │ Location         │ Tool     │
 ├──────────────┼──────────────────────────────────────────┼──────────────────┼──────────┤
 │ 🔴 CRITICAL  │ Hardcoded AWS secret key                 │ config.py:14     │ secrets  │
 │ 🔴 CRITICAL  │ Hardcoded OpenAI API key                 │ llm_client.py:8  │ secrets  │
 │ 🔴 CRITICAL  │ SQL injection via string format          │ db/queries.py:41 │ semgrep  │
 │ 🟠 HIGH      │ Use of MD5 for password hashing          │ auth/utils.py:27 │ bandit   │
 │ 🟠 HIGH      │ requests 2.28.0 — CVE-2023-32681 (8.1)  │ requirements.txt │ pip-aud  │
 │ 🟡 MEDIUM    │ Shell injection via subprocess           │ runner.py:19     │ bandit   │
 │ 🟡 MEDIUM    │ Hardcoded JWT secret                     │ auth/tokens.py:3 │ secrets  │
 └──────────────┴──────────────────────────────────────────┴──────────────────┴──────────┘

  3 CRITICAL  │  7 HIGH  │  12 MEDIUM  │  34 LOW
```

---

## What It Detects

| Category | Tool | What it catches |
|---|---|---|
| Hardcoded secrets | trufflehog + entropy | API keys, AWS creds, JWT tokens, PEM keys |
| Python SAST | Bandit | Injections, weak crypto, unsafe shell exec |
| Pattern analysis | Semgrep | OWASP Top 10 vulnerability patterns |
| Dependency CVEs | pip-audit | Known CVEs with CVSS v3 scores |
| Vulnerability DB | Safety | Package vulnerability cross-reference |

All findings are normalized to a unified schema with **CWE tags**, **OWASP Top 10 categories**, and **deterministic fingerprints** for deduplication.

---

## Output Formats

```bash
velonus scan ./                         # Rich terminal table (default)
velonus scan ./ --format json           # JSON array — pipe to jq, scripts, etc.
velonus scan ./ --sarif                 # SARIF file → GitHub Security tab
velonus scan ./ --severity high         # Filter to HIGH and CRITICAL only
velonus scan ./ -o results/scan.sarif   # Write SARIF to a custom path
```

---

## CI Integration

```yaml
- name: Velonus security scan
  run: |
    pip install velonus
    velonus scan . --sarif -o velonus.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: velonus.sarif
```

Velonus exits `1` on CRITICAL or HIGH findings — use it as a hard CI gate.

---

## Roadmap

| | Phase | Status |
|---|---|---|
| ✅ | Phase 0 — CLI + secret detection | Done |
| ✅ | Phase 1 — Full scanner pipeline (Bandit, Semgrep, pip-audit, Safety) | Done |
| 🔨 | Phase 2 — AI context engine (exploitability scoring + fix generation) | Building |
| 🔜 | Phase 3 — GitHub PR integration (inline fixes, one-click accept) | Planned |
| 🔜 | Phase 4 — Web dashboard | Planned |

---

## Alpha Notice

Velonus is in alpha. It works — we use it ourselves — and we want your feedback.  
Expect rough edges. [Report issues](https://github.com/AliAmmar15/Velonus/issues) and we will fix them fast.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, test instructions, and PR guidelines.  
Found a security issue? See [SECURITY.md](SECURITY.md).  
All contributions welcome — especially scanner improvements and false-positive reports.

---

## License

MIT — see [LICENSE](LICENSE).


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
velonus --help
```

---

## Usage

### Scan a project

```bash
# Scan the current directory
velonus scan ./

# Scan a specific path
velonus scan ./src

# Only show HIGH and above
velonus scan ./ --severity high

# Verbose output (shows per-tool timing)
velonus scan ./ --verbose
```

### Output formats

```bash
# Default: rich terminal table
velonus scan ./

# JSON (pipe-friendly)
velonus scan ./ --format json

# Write a SARIF file (for GitHub Security tab)
velonus scan ./ --sarif

# Write SARIF to a custom path
velonus scan ./ -o results/velonus.sarif
```

### Use in CI (GitHub Actions)

```yaml
- name: Velonus security scan
  run: velonus scan . --sarif -o velonus-results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: velonus-results.sarif
```

Velonus exits with code `1` when CRITICAL or HIGH findings are detected — use this as a CI gate.

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: velonus
        name: Velonus security scan
        entry: velonus scan
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

Velonus is currently in private development. Contribution guidelines will be published when the CLI core is open sourced after Phase 5.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions that apply today.

---

## License

Private — All rights reserved until open source release.
