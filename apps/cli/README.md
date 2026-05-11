# velonus-cli

> AI-native application security scanner for developers.  
> Finds real issues. Explains why they matter. Generates fixes.

---

## Table of Contents

- [velonus-cli](#velonus-cli)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [velonus scan](#velonus-scan)
  - [velonus auth](#velonus-auth)
  - [velonus config](#velonus-config)
- [Output Formats](#output-formats)
- [Severity Levels](#severity-levels)
- [CI/CD Integration](#cicd-integration)
- [Roadmap](#roadmap)

---

## Installation

### Requirements

- Python 3.12+
- Windows / macOS / Linux

### Install via pip

```bash
pip install -e apps/cli
```

> The package name is `velonus-cli`. The CLI command installed is `velonus`.

### Add to PATH (Windows — run once)

After installing, make the `velonus` command available in every terminal:

```powershell
[System.Environment]::SetEnvironmentVariable(
    "PATH",
    "C:\Users\$env:USERNAME\AppData\Roaming\Python\Python313\Scripts;" + [System.Environment]::GetEnvironmentVariable("PATH","User"),
    "User"
)
```

Then restart your terminal. Verify with:

```powershell
velonus --version
```

---

## Quick Start

```bash
# Scan the current directory
velonus scan ./

# Scan a specific project
velonus scan ./my-python-project

# Only show HIGH and CRITICAL findings
velonus scan ./ --severity high

# Output as JSON (for piping or tooling)
velonus scan ./ --format json
```

---

## Commands

### `velonus scan`

Runs the security scanner pipeline on a local path and prints findings to the terminal.

```
velonus scan [PATH] [OPTIONS]
```

| Argument / Option | Default | Description |
|---|---|---|
| `PATH` | `.` | Path to the project or file to scan |
| `--format`, `-f` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `--severity`, `-s` | `info` | Minimum severity to show: `critical`, `high`, `medium`, `low`, `info` |
| `--verbose`, `-v` | off | Show resolved target path and extra detail |
| `--help` | | Show help and exit |

#### Examples

```bash
# Scan current directory, show all findings
velonus scan ./

# Scan a subdirectory
velonus scan ./apps/api

# Only show critical and high severity findings
velonus scan ./ --severity high

# Show resolved path before scanning
velonus scan ./ --verbose

# Export findings as JSON
velonus scan ./ --format json

# Export findings as JSON, high+ only, redirect to file
velonus scan ./ --format json --severity high > findings.json

# SARIF output (for GitHub Code Scanning — Phase 1)
velonus scan ./ --format sarif
```

#### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no HIGH or CRITICAL findings |
| `1` | Scan completed, one or more HIGH or CRITICAL findings found |

Exit code `1` on HIGH/CRITICAL is intentional — use it as a CI gate to block merges.

---

### `velonus auth`

Manages authentication with the Velonus API. **Available in Phase 2.**

```
velonus auth [COMMAND]
```

| Command | Description |
|---|---|
| `velonus auth login` | Authenticate via Clerk (browser OAuth flow) |
| `velonus auth logout` | Clear stored credentials |
| `velonus auth status` | Show whether you are currently authenticated |

```bash
velonus auth login
velonus auth logout
velonus auth status
```

> These commands are stubbed in Phase 0. They will be fully functional in Phase 2 when the API backend is live.

---

### `velonus config`

Manages local CLI configuration. **Available in Phase 2.**

```
velonus config [COMMAND]
```

| Command | Description |
|---|---|
| `show` | Print the current configuration |
| `set <key> <value>` | Set a configuration value |

```bash
velonus config show
velonus config set api_url https://api.velonus.dev
```

> Stubbed in Phase 0.

---

## Output Formats

### `terminal` (default)

Colored Rich table with severity badges, file paths, line numbers, rule IDs, and messages. Best for interactive use.

```
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity       ┃ Tool       ┃ File          ┃ Line  ┃ Rule             ┃ Message                      ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 🔴 CRITICAL    │ secrets    │ config.py     │ 12    │ aws-access-key   │ Hardcoded AWS access key…    │
│ 🟠 HIGH        │ bandit     │ auth/views.py │ 87    │ B106             │ Hardcoded password in func…  │
│ 🟡 MEDIUM      │ semgrep    │ db/query.py   │ 43    │ python.sqli      │ Possible SQL injection…      │
└────────────────┴────────────┴───────────────┴───────┴──────────────────┴──────────────────────────────┘

Total: 3 findings  —  1 CRITICAL  1 HIGH  1 MEDIUM
```

### `json`

Newline-delimited JSON array. Each element is a serialized `NormalizedFinding`. Suitable for piping into other tools or storing results.

```bash
velonus scan ./ --format json | python -m json.tool
velonus scan ./ --format json > scan-results.json
```

### `sarif`

Static Analysis Results Interchange Format — compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SAST tooling. **Available in Phase 1.**

---

## Severity Levels

| Badge | Level | Color | When it's used |
|---|---|---|---|
| 🔴 | `CRITICAL` | Bold red | Hardcoded secrets, RCE, auth bypass |
| 🟠 | `HIGH` | Orange | SQL injection, command injection, insecure deserialization |
| 🟡 | `MEDIUM` | Yellow | XSS, weak crypto, path traversal |
| 🔵 | `LOW` | Blue | Insecure defaults, minor misconfigurations |
| ⚪ | `INFO` | Grey | Style issues, informational notes |

Use `--severity high` to only surface findings worth acting on immediately. Use `--severity info` (default) to see everything.

---

## CI/CD Integration

### GitHub Actions

Add this to `.github/workflows/security.yml`:

```yaml
name: Velonus Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install velonus-cli
        run: pip install -e apps/cli

      - name: Run security scan
        run: velonus scan ./ --severity high
        # exits 1 if HIGH or CRITICAL findings are found — blocks the merge
```

### Pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: velonus-scan
        name: Velonus Security Scan
        entry: velonus scan
        args: ["./", "--severity", "high"]
        language: system
        pass_filenames: false
```

---

## Roadmap

| Phase | Status | What ships |
|---|---|---|
| **Phase 0** — Foundation | 🟡 In progress | CLI skeleton, Rich output, `NormalizedFinding` model |
| **Phase 1** — Scanner Pipeline | 🔴 Not started | Real secret detection, Bandit, Semgrep, pip-audit, SARIF |
| **Phase 2** — AI Layer | 🔴 Not started | AI prioritization, exploitability scoring, fix generation |
| **Phase 3** — GitHub Integration | 🔴 Not started | PR inline review comments, one-click fix suggestions |
| **Phase 4** — Dashboard | 🔴 Not started | Web UI, scan history, finding trends |
| **Phase 5** — OSS Launch | 🔴 Not started | PyPI publish, open-source CLI core, pricing |

---

## License

MIT — scanner CLI core is open source.  
AI engine, PR integration, and dashboard are proprietary.

