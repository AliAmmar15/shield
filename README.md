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

## Quick Start

```bash
# Install
pip install shield-cli

# Scan your project
shield scan ./

# Scan with AI prioritization (requires free account)
shield scan ./ --ai
```

---

## Example Output

```
✓ Detected Python project (FastAPI)
✓ Running secret detection...          [0.3s]
✓ Running Bandit...                    [2.1s]
✓ Running Semgrep...                   [4.2s]
✓ Running pip-audit...                 [1.8s]
──────────────────────────────────────────────
  3 CRITICAL  │  7 HIGH  │  12 MEDIUM  │  34 LOW

⚠ CRITICAL  Hardcoded AWS key detected
  → src/config.py:14
  → Fix: shield fix src/config.py:14
```

---

## Status

Shield is currently in active development. We are working through the following phases:

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | CLI foundation + secret detection | Completed |
| 1 | Full scanner pipeline + normalization | In Progress |
| 2 | AI context + remediation engine | Planned |
| 3 | GitHub PR integration | Planned |
| 4 | Web dashboard | Planned |
| 5 | open source | ⏳ Planned |

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
