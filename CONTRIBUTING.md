# Contributing to Velonus

Thank you for your interest in contributing. This guide covers everything you need to get the dev environment running and a PR merged.

---

## Table of Contents

- [Dev Environment Setup](#dev-environment-setup)
- [Running Tests](#running-tests)
- [Linting and Formatting](#linting-and-formatting)
- [Type Checking](#type-checking)
- [PR Guidelines](#pr-guidelines)
- [Issue Templates](#issue-templates)

---

## Dev Environment Setup

**Requirements:** Python 3.12+, [uv](https://docs.astral.sh/uv/) package manager.

```bash
# 1. Clone the repo
git clone https://github.com/AliAmmar15/Velonus
cd Velonus

# 2. Install all workspace packages and dev dependencies
uv sync --all-extras --dev

# 3. Activate the virtual environment
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\Activate.ps1       # Windows PowerShell

# 4. Install the CLI and scanner in editable mode
pip install -e apps/cli
pip install -e packages/scanner
pip install -e packages/normalizer
```

**Verify everything is working:**

```bash
shield --help
shield scan ./apps/cli/shield
```

---

## Running Tests

All unit tests live in `apps/cli/tests/`. Run them with:

```bash
pytest apps/cli/tests/
```

For verbose output with short tracebacks:

```bash
pytest apps/cli/tests/ -v --tb=short
```

For a specific test file:

```bash
pytest apps/cli/tests/test_secrets.py -v
```

**Tests must pass before any PR is opened.** CI blocks merges if `pytest` exits non-zero.

---

## Linting and Formatting

We use [ruff](https://docs.astral.sh/ruff/) as the single tool for linting and formatting. Do **not** use black, isort, or flake8.

```bash
# Check for lint errors
ruff check .

# Auto-fix safe lint errors
ruff check . --fix

# Check formatting (what CI runs)
ruff format --check .

# Auto-format all files
ruff format .
```

Run both before opening a PR:

```bash
ruff check . && ruff format .
```

---

## Type Checking

We use [mypy](https://mypy.readthedocs.io/) in strict mode:

```bash
mypy apps/cli/shield --strict --ignore-missing-imports
```

All new code must pass mypy strict with zero errors. PRs that introduce `type: ignore` comments require an explanation in a code comment.

---

## PR Guidelines

1. **One feature or fix per PR.** Do not bundle unrelated changes.
2. **Tests are required.** Every new scanner wrapper, formatter, or utility needs matching unit tests.
3. **Ruff must be clean.** Run `ruff check . && ruff format --check .` locally before pushing.
4. **mypy must be clean.** Run `mypy apps/cli/shield --strict --ignore-missing-imports` locally.
5. **Target `main`.** All PRs merge into `main`. There are no long-lived feature branches.
6. **Describe the change.** Fill out the PR template — a clear description and a filled checklist unblocks review.
7. **Keep it small.** PRs under 400 lines of diff get reviewed faster. Split large changes when possible.
8. **No AI-generated placeholder code.** Every function must be functional and tested.

### Commit message format

```
<type>: <short imperative summary>

Types: feat | fix | refactor | test | docs | infra | chore
```

Examples:
```
feat: add semgrep CWE extraction from rule metadata
fix: handle bandit exit code 2 on bad target path
test: cover pip-audit CVSS v3 threshold edge cases
docs: add CONTRIBUTING.md and issue templates
```

---

## Issue Templates

Use the issue templates in `.github/ISSUE_TEMPLATE/`:

- **Bug report** — for unexpected behaviour, crashes, or wrong output
- **Feature request** — for new detection rules, output formats, or integrations

For security vulnerabilities, **do not open a public issue**. See [SECURITY.md](SECURITY.md).
