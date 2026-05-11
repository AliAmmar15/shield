# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in Velonus — including the CLI, the API, the scanner pipeline, or the AI engine — please report it privately by emailing:

**security@velonus.dev**

Include as much detail as possible:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

We will acknowledge your report within **48 hours** and aim to provide an initial assessment within **5 business days**.

---

## Response Commitment

| Timeline | Action |
|---|---|
| 48 hours | Acknowledgement of your report |
| 5 business days | Initial severity assessment and triage |
| 30 days | Patch release for confirmed Critical / High vulnerabilities |
| 90 days | Coordinated public disclosure (aligned with reporter) |

We follow responsible disclosure. If you have found a vulnerability and report it in good faith, we will not pursue legal action against you.

---

## Scope

### In scope

- `velonus-cli` — the open-source CLI scanner
- `velonus-api` — the FastAPI backend (when live)
- Scanner pipeline and detector wrappers (Bandit, Semgrep, pip-audit, Safety, secrets)
- Authentication and authorization in the API layer
- Data exposure via findings storage or the dashboard

### Out of scope

The following are **not** in scope for this security policy:

- Vulnerabilities in upstream tools we wrap (Semgrep, Bandit, pip-audit, Safety, trufflehog) — please report those to their respective projects
- Denial of service via extremely large codebases (a known limitation, not a vulnerability)
- Issues that require physical access to a machine already running the CLI
- Findings that only affect development / test environments with no production data
- Social engineering attacks

---

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Yes |
| Published releases | ✅ Yes (latest only) |
| Older releases | ❌ No — please upgrade |

---

## Disclosure Policy

Once a fix is ready and released, we will publish a security advisory on GitHub. We credit researchers who report valid vulnerabilities unless they prefer to remain anonymous.
