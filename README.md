# SENTINEL — Automated Web Security Scanner & Evidence Workstation

SENTINEL identifies observable HTTP security-configuration issues, explains
their implications, preserves supporting evidence, and generates actionable
reports. It is built for cybersecurity students, junior analysts, pentest
trainees and developers learning secure web configuration — and for a
bootcamp/GitHub portfolio.

> **Evidence, not assumptions.** SENTINEL records what was actually seen,
> keeps blocked checks separate from findings, and never fabricates results.

## Features

- **Forensic workstation UI** — warm-neutral light theme with a designed dark
  theme, deep forest-green accent, monospaced evidence blocks, persistent left
  navigation, findings register with search/filter/sort, and a per-finding
  inspection panel.
- **Server-side scanner** — one passive GET request from the local backend
  inspects the *full* response header set, cookies and basic TLS metadata
  (not limited by browser CORS).
- **18 registered checks** — CSP (+ weakness analysis), HSTS, MIME sniffing,
  framing defense, Referrer-Policy, Permissions-Policy, Server/X-Powered-By
  disclosure, X-XSS-Protection, Cache-Control, COOP, cookie flags
  (Secure/HttpOnly/SameSite — names only, values never recorded), HTTPS
  transport, certificate verification and expiry window.
- **Three execution modes** — `Server scan` (recommended), `Demo profiles`
  (mixed / hardened / weak, canned for training), and `Live browser request`
  (CORS-bound, honestly reports blocked requests instead of inventing data).
- **Evidence-first reporting** — JSON, CSV, Markdown and a standalone
  print-to-PDF HTML report, all generated locally, with a SHA-256 evidence
  digest over the canonical observation set.
- **Scan history** — SQLite database on this machine, viewable/loadeable from
  the UI; browser-mode records taken offline fall back to localStorage.
- **Hardened transport (SSRF-safe)** — redirects are followed manually, with
  every hop parsed, resolved and checked against the destination IP policy
  *before* any connection; sockets connect only to validated addresses
  (connection pinning), closing the DNS-rebinding TOCTOU window while
  preserving TLS certificate + hostname verification. Redirect loops and
  over-long chains are aborted with clear errors.
- **Authorization confirmation** — real scans are disabled in the UI until an
  explicit confirmation is checked, and the backend independently rejects
  requests without `authorization: true` (400/403). Demo profiles need no
  confirmation because no request is ever made.
- **Local API hardening** — no CORS, strict loopback Host allowlist and
  Origin checks across all API routes (including history/report reads), strict
  security headers/CSP, request size limits, per-client rate limiting and a
  bounded concurrency gate.
- **Safe report exports** — CSV formula-like cells are neutralized; HTML
  documentation links accept only valid HTTPS URLs without embedded credentials.
- **Educational scoring** — documented deduction model (`100 − 25·Critical −
  15·High − 8·Medium − 3·Low`, clamped 0–100) plus letter grades.

## Quickstart

Requirements: **Python 3.10+** (no database server, no Node build step).

```bash
cd SENTINEL
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
python -m backend.app
```

Then open **http://127.0.0.1:5050** — the same process serves the UI and the
API. Prefer one command? Use `./run.sh`.

Scan only websites **you own or have explicit permission to assess**.

### Run the tests

```bash
pip install -r backend/requirements-dev.txt
python -m pytest tests/ -v
```

## Configuration (environment variables)

| Variable                     | Default     | Meaning                                        |
| ---------------------------- | ----------- | ---------------------------------------------- |
| `SENTINEL_HOST`              | `127.0.0.1` | Bind address                                   |
| `SENTINEL_PORT`              | `5050`      | Bind port                                      |
| `SENTINEL_ALLOW_PRIVATE`     | unset       | `1` enables scanning private/loopback lab targets (SSRF guard opt-out) |
| `SENTINEL_DB`                | `backend/data/sentinel.db` | SQLite history path            |
| `SENTINEL_MAX_HISTORY`       | `200`       | Stored scan records cap                        |
| `SENTINEL_CONNECT_TIMEOUT`   | `5`         | Outbound connect timeout (s)                   |
| `SENTINEL_READ_TIMEOUT`      | `10`        | Outbound read timeout (s)                      |
| `SENTINEL_DNS_TIMEOUT`       | `5`         | DNS resolution timeout (s)                     |
| `SENTINEL_MAX_REDIRECTS`     | `5`         | Redirect hops followed per scan                |
| `SENTINEL_SCAN_DEADLINE`     | `60`        | Overall per-scan time budget (s)               |
| `SENTINEL_MAX_RESPONSE_BYTES`| `65536`     | Response bytes consumed before closing         |
| `SENTINEL_ALLOWED_PORTS`     | `80,443,8080,8443` | Port allowlist for targets              |
| `SENTINEL_MAX_CONCURRENT`    | `2`         | Concurrent scans (extras get HTTP 503)         |
| `SENTINEL_RATE_LIMIT`        | `12`        | Scans per minute per client (HTTP 429 beyond)  |

## Execution modes

| Mode | Where the request happens | Sees | Use for |
| --- | --- | --- | --- |
| **Server scan** | local backend | full headers, cookie flags, TLS metadata | real, authorized assessments |
| **Demo profiles** | nowhere (canned) | simulated evidence | training, UI exploration, screenshots |
| **Live browser request** | the page itself | only CORS-exposed headers | learning CORS boundaries |

## Project structure

```
SENTINEL/
├── frontend/
│   ├── index.html
│   ├── css/{styles.css, themes.css}
│   ├── js/{app, api, scanner-ui, findings, reports, history, validation}.js
│   └── assets/favicon.svg
├── backend/
│   ├── app.py               Flask API + static UI server (auth, rate limit, headers)
│   ├── scanner.py           scan orchestration (server / demo / browser import)
│   ├── safe_transport.py    SSRF-safe transport: pinning + manual redirects
│   ├── ip_policy.py         destination IP policy (v4/v6, embedded IPv4)
│   ├── target_validation.py URL validation, port allowlist, bounded DNS
│   ├── security_checks.py   18-check registry (pure, testable functions)
│   ├── scoring.py           educational score + grade model
│   ├── report_generator.py  JSON / CSV / Markdown / printable HTML
│   ├── storage.py           SQLite history
│   └── requirements.txt
├── tests/                   pytest suite (unit + API + security + assets)
├── docs/{ARCHITECTURE, SECURITY, METHODOLOGY, API}.md
├── run.sh
├── LICENSE
└── README.md
```

## Bootcamp submission

For a concise project overview, five-minute demonstration plan, architecture, safety controls, limitations, and oral-review preparation, see [`docs/BOOTCAMP_SUBMISSION.md`](docs/BOOTCAMP_SUBMISSION.md). Use [`SUBMISSION_CHECKLIST.md`](SUBMISSION_CHECKLIST.md) before submitting and [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) to rehearse the demonstration.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module map, request flow,
  storage schema, how to add a check.
- [`docs/SECURITY.md`](docs/SECURITY.md) — SSRF threat model, redirect
  validation, connection pinning, DNS rebinding, Flask hardening, limitations.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — every check, severity
  rationale, score model, limitations.
- [`docs/API.md`](docs/API.md) — endpoint reference with curl examples.
- [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — patch summary and validation limitations.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes (v2.5.0 submission-readiness release).

## Responsible use

SENTINEL is a **passive, limited configuration review** tool. It does not
crawl, exploit, brute-force, scan ports, or prove whether a site is
vulnerable. Missing headers are not automatically exploitable flaws, and a
score is an educational heuristic — not a certification. Real scans require
the authorization confirmation; that record documents your claim of
permission and is an accountability measure, not legal authorization. The
maintainers accept no liability for misuse; assess only authorized targets.

## License

[MIT](LICENSE)
