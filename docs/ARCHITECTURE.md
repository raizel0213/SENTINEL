# SENTINEL — Architecture

SENTINEL is a local, full-stack educational security scanner: a Python
(Flask) backend that performs passive HTTP configuration checks and a
dependency-free vanilla JS frontend that preserves the SENTINEL 1.x forensic
workstation identity.

```
Browser (frontend/)                      Backend (backend/)
┌─────────────────────────┐   fetch()   ┌──────────────────────────────┐
│ app.js        (state)   │ ──────────► │ app.py        Flask routes    │
│ scanner-ui.js (modes)   │             │  ├─ authorization + rate gate │
│ findings.js   (register)│             │  ├─ target_validation (SSRF)  │
│ history.js    (records) │ ◄────────── │  ├─ safe_transport (pinning,  │
│ reports.js    (exports) │    JSON     │  │   manual redirects)        │
│ validation.js (parity)  │             │  ├─ scanner.py  orchestration │
│ api.js        (client)  │             │  │   ├─ security_checks (18)  │
└─────────────────────────┘             │  │   └─ scoring.py            │
                                        │  ├─ storage.py  SQLite        │
                                        │  └─ report_generator          │
                                        └──────────────────────────────┘
```

## Backend modules

| Module | Responsibility |
| --- | --- |
| `config.py` | All tunables, env-overridable (`SENTINEL_*`). |
| `target_validation.py` | URL parsing (scheme/credentials/hostname shape/port allowlist), bounded DNS resolution and the destination IP policy. Raises `TargetValidationError(code, message)`; codes map to HTTP statuses in `app.py`. |
| `ip_policy.py` | Destination IP policy: explicit v4/v6 blocklists plus embedded-IPv4 evaluation (mapped, 6to4, NAT64, Teredo). `DestinationPolicy.require_allowed` refuses if ANY address violates. |
| `safe_transport.py` | SSRF-safe stdlib transport: resolves → validates every address → connects the socket to a validated IP (pinning) → TLS verifies the original hostname → manual redirect loop with per-hop revalidation, loop detection, caps and body limits. |
| `security_checks.py` | Registry of 18 pure check functions. Each receives a `ScanContext` and returns 0..n findings in the exact shape the UI renders. A crashing check degrades to an `Info` record instead of failing the scan. |
| `scanner.py` | Orchestration for the three modes; server mode consumes `safe_transport.fetch_validated` and finalizes the record (evidence digest included). |
| `scoring.py` | Deduction model and grades (see METHODOLOGY). |
| `storage.py` | SQLite via one connection per call (thread-safe with the dev server); history capped at `MAX_HISTORY`. |
| `report_generator.py` | Format builders returning `(content, mimetype, filename)`. |
| `app.py` | Route definitions, authorization enforcement, same-origin guard, security headers, rate limiter + scan gate, JSON error envelope, static serving of `frontend/`. |

Import shim: every module uses `try: from . import config except ImportError: import config`,
so both `python -m backend.app` and `python backend/app.py` work.

## Request flow (server scan)

1. `POST /api/scan {"mode":"server","target":"https://…","authorization":true}`.
2. `app.py` enforces the authorization boolean (400/403), the rate limit
   (429) and the concurrency gate (503) — all before any network activity.
3. `safe_transport.fetch_validated` per hop: `parse_url` (scheme/credentials/
   ports) → resolve (bounded) → every address checked by the destination IP
   policy → socket connected to a validated IP (pinning) → TLS verifies the
   original hostname → response read with body cap. Redirects repeat the
   same validation before any connection; loops and over-long chains abort
   with clear error codes.
4. Context assembled: final URL/status, lowercase header map (Set-Cookie kept
   separate), raw `Set-Cookie` list across the redirect chain, parsed cookie
   flags (names only), redirect chain (with resolved IP + decision per hop),
   TLS metadata from the pinned connection.
5. All 18 checks run; scoring/grades/counts computed; record finalized with
   a SHA-256 evidence digest.
6. `storage.save_scan` (best effort) and the record is returned as JSON.

Error contract: `{"error": {"code": "...", "message": "..."}}` with status
400 (bad input / missing authorization), 403 (private target, refused
authorization, cross-origin call), 429/503 (limits), 404, 405, 413, 500,
502 (target unreachable, redirect loop/cap), 504 (scan deadline).
Connection-level failures never fabricate findings — the UI shows the error
instead, mirroring SENTINEL 1.x honesty rules.

## Record schema (v2)

```
{ id, schema_version, product, version, mode: server|demo|browser,
  mode_label, target, final_url, timestamp, http_status, duration_ms,
  observed, score, grade, counts{total,critical,high,medium,low,info,pass},
  redirect_chain[{url,status,location,resolved_ip,resolved_ips,decision}],
  tls{verified,cert_error,not_after,days_left},
  evidence{algorithm,hash},                      # server mode
  authorization_confirmed,                       # server/browser modes
  checks[{id,severity,name,header,status,evidence,description,
  impact,fix,docs}], limitations[] }
```

The `checks` shape is identical to SENTINEL 1.x, so the frontend register,
detail panel and CSV columns are unchanged.

## Frontend modules

Classic scripts (no build step) in dependency order — `validation → api →
findings → history → reports → scanner-ui → app` — each attaching a namespace
object to `window.SENTINEL`. `app.js` owns central state and the boot
sequence: health probe → registry fetch → load latest record (or a
non-persisted demo) → merged history. All rendering uses
`createElement/textContent`; data is never injected via `innerHTML`.

Offline degradation: if the API is unreachable the UI stays usable — browser
mode works, records fall back to `localStorage`, and JSON/CSV exports are
generated client-side. Markdown/HTML reports and demo profiles require the
backend and say so.

## Storage

`scans(id PK, created_at, mode, mode_label, target, score, total, high,
record JSON)` — WAL mode, insert-or-replace, oldest rows pruned past
`SENTINEL_MAX_HISTORY`.

## Known limitations (documented trade-offs)

- **Multi-address hosts**: the transport connects to the first validated
  address; no Happy Eyeballs. Failures surface as `CONNECTION_FAILED`
  rather than silent retries. The rebinding TOCTOU gap of v2.0.0 is closed
  by pinning (see docs/SECURITY.md §2.4 for the full analysis).
- **Single request**: route-specific configuration differences are invisible.
- **TLS depth**: certificate metadata only, no cipher/protocol audit.
- **Dev server**: Flask's built-in server is intended for local use; put a
  WSGI server behind a reverse proxy if you ever expose it (not recommended).

## Adding a check (3 steps)

1. Write `@check("HDR-0XX", "Name", "category", "description")` in
   `security_checks.py` returning a `finding(...)` (or `None`).
2. Add unit tests in `tests/test_security_checks.py`.
3. Nothing else — the registry, `/api/checks`, the methodology page and all
   scans pick it up automatically.
