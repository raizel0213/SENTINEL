# SENTINEL — API Reference (v2.5.0)

Base URL while running locally: `http://127.0.0.1:5050`

All responses are JSON unless noted. Errors use one envelope:

```json
{ "error": { "code": "MACHINE_READABLE_CODE", "message": "human explanation" } }
```

The API is **same-origin only**: no CORS headers are emitted, and requests
carrying a foreign `Origin` header are rejected with 403
`CROSS_ORIGIN_BLOCKED`. Real scans additionally require an explicit
`authorization` boolean (see below).

## System

### `GET /api/health`

```json
{ "status": "ok", "product": "SENTINEL", "version": "2.5.0",
  "checks_registered": 18, "history_records": 3,
  "allow_private_targets": false,
  "rate_limit_per_minute": 12, "max_concurrent_scans": 2, "uptime_s": 41 }
```

### `GET /api/checks`

Registry metadata used by the methodology page:

```json
{ "count": 18, "checks": [ { "id": "HDR-001", "name": "Content Security Policy",
  "category": "headers", "description": "…" } ] }
```

## Scanning

### `POST /api/scan`

Three modes, selected by `mode`. **Real scans require the explicit
authorization confirmation** — an exact JSON boolean `"authorization":
true`. Missing, malformed or non-boolean values are rejected with HTTP 400
`AUTHORIZATION_INVALID`; an explicit `false` is refused with HTTP 403
`AUTHORIZATION_REQUIRED`. Demo mode makes no request and needs no field.

```bash
# Server scan (real request, all checks; authorization required)
curl -s -X POST http://127.0.0.1:5050/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"mode":"server","target":"https://example.com","authorization":true}'

# Demo profile (no request; persist=false skips history)
curl -s -X POST http://127.0.0.1:5050/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"mode":"demo","profile":"demo-mixed","persist":false}'

# Store a browser-mode result performed by the UI (authorization required)
curl -s -X POST http://127.0.0.1:5050/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"mode":"browser","authorization":true,"result":{"target":"https://example.com/","http_status":200,"checks":[]}}'
```

Response: the full scan record (see ARCHITECTURE for the schema). Server
records include `authorization_confirmed: true` and an `evidence` object
with a SHA-256 digest over the canonical observation set.

| Status | Codes |
| --- | --- |
| 400 | `INVALID_JSON`, `INVALID_URL`, `UNSUPPORTED_SCHEME`, `URL_CREDENTIALS`, `DISALLOWED_PORT`, `INVALID_REDIRECT`, `DNS_RESOLUTION_FAILED`, `AUTHORIZATION_INVALID`, `UNKNOWN_MODE`, `UNKNOWN_PROFILE`, `INVALID_RESULT` |
| 403 | `PRIVATE_TARGET_BLOCKED`, `AUTHORIZATION_REQUIRED`, `CROSS_ORIGIN_BLOCKED` |
| 429 | `RATE_LIMITED` — per-client scan rate exceeded |
| 502 | `CONNECTION_FAILED`, `REDIRECT_LOOP`, `TOO_MANY_REDIRECTS` |
| 503 | `SCAN_BUSY` — concurrency gate full |
| 504 | `SCAN_TIMEOUT` — overall scan budget exceeded |
| 413 | `PAYLOAD_TOO_LARGE` — request body over the size limit |

## History

| Endpoint | Meaning |
| --- | --- |
| `GET /api/scans` | Summaries, newest first: `{count, items:[{id, timestamp, target, mode, mode_label, score, total, high}]}` |
| `GET /api/scans/<id>` | Full record |
| `DELETE /api/scans/<id>` | Delete one → `{deleted: 1}` |
| `DELETE /api/scans` | Clear all → `{deleted: n}` |

## Reports

### `GET /api/scans/<id>/report?format=json|csv|md|html`

```bash
# Save the standalone printable HTML report (replace <id> with a scan id).
curl -sS "http://127.0.0.1:5050/api/scans/<id>/report?format=html" \
  -o sentinel-report.html
```

Open the saved HTML report in a browser and use **Print → Save as PDF** to create a PDF copy.

- `json` — full report + metadata (attachment)
- `csv` — findings table with the 1.x column set (attachment)
- `md` — Markdown report (attachment)
- `html` — standalone print-styled page, served **inline** so it can be
  printed/saved as PDF directly (`Content-Disposition: inline`)

Unknown formats → 400 `UNKNOWN_FORMAT`; unknown ids → 404 `NOT_FOUND`.

## Static frontend

`/` serves `frontend/index.html`; `/css/*`, `/js/*`, `/assets/*` are static.
Unknown non-API paths return a plain-text 404; unknown API paths return the
JSON error envelope.
