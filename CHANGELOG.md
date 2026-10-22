# Changelog

## [2.5.0] - 2026-10-22

### Submission-readiness improvements
- Added a bootcamp submission guide with project summary, architecture, safe demo steps, evaluation talking points, and explicit scope/limitations.
- Added a concise submission checklist and instructor demonstration script.
- Aligned current-facing version metadata and documentation with v2.5.0.
- Hardened the browser/offline CSV fallback against spreadsheet formula injection and included the explicit `outcome` column, matching the backend report's evidence model.
- Updated validation notes to distinguish static checks from tests that require Flask and a dependency-installed environment.

### Validation boundary
- Python compilation and JavaScript syntax checks are run for this package.
- The full pytest suite cannot be claimed as passed in the packaging environment unless Flask and all development dependencies are available; see `docs/VALIDATION_REPORT.md`.


## [2.4.0] - 2026-10-22

### Accuracy and evidence model
- Added explicit `outcome` values separate from severity and introduced assessment coverage summaries.
- Dashboard now counts potential findings separately from all check records.
- CSP weakness evaluation is explicitly marked not applicable when no enforced CSP is available, instead of silently omitting the registry check.
- Referrer-Policy handling now recognizes valid comma-separated fallback policies and no longer labels every unknown value as a browser default.
- Permissions-Policy checks now flag obviously malformed directive shapes instead of treating any non-empty header as a pass.
- Reports include outcome labels and assessment coverage; JSON and CSV preserve the richer evidence model.
- Updated regression tests and current-facing release metadata.

### Limitations
- Permissions-Policy syntax checking is intentionally lightweight, not a full standards parser.
- The complete pytest suite must be run in an environment with Flask and the project's development dependencies installed.

## [2.3.0] - 2026-10-22

### Accuracy and evidence quality
- Browser-mode observations are now explicitly unscored. Browser JavaScript sees a CORS-filtered response-header subset, so a header that is not exposed cannot be reported as missing from the server.
- Browser-mode imports no longer trust client-supplied severities or treat header presence as a passing security control; observations are retained as informational evidence.
- The dashboard and offline reports label browser results as unscored and explain the limitation.
- Added regression coverage for unscored browser-mode imports and informational-only observations.

### Validation note
- This release was statically checked in the build environment. The full pytest suite must be run in the project's dependency-installed virtual environment before relying on the release; Flask was unavailable in this build environment.

## [2.2.0] - 2026-10-21

### Security fixes
- Restrict the local service to loopback Host names and reject mismatched or malformed Origin headers on all API routes, including read-only history and report endpoints, reducing DNS-rebinding and cross-origin data exposure risk.
- Neutralize spreadsheet formula-like values in CSV exports, including formula triggers preceded by whitespace/control characters.
- Render report documentation references as clickable links only when they are valid HTTPS URLs without embedded credentials; other values are escaped plain text.
- Added regression tests for Host/Origin validation, CSV formula injection, and unsafe HTML report references.

### Validation
- Static syntax checks are included in the release review; run the full pytest suite in an environment with dependencies installed before production use.

## v2.1.0 — Security Hardening, Bug Fixes & Verified Release

Security release. All changes were verified against the actual v2.0.0
implementation and covered by the automated test suite (unit, transport,
redirect, authorization, API and asset-integrity tests).

### Fixed — Critical

- **SSRF via redirects** (`backend/scanner.py`, new `backend/safe_transport.py`).
  v2.0.0 fetched targets with `requests` + `allow_redirects=True`; redirect
  destinations were never re-validated, so a public target could bounce the
  scanner at `http://127.0.0.1/`, `http://169.254.169.254/` or internal
  ranges. Redirects are now followed manually: every hop is parsed, resolved
  and checked against the destination IP policy *before* any connection is
  attempted, with a configurable hop cap and loop detection
  (`REDIRECT_LOOP`, `TOO_MANY_REDIRECTS` errors).
- **DNS rebinding TOCTOU** (new `backend/safe_transport.py`). v2.0.0 resolved
  the target once for validation and let the HTTP client resolve it again at
  connect time, so the connected IP was never the validated IP. The new
  transport connects its socket directly to a policy-approved address
  (connection pinning) — no second DNS lookup exists on the request path —
  while TLS keeps verifying the certificate and hostname of the ORIGINAL
  name (`ssl.create_default_context()`, SNI bound to the hostname).
- **Missing authorization enforcement** (`backend/app.py`). v2.0.0 ran real
  scans with no authorization field at all. Real modes (`server`, `browser`)
  now require an explicit JSON boolean `authorization: true`:
  missing/malformed/non-boolean → HTTP 400 `AUTHORIZATION_INVALID`,
  explicit `false` → HTTP 403 `AUTHORIZATION_REQUIRED`. Demo mode (no
  network) is explicitly exempt. The frontend mirrors this with a
  confirmation checkbox that keeps the scan button disabled until checked,
  and states plainly that the check is an accountability measure, not legal
  authorization.

### Fixed — High

- **Wildcard CORS on the localhost API** (`backend/app.py`). Any web page
  could send (and read responses from) a user's local SENTINEL instance —
  a drive-by scan/read primitive. All `Access-Control-*` headers were
  removed and state-changing API calls presenting a foreign `Origin` header
  are now rejected with HTTP 403 `CROSS_ORIGIN_BLOCKED`. The UI must be
  served by the backend (the `file://` CORS fallback was removed).
- **TLS metadata connection bypassed the SSRF guard** (`backend/scanner.py`).
  `_tls_info()` opened a second, unvalidated connection that re-resolved
  DNS independently. Certificate metadata is now captured from the same
  pinned, verified connection used for the scan; the `ssl._ssl.
  _test_decode_cert` private-API + temp-file workaround is gone.

### Added — defence in depth

- **Destination IP policy** (`backend/ip_policy.py`): explicit blocklists for
  loopback, private, CGNAT, link-local, multicast, reserved, documentation,
  benchmark and unspecified ranges (v4 + v6); IPv4-mapped IPv6, 6to4,
  NAT64 and Teredo embedded IPv4 addresses are extracted and evaluated;
  a destination is refused if ANY resolved address violates the policy.
- **Port allowlist** for targets (`80, 443, 8080, 8443` by default,
  `SENTINEL_ALLOWED_PORTS`) — the scanner cannot be aimed at arbitrary
  internal service ports; `DISALLOWED_PORT` rejection.
- **Bounded DNS resolution** (`SENTINEL_DNS_TIMEOUT`, default 5s) — a hung
  resolver can no longer stall a worker indefinitely.
- **Resource limits**: connect/read timeouts, overall per-scan deadline
  (`SENTINEL_SCAN_DEADLINE`), redirect cap (`SENTINEL_MAX_REDIRECTS`),
  response-body consumption cap (`SENTINEL_MAX_RESPONSE_BYTES`) — bodies are
  never stored, headers are the evidence.
- **Concurrency gate + rate limiting** (`backend/app.py`): at most
  `SENTINEL_MAX_CONCURRENT` scans run at once (extras get HTTP 503
  `SCAN_BUSY`); per-client fixed-window rate limit (HTTP 429
  `RATE_LIMITED`).
- **Strict security headers** on every response served by the app:
  `Content-Security-Policy` (self-only, `frame-ancestors 'none'`),
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`,
  `Cross-Origin-Opener-Policy`, `Permissions-Policy`, `Cache-Control:
  no-store` on API responses.
- **Evidence digest**: server-scan records now carry a SHA-256 hash over the
  canonical observation set (target, final URL, status, sorted headers,
  redirect chain, timestamp).
- **Redirect chain evidence** now includes the resolved IP and the decision
  (`followed` / `final` / `loop-aborted`) for every hop.

### Changed

- `requests` is no longer a dependency (stdlib `http.client`/`ssl`/
  `socket` transport); `requirements.txt` now contains Flask only.
- Client-side `validation.js` mirrors the port allowlist for immediate
  feedback; the backend remains the security boundary.
- Frontend version strings, methodology copy and the offline notice updated
  for v2.1.0; the scan timeout in `api.js` was raised to 90s to cover the
  full redirect budget.

### Verified

- Redirect handling exercised (at unit and real-socket level) against:
  public HTTPS, public HTTP, `127.0.0.1`, `localhost`, private IPv4, IPv6
  loopback, link-local, a hostname resolving to a prohibited address, a
  chain that eventually redirects to a prohibited address, and a redirect
  loop — prohibited destinations are refused before connecting (asserted
  with a socket spy).
- Automated tests prove that scan requests without a valid authorization
  field are rejected (400/403) and that **no outbound connection is
  attempted** for those requests.

### Upgrading from v2.0.0

API clients must send `"authorization": true` for `mode: "server"` and
`mode: "browser"` scan requests. `demo` mode is unchanged. Open the UI via
the backend at `http://127.0.0.1:5050` (the `file://` mode is no longer
supported).
