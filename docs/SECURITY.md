# SENTINEL Security Notes (v2.5.0)

This document explains the security design of SENTINEL's outbound request
path, the API hardening, and the limits of what the tool guarantees. It is
written for reviewers, instructors and contributors.

## 1. Threat model

SENTINEL is a local, single-user educational scanner. The operator points it
at a target; the backend performs the HTTP request from the operator's
machine. The realistic adversaries are:

1. **A malicious scan target** — the target controls response headers and
   redirect targets and may try to turn the scanner into an SSRF foothold
   against the operator's network (cloud metadata endpoints, internal
   services, localhost ports).
2. **A remote web page** — anything the operator browses while SENTINEL runs
   must not be able to drive or read the local API.
3. **The operator's own input** — malformed URLs, oversized payloads, or
   careless use against targets they do not own.

SENTINEL performs **one passive GET per scan**. It never crawls, fuzzes,
brute-forces, executes content, downloads site payloads for analysis, sends
cookies or credentials, or disables TLS verification.

## 2. SSRF defences

### 2.1 Initial target validation (`backend/target_validation.py`)

Structural checks (no network): only `http`/`https` schemes, no embedded
`user:pass@` credentials, no whitespace/control characters/backslashes,
well-formed hostnames (label length, allowed characters, IDNA), and a port
allowlist (`80, 443, 8080, 8443` by default).

### 2.2 Destination IP policy (`backend/ip_policy.py`)

Every address the scanner could contact is evaluated with an explicit,
version-stable blocklist plus Python's `ipaddress` properties:

- loopback, private (RFC1918), CGNAT (100.64/10), link-local (169.254/16 —
  which covers cloud metadata endpoints), multicast, reserved (240/4,
  broadcast), unspecified, documentation and benchmark ranges;
- the same policy for IPv6 (`::1`, ULA `fc00::/7`, link-local `fe80::/10`,
  multicast, discard-only, documentation, benchmark, ORCHID);
- **embedded IPv4** is extracted and evaluated: IPv4-mapped IPv6
  (`::ffff:10.0.0.1`), 6to4 (`2002::/16`), NAT64 (`64:ff9b::/96`) and Teredo
  (`2001:0::/32`, both embedded addresses).

A hostname is refused if **any** of its resolved addresses violates the
policy (defence against round-robin records that mix public and internal
addresses). Rejections raise `PRIVATE_TARGET_BLOCKED` before any connection
is attempted.

By default the policy blocks all non-public destinations. Lab mode
(`SENTINEL_ALLOW_PRIVATE=1`) is an explicit opt-in for scanning your own
infrastructure.

### 2.3 Redirect handling (`backend/safe_transport.py`)

v2.0.0 followed redirects with `requests`' automatic behaviour — the scanner
would happily follow a public page's 302 into `http://127.0.0.1/`. v2.3.0
never delegates redirect following to the HTTP client:

1. the request is sent with redirects disabled (the transport is
   request-at-a-time by construction);
2. the redirect response is inspected;
3. the `Location` value is resolved relative to the current URL;
4. the new URL is structurally validated (same scheme/credential/port
   rules as the initial target);
5. the new hostname is resolved;
6. every resolved address is checked against the same IP policy;
7. only a fully validated hop is connected;
8. the process repeats for the next response;
9. the chain stops at `SENTINEL_MAX_REDIRECTS` hops
   (`TOO_MANY_REDIRECTS`);
10. a destination that repeats a previously visited URL aborts the chain
    (`REDIRECT_LOOP`).

Prohibited destinations are refused **before** they are contacted — the
automated tests assert with a socket spy that no connection to a prohibited
address is ever attempted, for every scenario class (public HTTPS, public
HTTP, loopback, private IPv4, IPv6 loopback, link-local, hostname resolving
to a prohibited address, chains that turn prohibited mid-way, loops).

### 2.4 DNS rebinding and connection pinning

Validating a hostname and then letting an HTTP client resolve it again is
**not** rebinding protection: between the check and the connect, DNS can
return a different address (time-of-check-to-time-of-use). v2.0.0 had this
gap and documented it as a known limitation.

v2.3.0 closes it with **connection pinning**:

1. the transport resolves the hostname itself (bounded by
   `SENTINEL_DNS_TIMEOUT`);
2. all resolved addresses are validated by the policy;
3. the socket is created with `socket.create_connection((validated_ip,
   port))` — a literal IP, so **no second resolution happens** on the
   request path;
4. for HTTPS, the socket is wrapped with `ssl.create_default_context()` and
   `server_hostname=<original hostname>`: certificate chain and hostname
   verification remain bound to the name the user typed, and SNI is correct.
   The pinned IP is only the TCP destination.

The connected address is therefore always an address the policy approved in
the same request cycle. TLS verification is never disabled; on verification
failure the scan produces the TLS-002 High finding instead of results.

**Remaining limitations (documented, deliberate):**

- Multi-address hosts: the transport connects to the first validated
  address (no Happy Eyeballs). If that connection fails, the scan fails
  with `CONNECTION_FAILED` rather than silently trying addresses that were
  validated moments earlier in a different order.
- Lab mode (`SENTINEL_ALLOW_PRIVATE=1`) intentionally permits private
  targets; the pinning and redirect guarantees still apply.
- The in-process DNS cache is whatever the OS resolver provides; resolution
  and connect use the same in-process result set.
- The rate limiter and concurrency gate are in-memory (single process).

### 2.5 Request resource limits

- connect timeout 5s, read timeout 10s, DNS timeout 5s (all configurable);
- redirect cap 5 and loop detection;
- overall per-scan deadline (60s default) enforced between hops;
- response bodies are consumed only up to 64 KB and then discarded —
  headers are the evidence, and arbitrarily large responses cannot be
  buffered.

### 2.6 Network behaviour guarantees

No port scanning, no remote code execution, no downloading or executing of
website content, no brute force or exploitation attempts. Users cannot
supply arbitrary request headers: the transport sends a fixed header set
(`Host`, `User-Agent`, `Accept`, `Accept-Encoding: identity`,
`Connection: close`) and nothing else — no cookies, credentials or
authentication tokens ever reach the target, and TLS verification cannot be
turned off from the API.

## 3. Authorization confirmation

Real scans require an explicit authorization confirmation, enforced in both
layers:

- **Frontend** (`frontend/index.html`, `frontend/js/scanner-ui.js`): a
  checkbox ("I confirm that I own this target or have explicit permission to
  assess it…") keeps the scan button disabled until checked. The copy states
  that this is an accountability measure, not proof of legal authorization.
- **Backend** (`backend/app.py`): `mode: "server"` and `mode: "browser"`
  requests must carry `"authorization": true`. Missing / non-boolean values
  → HTTP 400 `AUTHORIZATION_INVALID`; explicit `false` → HTTP 403
  `AUTHORIZATION_REQUIRED`. Demo mode performs no request and is exempt by
  design; there is no way for demo mode to reach the live code path.
- Automated tests prove requests without authorization are rejected and
  that **no outbound HTTP request is made**.

## 4. Local API hardening (`backend/app.py`, v2.3.0)

- **No CORS.** No `Access-Control-*` headers are emitted. Every request is
  checked against a strict loopback `Host` allowlist (`localhost`,
  `127.0.0.1`, `[::1]`) before route handling; unexpected hostnames and
  mismatched explicit ports are rejected with 403 `HOST_NOT_ALLOWED`.
  Malformed or foreign `Origin` headers are rejected with 403
  `CROSS_ORIGIN_BLOCKED` on *all* API routes, including read-only history,
  health and report endpoints. This blocks the common DNS-rebinding pattern
  where a hostile hostname resolves to loopback and is sent as `Host`.
  The UI is served by the backend and is same-origin; the old `file://`
  fallback was removed.
- **Security headers on every response**: `Content-Security-Policy`
  (`default-src 'self'`, `frame-ancestors 'none'`, `base-uri 'none'`),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Permissions-Policy`, and `Cache-Control: no-store` for API paths.
- **Request size limit**: `MAX_CONTENT_LENGTH` (1 MB, mostly for
  browser-mode imports) with a 413 handler.
- **Rate limiting**: fixed window per client, default 12 scans/minute →
  429 `RATE_LIMITED`.
- **Concurrency gate**: bounded semaphore, default 2 concurrent scans →
  503 `SCAN_BUSY`.
- **Error hygiene**: JSON error envelopes with machine-readable codes; no
  stack traces or internal details in responses (exceptions are logged
  server-side); debug mode is never enabled in `main()`.
- **Storage**: SQLite accessed only through parameterized queries; history
  is capped; cookie values are never recorded (names and flags only).

## 5. Report generation safety

- CSV cells whose first meaningful character is `=`, `+`, `-` or `@` are
  prefixed with an apostrophe, including when whitespace/control characters
  come first. CSV quoting alone is not spreadsheet formula-injection defense.
- HTML reports render documentation references as links only for valid HTTPS
  URLs without embedded credentials. Other values are escaped and rendered
  as plain text, never as an active link.

## 6. Reporting a security issue

This is an educational tool, but if you find a real weakness, please open a
private security advisory rather than a public issue. Known limitations are
listed in §2.4 — findings in that list are acknowledged by design.
