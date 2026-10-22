# SENTINEL 2.5.0 — Methodology & Limitations

SENTINEL is a **passive, limited configuration review** tool. It performs one
GET request (server mode), inspects observable response properties, and
reports what it saw. It does not crawl, exploit, brute-force, scan ports, or
prove whether a site is vulnerable. Missing headers are configuration
weaknesses, not automatically exploitable flaws.

## Check registry (18 checks)

### Headers (12)

| ID | Check | Severities |
| --- | --- | --- |
| HDR-001 | Content Security Policy | High (missing) · Medium (Report-Only only) · Pass (enforced) |
| HDR-002 | CSP weaknesses | Medium (unsafe-inline/eval, wildcard script sources) · Low (no object-src/base-uri fallback) · Pass · not applicable when no enforced CSP |
| HDR-003 | Strict-Transport-Security | Medium (missing on HTTPS) · Low (max-age < 15 768 000, unparseable) · Info (n/a over HTTP) · Pass |
| HDR-004 | X-Content-Type-Options | Low (missing or invalid value) · Pass (nosniff) |
| HDR-005 | Framing defense | Medium (neither X-Frame-Options nor frame-ancestors) · Low (deprecated ALLOW-FROM) · Pass |
| HDR-006 | Referrer-Policy | Medium (unsafe-url/empty) · Low (missing, unrecognized) · Info (less restrictive recognized value or unrecognized token) · Pass (restrictive recognized values) |
| HDR-007 | Permissions-Policy | Low (missing) · Pass |
| HDR-008 | Server version disclosure | Low (version digits) · Info (generic value) · Pass (absent) |
| HDR-009 | X-Powered-By disclosure | Low (present) · Pass |
| HDR-010 | X-XSS-Protection | Info (deprecated header present) · Pass |
| HDR-011 | Cache-Control | Info (absent — heuristic caching applies) · Pass |
| HDR-012 | Cross-Origin-Opener-Policy | Info (absent or no isolation / unrecognized value) · Pass (recognized isolation policy) |

### Cookies (3)

Cookie **values are never recorded** — only names and attributes — so reports
can be shared without leaking session material.

| ID | Check | Severities |
| --- | --- | --- |
| COOKIE-001 | Secure flag | Medium (any observed cookie missing it) · Pass · not applicable when no cookie is observed |
| COOKIE-002 | HttpOnly flag | Medium (session-like names missing it) · Low · Pass |
| COOKIE-003 | SameSite attribute | Low · Pass |

### Transport (3)

| ID | Check | Severities |
| --- | --- | --- |
| TLS-001 | HTTPS transport | High (final response over cleartext HTTP) · Pass (HTTPS, notes HTTP→HTTPS redirect) |
| TLS-002 | Certificate verification | High (verification failed — recorded even when no response could be processed) · Info (n/a, metadata unavailable) · Pass |
| TLS-003 | Certificate expiry | Medium (expired or ≤14 days) · Low (≤45 days) · Pass · skipped when metadata unavailable |

## Explicit outcomes and assessment coverage

Every generated check now carries an `outcome` separate from `severity`:

- `finding`: a defined rule observed a potential weakness
- `pass`: the defined check ran and its condition was satisfied
- `informational`: an observation that does not itself imply a weakness
- `inconclusive`: the check errored or evidence was insufficient
- `not_tested`: the check was skipped
- `not_applicable`: the check does not apply to the observed context

The dashboard's **Potential findings** count excludes passes and informational
observations. The register still contains all check records. Assessment coverage
is the share of applicable registry checks with a conclusive result; omitted registry
checks count as not tested, not-applicable checks are excluded from the denominator,
and inconclusive checks reduce coverage. Browser-mode coverage is not applicable
because browser-visible observations do not represent execution of the server-side registry; imported browser observations are marked inconclusive for server-side control assessment.
A high coverage percentage does not mean the site is secure: it only describes
how much of SENTINEL's limited check set reached a conclusive result.

The CSP weakness check is explicitly marked not applicable when no enforced CSP
exists; the missing policy is reported separately by HDR-001 rather than silently
omitting the second registry check.

## Score model

Inherited from SENTINEL 1.x for comparability:

```
score = clamp(100 − 25·Critical − 15·High − 8·Medium − 3·Low, 0, 100)
```

Info and Pass records deduct nothing. Letter grades are an additional
educational aid: **A+** ≥95, **A** ≥85, **B** ≥70, **C** ≥55, **D** ≥40,
**F** <40. The score is a learning aid — not an industry rating, a
certification, or a risk quantification.

Note: SENTINEL 1.x demo records carried hand-written scores that did not
match the documented model (72/48 where the model yields 74/49). SENTINEL 2.x
computes every score — including demos — from the same function, so the
methodology page and the data always agree.

## Boundaries by execution mode

- **Server scan** reads the full header set, cookie attributes and basic TLS
  metadata. It still sees only what the *final* response of *one* request
  exposes; route-specific behavior, method-specific policies and
  infrastructure diversity are invisible.
- **Browser mode** is governed by CORS and is intentionally **not scored**.
  JavaScript sees only a CORS-filtered subset of response headers; an unexposed
  header is inconclusive, not proof that the server omitted it. An observed
  header is recorded as an observation, not a passing control, because its
  policy may still be ineffective. A server that does not allow browser access
  cannot be inspected; SENTINEL records the block instead of inventing results.
  `Set-Cookie` and `HttpOnly` are not available to ordinary page JavaScript, so
  cookie checks do not apply.
- **Demo profiles** make no request at all; their evidence is clearly
  labeled `SIMULATED`.

## Safety guard rails

- Only `http`/`https`; no embedded credentials; ≤2048 chars; no whitespace.
- Hostnames must resolve; **every** resolved address (including IPv4-mapped
  IPv6) must be public unless `SENTINEL_ALLOW_PRIVATE=1`.
- Requests carry a descriptive `SENTINEL/2.5.0 (+educational scanner…)`
  User-Agent, a fixed minimal header set (no cookies or credentials),
  configurable connect/read/DNS timeouts, and response bodies are consumed
  only up to a small cap before the connection is closed.
- Redirects are followed manually: every hop is validated (URL structure,
  resolved addresses, destination policy) before any connection, and the
  chain is recorded hop-by-hop with the resolved IP and the decision
  (`followed` / `final` / `loop-aborted`). Chains that exceed the configured
  redirect cap or repeat a URL abort with a clear error instead of results.
- DNS rebinding is mitigated by connection pinning: the socket connects only
  to addresses the destination policy approved in the same request cycle
  (see SECURITY.md §2.4).

## Responsible use

Only assess targets you own or have explicit permission to test. Prefer a
controlled local environment for repeatable validation. A SENTINEL report is
a starting point for a conversation about secure configuration — not a
penetration test and not a compliance artifact.
