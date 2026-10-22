"""SENTINEL scan orchestration.

Three execution paths produce the same record shape:

* run_server_scan        - real HTTP request from this machine, all checks run
* run_demo_scan          - canned educational profiles (no network activity)
* import_browser_result  - stores a browser-mode scan performed by the UI

v2.5.0: server scans run through :mod:`backend.safe_transport` - a validated,
DNS-pinned transport with manual redirect handling. The previous
``requests``-based path followed redirects automatically (SSRF via redirect)
and re-resolved DNS at connect time (rebinding TOCTOU); both gaps are closed.

Every record is finalized through the same scoring model and (optionally)
persisted to the SQLite history database.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
import socket
import time
import uuid
from typing import Any, Dict, List, Optional

try:
    from . import config, safe_transport, scoring, security_checks, storage, target_validation
    from .safe_transport import ConnectionFailure, TLSFailure
    from .target_validation import TargetValidationError
except ImportError:  # pragma: no cover - direct script execution
    import config
    import safe_transport
    import scoring
    import security_checks
    import storage
    import target_validation
    from safe_transport import ConnectionFailure, TLSFailure
    from target_validation import TargetValidationError


class ScanError(Exception):
    """Raised when a scan cannot produce trustworthy results."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


SERVER_LIMITATIONS = [
    "Passive header review only - no crawling, fuzzing, brute forcing or exploitation "
    "is performed.",
    "Missing headers are configuration weaknesses, not proven exploitable vulnerabilities.",
    "TLS inspection covers certificate metadata, not cipher-suite strength or protocol "
    "policy.",
    "Results reflect a single request at a single point in time; configuration can "
    "differ per route, method or client.",
]

BROWSER_LIMITATIONS = [
    "Browser CORS can prevent response inspection.",
    "Set-Cookie and HttpOnly details are not available to ordinary page JavaScript.",
    "This is not a full vulnerability scan.",
    "Only headers the browser exposes to JavaScript can be checked.",
]

DEMO_LIMITATIONS = [
    "Simulated record for interface testing - no request was made to the target.",
    "Evidence strings are illustrative, not observed from a live response.",
    "Demo scores follow the documented scoring model for training consistency.",
]


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _base_record(mode: str, mode_label: str, target: str) -> Dict[str, Any]:
    return {
        "id": _new_id(),
        "schema_version": 2,
        "product": config.PRODUCT,
        "version": config.VERSION,
        "mode": mode,
        "mode_label": mode_label,
        "target": target,
        "final_url": target,
        "timestamp": _utcnow(),
        "http_status": None,
        "duration_ms": None,
        "observed": 0,
        "score": None,
        "grade": None,
        "counts": None,
        "redirect_chain": [],
        "tls": None,
        "checks": [],
        "limitations": [],
    }


def _finalize(record: Dict[str, Any], checks: List[Dict[str, Any]],
              score: Optional[int] = None) -> Dict[str, Any]:
    record["checks"] = checks
    record["counts"] = scoring.counts_for(checks)
    record["assessment"] = scoring.assessment_summary(checks, registered_checks=len(security_checks.REGISTRY))
    # Browser JavaScript sees only a CORS-filtered subset of response headers;
    # absence is not proof of server-side absence and presence alone does not
    # validate a policy. A numeric score would therefore be misleading.
    if record.get("mode") == "browser":
        # Browser imports are observations from a CORS-filtered client context,
        # not coverage of the server-side check registry.
        record["assessment"].update({
            "coverage_percent": None,
            "applicable_checks": None,
            "conclusive_checks": None,
            "not_tested": None,
        })
        record["score_applicable"] = False
        record["score"] = None
        record["grade"] = None
    else:
        record["score_applicable"] = True
        record["score"] = score if score is not None else scoring.compute_score(checks)
        record["grade"] = scoring.grade_for(record["score"])
    return record


def _persist(record: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
    if persist:
        try:
            storage.save_scan(record)
        except Exception as exc:  # noqa: BLE001 - history is best-effort
            print(f"[sentinel] history write failed: {exc.__class__.__name__}: {exc}")
    return record


def _evidence_digest(record: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, str]:
    """Content hash over the canonical observation set (evidence integrity)."""
    canonical = {
        "product": record["product"],
        "version": record["version"],
        "target": record["target"],
        "final_url": record["final_url"],
        "timestamp": record["timestamp"],
        "http_status": record["http_status"],
        "headers": sorted(headers.items()),
        "redirect_chain": record["redirect_chain"],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {"algorithm": "sha256", "hash": hashlib.sha256(blob.encode("utf-8")).hexdigest()}


_NETWORK_ERRORS = (OSError, http.client.HTTPException)


# ---------------------------------------------------------------------------
# Server-side scan
# ---------------------------------------------------------------------------

def _tls_failure_record(target: str, detail: str, resolved_ips: List[str],
                        duration_ms: int) -> Dict[str, Any]:
    record = _base_record("server", "Server-side scan", target)
    record.update({
        "http_status": None,
        "duration_ms": duration_ms,
        "observed": 0,
        "resolved_ips": resolved_ips,
        "tls": {"verified": False, "cert_error": "TLS verification failed: " + detail[:300],
                "not_after": None, "days_left": None},
        "limitations": list(SERVER_LIMITATIONS),
    })
    checks = [
        security_checks.finding(
            "TLS-002", "High", "TLS certificate verification failed", "TLS", "Failed",
            record["tls"]["cert_error"],
            "The TLS certificate presented by the target could not be verified against "
            "the local trust store.",
            "Clients may be exposed to man-in-the-middle attacks; confidentiality and "
            "integrity cannot be assured.",
            "Fix or replace the certificate (validity, hostname match, complete chain) "
            "before serving the site publicly.",
            security_checks.DOCS["tls"],
        ),
        security_checks.finding(
            "SCAN-INFO", "Info", "Response not inspected", "Scan", "Unavailable",
            "No HTTP response was processed because TLS verification failed.",
            "Header checks require a verified connection; nothing was inferred about the "
            "server configuration.",
            "All header checks were skipped for this target.",
            "Repair TLS, then re-run the scan.",
            security_checks.DOCS["tls"],
        ),
    ]
    return _finalize(record, checks, score=scoring.compute_score(checks))


def run_server_scan(target_raw: str) -> Dict[str, Any]:
    """Perform a real, single-request, passive scan against a validated target.

    The request path is provided by :mod:`backend.safe_transport`:
    every URL (initial target and each redirect hop) is parsed, resolved,
    and checked against the destination IP policy BEFORE any connection is
    made; sockets connect only to validated addresses (pinning).
    """
    started = time.perf_counter()
    limits = safe_transport.FetchLimits.from_config()

    try:
        outcome = safe_transport.fetch_validated(target_raw, limits)
    except TLSFailure as exc:
        duration = int((time.perf_counter() - started) * 1000)
        fallback_target = exc.url or target_raw
        return _tls_failure_record(fallback_target, exc.detail, exc.resolved_ips, duration)
    except ConnectionFailure as exc:
        raise ScanError(
            "CONNECTION_FAILED",
            f"The target could not be reached ({exc.__class__.__name__}). "
            "No findings were fabricated.",
        ) from exc
    except _NETWORK_ERRORS as exc:  # pragma: no cover - defensive
        raise ScanError(
            "CONNECTION_FAILED",
            f"The target could not be reached ({exc.__class__.__name__}). "
            "No findings were fabricated.",
        ) from exc
    # TargetValidationError (invalid URL, DNS failure, prohibited destination,
    # redirect loop, redirect cap, deadline) propagates to the API layer.

    duration = int((time.perf_counter() - started) * 1000)
    response = outcome.response

    # --- headers (duplicate non-cookie headers joined with ", ") -----------
    headers: Dict[str, str] = {}
    for key, value in response.headers:
        lowered = str(key).lower()
        if lowered == "set-cookie":
            continue  # handled separately, values never recorded
        headers[lowered] = (headers[lowered] + ", " + str(value)) if lowered in headers else str(value)

    # --- Set-Cookie collection across the redirect chain -------------------
    cookies: List[Dict[str, Any]] = []
    seen_names = set()
    for raw in outcome.set_cookies:
        parsed = security_checks.parse_set_cookie(raw)
        if parsed["name"] and parsed["name"] not in seen_names:
            seen_names.add(parsed["name"])
            cookies.append(parsed)

    final = target_validation.parse_url(outcome.final_url)

    context = security_checks.ScanContext(
        target_url=outcome.request_url,
        final_url=outcome.final_url,
        scheme=final.scheme,
        status_code=response.status,
        headers=headers,
        set_cookies=outcome.set_cookies,
        cookies=cookies,
        redirect_chain=outcome.redirect_chain,
        tls=response.tls,
        duration_ms=duration,
    )
    checks = security_checks.run_all_checks(context)

    record = _base_record("server", "Server-side scan", outcome.request_url)
    record.update({
        "final_url": outcome.final_url,
        "http_status": response.status,
        "duration_ms": duration,
        "observed": len(headers),
        "redirect_chain": outcome.redirect_chain,
        "tls": response.tls,
        "resolved_ips": outcome.first_hop_ips,
        "authorization_confirmed": True,
        "body_bytes_read": response.body_bytes_read,
        "body_truncated": response.body_truncated,
        "limitations": list(SERVER_LIMITATIONS),
    })
    record["evidence"] = _evidence_digest(record, headers)
    return _persist(_finalize(record, checks))


# ---------------------------------------------------------------------------
# Demo profiles (ported verbatim from SENTINEL 1.x, IDs aligned to registry)
# ---------------------------------------------------------------------------

DEMO_PROFILES: Dict[str, Dict[str, Any]] = {
    "demo-mixed": {
        "label": "Demo \u00b7 mixed findings",
        "target": "https://training.example.test",
        "checks": [
            {
                "id": "HDR-001", "severity": "High", "name": "Content Security Policy missing",
                "header": "Content-Security-Policy", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "A Content Security Policy can reduce the impact of some "
                               "injection attacks by restricting the sources from which a "
                               "page may load content.",
                "impact": "Without a suitable policy, the browser may have fewer "
                          "restrictions on script and resource loading. Risk depends on "
                          "the application and other controls.",
                "fix": "Design a policy for the application's actual resource "
                       "requirements. Start with Report-Only mode, review violations, "
                       "then enforce a tested policy.",
                "docs": security_checks.DOCS["csp"],
            },
            {
                "id": "HDR-003", "severity": "Medium", "name": "HSTS not observed",
                "header": "Strict-Transport-Security", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "HSTS tells supporting browsers to use HTTPS for future "
                               "visits after receiving the policy over a secure connection.",
                "impact": "Users may have less protection against certain downgrade or "
                          "first-visit scenarios, depending on deployment.",
                "fix": "After confirming HTTPS works across relevant subdomains, configure "
                       "an appropriate Strict-Transport-Security policy over HTTPS.",
                "docs": security_checks.DOCS["hsts"],
            },
            {
                "id": "HDR-006", "severity": "Low", "name": "Referrer policy not observed",
                "header": "Referrer-Policy", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "Referrer-Policy controls how much referrer information "
                               "browsers include with outgoing requests.",
                "impact": "URLs may reveal more navigation context than intended, "
                          "depending on browser defaults and link destinations.",
                "fix": "Consider a policy such as strict-origin-when-cross-origin after "
                       "checking application requirements.",
                "docs": security_checks.DOCS["rp"],
            },
            {
                "id": "TLS-001", "severity": "Pass", "name": "HTTPS target configured",
                "header": "HTTPS", "status": "Present",
                "evidence": "Demo profile uses an HTTPS URL. No live connection was made.",
                "description": "The target profile uses an HTTPS URL scheme.",
                "impact": "This only confirms the configured URL scheme in this demo. It "
                          "does not verify certificate validity or the live TLS connection.",
                "fix": "For a real assessment, verify certificate validity, redirects, and "
                       "the actual connection in an authorized test environment.",
                "docs": security_checks.DOCS["https"],
            },
        ],
    },
    "demo-good": {
        "label": "Demo \u00b7 hardened profile",
        "target": "https://hardened.example.test",
        "checks": [
            {
                "id": "HDR-003", "severity": "Pass", "name": "HSTS observed",
                "header": "Strict-Transport-Security", "status": "Present",
                "evidence": "Strict-Transport-Security: max-age=31536000; includeSubDomains (simulated)",
                "description": "The example response includes an HSTS policy.",
                "impact": "The policy instructs supporting browsers to prefer HTTPS for "
                          "the configured period.",
                "fix": "Review max-age and includeSubDomains against your actual domain "
                       "and deployment needs.",
                "docs": security_checks.DOCS["hsts"],
            },
            {
                "id": "HDR-001", "severity": "Pass", "name": "Content Security Policy observed",
                "header": "Content-Security-Policy", "status": "Present",
                "evidence": "Content-Security-Policy: default-src 'self'; object-src 'none'; "
                            "base-uri 'self' (simulated)",
                "description": "The example response includes a restrictive-looking CSP.",
                "impact": "A policy can limit resource loading, but its effectiveness "
                          "depends on the full policy and application context.",
                "fix": "Review the policy against real application behavior and avoid "
                       "unsafe exceptions where possible.",
                "docs": security_checks.DOCS["csp"],
            },
            {
                "id": "HDR-004", "severity": "Pass", "name": "MIME sniffing protection observed",
                "header": "X-Content-Type-Options", "status": "Present",
                "evidence": "X-Content-Type-Options: nosniff (simulated)",
                "description": "The response indicates that browsers should not MIME-sniff "
                               "certain responses.",
                "impact": "This can reduce risks caused by content being interpreted as a "
                          "different MIME type.",
                "fix": "Keep nosniff enabled and serve correct Content-Type values.",
                "docs": security_checks.DOCS["xcto"],
            },
            {
                "id": "HDR-007", "severity": "Low", "name": "Permissions Policy review",
                "header": "Permissions-Policy", "status": "Review",
                "evidence": "A minimal policy is simulated; directive coverage was not evaluated.",
                "description": "Permissions Policy can limit access to selected browser features.",
                "impact": "A policy that is absent or too broad may not express the "
                          "application's intended feature restrictions.",
                "fix": "Define a policy appropriate to features the application actually "
                       "uses; do not blindly disable needed features.",
                "docs": security_checks.DOCS["pp"],
            },
        ],
    },
    "demo-poor": {
        "label": "Demo \u00b7 weak configuration",
        "target": "https://legacy.example.test",
        "checks": [
            {
                "id": "HDR-001", "severity": "High", "name": "Content Security Policy missing",
                "header": "Content-Security-Policy", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "No CSP is shown in this example response.",
                "impact": "The browser may have fewer restrictions on scripts and other "
                          "loaded resources.",
                "fix": "Develop and test an application-specific policy, initially using "
                       "Report-Only mode if needed.",
                "docs": security_checks.DOCS["csp"],
            },
            {
                "id": "HDR-003", "severity": "High", "name": "HSTS not observed",
                "header": "Strict-Transport-Security", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "No HSTS header is shown in this example response.",
                "impact": "HTTPS downgrade protections may be reduced in some circumstances.",
                "fix": "Configure HSTS only after confirming HTTPS works reliably for the "
                       "intended host and subdomains.",
                "docs": security_checks.DOCS["hsts"],
            },
            {
                "id": "HDR-005", "severity": "Medium",
                "name": "Clickjacking defense not observed",
                "header": "X-Frame-Options / CSP frame-ancestors", "status": "Missing",
                "evidence": "Neither header is present in simulated response.",
                "description": "These controls can restrict whether a page is embedded in a frame.",
                "impact": "If sensitive actions are available, framing can contribute to "
                          "clickjacking risk depending on other defenses.",
                "fix": "Use CSP frame-ancestors and/or X-Frame-Options where appropriate "
                       "for the application.",
                "docs": security_checks.DOCS["xfo"],
            },
            {
                "id": "HDR-004", "severity": "Medium",
                "name": "MIME sniffing protection missing",
                "header": "X-Content-Type-Options", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "The example response does not include nosniff.",
                "impact": "Incorrect content types may be interpreted unexpectedly in "
                          "some contexts.",
                "fix": "Serve accurate Content-Type values and consider "
                       "X-Content-Type-Options: nosniff.",
                "docs": security_checks.DOCS["xcto"],
            },
            {
                "id": "HDR-006", "severity": "Low", "name": "Referrer policy not observed",
                "header": "Referrer-Policy", "status": "Missing",
                "evidence": "Header not present in simulated response.",
                "description": "No explicit Referrer-Policy is shown.",
                "impact": "Referrer information may be shared according to browser defaults.",
                "fix": "Choose a policy appropriate to application privacy and navigation "
                       "requirements.",
                "docs": security_checks.DOCS["rp"],
            },
        ],
    },
}


def run_demo_scan(profile: str, persist: bool = True) -> Dict[str, Any]:
    """Build a demo record from a canned profile (no network activity)."""
    demo = DEMO_PROFILES.get(profile)
    if not demo:
        raise ScanError("UNKNOWN_PROFILE", f"Unknown demo profile '{profile}'.")
    checks = [dict(c) for c in demo["checks"]]
    record = _base_record("demo", demo["label"], demo["target"])
    record["limitations"] = list(DEMO_LIMITATIONS)
    return _persist(_finalize(record, checks), persist)


# ---------------------------------------------------------------------------
# Browser-mode import
# ---------------------------------------------------------------------------

_ALLOWED_CHECK_KEYS = ("id", "severity", "name", "header", "status",
                       "evidence", "description", "impact", "fix", "docs")
_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info", "Pass"}


def import_browser_result(result: Any, persist: bool = True) -> Dict[str, Any]:
    """Persist a browser-mode scan performed by the UI.

    The payload is sanitized defensively (type checks, length caps, severity
    whitelist) because it originates from the client.
    """
    if not isinstance(result, dict):
        raise ScanError("INVALID_RESULT", "'result' must be an object.")
    target = str(result.get("target") or "").strip()
    if not target:
        raise ScanError("INVALID_RESULT", "Browser result is missing a target.")

    raw_checks = result.get("checks") or []
    if not isinstance(raw_checks, list):
        raise ScanError("INVALID_RESULT", "'checks' must be a list.")
    raw_checks = raw_checks[: config.MAX_BROWSER_CHECKS]

    checks: List[Dict[str, str]] = []
    for entry in raw_checks:
        if not isinstance(entry, dict):
            continue
        clean: Dict[str, str] = {}
        for key in _ALLOWED_CHECK_KEYS:
            value = entry.get(key)
            clean[key] = str(value)[: config.MAX_STRING_LENGTH] if value is not None else ""
        # Browser-mode input is client-originated and inherently incomplete.
        # Do not trust client-supplied severity or treat exposed headers as
        # passing controls; these records are observations, not scored findings.
        clean["severity"] = "Info"
        # Client-visible observations cannot establish server-side control
        # effectiveness; classify each imported browser record accordingly.
        clean["outcome"] = "inconclusive"
        checks.append(clean)

    record = _base_record("browser", "Live browser request", target)
    record.update({
        "http_status": _int_or_none(result.get("http_status")),
        "duration_ms": _int_or_none(result.get("duration_ms")),
        "observed": _int_or_none(result.get("observed")) or 0,
        "authorization_confirmed": True,
        "limitations": list(BROWSER_LIMITATIONS) + [
            "Browser-mode results are not scored: CORS-filtered header visibility cannot establish server-side absence or policy effectiveness."
        ],
    })
    return _persist(_finalize(record, checks), persist)
