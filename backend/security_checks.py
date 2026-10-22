"""SENTINEL security check registry.

Each check is a small, pure function that receives a :class:`ScanContext`
and returns zero, one or several finding dictionaries. Findings use the same
shape as the frontend evidence model so records render without translation:

    {id, severity, name, header, status, evidence, description,
     impact, fix, docs}

Severity policy (see docs/METHODOLOGY.md):

    Critical/High  control absent where its absence is broadly risky
    Medium         control absent or weakened in common deployments
    Low            hardening opportunity / deprecated or weak value
    Info           observation with no direct score impact
    Pass           control observed and reasonable

All checks are passive: they inspect the response of a single HTTP request.
Nothing is crawled, fuzzed or exploited.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
DOCS: Dict[str, str] = {
    "csp": MDN + "Content-Security-Policy",
    "hsts": MDN + "Strict-Transport-Security",
    "xcto": MDN + "X-Content-Type-Options",
    "xfo": MDN + "X-Frame-Options",
    "rp": MDN + "Referrer-Policy",
    "pp": MDN + "Permissions_Policy",
    "coop": MDN + "Cross-Origin-Opener-Policy",
    "cache": MDN + "Cache-Control",
    "server": MDN + "Server",
    "xxss": MDN + "X-XSS-Protection",
    "cookies": MDN + "Set-Cookie",
    "https": "https://developer.mozilla.org/en-US/docs/Web/HTTPS",
    "tls": "https://developer.mozilla.org/en-US/docs/Glossary/TLS",
}

# Session-cookie name heuristics (used to raise HttpOnly severity).
SESSION_HINTS = ("sess", "sid", "auth", "token", "login", "remember")


@dataclass
class ScanContext:
    """Everything the checks are allowed to look at for one scan."""

    target_url: str
    final_url: str
    scheme: str = "https"
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)          # lowercase -> value
    set_cookies: List[str] = field(default_factory=list)           # raw Set-Cookie strings
    cookies: List[Dict[str, Any]] = field(default_factory=list)    # parsed flags (names only)
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    tls: Optional[Dict[str, Any]] = None
    duration_ms: Optional[int] = None

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())

    def __post_init__(self) -> None:
        # Defensive normalization: scanner code lowercases keys already, but
        # tests and future callers can pass natural-case headers safely.
        self.headers = {str(k).lower(): v for k, v in (self.headers or {}).items()}


@dataclass
class Check:
    """A registered check with its metadata."""

    id: str
    name: str
    category: str
    description: str
    func: Callable[[ScanContext], Any]


REGISTRY: List[Check] = []


def check(cid: str, name: str, category: str, description: str):
    """Decorator that registers a check function in the registry."""

    def decorator(fn: Callable[[ScanContext], Any]) -> Callable[[ScanContext], Any]:
        REGISTRY.append(Check(id=cid, name=name, category=category,
                              description=description, func=fn))
        return fn

    return decorator


def finding(cid, severity, name, header, status, evidence, description, impact, fix, docs):
    """Build a finding dict in the exact shape the frontend renders."""
    status_text = str(status or "").strip().lower()
    severity_text = str(severity or "Info").strip().lower()
    if status_text in {"not applicable", "n/a"}:
        outcome = "not_applicable"
    elif status_text in {"not tested", "skipped"}:
        outcome = "not_tested"
    elif (status_text in {"error", "inconclusive", "blocked", "unavailable"}
          or "unavailable" in status_text or status_text.endswith(" error")):
        outcome = "inconclusive"
    elif severity_text == "pass":
        outcome = "pass"
    elif severity_text in {"critical", "high", "medium", "low"}:
        outcome = "finding"
    else:
        outcome = "informational"
    return {
        "id": cid,
        "severity": severity,
        "outcome": outcome,
        "name": name,
        "header": header,
        "status": status,
        "evidence": evidence,
        "description": description,
        "impact": impact,
        "fix": fix,
        "docs": docs,
    }


def _trunc(value: Any, limit: int = 400) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def parse_set_cookie(raw: str) -> Dict[str, Any]:
    """Extract cookie name and security flags from a Set-Cookie header.

    Cookie VALUES are intentionally never recorded: SENTINEL stores names
    and attributes only, so reports can be shared without leaking session
    material.
    """
    parts = [p.strip() for p in str(raw).split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    flags: Dict[str, Any] = {"secure": False, "httponly": False, "samesite": None}
    for attr in parts[1:]:
        low = attr.lower()
        if low == "secure":
            flags["secure"] = True
        elif low == "httponly":
            flags["httponly"] = True
        elif low.startswith("samesite="):
            flags["samesite"] = attr.split("=", 1)[1].strip()
    name_lower = name.lower()
    flags["name"] = name
    flags["session_like"] = any(hint in name_lower for hint in SESSION_HINTS)
    return flags


def directive_sources(policy: str, directive: str) -> List[str]:
    """Return the (lower-cased) source list of one CSP directive."""
    match = re.search(r"(?:^|;)\s*" + re.escape(directive) + r"\s+([^;]*)", policy, re.I)
    if not match:
        return []
    return [src.strip().lower() for src in match.group(1).split() if src.strip()]


# ---------------------------------------------------------------------------
# Content Security Policy
# ---------------------------------------------------------------------------

@check("HDR-001", "Content Security Policy", "headers",
       "Presence and enforcement of a Content-Security-Policy response header.")
def check_csp(ctx: ScanContext):
    value = ctx.header("content-security-policy")
    report_only = ctx.header("content-security-policy-report-only")

    if value:
        return finding(
            "HDR-001", "Pass", "Content Security Policy observed", "Content-Security-Policy",
            "Present", "Content-Security-Policy: " + _trunc(value),
            "A Content Security Policy restricts the sources from which a page may load "
            "content, reducing the impact of injection attacks.",
            "The policy is present; its effectiveness depends on how restrictive the "
            "directives are for this application (see HDR-002).",
            "Review the policy against real application behavior and keep directives as "
            "strict as practical. Use Report-Only mode when introducing changes.",
            DOCS["csp"],
        )

    if report_only:
        return finding(
            "HDR-001", "Medium", "CSP present only in Report-Only mode",
            "Content-Security-Policy", "Report-Only",
            "Content-Security-Policy-Report-Only: " + _trunc(report_only),
            "The response ships a CSP in Report-Only mode, so the browser reports "
            "violations without enforcing the policy.",
            "Violations are observed but not blocked, so protection against injection is "
            "not yet active on this response.",
            "Once violation reports look clean, enforce the policy by serving it as "
            "Content-Security-Policy (keep the Report-Only copy for monitoring if useful).",
            DOCS["csp"],
        )

    return finding(
        "HDR-001", "High", "Content Security Policy missing", "Content-Security-Policy",
        "Missing", "Header not present in the response.",
        "A Content Security Policy can reduce the impact of some injection attacks by "
        "restricting the sources from which a page may load content.",
        "Without a suitable policy, the browser may have fewer restrictions on script and "
        "resource loading. Risk depends on the application and its other controls.",
        "Design a policy for the application's actual resource requirements. Start with "
        "Report-Only mode, review violations, then enforce a tested policy.",
        DOCS["csp"],
    )


@check("HDR-002", "CSP policy weaknesses", "headers",
       "Flags common CSP weakeners: unsafe-inline/unsafe-eval, wildcards, missing object-src or base-uri.")
def check_csp_weaknesses(ctx: ScanContext):
    value = ctx.header("content-security-policy")
    if not value:
        return finding(
            "HDR-002", "Info", "CSP weakness check not applicable", "Content-Security-Policy",
            "Not applicable", "No enforced Content-Security-Policy was available to inspect.",
            "CSP directive analysis requires an enforced policy. The absence of a policy is reported separately by HDR-001.",
            "This check cannot characterize CSP quality when no enforced CSP is present.",
            "Add and validate a policy appropriate to the application, then rerun the assessment.",
            DOCS["csp"],
        )

    script_sources = directive_sources(value, "script-src") or directive_sources(value, "default-src")
    script_issues: List[str] = []
    if script_sources:
        if "'unsafe-inline'" in script_sources:
            script_issues.append(
                "script-src (or default-src) allows 'unsafe-inline', which defeats most "
                "XSS protections the policy would otherwise provide.")
        if "'unsafe-eval'" in script_sources:
            script_issues.append(
                "script-src (or default-src) allows 'unsafe-eval', enabling eval()-style "
                "code execution paths.")
        if "*" in script_sources or "http:" in script_sources or "https:" in script_sources:
            script_issues.append(
                "script-src (or default-src) accepts wildcard or plain-scheme sources, "
                "allowing arbitrary script hosts.")

    structural_issues: List[str] = []
    lowered = value.lower()
    if "object-src" not in lowered and "default-src" not in lowered:
        structural_issues.append("No object-src or default-src fallback: object/plugin sources are unrestricted.")
    if "base-uri" not in lowered:
        structural_issues.append("No base-uri directive: injected markup could retarget relative URLs.")

    if not script_issues and not structural_issues:
        return finding(
            "HDR-002", "Pass", "No obvious CSP weaknesses", "Content-Security-Policy",
            "Pass", "Content-Security-Policy: " + _trunc(value),
            "No common policy weakeners were found in the delivered CSP.",
            "A restrictive baseline reduces the chance that injected markup can load "
            "hostile resources.",
            "Keep directives tight as the application evolves; re-review after dependency "
            "or template changes.",
            DOCS["csp"],
        )

    issues = script_issues + structural_issues
    severity = "Medium" if script_issues else "Low"
    return finding(
        "HDR-002", severity, "CSP contains weakening patterns", "Content-Security-Policy",
        "Review", " ".join(issues) + " Policy: " + _trunc(value),
        "CSP effectiveness depends on its directives; common weakeners substantially "
        "reduce the protection the policy provides.",
        "Inline script allowance, eval or wildcard sources each widen the attack surface "
        "for cross-site scripting and data exfiltration.",
        "Prefer nonce- or hash-based script allowances over unsafe-inline, remove eval, "
        "pin explicit hosts, and add object-src/base-uri fallbacks.",
        DOCS["csp"],
    )


# ---------------------------------------------------------------------------
# Transport security
# ---------------------------------------------------------------------------

@check("HDR-003", "Strict-Transport-Security (HSTS)", "transport",
       "HSTS presence and max-age sanity on HTTPS responses.")
def check_hsts(ctx: ScanContext):
    if ctx.scheme != "https":
        return finding(
            "HDR-003", "Info", "HSTS not applicable over HTTP", "Strict-Transport-Security",
            "Not applicable", "Final response scheme: " + ctx.scheme,
            "HSTS policies are only honored when delivered over a secure connection.",
            "Browsers ignore HSTS on plain HTTP; transport protection itself is covered "
            "by the TLS-001 check.",
            "Serve the site over HTTPS first; HSTS becomes meaningful only afterwards.",
            DOCS["hsts"],
        )

    value = ctx.header("strict-transport-security")
    if value is None:
        return finding(
            "HDR-003", "Medium", "HSTS not observed", "Strict-Transport-Security",
            "Missing", "Header not present in the final response.",
            "HSTS tells supporting browsers to use HTTPS for future visits after "
            "receiving the policy over a secure connection.",
            "Users may have less protection against certain downgrade or first-visit "
            "scenarios, depending on deployment.",
            "After confirming HTTPS works across relevant subdomains, configure an "
            "appropriate Strict-Transport-Security policy over HTTPS.",
            DOCS["hsts"],
        )

    evidence = "Strict-Transport-Security: " + _trunc(value)
    max_age_matches = re.findall(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", value, re.I)
    if len(max_age_matches) > 1:
        return finding(
            "HDR-003", "Low", "HSTS has duplicate max-age directives", "Strict-Transport-Security",
            "Invalid", evidence,
            "More than one max-age directive was observed; policy interpretation may be ambiguous.",
            "The scanner cannot confidently determine the intended HSTS lifetime from duplicate directives.",
            "Publish one valid numeric max-age directive and remove duplicates.",
            DOCS["hsts"],
        )
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?=;|$)", value, re.I)
    if not match:
        return finding(
            "HDR-003", "Low", "HSTS header could not be parsed", "Strict-Transport-Security",
            "Review", evidence,
            "The header is present but no numeric max-age directive was found.",
            "Browsers may ignore a policy without a valid max-age, making the header "
            "ineffective.",
            "Publish max-age=<seconds> (start low and raise gradually), then add "
            "includeSubDomains when appropriate.",
            DOCS["hsts"],
        )

    max_age = int(match.group(1))
    notes: List[str] = []
    if "includesubdomains" not in value.lower():
        notes.append("includeSubDomains not present")
    if "preload" not in value.lower():
        notes.append("preload not present")
    extra = ("; " + ", ".join(notes) + " (informational)") if notes else ""

    if max_age < 15768000:
        return finding(
            "HDR-003", "Low", "HSTS max-age below common recommendation",
            "Strict-Transport-Security", "Short max-age",
            evidence + f" \u2014 max-age={max_age} (common recommendation is >= 15768000, about 6 months).",
            "Short policies expire quickly, shrinking the window of protection between visits.",
            "Visitors lose their enforced HTTPS preference sooner, leaving a recurring "
            "first-visit-style exposure.",
            "Raise max-age gradually once HTTPS is confirmed stable for the domain and "
            "its subdomains.",
            DOCS["hsts"],
        )

    return finding(
        "HDR-003", "Pass", "HSTS observed", "Strict-Transport-Security",
        "Present", evidence + extra,
        "The response includes an HSTS policy.",
        "The policy instructs supporting browsers to prefer HTTPS for the configured period.",
        "Review max-age and includeSubDomains against your actual domain and deployment needs.",
        DOCS["hsts"],
    )


# ---------------------------------------------------------------------------
# Header-level hardening controls
# ---------------------------------------------------------------------------

@check("HDR-004", "MIME sniffing protection", "headers",
       "X-Content-Type-Options: nosniff presence and validity.")
def check_x_content_type(ctx: ScanContext):
    value = ctx.header("x-content-type-options")
    if value is None:
        return finding(
            "HDR-004", "Low", "MIME sniffing protection not observed", "X-Content-Type-Options",
            "Missing", "Header not present in the response.",
            "X-Content-Type-Options: nosniff stops browsers from interpreting files as a "
            "different MIME type than declared.",
            "Incorrect or attacker-influenced content types may be executed or interpreted "
            "unexpectedly in some contexts.",
            "Serve accurate Content-Type values and add X-Content-Type-Options: nosniff to "
            "all responses.",
            DOCS["xcto"],
        )

    if value.strip().lower() != "nosniff":
        return finding(
            "HDR-004", "Low", "MIME sniffing header has an unrecognized value",
            "X-Content-Type-Options", "Invalid",
            "X-Content-Type-Options: " + _trunc(value),
            "nosniff is the only value browsers act on; other values have no effect.",
            "The header is present but likely provides no protection as delivered.",
            "Set the header value exactly to nosniff.",
            DOCS["xcto"],
        )

    return finding(
        "HDR-004", "Pass", "MIME sniffing protection observed", "X-Content-Type-Options",
        "Present", "X-Content-Type-Options: " + _trunc(value),
        "The response indicates that browsers should not MIME-sniff certain responses.",
        "This reduces risks caused by content being interpreted as a different MIME type.",
        "Keep nosniff enabled and serve correct Content-Type values.",
        DOCS["xcto"],
    )


@check("HDR-005", "Clickjacking / framing defense", "headers",
       "X-Frame-Options or CSP frame-ancestors controls whether the page can be framed.")
def check_framing(ctx: ScanContext):
    csp_value = ctx.header("content-security-policy") or ""
    frame_ancestors = directive_sources(csp_value, "frame-ancestors")
    xfo = ctx.header("x-frame-options")

    if frame_ancestors:
        return finding(
            "HDR-005", "Pass", "Framing policy observed via CSP", "CSP frame-ancestors",
            "Present", "Content-Security-Policy frame-ancestors: " + _trunc(" ".join(frame_ancestors)),
            "frame-ancestors restricts which documents may embed this page in a frame.",
            "Modern browsers enforce frame-ancestors ahead of X-Frame-Options, giving "
            "finer-grained embedding control.",
            "Keep the directive aligned with legitimate embedding needs (empty/'none' if "
            "the page is never framed).",
            DOCS["csp"],
        )

    if xfo:
        normalized = xfo.strip().upper()
        if normalized in ("DENY", "SAMEORIGIN"):
            return finding(
                "HDR-005", "Pass", "Framing defense observed", "X-Frame-Options",
                "Present", "X-Frame-Options: " + _trunc(xfo),
                "X-Frame-Options instructs browsers not to render the page inside a frame "
                "(or only within the same origin).",
                "Framing-based clickjacking is blocked in browsers that honor the header.",
                "Consider adding CSP frame-ancestors as the more modern control, and keep "
                "X-Frame-Options for older browsers.",
                DOCS["xfo"],
            )
        if normalized.startswith("ALLOW-FROM"):
            return finding(
                "HDR-005", "Low", "Deprecated X-Frame-Options ALLOW-FROM", "X-Frame-Options",
                "Deprecated", "X-Frame-Options: " + _trunc(xfo),
                "ALLOW-FROM is obsolete and is ignored by modern browsers.",
                "The intended framing restriction is probably not enforced in current "
                "browsers, leaving the page framable.",
                "Replace ALLOW-FROM with a CSP frame-ancestors directive.",
                DOCS["csp"],
            )
        return finding(
            "HDR-005", "Low", "X-Frame-Options value unrecognized", "X-Frame-Options",
            "Invalid", "X-Frame-Options: " + _trunc(xfo),
            "The header is present but its value is not DENY or SAMEORIGIN.",
            "Browsers may ignore an unrecognized framing policy, so the intended protection may not apply.",
            "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors where appropriate.",
            DOCS["xfo"],
        )

    return finding(
        "HDR-005", "Medium", "Clickjacking defense not observed",
        "X-Frame-Options / CSP frame-ancestors", "Missing",
        "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
        "These controls restrict whether a page can be embedded in a frame.",
        "If sensitive actions are available, framing can contribute to clickjacking risk "
        "depending on other defenses.",
        "Use CSP frame-ancestors and/or X-Frame-Options where appropriate for the "
        "application.",
        DOCS["xfo"],
    )


@check("HDR-006", "Referrer policy", "headers",
       "Referrer-Policy presence and strength of the chosen value.")
def check_referrer(ctx: ScanContext):
    value = ctx.header("referrer-policy")
    if value is None:
        return finding(
            "HDR-006", "Low", "Referrer policy not observed", "Referrer-Policy",
            "Missing", "Header not present in the response.",
            "Referrer-Policy controls how much referrer information browsers include "
            "with outgoing requests.",
            "URLs may reveal more navigation context than intended, depending on browser "
            "defaults and link destinations.",
            "Consider a policy such as strict-origin-when-cross-origin after checking "
            "application requirements.",
            DOCS["rp"],
        )

    recognized = {
        "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
        "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
    }
    # Multiple comma-separated policies are permitted; browsers use the last
    # recognized policy. Unknown tokens alone are not equivalent to a browser default.
    tokens = [token.strip().lower() for token in value.split(",") if token.strip()]
    effective = next((token for token in reversed(tokens) if token in recognized), None)
    if effective is None:
        return finding(
            "HDR-006", "Info", "Referrer policy value unrecognized", "Referrer-Policy",
            "Invalid", "Referrer-Policy: " + _trunc(value),
            "No recognized Referrer-Policy token was found in the observed value.",
            "The browser may ignore an unrecognized policy; the effective behavior cannot be inferred reliably from this header alone.",
            "Use a recognized policy such as strict-origin-when-cross-origin, no-referrer, or same-origin.",
            DOCS["rp"],
        )

    if effective == "unsafe-url":
        return finding(
            "HDR-006", "Medium", "Referrer policy permits full URL sharing", "Referrer-Policy",
            "Weak", "Referrer-Policy: " + _trunc(value) + f" (effective recognized token: {effective})",
            "unsafe-url sends the full URL, including path and query, to destinations regardless of origin.",
            "Paths and query strings can contain identifiers or sensitive navigation context.",
            "Prefer strict-origin-when-cross-origin or a stricter policy after checking application requirements.",
            DOCS["rp"],
        )

    strict_values = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if effective in strict_values:
        return finding(
            "HDR-006", "Pass", "Referrer policy observed", "Referrer-Policy",
            "Present", "Referrer-Policy: " + _trunc(value) + f" (effective recognized token: {effective})",
            "The response sets a recognized policy that limits referrer disclosure.",
            "The exact protection depends on the selected policy and navigation context.",
            "Keep the policy aligned with application privacy requirements.",
            DOCS["rp"],
        )

    return finding(
        "HDR-006", "Info", "Referrer policy uses a less restrictive recognized value",
        "Referrer-Policy", "Review", "Referrer-Policy: " + _trunc(value) + f" (effective recognized token: {effective})",
        "A recognized policy is present, but it allows more referrer information in some navigation contexts than stricter alternatives.",
        "Cross-origin destinations may receive more navigation context than with a stricter policy.",
        "Consider strict-origin-when-cross-origin or no-referrer if compatible with the application.",
        DOCS["rp"],
    )


@check("HDR-007", "Permissions Policy", "headers",
       "Permissions-Policy presence (browser feature restriction surface).")
def check_permissions_policy(ctx: ScanContext):
    value = ctx.header("permissions-policy")
    if value is None:
        return finding(
            "HDR-007", "Low", "Permissions Policy not observed", "Permissions-Policy",
            "Missing", "Header not present in the response.",
            "Permissions-Policy can limit access to selected browser features such as "
            "camera, geolocation or fullscreen.",
            "A policy that is absent or too broad may not express the application's "
            "intended feature restrictions.",
            "Define a policy appropriate to the features the application actually uses; "
            "do not blindly disable features it needs.",
            DOCS["pp"],
        )

    # Lightweight syntax sanity check only; this is not a complete parser for
    # the Permissions Policy grammar or a proof that each directive is effective.
    directives = [part.strip() for part in value.split(",") if part.strip()]
    if not directives or any("=" not in part or not re.match(r"^[a-z][a-z0-9-]*\s*=\s*.+$", part, re.I) for part in directives):
        return finding(
            "HDR-007", "Low", "Permissions Policy value appears malformed", "Permissions-Policy",
            "Invalid", "Permissions-Policy: " + _trunc(value),
            "The header is present, but one or more directive segments do not match the basic feature=allowlist shape.",
            "Malformed directives may not express the intended feature restrictions; this lightweight check does not validate the full grammar.",
            "Validate the policy against the current Permissions Policy grammar and the features your application uses.",
            DOCS["pp"],
        )

    return finding(
        "HDR-007", "Pass", "Permissions Policy observed", "Permissions-Policy",
        "Present", "Permissions-Policy: " + _trunc(value),
        "The response declares a Permissions-Policy.",
        "Declared feature restrictions reduce the surface for unwanted API use, "
        "including by embedded third-party content.",
        "Review the directive list against the features the application genuinely uses.",
        DOCS["pp"],
    )


# ---------------------------------------------------------------------------
# Informational / fingerprinting headers
# ---------------------------------------------------------------------------

@check("HDR-008", "Server version disclosure", "headers",
       "Server header with an explicit software version helps attackers fingerprint the stack.")
def check_server_header(ctx: ScanContext):
    value = ctx.header("server")
    if not value:
        return finding(
            "HDR-008", "Pass", "No Server header disclosed", "Server",
            "Not present", "No Server header was returned.",
            "The Server header advertises the responding software (and often its version).",
            "Nothing is disclosed by this response, which slightly reduces fingerprinting "
            "value for attackers.",
            "No action required; keep it this way when configuring new infrastructure.",
            DOCS["server"],
        )

    if re.search(r"\d+\.\d+", value):
        return finding(
            "HDR-008", "Low", "Server version disclosed", "Server",
            "Version disclosed", "Server: " + _trunc(value),
            "The Server header includes a version number for the responding software.",
            "Attackers can match the version against known CVEs to select exploits before "
            "sending any payload.",
            "Suppress or trim version information at the web server or proxy "
            "(e.g. ServerTokens Prod in Apache, server_tokens off in nginx).",
            DOCS["server"],
        )

    return finding(
        "HDR-008", "Info", "Server header present without version", "Server",
        "Generic", "Server: " + _trunc(value),
        "The Server header names the software but includes no version digits.",
        "Product names alone have lower fingerprinting value than full versions.",
        "Acceptable for most deployments; remove entirely if your threat model prefers "
        "minimizing disclosures.",
        DOCS["server"],
    )


@check("HDR-009", "X-Powered-By disclosure", "headers",
       "X-Powered-By reveals framework or language details.")
def check_x_powered_by(ctx: ScanContext):
    value = ctx.header("x-powered-by")
    if not value:
        return finding(
            "HDR-009", "Pass", "No X-Powered-By disclosure", "X-Powered-By",
            "Not present", "No X-Powered-By header was returned.",
            "X-Powered-By typically advertises the framework, runtime or platform behind "
            "an application.",
            "Nothing is disclosed by this response.",
            "No action required.",
            DOCS["server"],
        )

    return finding(
        "HDR-009", "Low", "Framework disclosed via X-Powered-By", "X-Powered-By",
        "Disclosed", "X-Powered-By: " + _trunc(value),
        "The response advertises the technology stack (framework, runtime or platform).",
        "Stack details help attackers pick believable payloads and known CVEs for the "
        "disclosed component.",
        "Remove the header (e.g. expose_php=Off, app.disable('x-powered-by') in Express, "
        "or strip it at the reverse proxy).",
        DOCS["server"],
    )


@check("HDR-010", "X-XSS-Protection (deprecated)", "headers",
       "Detects the retired X-XSS-Protection header, which modern browsers ignore.")
def check_xss_protection(ctx: ScanContext):
    value = ctx.header("x-xss-protection")
    if not value:
        return finding(
            "HDR-010", "Pass", "No deprecated XSS-auditor header", "X-XSS-Protection",
            "Not present", "No X-XSS-Protection header was returned.",
            "X-XSS-Protection configured the legacy browser XSS auditor, which has been "
            "removed from modern browsers.",
            "Its absence has no effect on current browsers; CSP (HDR-001) is the "
            "meaningful control.",
            "No action required; rely on a Content Security Policy instead.",
            DOCS["xxss"],
        )

    return finding(
        "HDR-010", "Info", "Deprecated X-XSS-Protection header present", "X-XSS-Protection",
        "Deprecated", "X-XSS-Protection: " + _trunc(value),
        "The response still ships the retired XSS-auditor header.",
        "No modern browser honors it; the value '0' was once used to disable harmful "
        "auditor behavior but the auditor itself is gone.",
        "Remove the header and invest in a tested Content Security Policy instead.",
        DOCS["xxss"],
    )


@check("HDR-011", "Cache-Control directive", "headers",
       "Whether the response expresses any caching intent via Cache-Control.")
def check_cache_control(ctx: ScanContext):
    value = ctx.header("cache-control")
    if not value:
        return finding(
            "HDR-011", "Info", "No Cache-Control directive", "Cache-Control",
            "Not present", "Header not present in the response.",
            "Cache-Control tells browsers and intermediaries how a response may be stored "
            "and reused.",
            "Without explicit directives, heuristic caching applies; sensitive responses "
            "may be stored more widely than intended.",
            "Set explicit Cache-Control values, and no-store for authenticated or "
            "sensitive responses.",
            DOCS["cache"],
        )

    return finding(
        "HDR-011", "Pass", "Cache-Control observed", "Cache-Control",
        "Present", "Cache-Control: " + _trunc(value),
        "The response expresses explicit caching intent.",
        "Caching behavior is under the application's control rather than left to "
        "browser heuristics.",
        "Confirm the directives match the sensitivity of the content (no-store for "
        "sensitive data).",
        DOCS["cache"],
    )


@check("HDR-012", "Cross-Origin-Opener-Policy", "headers",
       "COOP isolates the browsing context from cross-origin popups.")
def check_coop(ctx: ScanContext):
    value = ctx.header("cross-origin-opener-policy")
    if not value:
        return finding(
            "HDR-012", "Info", "Cross-Origin-Opener-Policy not observed",
            "Cross-Origin-Opener-Policy", "Not present", "Header not present in the response.",
            "COOP isolates a document from cross-origin windows opened via window.open or "
            "target=_blank, enabling process-level isolation.",
            "Without COOP, cross-origin popups keep reference access, enabling attacks "
            "such as XS-Leaks.",
            "Consider Cross-Origin-Opener-Policy: same-origin where the application does "
            "not require cross-origin window interaction.",
            DOCS["coop"],
        )

    normalized = value.strip().lower()
    if normalized not in {"unsafe-none", "same-origin-allow-popups", "same-origin"}:
        return finding(
            "HDR-012", "Info", "Cross-Origin-Opener-Policy value unrecognized",
            "Cross-Origin-Opener-Policy", "Invalid",
            "Cross-Origin-Opener-Policy: " + _trunc(value),
            "The header is present but its value is not one of the recognized COOP policies.",
            "The browser may ignore an unrecognized value; isolation behavior cannot be inferred reliably.",
            "Use a recognized policy and verify it against the application's popup and cross-origin requirements.",
            DOCS["coop"],
        )
    if normalized == "unsafe-none":
        return finding(
            "HDR-012", "Info", "COOP explicitly allows default opener behavior",
            "Cross-Origin-Opener-Policy", "Present, no isolation",
            "Cross-Origin-Opener-Policy: " + _trunc(value),
            "unsafe-none is a recognized policy but does not isolate the browsing context group.",
            "Cross-window references may remain available where browser rules permit.",
            "Consider same-origin or same-origin-allow-popups only if compatible with the application's workflows.",
            DOCS["coop"],
        )
    return finding(
        "HDR-012", "Pass", "Cross-Origin-Opener-Policy observed",
        "Cross-Origin-Opener-Policy", "Present",
        "Cross-Origin-Opener-Policy: " + _trunc(value),
        "The response declares a recognized cross-origin opener policy.",
        "The selected policy controls cross-window isolation behavior.",
        "Review the chosen value against any legitimate cross-origin window workflows.",
        DOCS["coop"],
    )


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

@check("COOKIE-001", "Cookie Secure flag", "cookies",
       "Cookies delivered without the Secure attribute can travel over plain HTTP.")
def check_cookie_secure(ctx: ScanContext):
    if not ctx.cookies:
        return finding(
            "COOKIE-001", "Info", "Cookie Secure check not applicable", "Set-Cookie",
            "Not applicable", "No Set-Cookie headers were exposed on the final response.",
            "Cookie attributes control how browsers store and transmit site cookies.",
            "No cookies were visible in this single response, so cookie attributes cannot be assessed. This does not establish that the site never sets cookies.",
            "If cookies are expected, confirm they are set on the relevant routes and responses.",
            DOCS["cookies"],
        )

    missing = [c["name"] for c in ctx.cookies if not c["secure"]]
    names = ", ".join(c["name"] for c in ctx.cookies)
    if not missing:
        return finding(
            "COOKIE-001", "Pass", "All observed cookies use Secure", "Set-Cookie",
            "Present", "Observed cookies (names only): " + names,
            "The Secure attribute stops cookies being sent over unencrypted connections.",
            "Cookie exposure over plain HTTP is prevented for the observed cookies.",
            "Keep the attribute on every new cookie.",
            DOCS["cookies"],
        )

    return finding(
        "COOKIE-001", "Medium", "Cookies missing the Secure flag", "Set-Cookie",
        "Missing", "Cookies without Secure: " + ", ".join(missing) +
        ". Observed cookies (names only): " + names,
        "The Secure attribute prevents browsers from sending a cookie over plain HTTP.",
        "Cookies may be exposed on insecure connections or leaked through a crafted "
        "downgrade link.",
        "Add the Secure attribute to every cookie (requires HTTPS).",
        DOCS["cookies"],
    )


@check("COOKIE-002", "Cookie HttpOnly flag", "cookies",
       "Cookies without HttpOnly are readable by page JavaScript (XSS exfiltration).")
def check_cookie_httponly(ctx: ScanContext):
    if not ctx.cookies:
        return finding(
            "COOKIE-002", "Info", "Cookie HttpOnly check not applicable", "Set-Cookie",
            "Not applicable", "No Set-Cookie headers were exposed on the final response.",
            "HttpOnly controls JavaScript access to cookies when cookies are set.",
            "This response provides no cookie attributes to inspect; other routes may set cookies.",
            "Recheck routes that create sessions or authentication cookies.",
            DOCS["cookies"],
        )

    missing = [c["name"] for c in ctx.cookies if not c["httponly"]]
    if not missing:
        return finding(
            "COOKIE-002", "Pass", "All observed cookies use HttpOnly", "Set-Cookie",
            "Present", "Observed cookies (names only): " + ", ".join(c["name"] for c in ctx.cookies),
            "HttpOnly hides cookies from document.cookie and other JavaScript access.",
            "Script-driven cookie theft is harder for the observed cookies.",
            "Keep the attribute on every session cookie.",
            DOCS["cookies"],
        )

    session_missing = [n for n in missing
                       if any(c["name"] == n and c["session_like"] for c in ctx.cookies)]
    severity = "Medium" if session_missing else "Low"
    detail = ("Session-like cookies without HttpOnly: " + ", ".join(session_missing)
              if session_missing else
              "Cookies without HttpOnly: " + ", ".join(missing))
    return finding(
        "COOKIE-002", severity, "Cookies missing the HttpOnly flag", "Set-Cookie",
        "Missing", detail + ". Observed cookies (names only): " + ", ".join(c["name"] for c in ctx.cookies),
        "HttpOnly prevents JavaScript from reading a cookie, limiting what an XSS "
        "payload can exfiltrate.",
        "Without it, any injected script can read the cookie value; for session-like "
        "cookies this enables session hijacking.",
        "Add HttpOnly to session and authentication cookies; leave it off only for "
        "values the frontend genuinely needs.",
        DOCS["cookies"],
    )


@check("COOKIE-003", "Cookie SameSite attribute", "cookies",
       "Cookies without SameSite rely on browser defaults for cross-site sending.")
def check_cookie_samesite(ctx: ScanContext):
    if not ctx.cookies:
        return finding(
            "COOKIE-003", "Info", "Cookie SameSite check not applicable", "Set-Cookie",
            "Not applicable", "No Set-Cookie headers were exposed on the final response.",
            "SameSite controls whether a cookie is sent with cross-site requests.",
            "No cookie attributes were available to inspect on this response; other routes may set cookies.",
            "Recheck routes that create sessions or authentication cookies.",
            DOCS["cookies"],
        )

    missing = [c["name"] for c in ctx.cookies if not c["samesite"]]
    if not missing:
        return finding(
            "COOKIE-003", "Pass", "All observed cookies declare SameSite", "Set-Cookie",
            "Present", "Observed cookies (names only): " + ", ".join(c["name"] for c in ctx.cookies),
            "SameSite controls whether a cookie is sent with cross-site requests.",
            "Explicit SameSite values make CSRF exposure predictable instead of "
            "default-dependent.",
            "Keep Lax or Strict for state-changing cookies.",
            DOCS["cookies"],
        )

    return finding(
        "COOKIE-003", "Low", "Cookies missing the SameSite attribute", "Set-Cookie",
        "Missing", "Cookies without SameSite: " + ", ".join(missing) +
        ". Observed cookies (names only): " + ", ".join(c["name"] for c in ctx.cookies),
        "SameSite=Lax/Strict restricts cross-site cookie sending, complementing CSRF defenses.",
        "Cross-site requests may carry these cookies depending on browser defaults, "
        "weakening CSRF resistance.",
        "Add SameSite=Lax (or Strict for sensitive cookies) unless cross-site usage is "
        "intended.",
        DOCS["cookies"],
    )


# ---------------------------------------------------------------------------
# TLS / scheme
# ---------------------------------------------------------------------------

@check("TLS-001", "HTTPS transport", "transport",
       "Whether the final response was delivered over HTTPS.")
def check_https(ctx: ScanContext):
    if ctx.scheme == "https":
        evidence = "Final URL scheme: https."
        if any(str(hop.get("url", "")).lower().startswith("http:") for hop in ctx.redirect_chain[:-1]):
            evidence += " An HTTP request was redirected to HTTPS in the observed chain."
        return finding(
            "TLS-001", "Pass", "HTTPS transport in use", "URL scheme",
            "Present", evidence,
            "HTTPS provides transport encryption and server authentication for the request.",
            "The scanned response was delivered over an encrypted channel.",
            "Verify certificate validity and HSTS separately (TLS-002/003, HDR-003); "
            "SENTINEL does not perform a full TLS audit.",
            DOCS["https"],
        )

    return finding(
        "TLS-001", "High", "Target served over cleartext HTTP", "URL scheme",
        "Cleartext", "Final URL scheme: http",
        "HTTP does not provide transport encryption for the request or response.",
        "Anyone on the path can read and modify traffic, including cookies, tokens and "
        "the returned page content.",
        "Serve the site over HTTPS and redirect HTTP requests to the secure origin.",
        DOCS["https"],
    )


@check("TLS-002", "TLS certificate verification", "transport",
       "Whether the certificate chain verified against the local trust store.")
def check_tls_verification(ctx: ScanContext):
    tls = ctx.tls or {}
    if ctx.scheme != "https":
        return finding(
            "TLS-002", "Info", "TLS verification not applicable", "TLS",
            "Not applicable", "Final URL scheme: " + ctx.scheme,
            "Certificate verification is only meaningful for HTTPS responses.",
            "No TLS session was established by this scan.",
            "Move to HTTPS to gain transport security.",
            DOCS["tls"],
        )

    if tls.get("verified") is False:
        return finding(
            "TLS-002", "High", "TLS certificate verification failed", "TLS",
            "Failed", str(tls.get("cert_error") or "Certificate verification error."),
            "The certificate presented by the target could not be verified against the "
            "local trust store (self-signed, expired, wrong host or incomplete chain).",
            "Clients may be exposed to man-in-the-middle attacks; confidentiality and "
            "integrity cannot be assured.",
            "Fix or replace the certificate (validity, hostname match, complete chain) "
            "before serving the site publicly.",
            DOCS["tls"],
        )

    if tls.get("cert_error"):
        return finding(
            "TLS-002", "Info", "Certificate metadata unavailable", "TLS",
            "Limited", str(tls.get("cert_error")),
            "The TLS connection succeeded, but additional certificate metadata (expiry) "
            "could not be collected.",
            "Certificate expiry monitoring is not possible from this scan.",
            "Check expiry with an authorized TLS assessment or monitoring tool.",
            DOCS["tls"],
        )

    return finding(
        "TLS-002", "Pass", "TLS certificate chain verified", "TLS",
        "Verified", "The HTTPS request completed with certificate verification enabled.",
        "The certificate presented by the target chained to a trusted root and matched "
        "the requested hostname.",
        "Confidentiality and integrity of the scanned exchange are protected against "
        "active network attackers.",
        "Keep certificates renewed automatically (e.g. ACME-based tooling).",
        DOCS["tls"],
    )


@check("TLS-003", "Certificate expiry window", "transport",
       "Days remaining before the leaf certificate expires, when metadata was collectable.")
def check_tls_expiry(ctx: ScanContext):
    tls = ctx.tls or {}
    if ctx.scheme != "https" or not tls:
        return None
    days_left = tls.get("days_left")
    if days_left is None:
        return None

    evidence = "Certificate expires " + str(tls.get("not_after") or "unknown") + \
               f" (in {days_left} days)."
    if days_left < 0:
        return finding(
            "TLS-003", "Medium", "Certificate has expired", "TLS", "Expired", evidence,
            "The leaf certificate is past its notAfter date.",
            "Browsers reject expired certificates, breaking availability and prompting "
            "users to bypass warnings.",
            "Renew the certificate immediately and automate renewal.",
            DOCS["tls"],
        )
    if days_left <= 14:
        return finding(
            "TLS-003", "Medium", "Certificate expires imminently", "TLS", "Expiring",
            evidence,
            "The leaf certificate expires within two weeks.",
            "Missed renewals translate directly into outages for visitors.",
            "Renew now and verify the automated renewal pipeline.",
            DOCS["tls"],
        )
    if days_left <= 45:
        return finding(
            "TLS-003", "Low", "Certificate expires soon", "TLS", "Expiring", evidence,
            "The leaf certificate expires within roughly 45 days.",
            "Short remaining validity leaves little margin for renewal failures.",
            "Confirm automated renewal is scheduled and succeeding.",
            DOCS["tls"],
        )
    return finding(
        "TLS-003", "Pass", "Certificate validity window is healthy", "TLS", "Present",
        evidence,
        "The certificate has a comfortable remaining validity period.",
        "No expiry-related action is needed at this time.",
        "Keep renewal automation in place.",
        DOCS["tls"],
    )


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

def run_all_checks(ctx: ScanContext) -> List[Dict[str, Any]]:
    """Execute every registered check; a crashing check degrades to an Info
    record instead of failing the whole scan."""
    results: List[Dict[str, Any]] = []
    for check_def in REGISTRY:
        try:
            outcome = check_def.func(ctx)
        except Exception as exc:  # noqa: BLE001 - resilience over purity
            outcome = finding(
                check_def.id, "Info", check_def.name + " \u2014 check error", check_def.category,
                "Error", "The check could not be completed: " + str(exc),
                "An unexpected error occurred while evaluating this check.",
                "This observation is incomplete; re-run the scan if it persists.",
                "No remediation can be derived from an errored check.",
                DOCS["https"],
            )
        if not outcome:
            continue
        if isinstance(outcome, list):
            results.extend(outcome)
        else:
            results.append(outcome)
    return results


def registry_metadata() -> List[Dict[str, str]]:
    """Metadata for the methodology page and /api/checks."""
    return [
        {"id": c.id, "name": c.name, "category": c.category, "description": c.description}
        for c in REGISTRY
    ]
