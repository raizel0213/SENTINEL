"""SSRF-hardened HTTP transport for SENTINEL.

This module replaces the previous ``requests``-based fetch (which followed
redirects automatically and re-resolved DNS at connect time) with a
validated, pinned request path built on the standard library.

Why a custom transport? Two gaps cannot be closed with
``requests``/``urllib3`` as-is:

1. **Redirect SSRF** - automatic redirect following re-issues requests to
   whatever ``Location`` the response names, with no opportunity to
   re-apply the destination policy. Here redirects are followed manually:
   every hop is parsed, resolved and policy-checked BEFORE any connection
   is attempted, and prohibited hops are refused without contacting them.

2. **DNS rebinding (TOCTOU)** - validating a hostname and then letting the
   HTTP client resolve it again means the connection may use an address
   that was never checked. This transport resolves first, validates every
   address, and then connects its socket directly to a validated IP
   (connection pinning). No second DNS lookup happens on the request path.
   TLS uses ``ssl.create_default_context()`` with ``server_hostname`` set
   to the ORIGINAL hostname, so certificate verification and SNI remain
   bound to the name the user typed - the pinned IP is only the TCP
   destination. This genuinely closes the rebinding window for the
   initial request; see "Limitations" in docs/SECURITY.md.

Resource limits: connect/read timeouts, a bounded DNS lookup, a redirect
cap with loop detection, an overall per-scan deadline, and a response-body
consumption cap (headers are the evidence; bodies are discarded).
"""
from __future__ import annotations

import datetime as dt
import email.utils
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

try:
    from . import config, ip_policy, target_validation
    from .target_validation import ParsedTarget, TargetValidationError
except ImportError:  # pragma: no cover - direct script execution
    import config
    import ip_policy
    import target_validation
    from target_validation import ParsedTarget, TargetValidationError


class TLSFailure(Exception):
    """TLS certificate verification failed for a validated destination."""

    def __init__(self, detail: str, url: str = "", resolved_ips: Optional[List[str]] = None):
        super().__init__(detail)
        self.detail = detail
        self.url = url
        self.resolved_ips = resolved_ips or []


class ConnectionFailure(Exception):
    """The validated destination could not be reached (TCP/protocol level)."""

    def __init__(self, detail: str, url: str = ""):
        super().__init__(detail)
        self.detail = detail
        self.url = url


class ScanDeadlineExceeded(TargetValidationError):
    def __init__(self, message: str = ""):
        super().__init__("SCAN_TIMEOUT", message or "The scan exceeded its overall time budget.")


class RedirectLoopError(TargetValidationError):
    def __init__(self, url: str):
        super().__init__(
            "REDIRECT_LOOP",
            f"Redirect loop detected at {url}. The chain was aborted before repeating it.",
        )
        self.url = url


class TooManyRedirectsError(TargetValidationError):
    def __init__(self, limit: int):
        super().__init__(
            "TOO_MANY_REDIRECTS",
            f"More than {limit} redirects were returned; the chain was stopped.",
        )


@dataclass
class FetchLimits:
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    dns_timeout: float = 5.0
    max_redirects: int = 5
    deadline_s: float = 60.0
    max_body_bytes: int = 65536

    @classmethod
    def from_config(cls) -> "FetchLimits":
        return cls(
            connect_timeout=config.CONNECT_TIMEOUT,
            read_timeout=config.READ_TIMEOUT,
            dns_timeout=config.DNS_TIMEOUT,
            max_redirects=config.MAX_REDIRECTS,
            deadline_s=config.SCAN_DEADLINE,
            max_body_bytes=config.MAX_RESPONSE_BYTES,
        )


@dataclass
class SingleResponse:
    """One raw HTTP response from a pinned connection."""

    url: str
    status: int
    headers: List[Tuple[str, str]]          # original casing, duplicates kept
    tls: Optional[Dict[str, Any]] = None    # peer certificate metadata (https only)
    body_bytes_read: int = 0
    body_truncated: bool = False
    duration_ms: int = 0

    def header(self, name: str) -> Optional[str]:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def header_all(self, name: str) -> List[str]:
        lowered = name.lower()
        return [v for (k, v) in self.headers if k.lower() == lowered]

    @property
    def header_map(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for key, value in self.headers:
            lowered = key.lower()
            if lowered == "set-cookie":
                continue
            out[lowered] = (out[lowered] + ", " + value) if lowered in out else value
        return out


@dataclass
class FetchOutcome:
    """Final result of a fully validated fetch (all hops included)."""

    request_url: str
    final_url: str
    response: SingleResponse
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    set_cookies: List[str] = field(default_factory=list)   # raw, across all hops

    @property
    def status(self) -> int:
        return self.response.status

    @property
    def first_hop_ips(self) -> List[str]:
        return list(self.redirect_chain[0].get("resolved_ips", [])) if self.redirect_chain else []


# Type of the injectable low-level opener (tests substitute this).
Opener = Callable[[ParsedTarget, str, FetchLimits], SingleResponse]


# ---------------------------------------------------------------------------
# Pinned single-request opener (production implementation)
# ---------------------------------------------------------------------------

def _tls_metadata(tls_sock: ssl.SSLSocket) -> Dict[str, Any]:
    """Peer certificate summary from the ALREADY verified connection."""
    cert = tls_sock.getpeercert()
    info: Dict[str, Any] = {
        "verified": True,
        "cert_error": None,
        "not_after": None,
        "days_left": None,
    }
    not_after = (cert or {}).get("notAfter")
    if not_after:
        try:
            when = email.utils.parsedate_to_datetime(not_after)
            info["not_after"] = when.date().isoformat()
            info["days_left"] = (when - dt.datetime.now(dt.timezone.utc)).days
        except (TypeError, ValueError):  # pragma: no cover - malformed date
            pass
    return info


def open_pinned(parsed: ParsedTarget, ip: str, limits: FetchLimits) -> SingleResponse:
    """Perform ONE request, connecting the socket to the validated ``ip``.

    The TCP destination is the policy-approved address (no second DNS
    lookup exists on this path). For HTTPS the TLS handshake uses the
    original hostname for SNI and certificate verification.
    """
    started = time.perf_counter()
    is_https = parsed.scheme == "https"
    conn: Optional[http.client.HTTPConnection] = None
    try:
        sock = socket.create_connection(
            (ip, parsed.effective_port), timeout=limits.connect_timeout
        )
        sock.settimeout(limits.read_timeout)

        tls_info: Optional[Dict[str, Any]] = None
        if is_https:
            ctx = ssl.create_default_context()  # verifies cert + hostname
            tls_sock = ctx.wrap_socket(sock, server_hostname=parsed.hostname)
            tls_info = _tls_metadata(tls_sock)
            sock = tls_sock

        conn = http.client.HTTPConnection(
            parsed.display_host, parsed.effective_port, timeout=limits.read_timeout
        )
        conn.sock = sock  # pre-set socket: http.client will not re-resolve

        headers = {
            "Host": parsed.host_header,
            "User-Agent": config.USER_AGENT,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        conn.request("GET", parsed.path_with_query, headers=headers)
        response = conn.getresponse()

        raw_pairs = response.getheaders()
        header_pairs = [(str(k), str(v)) for (k, v) in raw_pairs]

        # Bounded body consumption: headers are the evidence; the body is
        # never stored or analysed. Reading is capped, then the connection
        # is closed (Connection: close was requested anyway).
        remaining = limits.max_body_bytes
        total = 0
        while remaining > 0:
            chunk = response.read(min(16384, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        truncated = bool(remaining == 0 and response.read(1))

        return SingleResponse(
            url=parsed.canonical_url,
            status=response.status,
            headers=header_pairs,
            tls=tls_info,
            body_bytes_read=total,
            body_truncated=truncated,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
    except ssl.SSLCertVerificationError as exc:
        raise TLSFailure(
            f"Certificate verification failed for {parsed.display_host} ({exc.__class__.__name__}). "
            "The certificate was not accepted by the local trust store.",
            url=parsed.canonical_url,
        ) from exc
    except (ssl.SSLError,) as exc:
        raise TLSFailure(
            f"TLS handshake failed for {parsed.display_host} ({exc.__class__.__name__}).",
            url=parsed.canonical_url,
        ) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise ConnectionFailure(
            f"The request to {parsed.display_host} timed out.", url=parsed.canonical_url
        ) from exc
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        raise ConnectionFailure(
            f"Could not reach {parsed.display_host} ({exc.__class__.__name__}).",
            url=parsed.canonical_url,
        ) from exc
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing must never mask errors
                pass


# ---------------------------------------------------------------------------
# Validated redirect-aware fetch
# ---------------------------------------------------------------------------

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def fetch_validated(target_url: str,
                    limits: Optional[FetchLimits] = None,
                    *,
                    resolver: Optional[Callable[[str, int, float], List[Any]]] = None,
                    policy: Optional[ip_policy.DestinationPolicy] = None,
                    opener: Optional[Opener] = None) -> FetchOutcome:
    """Fetch ``target_url`` through the fully validated request path.

    Per hop: parse URL -> resolve -> validate EVERY address against the
    policy -> connect pinned -> read response. Redirects are followed
    manually with the same checks applied to each destination BEFORE it is
    contacted. Prohibited hops raise TargetValidationError instead of being
    requested.
    """
    limits = limits or FetchLimits.from_config()
    resolver = resolver or _default_resolver
    policy = policy or ip_policy.DestinationPolicy(allow_private=config.ALLOW_PRIVATE_TARGETS)
    opener = opener or open_pinned

    started = time.monotonic()
    seen: List[str] = []
    chain: List[Dict[str, Any]] = []
    set_cookies: List[str] = []

    current = target_validation.normalize_url(target_url)
    for _hop in range(limits.max_redirects + 1):
        if time.monotonic() - started > limits.deadline_s:
            raise ScanDeadlineExceeded(
                f"The scan exceeded its {limits.deadline_s:g}s overall budget "
                f"while {len(chain)} hop(s) into the redirect chain."
            )

        parsed = target_validation.parse_url(current)
        if current in seen:
            raise RedirectLoopError(current)
        seen.append(current)

        if parsed.ip_literal is not None:
            addresses: List[Any] = [parsed.ip_literal]
        else:
            addresses = resolver(parsed.hostname, parsed.effective_port, limits.dns_timeout)

        try:
            policy.require_allowed(addresses)
        except ip_policy.PolicyViolation as exc:
            raise TargetValidationError(
                "PRIVATE_TARGET_BLOCKED",
                f"'{parsed.hostname}' resolves to {exc.ip}, a {exc.reason}. Scanning private "
                "or loopback infrastructure is disabled by default (SSRF guard). Set "
                "SENTINEL_ALLOW_PRIVATE=1 to scan your own lab targets.",
            ) from exc

        chosen_ip = str(addresses[0])
        response = opener(parsed, chosen_ip, limits)
        set_cookies.extend(response.header_all("Set-Cookie"))

        location = response.header("Location") if response.status in _REDIRECT_STATUSES else None
        if location is None:
            chain.append({
                "url": current,
                "status": response.status,
                "location": None,
                "resolved_ip": chosen_ip,
                "resolved_ips": [str(a) for a in addresses],
                "decision": "final",
            })
            return FetchOutcome(
                request_url=chain[0]["url"],
                final_url=current,
                response=response,
                redirect_chain=chain,
                set_cookies=set_cookies,
            )

        # --- redirect hop: validate the destination BEFORE contacting it ---
        try:
            next_url = target_validation.normalize_url(urljoin(current, location.strip()))
        except TargetValidationError as exc:
            raise TargetValidationError(
                "INVALID_REDIRECT",
                f"Redirect Location '{location[:200]}' was rejected: {exc}",
            ) from exc
        if next_url in seen:
            chain.append({
                "url": current,
                "status": response.status,
                "location": location,
                "resolved_ip": chosen_ip,
                "resolved_ips": [str(a) for a in addresses],
                "decision": "loop-aborted",
            })
            raise RedirectLoopError(next_url)
        chain.append({
            "url": current,
            "status": response.status,
            "location": location,
            "resolved_ip": chosen_ip,
            "resolved_ips": [str(a) for a in addresses],
            "decision": "followed",
        })
        current = next_url

    raise TooManyRedirectsError(limits.max_redirects)


def _default_resolver(hostname: str, port: int, timeout: float) -> List[Any]:
    return target_validation.resolve_host(hostname, port, timeout)
