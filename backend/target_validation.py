"""Target validation and SSRF guard rails.

The backend performs HTTP requests from the machine running SENTINEL, which
makes the scanner a potential SSRF foothold if it can be pointed at internal
infrastructure. Validation happens in two layers:

1. :func:`parse_url` - structural checks only (scheme, credentials,
   hostname shape, allowed ports). No DNS, no network.
2. :func:`resolve_host` + :func:`validate_target` - DNS resolution with a
   bounded timeout, followed by the destination IP policy: EVERY resolved
   address must be public unless lab mode is enabled
   (``SENTINEL_ALLOW_PRIVATE=1``).

Layer 1 is reused per redirect hop by :mod:`backend.safe_transport`, so a
redirect cannot smuggle in a scheme, credential or port the initial target
could not have used.

v2.3.0 note: resolving first and connecting later is NOT, by itself, DNS
rebinding protection. :mod:`backend.safe_transport` closes that gap by
connecting only to addresses that were validated by the policy in the same
request cycle (connection pinning). This module provides the primitives.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

try:
    from . import config, ip_policy
except ImportError:  # pragma: no cover - direct script execution
    import config
    import ip_policy


class TargetValidationError(ValueError):
    """Raised when a scan target is rejected before any request is made."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# URL parsing (structural, no network)
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = ("http", "https")


@dataclasses.dataclass(frozen=True)
class ParsedTarget:
    """A structurally valid scan target. No DNS has happened yet."""

    raw: str
    canonical_url: str
    scheme: str
    hostname: str            # lower-cased, no brackets, no trailing dot
    display_host: str        # as it should appear in URLs (brackets for IPv6)
    port: Optional[int]      # explicitly present in the URL, or None
    effective_port: int      # port or scheme default
    path_with_query: str     # request target for HTTP/1.1
    host_header: str         # value for the Host header
    ip_literal: Optional[ipaddress._BaseAddress] = None

    @property
    def url(self) -> str:
        return self.canonical_url


def _validate_hostname(host: str) -> str:
    """Reject malformed hostnames; return the IDNA-normalised form."""
    if len(host) > 253:
        raise TargetValidationError("INVALID_URL", "Host name is too long.")
    labels = host.split(".")
    for label in labels:
        if not label:
            raise TargetValidationError("INVALID_URL", "Host name contains an empty label.")
        if len(label) > 63:
            raise TargetValidationError("INVALID_URL", "Host name label exceeds 63 characters.")
        if label[0] == "-" or label[-1] == "-":
            raise TargetValidationError("INVALID_URL", "Host name labels may not start or end with '-'.")
        if not all(ch.isalnum() or ch == "-" for ch in label):
            raise TargetValidationError(
                "INVALID_URL",
                f"Host name contains characters that are not valid in DNS names ('{label}').",
            )
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise TargetValidationError(
            "INVALID_URL", "Host name could not be converted to its IDNA form."
        ) from exc


def _try_parse_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def parse_url(raw_url: str) -> ParsedTarget:
    """Structurally validate a scan target URL. Raises TargetValidationError."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise TargetValidationError("INVALID_URL", "A target URL is required.")

    # Control characters are rejected on the RAW input before any stripping:
    # str.strip() would otherwise silently remove trailing ones.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_url):
        raise TargetValidationError("INVALID_URL", "Target URL contains control characters.")

    value = raw_url.strip()
    if len(value) > 2048:
        raise TargetValidationError("INVALID_URL", "Target URL exceeds the 2048 character limit.")
    if any(ch.isspace() for ch in value):
        raise TargetValidationError("INVALID_URL", "Target URL contains whitespace.")
    if "\\" in value:
        raise TargetValidationError(
            "INVALID_URL", "Target URL contains a backslash, which parsers treat inconsistently."
        )

    parts = urlsplit(value)
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetValidationError(
            "UNSUPPORTED_SCHEME", "Only http:// and https:// targets are supported."
        )
    if not parts.hostname:
        raise TargetValidationError("INVALID_URL", "Target URL is missing a host name.")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise TargetValidationError(
            "URL_CREDENTIALS", "URLs containing embedded credentials are not accepted."
        )

    try:
        port = parts.port  # raises ValueError for out-of-range / non-numeric
    except ValueError:
        raise TargetValidationError("INVALID_URL", "Target URL contains an invalid port.") from None

    raw_host = parts.hostname  # urlsplit already lower-cases and strips brackets
    ip_literal = _try_parse_ip(raw_host)
    if ip_literal is not None:
        hostname = str(ip_literal)
        display_host = f"[{hostname}]" if isinstance(ip_literal, ipaddress.IPv6Address) else hostname
    else:
        hostname = _validate_hostname(raw_host)
        display_host = hostname

    effective_port = port or (443 if scheme == "https" else 80)
    if port is not None and effective_port not in config.ALLOWED_PORTS:
        raise TargetValidationError(
            "DISALLOWED_PORT",
            f"Port {effective_port} is not permitted. Allowed ports: "
            f"{', '.join(str(p) for p in sorted(config.ALLOWED_PORTS))}.",
        )

    path = parts.path or "/"
    path_with_query = path + (f"?{parts.query}" if parts.query else "")
    default_port = 443 if scheme == "https" else 80
    host_header = display_host if effective_port == default_port else f"{display_host}:{effective_port}"
    netloc = host_header
    canonical = urlunsplit((scheme, netloc, path, parts.query, ""))

    return ParsedTarget(
        raw=value,
        canonical_url=canonical,
        scheme=scheme,
        hostname=hostname,
        display_host=display_host,
        port=port,
        effective_port=effective_port,
        path_with_query=path_with_query,
        host_header=host_header,
        ip_literal=ip_literal,
    )


def normalize_url(raw_url: str) -> str:
    """Validate and return the canonical URL for a target or redirect hop."""
    return parse_url(raw_url).canonical_url


# ---------------------------------------------------------------------------
# DNS resolution (bounded)
# ---------------------------------------------------------------------------

def resolve_host(host: str, port: int, timeout: Optional[float] = None) -> List[ipaddress._BaseAddress]:
    """Resolve a hostname to ALL of its addresses.

    Resolution runs in a worker thread so a hung resolver cannot stall a
    Flask worker forever; ``timeout`` (seconds) bounds the wait. Raises
    TargetValidationError("DNS_RESOLUTION_FAILED") on any failure.
    """
    timeout = config.DNS_TIMEOUT if timeout is None else timeout

    def _lookup():
        return socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="sentinel-dns")
    try:
        future = executor.submit(_lookup)
        try:
            infos = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            raise TargetValidationError(
                "DNS_RESOLUTION_FAILED",
                f"Resolving '{host}' exceeded the {timeout:g}s DNS timeout.",
            ) from exc
    except socket.gaierror as exc:
        detail = exc.args[0] if exc.args else str(exc)
        raise TargetValidationError(
            "DNS_RESOLUTION_FAILED",
            f"Could not resolve host '{host}' ({detail}).",
        ) from exc
    except OSError as exc:
        raise TargetValidationError(
            "DNS_RESOLUTION_FAILED",
            f"Could not resolve host '{host}' ({exc.__class__.__name__}).",
        ) from exc
    finally:
        executor.shutdown(wait=False)

    resolved: List[ipaddress._BaseAddress] = []
    seen = set()
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if str(ip) not in seen:
            seen.add(str(ip))
            resolved.append(ip)

    if not resolved:
        raise TargetValidationError(
            "DNS_RESOLUTION_FAILED",
            f"Host '{host}' did not resolve to a usable IP address.",
        )
    return resolved


# ---------------------------------------------------------------------------
# Destination policy integration
# ---------------------------------------------------------------------------

def _policy(allow_private: Optional[bool] = None,
            allow_networks: Optional[List[str]] = None) -> ip_policy.DestinationPolicy:
    if allow_private is None:
        allow_private = config.ALLOW_PRIVATE_TARGETS
    return ip_policy.DestinationPolicy(allow_private=allow_private, allow_networks=allow_networks)


def enforce_destination_policy(addresses: List[ipaddress._BaseAddress],
                               host: str,
                               allow_private: Optional[bool] = None,
                               allow_networks: Optional[List[str]] = None) -> None:
    """Raise PRIVATE_TARGET_BLOCKED unless every address may be contacted."""
    try:
        _policy(allow_private, allow_networks).require_allowed(addresses)
    except ip_policy.PolicyViolation as exc:
        raise TargetValidationError(
            "PRIVATE_TARGET_BLOCKED",
            f"'{host}' resolves to {exc.ip}, a {exc.reason}. Scanning private or loopback "
            "infrastructure is disabled by default (SSRF guard). Set "
            "SENTINEL_ALLOW_PRIVATE=1 to scan your own lab targets.",
        ) from exc


def validate_target(raw_url: str, allow_private: Optional[bool] = None) -> Dict[str, Any]:
    """Validate a scan target end-to-end (structure + DNS + IP policy).

    Returns a dict with the normalized URL, scheme, host, port, resolved IPs
    and whether lab mode (private targets) was allowed for this request.
    Raises TargetValidationError with a machine-readable code on rejection.
    """
    parsed = parse_url(raw_url)

    if parsed.ip_literal is not None:
        resolved = [parsed.ip_literal]
    else:
        resolved = resolve_host(parsed.hostname, parsed.effective_port)

    enforce_destination_policy(resolved, parsed.hostname, allow_private=allow_private)

    if allow_private is None:
        allow_private = config.ALLOW_PRIVATE_TARGETS
    return {
        "url": parsed.canonical_url,
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.effective_port,
        "resolved_ips": [str(ip) for ip in resolved],
        "allow_private": bool(allow_private),
    }
