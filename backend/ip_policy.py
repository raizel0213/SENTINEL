"""Destination IP policy for outbound scanner requests.

Every IP address the scanner is about to contact - whether typed literally
in the URL or resolved from a hostname - must pass through
:class:`DestinationPolicy`. The policy is deliberately conservative and
deterministic: it combines Python's ``ipaddress`` properties with an
explicit blocklist so behaviour does not depend on the interpreter version.

Handled address families and encodings:

* plain IPv4 and IPv6 literals,
* IPv4-mapped IPv6 (``::ffff:10.0.0.1`` is judged as ``10.0.0.1``),
* 6to4 (``2002::/16``) - the embedded IPv4 address is evaluated,
* NAT64 (``64:ff9b::/96``) - the embedded IPv4 address is evaluated,
* Teredo (``2001:0::/32``) - both embedded IPv4 addresses are evaluated.

A destination is rejected if ANY address it resolves to violates the
policy (see ``require_allowed``).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# --- explicit blocklists (belt and braces; keep behaviour version-stable) --
BLOCKED_V4: Tuple[ipaddress.IPv4Network, ...] = tuple(ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",          # "this network" (includes unspecified)
        "10.0.0.0/8",         # RFC1918 private
        "100.64.0.0/10",      # CGNAT shared address space
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local (incl. cloud metadata endpoints)
        "172.16.0.0/12",      # RFC1918 private
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # TEST-NET-1
        "192.88.99.0/24",     # deprecated 6to4 relay anycast
        "192.168.0.0/16",     # RFC1918 private
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved (incl. 255.255.255.255 broadcast)
    ))

BLOCKED_V6: Tuple[ipaddress.IPv6Network, ...] = tuple(ipaddress.ip_network(n)
    for n in (
        "::/128",             # unspecified
        "::1/128",            # loopback
        "::ffff:0:0/96",      # IPv4-mapped (embedded form evaluated too)
        "64:ff9b::/96",       # NAT64 (embedded form evaluated too)
        "100::/64",           # discard-only
        "2001::/32",          # Teredo (embedded forms evaluated too)
        "2001:2::/48",        # benchmarking
        "2001:db8::/32",      # documentation
        "2001:10::/28",       # ORCHID (deprecated)
        "2002::/16",          # 6to4 (embedded form evaluated too)
        "fc00::/7",           # unique local addresses
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
    ))

PREFIX_6TO4 = ipaddress.ip_network("2002::/16")
PREFIX_TEREDO = ipaddress.ip_network("2001::/32")
PREFIX_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class PolicyViolation(Exception):
    """Raised when a candidate destination violates the IP policy."""

    def __init__(self, ip: str, reason: str, note: Optional[str] = None):
        super().__init__(f"{ip} is a {reason}")
        self.ip = ip
        self.reason = reason
        self.note = note


@dataclass(frozen=True)
class Decision:
    """Outcome of evaluating one address against the policy."""

    ip: str
    allowed: bool
    reason: Optional[str] = None
    note: Optional[str] = None  # e.g. "ipv4-mapped", "6to4-embedded"


def _blocked_reason_v4(ip: ipaddress.IPv4Address) -> Optional[str]:
    for network in BLOCKED_V4:
        if ip in network:
            return f"blocked range {network}"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_private:
        return "private address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    if not ip.is_global:
        return "non-global address"
    return None


def _blocked_reason_v6(ip: ipaddress.IPv6Address) -> Optional[str]:
    for network in BLOCKED_V6:
        if ip in network:
            return f"blocked range {network}"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_unspecified:
        return "unspecified address"
    if not ip.is_global:
        return "non-global address"
    return None


def _embedded_ipv4_checks(ip: ipaddress.IPv6Address) -> List[Tuple[ipaddress.IPv4Address, str]]:
    """Extract embedded IPv4 addresses that must be evaluated as well."""
    checks: List[Tuple[ipaddress.IPv4Address, str]] = []
    if ip.ipv4_mapped is not None:
        checks.append((ip.ipv4_mapped, "ipv4-mapped"))
        return checks
    raw = int(ip)
    if ip in PREFIX_6TO4:
        v4 = ipaddress.IPv4Address((raw >> 80) & 0xFFFFFFFF)
        checks.append((v4, "6to4-embedded"))
    elif ip in PREFIX_NAT64:
        v4 = ipaddress.IPv4Address(raw & 0xFFFFFFFF)
        checks.append((v4, "nat64-embedded"))
    elif ip in PREFIX_TEREDO:
        server = ipaddress.IPv4Address((raw >> 64) & 0xFFFFFFFF)
        client = ipaddress.IPv4Address((raw & 0xFFFFFFFF) ^ 0xFFFFFFFF)
        checks.append((server, "teredo-server"))
        checks.append((client, "teredo-client"))
    return checks


def evaluate_address(ip: IPAddress) -> List[Decision]:
    """Evaluate one address (plus any embedded IPv4) against the policy.

    Returns one or more decisions; the address is allowed only when every
    decision allows it.
    """
    decisions: List[Decision] = []
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4_checks(ip)
        if embedded:
            reason = _blocked_reason_v6(ip)
            if reason is None:
                decisions.append(Decision(str(ip), True, None, "ipv6"))
            for v4, note in embedded:
                v4_reason = _blocked_reason_v4(v4)
                decisions.append(Decision(
                    f"{ip} (embedded {v4})", v4_reason is None, v4_reason, note))
            return decisions
        reason = _blocked_reason_v6(ip)
        decisions.append(Decision(str(ip), reason is None, reason, "ipv6"))
        return decisions

    reason = _blocked_reason_v4(ip)
    decisions.append(Decision(str(ip), reason is None, reason, "ipv4"))
    return decisions


class DestinationPolicy:
    """Decides which destination addresses the scanner may connect to.

    ``allow_private`` is the documented lab-mode opt-in
    (``SENTINEL_ALLOW_PRIVATE=1``): it permits private/loopback targets for
    users scanning their own infrastructure. ``allow_networks`` exists for
    tests and controlled integrations that need to permit a narrow range.
    """

    def __init__(self, allow_private: bool = False,
                 allow_networks: Optional[Iterable[str]] = None):
        self.allow_private = bool(allow_private)
        self.allow_networks = tuple(ipaddress.ip_network(n) for n in (allow_networks or ()))

    def _explicitly_allowed(self, ip: IPAddress) -> bool:
        return self.allow_private or any(ip in net for net in self.allow_networks)

    def check(self, ip: IPAddress) -> List[Decision]:
        """Evaluate one address; lab mode overrides rejections."""
        decisions = evaluate_address(ip)
        if self.allow_private:
            return [Decision(d.ip, True, None, d.note) for d in decisions]
        return [
            Decision(d.ip, d.allowed or self._explicitly_allowed(ip), d.reason, d.note)
            if not d.allowed else d
            for d in decisions
        ]

    def check_all(self, addresses: Iterable[IPAddress]) -> List[Decision]:
        decisions: List[Decision] = []
        for ip in addresses:
            decisions.extend(self.check(ip))
        return decisions

    def require_allowed(self, addresses: Iterable[IPAddress]) -> List[str]:
        """Raise unless EVERY address is permitted; return the allowed list."""
        allowed: List[str] = []
        for ip in addresses:
            for decision in self.check(ip):
                if not decision.allowed:
                    raise PolicyViolation(decision.ip, decision.reason or "prohibited address",
                                          decision.note)
            allowed.append(str(ip))
        return allowed


def first_violation(addresses: Iterable[IPAddress]) -> Optional[Decision]:
    """Return the first disallowed decision for a candidate address list."""
    for ip in addresses:
        for decision in evaluate_address(ip):
            if not decision.allowed:
                return decision
    return None
