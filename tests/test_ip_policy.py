"""Unit tests for the destination IP policy (backend/ip_policy.py)."""
from __future__ import annotations

import ipaddress

import pytest

from backend.ip_policy import (
    Decision,
    DestinationPolicy,
    PolicyViolation,
    evaluate_address,
    first_violation,
)


def allowed(ip: str) -> bool:
    return all(d.allowed for d in evaluate_address(ipaddress.ip_address(ip)))


def reason(ip: str):
    violation = first_violation([ipaddress.ip_address(ip)])
    return violation.reason if violation else None


class TestBlockedV4:
    @pytest.mark.parametrize("ip", [
        "0.0.0.0", "0.0.0.5",            # this network
        "10.0.0.1", "10.255.255.255",    # RFC1918
        "100.64.1.1",                    # CGNAT
        "127.0.0.1", "127.8.8.8",        # loopback
        "169.254.169.254",               # link-local / cloud metadata
        "172.16.0.1", "172.31.255.255",  # RFC1918
        "192.0.0.1",                     # IETF protocol assignments
        "192.0.2.1",                     # TEST-NET-1
        "192.88.99.1",                   # deprecated 6to4 relay
        "192.168.1.10",                  # RFC1918
        "198.18.0.1",                    # benchmarking
        "198.51.100.7",                  # TEST-NET-2
        "203.0.113.9",                   # TEST-NET-3
        "224.0.0.1", "239.255.255.255",  # multicast
        "240.0.0.1", "255.255.255.255",  # reserved / broadcast
    ])
    def test_blocked(self, ip):
        assert not allowed(ip)
        assert reason(ip)

    @pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "1.1.1.1", "151.101.1.140"])
    def test_public_allowed(self, ip):
        assert allowed(ip)
        assert reason(ip) is None


class TestBlockedV6:
    @pytest.mark.parametrize("ip", [
        "::",                 # unspecified
        "::1",                # loopback
        "fc00::1", "fd12::1", # unique local
        "fe80::1",            # link-local
        "ff02::1",            # multicast
        "100::1",             # discard-only
        "2001:db8::1",        # documentation
        "2001:2::1",          # benchmarking
        "2002::1",            # 6to4 prefix itself
    ])
    def test_blocked(self, ip):
        assert not allowed(ip)

    @pytest.mark.parametrize("ip", ["2606:4700:4700::1111", "2001:4860:4860::8888"])
    def test_public_allowed(self, ip):
        assert allowed(ip)


class TestEmbeddedIpv4:
    def test_ipv4_mapped_private_blocked(self):
        violation = first_violation([ipaddress.ip_address("::ffff:10.0.0.5")])
        assert violation is not None
        assert "10.0.0.5" in violation.ip

    def test_ipv4_mapped_loopback_blocked(self):
        assert not allowed("::ffff:127.0.0.1")

    def test_ipv4_mapped_public_allowed(self):
        assert allowed("::ffff:8.8.8.8")

    def test_6to4_embedded_private_blocked(self):
        # 2002:0a00:0001:: embeds 10.0.0.1
        violation = first_violation([ipaddress.ip_address("2002:0a00:0001::")])
        assert violation is not None
        assert "10.0.0.1" in violation.ip

    def test_6to4_embedded_public_allowed(self):
        # 2002:5db8:d216:: embeds 93.184.216.34 (public)
        assert allowed("2002:5db8:d216::")

    def test_nat64_embedded_public_allowed(self):
        # 64:ff9b::808:808 embeds 8.8.8.8
        assert allowed("64:ff9b::808:808")

    def test_nat64_embedded_private_blocked(self):
        # 64:ff9b::a00:1 embeds 10.0.0.1
        assert not allowed("64:ff9b::a00:1")

    def test_teredo_embedded_private_blocked(self):
        # Teredo 2001:0:<server>:0000:<flags>:<port>:<obfuscated client>
        # client bytes are XOR-flipped; 0xA9FEBEEF -> 10.0.0.1 private
        client_v4 = ipaddress.IPv4Address("10.0.0.1")
        obfuscated = int(client_v4) ^ 0xFFFFFFFF
        teredo = f"2001:0:5db8:d216:8000:e000:{obfuscated >> 16:04x}:{obfuscated & 0xFFFF:04x}"
        assert not allowed(teredo)

    def test_teredo_embedded_public_allowed(self):
        client_v4 = ipaddress.IPv4Address("93.184.216.34")
        obfuscated = int(client_v4) ^ 0xFFFFFFFF
        teredo = f"2001:0:5db8:d216:8000:e000:{obfuscated >> 16:04x}:{obfuscated & 0xFFFF:04x}"
        assert allowed(teredo)


class TestDestinationPolicy:
    def test_require_allowed_raises_with_details(self):
        policy = DestinationPolicy()
        with pytest.raises(PolicyViolation) as exc:
            policy.require_allowed([ipaddress.ip_address("93.184.216.34"),
                                    ipaddress.ip_address("10.1.2.3")])
        assert exc.value.ip == "10.1.2.3"
        assert "10.0.0.0/8" in exc.value.reason

    def test_require_allowed_passes_public(self):
        policy = DestinationPolicy()
        out = policy.require_allowed([ipaddress.ip_address("93.184.216.34")])
        assert out == ["93.184.216.34"]

    def test_allow_networks_override(self):
        policy = DestinationPolicy(allow_networks=["127.0.0.0/8"])
        assert policy.require_allowed([ipaddress.ip_address("127.0.0.1")]) == ["127.0.0.1"]
        with pytest.raises(PolicyViolation):
            policy.require_allowed([ipaddress.ip_address("10.0.0.1")])

    def test_lab_mode_allows_everything(self):
        policy = DestinationPolicy(allow_private=True)
        assert policy.require_allowed([ipaddress.ip_address("192.168.1.1")]) == ["192.168.1.1"]
        assert policy.require_allowed([ipaddress.ip_address("::1")]) == ["::1"]

    def test_check_all_reports_each_address(self):
        policy = DestinationPolicy()
        decisions = policy.check_all([ipaddress.ip_address("8.8.8.8"),
                                      ipaddress.ip_address("::1")])
        assert [d.allowed for d in decisions] == [True, False]

    def test_decision_metadata(self):
        (decision,) = evaluate_address(ipaddress.ip_address("8.8.8.8"))
        assert isinstance(decision, Decision)
        assert decision.allowed is True
        assert decision.note == "ipv4"
