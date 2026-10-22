"""Tests for target validation, the SSRF guard and the destination policy."""
from __future__ import annotations

import ipaddress
import socket
import time

import pytest

from backend import config, ip_policy, target_validation
from backend.target_validation import TargetValidationError, parse_url, validate_target


def fake_resolve(mapping):
    """Build a socket.getaddrinfo replacement for fixed hosts."""
    def _getaddrinfo(host, port, *args, **kwargs):
        key = str(host).lower()
        if key not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[key], port or 80))]
    return _getaddrinfo


class TestBasicValidation:
    def test_valid_https_target(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"example.com": "93.184.216.34"}))
        info = validate_target("https://example.com/path?x=1")
        assert info["scheme"] == "https"
        assert info["host"] == "example.com"
        assert info["port"] == 443
        assert info["resolved_ips"] == ["93.184.216.34"]
        assert info["url"].startswith("https://example.com/")

    def test_missing_scheme_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("example.com")
        assert exc.value.code == "UNSUPPORTED_SCHEME"

    def test_ftp_scheme_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("ftp://example.com")
        assert exc.value.code == "UNSUPPORTED_SCHEME"

    def test_file_scheme_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("file:///etc/passwd")
        assert exc.value.code == "UNSUPPORTED_SCHEME"

    def test_empty_target_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("   ")
        assert exc.value.code == "INVALID_URL"

    def test_whitespace_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com/a b")
        assert exc.value.code == "INVALID_URL"

    def test_control_characters_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com/\x0b")
        assert exc.value.code == "INVALID_URL"

    def test_backslash_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target(r"https://example.com\@evil.test")
        assert exc.value.code == "INVALID_URL"

    def test_oversized_url_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com/" + "a" * 3000)
        assert exc.value.code == "INVALID_URL"

    def test_credentials_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://user:pass@example.com")
        assert exc.value.code == "URL_CREDENTIALS"

    def test_at_trick_rejected(self):
        """http://evil.test@127.0.0.1/ embeds userinfo — must be refused."""
        with pytest.raises(TargetValidationError) as exc:
            validate_target("http://evil.test@127.0.0.1/")
        assert exc.value.code == "URL_CREDENTIALS"

    def test_out_of_range_port_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com:99999/")
        assert exc.value.code == "INVALID_URL"

    def test_non_numeric_port_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com:abc/")
        assert exc.value.code == "INVALID_URL"

    def test_disallowed_port_rejected(self):
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://example.com:22/")
        assert exc.value.code == "DISALLOWED_PORT"

    def test_allowed_ports_accepted(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"example.com": "93.184.216.34"}))
        for port in (80, 443, 8080, 8443):
            info = validate_target(f"https://example.com:{port}/")
            assert info["port"] == port

    def test_malformed_hostname_labels_rejected(self):
        for host in ("example..com", "under_score.example", "-bad.example",
                     "bad-.example", "a" * 64 + ".example"):
            with pytest.raises(TargetValidationError) as exc:
                parse_url(f"https://{host}/")
            assert exc.value.code == "INVALID_URL", host

    def test_idna_hostname_normalized(self):
        parsed = parse_url("https://bücher.example/")
        assert parsed.hostname == "xn--bcher-kva.example"

    def test_ipv6_literal_parsed(self):
        parsed = parse_url("http://[::1]:8080/x")
        assert parsed.ip_literal == ipaddress.ip_address("::1")
        assert parsed.hostname == "::1"
        assert parsed.effective_port == 8080
        assert parsed.host_header == "[::1]:8080"

    def test_dns_failure(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({}))
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://nonexistent.invalid")
        assert exc.value.code == "DNS_RESOLUTION_FAILED"

    def test_dns_timeout_bounded(self, monkeypatch):
        """A hung resolver must hit the DNS timeout, not stall the worker."""
        def slow_getaddrinfo(host, port, *args, **kwargs):
            time.sleep(0.3)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 80))]

        monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
        monkeypatch.setattr(config, "DNS_TIMEOUT", 0.05)
        started = time.monotonic()
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://slow-dns.test/")
        assert exc.value.code == "DNS_RESOLUTION_FAILED"
        assert time.monotonic() - started < 0.3  # bounded well below the stub's delay


class TestSsrfGuard:
    def test_loopback_blocked(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"localhost": "127.0.0.1"}))
        with pytest.raises(TargetValidationError) as exc:
            validate_target("http://localhost:8080/")
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_private_range_blocked(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"intranet.lab": "192.168.1.10"}))
        with pytest.raises(TargetValidationError) as exc:
            validate_target("http://intranet.lab/")
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_link_local_blocked(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"metadata.internal": "169.254.169.254"}))
        with pytest.raises(TargetValidationError) as exc:
            validate_target("http://metadata.internal/latest/meta-data/")
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_all_resolved_addresses_validated(self, monkeypatch):
        """A host with mixed public + private records must be refused."""
        def multi_record(host, port, *a, **k):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 80)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.9.9.9", port or 80)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", multi_record)
        with pytest.raises(TargetValidationError) as exc:
            validate_target("https://mixed-records.test/")
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        assert "10.9.9.9" in str(exc.value)

    def test_policy_rejects_ipv6_loopback(self):
        violation = ip_policy.first_violation([ipaddress.ip_address("::1")])
        assert violation is not None

    def test_policy_rejects_ipv4_mapped_private(self):
        violation = ip_policy.first_violation([ipaddress.ip_address("::ffff:10.0.0.5")])
        assert violation is not None

    def test_policy_allows_public(self):
        assert ip_policy.first_violation([ipaddress.ip_address("93.184.216.34")]) is None

    def test_allow_private_flag_bypasses_guard(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"localhost": "127.0.0.1"}))
        info = validate_target("http://localhost:8080/", allow_private=True)
        assert info["allow_private"] is True
        assert info["host"] == "localhost"

    def test_guard_uses_config_flag(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo", fake_resolve({"localhost": "127.0.0.1"}))
        monkeypatch.setattr(config, "ALLOW_PRIVATE_TARGETS", True)
        info = validate_target("http://localhost/")  # no explicit flag -> config
        assert info["allow_private"] is True

    def test_ip_literal_target_checked_without_dns(self):
        """A literal private IP is blocked even when DNS is unavailable."""
        with pytest.raises(TargetValidationError) as exc:
            validate_target("http://10.1.2.3/")
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
