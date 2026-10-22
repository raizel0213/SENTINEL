"""Redirect validation and transport safety tests.

Covers the required redirect scenarios (public HTTPS/HTTP, loopback,
localhost, private IPv4, IPv6 loopback, link-local, hostname resolving to a
prohibited address, chains that turn prohibited mid-way, loops, caps) plus
connection pinning, body caps and request-header hygiene.

Two layers:
* Scripted: ``fetch_validated`` with a FakeResolver + ScriptedOpener —
  proves the validation state machine contacts only permitted destinations.
* Real socket: a local ThreadingHTTPServer on 127.0.0.1 with a lab policy —
  proves the production opener actually performs validated requests.
"""
from __future__ import annotations

import http.client
import socket

import pytest

from backend import config, ip_policy, safe_transport, target_validation
from backend.safe_transport import (
    FetchLimits,
    RedirectLoopError,
    TooManyRedirectsError,
)
from backend.target_validation import TargetValidationError

from conftest import FakeResolver, ScriptedOpener, sr

PUBLIC_A = "https://public-a.test/"
PUBLIC_B = "https://public-b.test/"
IP_A = "93.184.216.34"
IP_B = "93.184.216.35"


def limits(**overrides) -> FetchLimits:
    base = dict(connect_timeout=1.0, read_timeout=1.0, dns_timeout=1.0,
                max_redirects=5, deadline_s=10.0, max_body_bytes=65536)
    base.update(overrides)
    return FetchLimits(**base)


RESOLVER_MAP = {
    "public-a.test": [IP_A],
    "public-b.test": [IP_B],
    "localhost": ["127.0.0.1"],
    "intranet.lab": ["192.168.1.10"],
    "metadata.internal": ["169.254.169.254"],
    "mixed.test": [IP_A, "192.168.1.10"],       # public + private mix
    "mapped.test": ["::ffff:10.0.0.9"],         # IPv4-mapped private
}


def make_opener(spec: dict) -> ScriptedOpener:
    """spec: URL → (status, headers dict). 200 implicit when absent."""
    responses = {}
    for url, entry in spec.items():
        status, headers = entry
        responses[url] = sr(url, status=status, headers=headers)
    return ScriptedOpener(responses)


def fetch(url, opener, resolver=None, policy=None, lim=None):
    return safe_transport.fetch_validated(
        url, lim or limits(),
        resolver=resolver or FakeResolver(RESOLVER_MAP),
        policy=policy or ip_policy.DestinationPolicy(),
        opener=opener,
    )


# ---------------------------------------------------------------------------
# Scripted redirect scenarios (no real sockets at all)
# ---------------------------------------------------------------------------

class TestRedirectScenarios:
    def test_follows_public_https_redirect(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": PUBLIC_B}),
            PUBLIC_B: (200, {"Server": "ok"}),
        })
        outcome = fetch(PUBLIC_A, opener)
        assert outcome.status == 200
        assert outcome.final_url == PUBLIC_B
        assert [h["url"] for h in outcome.redirect_chain] == [PUBLIC_A, PUBLIC_B]
        assert outcome.redirect_chain[0]["decision"] == "followed"
        assert outcome.redirect_chain[-1]["decision"] == "final"
        opener.assert_only_connected([PUBLIC_A, PUBLIC_B])

    def test_follows_public_http_redirect(self):
        a, b = "http://public-a.test/", "http://public-b.test/"
        opener = make_opener({a: (301, {"Location": b}), b: (200, {})})
        outcome = fetch(a, opener)
        assert outcome.status == 200 and outcome.final_url == b

    def test_redirect_to_loopback_ip_refused_before_connecting(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://127.0.0.1/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        opener.assert_only_connected([PUBLIC_A])  # hop 2 never contacted

    def test_redirect_to_localhost_refused(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://localhost:8080/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        opener.assert_only_connected([PUBLIC_A])

    def test_redirect_to_private_ipv4_refused(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://10.0.0.5/admin"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        assert "10.0.0.5" in str(exc.value)
        opener.assert_only_connected([PUBLIC_A])

    def test_redirect_to_ipv6_loopback_refused(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://[::1]/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_redirect_to_link_local_refused(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": "http://169.254.169.254/latest/meta-data/"}),
        })
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_redirect_to_host_resolving_prohibited_refused(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://intranet.lab/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        opener.assert_only_connected([PUBLIC_A])

    def test_redirect_to_mapped_private_ipv6_refused(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "http://mapped.test/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"

    def test_chain_turning_prohibited_mid_way(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": PUBLIC_B}),
            PUBLIC_B: (302, {"Location": "http://192.168.0.20/"}),
        })
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        opener.assert_only_connected([PUBLIC_A, PUBLIC_B])

    def test_mixed_public_private_resolution_rejected(self):
        opener = make_opener({})
        with pytest.raises(TargetValidationError) as exc:
            fetch("https://mixed.test/", opener)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        assert opener.attempts == []

    def test_redirect_loop_detected(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": PUBLIC_B}),
            PUBLIC_B: (302, {"Location": PUBLIC_A}),
        })
        with pytest.raises(RedirectLoopError):
            fetch(PUBLIC_A, opener)
        opener.assert_only_connected([PUBLIC_A, PUBLIC_B])

    def test_self_redirect_detected(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": PUBLIC_A})})
        with pytest.raises(RedirectLoopError):
            fetch(PUBLIC_A, opener)
        opener.assert_only_connected([PUBLIC_A])

    def test_redirect_cap_enforced(self):
        spec = {}
        hosts = [f"https://hop{i}.test/" for i in range(4)]
        for i, host in enumerate(hosts[:-1]):
            RESOLVER_MAP.setdefault(f"hop{i}.test", [f"93.184.216.{40 + i}"])
            spec[host] = (302, {"Location": hosts[i + 1]})
        RESOLVER_MAP.setdefault("hop3.test", ["93.184.216.43"])
        spec[hosts[-1]] = (200, {})
        opener = ScriptedOpener({u: sr(u, status=s, headers=h) for u, (s, h) in spec.items()})
        with pytest.raises(TooManyRedirectsError):
            fetch(hosts[0], opener, lim=limits(max_redirects=2))
        assert len(opener.attempts) == 3  # h0, h1, h2 — h3 never contacted

    def test_relative_location_resolved(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": "/next-hop"}),
            "https://public-a.test/next-hop": (200, {}),
        })
        outcome = fetch(PUBLIC_A, opener)
        assert outcome.final_url == "https://public-a.test/next-hop"

    def test_scheme_relative_location_resolved(self):
        opener = make_opener({
            "http://public-a.test/": (302, {"Location": "//public-b.test/x"}),
            "http://public-b.test/x": (200, {}),
        })
        outcome = fetch("http://public-a.test/", opener)
        assert outcome.final_url == "http://public-b.test/x"

    def test_redirect_to_disallowed_scheme_rejected(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "ftp://public-b.test/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "INVALID_REDIRECT"

    def test_redirect_to_url_with_credentials_rejected(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "https://u:p@public-b.test/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code == "INVALID_REDIRECT"

    def test_redirect_with_disallowed_port_rejected(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": "https://public-b.test:22/"})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener)
        assert exc.value.code in ("INVALID_REDIRECT", "DISALLOWED_PORT")

    def test_redirect_status_without_location_is_final(self):
        opener = make_opener({PUBLIC_A: (302, {"Server": "no-location"})})
        outcome = fetch(PUBLIC_A, opener)
        assert outcome.status == 302 and outcome.final_url == PUBLIC_A

    def test_set_cookies_collected_across_hops(self):
        opener = ScriptedOpener({
            PUBLIC_A: sr(PUBLIC_A, status=307,
                         headers=[("Location", PUBLIC_B), ("Set-Cookie", "hop=1; Path=/")]),
            PUBLIC_B: sr(PUBLIC_B, status=200,
                         headers=[("Set-Cookie", "fin=2; Path=/"), ("Set-Cookie", "fin2=3")]),
        })
        outcome = fetch(PUBLIC_A, opener)
        assert outcome.set_cookies == ["hop=1; Path=/", "fin=2; Path=/", "fin2=3"]

    def test_resolved_ips_recorded_per_hop(self):
        opener = make_opener({
            PUBLIC_A: (302, {"Location": PUBLIC_B}),
            PUBLIC_B: (200, {}),
        })
        outcome = fetch(PUBLIC_A, opener)
        assert outcome.redirect_chain[0]["resolved_ips"] == [IP_A]
        assert outcome.redirect_chain[0]["resolved_ip"] == IP_A
        assert outcome.first_hop_ips == [IP_A]

    def test_invalid_initial_scheme_rejected_without_connection(self):
        opener = make_opener({})
        with pytest.raises(TargetValidationError) as exc:
            fetch("ftp://public-a.test/", opener)
        assert exc.value.code == "UNSUPPORTED_SCHEME"
        assert opener.attempts == []


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------

class TestDeadline:
    def test_deadline_exceeded_before_connect(self):
        opener = make_opener({PUBLIC_A: (302, {"Location": PUBLIC_B})})
        with pytest.raises(TargetValidationError) as exc:
            fetch(PUBLIC_A, opener, lim=limits(deadline_s=-1))
        assert exc.value.code == "SCAN_TIMEOUT"
        assert opener.attempts == []


# ---------------------------------------------------------------------------
# Real-socket end-to-end tests (local loopback lab server)
# ---------------------------------------------------------------------------

class TestRealSocket:
    def _limits(self):
        return limits(max_body_bytes=8192)

    def test_real_redirect_followed_end_to_end(self, lab_server, lab_policy):
        lab_server.routes = {
            "/redirect": (302, {"Location": f"{lab_server.base}/final"}, b""),
            "/final": (200, {"X-Final": "yes"}, b"done"),
        }
        outcome = safe_transport.fetch_validated(
            f"{lab_server.base}/redirect", self._limits(), policy=lab_policy)
        assert outcome.status == 200
        assert outcome.final_url == f"{lab_server.base}/final"
        assert len(outcome.redirect_chain) == 2
        assert outcome.redirect_chain[0]["resolved_ips"] == ["127.0.0.1"]

    def test_real_redirect_to_private_ip_refused_without_connection(
            self, lab_server, lab_policy, monkeypatch):
        attempts = []
        real_create = socket.create_connection

        def spy(address, *a, **k):
            attempts.append((str(address[0]), int(address[1])))
            return real_create(address, *a, **k)

        monkeypatch.setattr(socket, "create_connection", spy)
        lab_server.routes = {
            "/to-private": (302, {"Location": "http://10.255.255.1/admin"}, b""),
        }
        with pytest.raises(TargetValidationError) as exc:
            safe_transport.fetch_validated(
                f"{lab_server.base}/to-private", self._limits(), policy=lab_policy)
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        # only the lab server itself was contacted — never the private IP
        assert {a[0] for a in attempts} == {"127.0.0.1"}

    def test_real_redirect_loop_detected(self, lab_server, lab_policy):
        lab_server.routes = {
            "/loop-a": (302, {"Location": f"{lab_server.base}/loop-b"}, b""),
            "/loop-b": (302, {"Location": f"{lab_server.base}/loop-a"}, b""),
        }
        with pytest.raises(RedirectLoopError):
            safe_transport.fetch_validated(
                f"{lab_server.base}/loop-a", self._limits(), policy=lab_policy)

    def test_real_redirect_cap(self, lab_server, lab_policy):
        base = lab_server.base
        lab_server.routes = {
            "/h0": (302, {"Location": f"{base}/h1"}, b""),
            "/h1": (302, {"Location": f"{base}/h2"}, b""),
            "/h2": (302, {"Location": f"{base}/h3"}, b""),
        }
        with pytest.raises(TooManyRedirectsError):
            safe_transport.fetch_validated(
                f"{base}/h0", limits(max_redirects=1), policy=lab_policy)

    def test_body_cap_truncates(self, lab_server, lab_policy):
        big = b"x" * (512 * 1024)  # 512 KB body, cap is 8 KB
        lab_server.routes = {"/big": (200, {"Content-Type": "application/octet-stream"}, big)}
        outcome = safe_transport.fetch_validated(
            f"{lab_server.base}/big", self._limits(), policy=lab_policy)
        assert outcome.status == 200
        assert outcome.response.body_bytes_read == 8192
        assert outcome.response.body_truncated is True

    def test_request_header_hygiene(self, lab_server, lab_policy):
        lab_server.routes = {"/": (200, {}, b"ok")}
        outcome = safe_transport.fetch_validated(
            f"{lab_server.base}/", self._limits(), policy=lab_policy)
        assert outcome.status == 200
        sent = lab_server.requests[0]["headers"]
        assert sent["host"] == f"127.0.0.1:{lab_server.port}"
        assert sent["user-agent"].startswith("SENTINEL/")
        assert sent["accept"] == "*/*"
        assert sent["accept-encoding"] == "identity"
        assert sent["connection"] == "close"
        assert "cookie" not in sent
        assert "authorization" not in sent

    def test_default_policy_refuses_loopback_server(self, lab_server, socket_block):
        lab_server.routes = {"/": (200, {}, b"ok")}
        with pytest.raises(TargetValidationError) as exc:
            safe_transport.fetch_validated(f"{lab_server.base}/", self._limits())
        assert exc.value.code == "PRIVATE_TARGET_BLOCKED"
        assert socket_block.calls == []  # nothing was ever connected

    def test_lab_mode_allows_loopback_server(self, lab_server):
        lab_server.routes = {"/": (200, {}, b"ok")}
        policy = ip_policy.DestinationPolicy(allow_private=True)
        outcome = safe_transport.fetch_validated(f"{lab_server.base}/", self._limits(),
                                                 policy=policy)
        assert outcome.status == 200


# ---------------------------------------------------------------------------
# Pinned connection unit test (the production opener path, HTTP)
# ---------------------------------------------------------------------------

class TestPinnedConnection:
    def test_open_pinned_connects_to_given_ip_not_hostname(self, lab_server, monkeypatch):
        """The opener must dial the address it was given — here the lab
        server is reached via a 'pin' even though DNS would disagree."""
        lab_server.routes = {"/": (200, {"X-Ok": "1"}, b"pinned")}
        parsed = target_validation.parse_url(lab_server.base + "/")
        response = safe_transport.open_pinned(parsed, "127.0.0.1", self._limits())
        assert response.status == 200
        assert response.header("x-ok") == "1"

    def test_connection_refused_maps_to_connection_failure(self, monkeypatch):
        # port 9 (discard) is permitted for the test and refused on loopback
        monkeypatch.setattr(config, "ALLOWED_PORTS", frozenset({80, 443, 8080, 8443, 9}))
        parsed = target_validation.parse_url("http://127.0.0.1:9/")
        with pytest.raises(safe_transport.ConnectionFailure):
            safe_transport.open_pinned(parsed, "127.0.0.1", self._limits())

    def _limits(self):
        return limits()
