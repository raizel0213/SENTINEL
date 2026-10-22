"""Shared pytest fixtures for the SENTINEL test suite.

No test in this suite performs a real outbound HTTP request. The harness
offers:

* ``FakeResolver``        - hostname → address list (no DNS).
* ``ScriptedOpener``      - URL → canned response, records every connection
                            attempt so tests can assert which destinations
                            were actually contacted.
* ``socket_spy``          - wraps ``socket.create_connection`` to record (and
                            optionally block) every real connection attempt.
* ``lab_server``          - a real ThreadingHTTPServer bound to 127.0.0.1 for
                            end-to-end transport tests (lab-mode policy).
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import config, safe_transport  # noqa: E402
from backend.app import create_app  # noqa: E402
from backend.target_validation import TargetValidationError  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Never let tests touch the real history database; reset API limiters."""
    from backend import app as app_module
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test-history.db")
    app_module.RATE_LIMITER.reset()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Flask app wired to a throwaway SQLite database."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "api-history.db")
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def sample_record():
    """A minimal but complete scan record for report/storage tests."""
    return {
        "id": "abc123def456",
        "schema_version": 2,
        "product": "SENTINEL",
        "version": "2.5.0",
        "mode": "server",
        "mode_label": "Server-side scan",
        "target": "https://example.com/",
        "final_url": "https://example.com/",
        "timestamp": "2026-01-15T10:30:00Z",
        "http_status": 200,
        "duration_ms": 123,
        "observed": 5,
        "score": None,
        "grade": None,
        "counts": None,
        "redirect_chain": [{"url": "https://example.com/", "status": 200, "location": None}],
        "tls": {"verified": True, "cert_error": None, "not_after": "2026-06-01", "days_left": 137},
        "checks": [
            {
                "id": "HDR-001", "severity": "High", "name": "Content Security Policy missing",
                "header": "Content-Security-Policy", "status": "Missing",
                "evidence": "Header not present in the response.",
                "description": "CSP description.", "impact": "CSP impact.",
                "fix": "Add a CSP.", "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            },
            {
                "id": "HDR-004", "severity": "Pass", "name": "MIME sniffing protection observed",
                "header": "X-Content-Type-Options", "status": "Present",
                "evidence": "X-Content-Type-Options: nosniff",
                "description": "XCTO description.", "impact": "XCTO impact.",
                "fix": "Keep nosniff.", "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
            },
        ],
        "limitations": ["Passive header review only."],
    }


# ---------------------------------------------------------------------------
# Transport test doubles
# ---------------------------------------------------------------------------

class FakeResolver:
    """Stands in for DNS: hostname → list of addresses (strings)."""

    def __init__(self, mapping=None):
        self.mapping = {k.lower(): list(v) for k, v in (mapping or {}).items()}
        self.calls = []

    def __call__(self, hostname, port, timeout):
        self.calls.append((hostname, port))
        key = str(hostname).lower()
        if key not in self.mapping:
            raise TargetValidationError(
                "DNS_RESOLUTION_FAILED", f"Could not resolve host '{hostname}' (test stub)."
            )
        return [ipaddress.ip_address(a) for a in self.mapping[key]]


def sr(url, status=200, headers=None, tls=None, body_bytes_read=0, body_truncated=False):
    """Build a SingleResponse; headers given as dict or list of pairs."""
    if isinstance(headers, dict):
        pairs = [(k, v) for k, v in headers.items()]
    else:
        pairs = list(headers or [])
    return safe_transport.SingleResponse(url=url, status=status, headers=pairs, tls=tls,
                                         body_bytes_read=body_bytes_read,
                                         body_truncated=body_truncated)


class ScriptedOpener:
    """URL → canned SingleResponse; records every connection attempt."""

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.attempts = []  # (canonical_url, ip)

    def __call__(self, parsed, ip, limits):
        self.attempts.append((parsed.canonical_url, str(ip)))
        if parsed.canonical_url not in self.responses:
            raise AssertionError(f"unexpected connection attempt to {parsed.canonical_url}")
        return self.responses[parsed.canonical_url]

    def assert_only_connected(self, expected_urls):
        assert [a[0] for a in self.attempts] == list(expected_urls)


@pytest.fixture()
def strict_policy():
    from backend import ip_policy
    return ip_policy.DestinationPolicy()  # no lab mode, no overrides


class ConnectionLog:
    """Records connection attempts as (ip, port) tuples."""

    def __init__(self):
        self.calls = []


@pytest.fixture()
def socket_spy(monkeypatch):
    """Record every real socket connection attempt; pass through to the OS."""
    log = ConnectionLog()
    real_create = socket.create_connection

    def spy(address, *args, **kwargs):
        log.calls.append((str(address[0]), int(address[1])))
        return real_create(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", spy)
    return log


@pytest.fixture()
def socket_block(monkeypatch):
    """Refuse every real outbound connection attempt (records them)."""
    log = ConnectionLog()

    def block(address, *args, **kwargs):
        log.calls.append((str(address[0]), int(address[1])))
        raise AssertionError(f"outbound connection attempted to {address}")

    monkeypatch.setattr(socket, "create_connection", block)
    return log


# ---------------------------------------------------------------------------
# Real local HTTP server (loopback lab target)
# ---------------------------------------------------------------------------

class _LabHandler(BaseHTTPRequestHandler):
    """Serves scripted routes from ``server.routes``; records request headers."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802 - stdlib naming
        server = self.server
        server.requests.append({
            "path": self.path,
            "headers": {k.lower(): v for (k, v) in self.headers.items()},
        })
        route = server.routes.get(self.path)
        if route is None:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args):  # silence request logging
        pass


class LabServer(ThreadingHTTPServer):
    """Real HTTP server on 127.0.0.1 for end-to-end transport tests.

    Subclasses ThreadingHTTPServer so the request handler can reach
    ``self.server.routes`` / ``self.server.requests`` directly.
    """

    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _LabHandler)
        self.routes = {}
        self.requests = []

    @property
    def base(self) -> str:
        host, port = self.server_address
        return f"http://{host}:{port}"

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.shutdown()
        self.server_close()


@pytest.fixture()
def lab_server(monkeypatch):
    """Real HTTP server on 127.0.0.1. The ephemeral port is added to the
    port allowlist so the validated transport can address it."""
    server = LabServer().start()
    monkeypatch.setattr(config, "ALLOWED_PORTS",
                        frozenset(config.ALLOWED_PORTS | {server.port}))
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture()
def lab_policy():
    """Policy for lab tests: loopback allowed (the local server), nothing else."""
    from backend import ip_policy
    return ip_policy.DestinationPolicy(allow_networks=["127.0.0.0/8"])
