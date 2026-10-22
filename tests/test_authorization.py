"""Authorization confirmation enforcement (backend side).

Proves that scan requests without a valid ``authorization`` field are
rejected with 400/403 and that NO outbound connection is attempted for
them. The socket spy records every ``socket.create_connection`` call in
the process; a clean scan path must produce zero calls.
"""
from __future__ import annotations

import pytest

from backend import config, safe_transport
from backend.target_validation import TargetValidationError

AUTH_OK = {"mode": "server", "target": "https://example.com", "authorization": True}


class TestAuthorizationEnforcement:
    def test_missing_field_rejected_400(self, client, socket_block):
        response = client.post("/api/scan", json={"mode": "server", "target": "https://example.com"})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "AUTHORIZATION_INVALID"
        assert socket_block.calls == []

    def test_false_rejected_403(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": False})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "AUTHORIZATION_REQUIRED"
        assert socket_block.calls == []

    def test_string_true_rejected_400(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": "true"})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "AUTHORIZATION_INVALID"
        assert socket_block.calls == []

    def test_integer_one_rejected_400(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": 1})
        assert response.status_code == 400
        assert socket_block.calls == []

    def test_none_rejected_400(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": None})
        assert response.status_code == 400
        assert socket_block.calls == []

    def test_browser_mode_requires_authorization(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "browser", "result": {"target": "https://example.com/", "checks": []}})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "AUTHORIZATION_INVALID"
        assert socket_block.calls == []

    def test_browser_mode_with_authorization_accepted(self, client):
        response = client.post("/api/scan", json={
            "mode": "browser", "authorization": True,
            "result": {"target": "https://example.com/",
                       "checks": [{"id": "LIVE-001", "severity": "Pass", "name": "ok"}]}})
        assert response.status_code == 200
        record = response.get_json()
        assert record["mode"] == "browser"
        assert record["authorization_confirmed"] is True
        assert record["score"] is None
        assert record["score_applicable"] is False

    def test_demo_mode_needs_no_authorization(self, client, socket_block):
        """Demo profiles perform no request — explicitly exempt, and they
        must never reach the live scan path."""
        response = client.post("/api/scan", json={"mode": "demo", "profile": "demo-mixed",
                                                  "persist": False})
        assert response.status_code == 200
        assert response.get_json()["mode"] == "demo"
        assert socket_block.calls == []

    def test_authorized_scan_reaches_validation_and_fails_cleanly(
            self, client, monkeypatch, socket_block):
        """With authorization present, the request proceeds — here DNS fails
        (stubbed) and the API returns a clean target error. Still no socket."""
        def no_dns(hostname, port, timeout):
            raise TargetValidationError("DNS_RESOLUTION_FAILED", "stubbed resolver failure")

        monkeypatch.setattr(safe_transport, "_default_resolver", no_dns)
        response = client.post("/api/scan", json=AUTH_OK)
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "DNS_RESOLUTION_FAILED"
        assert socket_block.calls == []

    def test_authorized_private_target_still_blocked(self, client, socket_block):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "http://127.0.0.1/", "authorization": True})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "PRIVATE_TARGET_BLOCKED"
        assert socket_block.calls == []

    def test_authorization_checked_before_target_validation(self, client, socket_block):
        """A malformed target WITH no authorization must fail on
        authorization, not on the target — auth is the first gate."""
        response = client.post("/api/scan", json={"mode": "server", "target": "!!"})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "AUTHORIZATION_INVALID"
        assert socket_block.calls == []


class TestRateLimitAndGate:
    def test_rate_limit_returns_429(self, client, monkeypatch):
        from backend import app as app_module
        monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 2)
        app_module.RATE_LIMITER.reset()
        try:
            for _ in range(2):
                response = client.post("/api/scan", json={"mode": "demo", "persist": False})
                assert response.status_code == 200
            response = client.post("/api/scan", json={"mode": "demo", "persist": False})
            assert response.status_code == 429
            assert response.get_json()["error"]["code"] == "RATE_LIMITED"
        finally:
            app_module.RATE_LIMITER.reset()

    def test_concurrency_gate_returns_503(self, client, monkeypatch):
        import threading
        from backend import app as app_module
        monkeypatch.setattr(app_module, "SCAN_GATE", threading.BoundedSemaphore(0))
        response = client.post("/api/scan", json={"mode": "demo", "persist": False})
        assert response.status_code == 503
        assert response.get_json()["error"]["code"] == "SCAN_BUSY"

    def test_gate_released_after_scan(self, client, monkeypatch):
        """A completed demo scan must release the gate (second scan OK)."""
        for _ in range(3):
            response = client.post("/api/scan", json={"mode": "demo", "persist": False})
            assert response.status_code == 200
