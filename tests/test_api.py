"""API integration tests via the Flask test client (no real network)."""
from __future__ import annotations

import pytest

from backend import safe_transport, storage

from conftest import sr


class TestHealth:
    def test_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert data["checks_registered"] == 18
        assert data["version"] == "2.5.0"


class TestChecksEndpoint:
    def test_registry(self, client):
        response = client.get("/api/checks")
        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == len(data["checks"]) == 18
        ids = [c["id"] for c in data["checks"]]
        assert "HDR-001" in ids and "TLS-002" in ids


class TestScanEndpoint:
    def test_demo_scan_not_persisted(self, client):
        response = client.post("/api/scan", json={
            "mode": "demo", "profile": "demo-mixed", "persist": False})
        assert response.status_code == 200
        record = response.get_json()
        assert record["mode"] == "demo"
        assert record["score"] == 74  # High + Medium + Low per the model
        assert storage.count_scans() == 0

    def test_demo_scan_persisted(self, client):
        response = client.post("/api/scan", json={"mode": "demo", "profile": "demo-good"})
        assert response.status_code == 200
        assert storage.count_scans() == 1

    def test_unknown_profile(self, client):
        response = client.post("/api/scan", json={"mode": "demo", "profile": "nope"})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "UNKNOWN_PROFILE"

    def test_unknown_mode(self, client):
        response = client.post("/api/scan", json={"mode": "teleport"})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "UNKNOWN_MODE"

    def test_invalid_json(self, client):
        response = client.post("/api/scan", data="not json",
                               content_type="application/json")
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "INVALID_JSON"

    def test_unsupported_scheme(self, client):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "ftp://x", "authorization": True})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "UNSUPPORTED_SCHEME"

    def test_disallowed_port_rejected(self, client):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com:22/", "authorization": True})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "DISALLOWED_PORT"

    def test_private_target_blocked_403(self, client):
        response = client.post("/api/scan", json={
            "mode": "server", "target": "http://127.0.0.1/", "authorization": True})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "PRIVATE_TARGET_BLOCKED"

    def test_server_scan_mocked(self, client, monkeypatch):
        from backend.safe_transport import FetchOutcome

        headers = [
            ("Content-Type", "text/html"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ]
        chain = [{"url": "https://example.com/", "status": 200, "location": None,
                  "resolved_ip": "93.184.216.34", "resolved_ips": ["93.184.216.34"],
                  "decision": "final"}]
        outcome = FetchOutcome(
            request_url="https://example.com/", final_url="https://example.com/",
            response=sr("https://example.com/", status=200, headers=headers,
                        tls={"verified": True, "cert_error": None,
                             "not_after": "2027-06-01", "days_left": 400}),
            redirect_chain=chain)
        monkeypatch.setattr(safe_transport, "fetch_validated",
                            lambda target, limits=None, **kw: outcome)
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": True})
        assert response.status_code == 200
        record = response.get_json()
        assert record["mode"] == "server"
        assert record["http_status"] == 200
        assert record["authorization_confirmed"] is True
        assert record["evidence"]["algorithm"] == "sha256"

    def test_server_scan_redirect_error_mapped_502(self, client, monkeypatch):
        def boom(target, limits=None, **kw):
            raise safe_transport.RedirectLoopError("https://example.com/")

        monkeypatch.setattr(safe_transport, "fetch_validated", boom)
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": True})
        assert response.status_code == 502
        assert response.get_json()["error"]["code"] == "REDIRECT_LOOP"

    def test_server_scan_timeout_mapped_504(self, client, monkeypatch):
        def boom(target, limits=None, **kw):
            raise safe_transport.ScanDeadlineExceeded()

        monkeypatch.setattr(safe_transport, "fetch_validated", boom)
        response = client.post("/api/scan", json={
            "mode": "server", "target": "https://example.com", "authorization": True})
        assert response.status_code == 504
        assert response.get_json()["error"]["code"] == "SCAN_TIMEOUT"

    def test_browser_import(self, client):
        response = client.post("/api/scan", json={
            "mode": "browser", "authorization": True,
            "result": {"target": "https://example.com/", "http_status": 200,
                       "checks": [{"id": "LIVE-001", "severity": "Pass",
                                   "name": "HSTS observed"}]},
        })
        assert response.status_code == 200
        record = response.get_json()
        assert record["mode"] == "browser"
        assert record["score"] is None
        assert record["grade"] is None
        assert record["score_applicable"] is False
        assert record["checks"][0]["severity"] == "Info"

    def test_browser_import_invalid(self, client):
        response = client.post("/api/scan", json={
            "mode": "browser", "authorization": True, "result": {}})
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "INVALID_RESULT"


class TestHistoryEndpoints:
    def test_list_empty(self, client):
        data = client.get("/api/scans").get_json()
        assert data["count"] == 0 and data["items"] == []

    def test_list_after_demo(self, client):
        client.post("/api/scan", json={"mode": "demo", "profile": "demo-poor"})
        data = client.get("/api/scans").get_json()
        assert data["count"] == 1
        item = data["items"][0]
        assert item["mode"] == "demo"
        assert item["target"] == "https://legacy.example.test"

    def test_get_detail_404(self, client):
        response = client.get("/api/scans/missing-id")
        assert response.status_code == 404

    def test_delete_single(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        assert client.delete(f"/api/scans/{record['id']}").status_code == 200
        assert storage.count_scans() == 0

    def test_delete_missing_404(self, client):
        assert client.delete("/api/scans/none").status_code == 404

    def test_clear_all(self, client):
        client.post("/api/scan", json={"mode": "demo", "profile": "demo-mixed"})
        client.post("/api/scan", json={"mode": "demo", "profile": "demo-good"})
        assert client.delete("/api/scans").get_json()["deleted"] == 2
        assert storage.count_scans() == 0


class TestReportEndpoint:
    def test_formats(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        expectations = {
            "json": (b"SENTINEL", "application/json"),
            "csv": (b'"severity"', "text/csv"),
            "md": (b"# SENTINEL", "text/markdown"),
            "html": (b"<!doctype html>", "text/html"),
        }
        for fmt, (needle, mimetype) in expectations.items():
            response = client.get(f"/api/scans/{record['id']}/report?format={fmt}")
            assert response.status_code == 200
            assert mimetype in response.headers["Content-Type"]
            assert needle in response.data

    def test_html_inline_disposition(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        response = client.get(f"/api/scans/{record['id']}/report?format=html")
        assert response.headers["Content-Disposition"].startswith("inline")

    def test_csv_attachment_disposition(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        response = client.get(f"/api/scans/{record['id']}/report?format=csv")
        assert response.headers["Content-Disposition"].startswith("attachment")

    def test_unknown_format_400(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        response = client.get(f"/api/scans/{record['id']}/report?format=docx")
        assert response.status_code == 400

    def test_unknown_scan_404(self, client):
        assert client.get("/api/scans/nope/report").status_code == 404


class TestStaticServing:
    def test_index_served(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"SENTINEL" in response.data

    def test_static_assets(self, client):
        for path in ("/css/styles.css", "/css/themes.css", "/js/app.js",
                     "/assets/favicon.svg"):
            assert client.get(path).status_code == 200, path

    def test_unknown_api_json_404(self, client):
        response = client.get("/api/nope")
        assert response.status_code == 404
        assert response.get_json()["error"]["code"] == "NOT_FOUND"

    def test_unknown_page_plain_404(self, client):
        assert client.get("/nope.html").status_code == 404
