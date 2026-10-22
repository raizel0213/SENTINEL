"""Flask application security hardening tests: headers, CORS/origin policy,
error hygiene and static-serving behaviour."""
from __future__ import annotations

import threading

from backend import config


class TestSecurityHeaders:
    def test_headers_on_ui(self, client):
        response = client.get("/")
        assert response.status_code == 200
        csp = response.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert response.headers.get("Referrer-Policy") == "no-referrer"

    def test_headers_on_api(self, client):
        response = client.get("/api/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("Cache-Control") == "no-store"

    def test_no_cors_headers_anywhere(self, client):
        for path in ("/", "/api/health", "/api/scans"):
            response = client.get(path)
            assert "Access-Control-Allow-Origin" not in response.headers, path
            assert "Access-Control-Allow-Headers" not in response.headers, path


class TestSameOriginGuard:
    def test_foreign_origin_rejected(self, client):
        response = client.post("/api/scan", json={"mode": "demo"},
                               headers={"Origin": "https://evil.example"})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "CROSS_ORIGIN_BLOCKED"

    def test_foreign_origin_rejected_on_delete(self, client):
        response = client.delete("/api/scans", headers={"Origin": "https://evil.example"})
        assert response.status_code == 403

    def test_same_origin_allowed(self, client):
        response = client.post("/api/scan", json={"mode": "demo", "persist": False},
                               headers={"Origin": "http://localhost"})
        assert response.status_code == 200

    def test_foreign_origin_rejected_on_read_endpoints(self, client):
        # GET endpoints expose scan history and reports; they must not trust a
        # foreign Origin even though CORS headers are absent.
        response = client.get("/api/health", headers={"Origin": "https://evil.example"})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "CROSS_ORIGIN_BLOCKED"

    def test_dns_rebinding_host_rejected(self, client):
        response = client.get("/api/scans", headers={"Host": "attacker.example"})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "HOST_NOT_ALLOWED"

    def test_malformed_origin_rejected(self, client):
        response = client.get("/api/health", headers={"Origin": "javascript:alert(1)"})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "CROSS_ORIGIN_BLOCKED"

    def test_unexpected_host_port_rejected(self, client):
        wrong_port = config.PORT + 1 if config.PORT < 65535 else config.PORT - 1
        response = client.get("/api/health", headers={"Host": f"localhost:{wrong_port}"})
        assert response.status_code == 403
        assert response.get_json()["error"]["code"] == "HOST_NOT_ALLOWED"

    def test_foreign_origin_rejected_on_history_and_reports(self, client):
        record = client.post("/api/scan", json={"mode": "demo"}).get_json()
        history = client.get("/api/scans", headers={"Origin": "https://evil.example"})
        report = client.get(
            f"/api/scans/{record['id']}/report?format=html",
            headers={"Origin": "https://evil.example"},
        )
        assert history.status_code == 403
        assert report.status_code == 403


class TestErrorHygiene:
    def test_unknown_api_404_json(self, client):
        response = client.get("/api/nope")
        assert response.status_code == 404
        assert response.get_json()["error"]["code"] == "NOT_FOUND"

    def test_method_not_allowed_json(self, client):
        response = client.get("/api/scan")
        assert response.status_code == 405
        assert response.get_json()["error"]["code"] == "METHOD_NOT_ALLOWED"

    def test_payload_too_large_413(self, client):
        response = client.post(
            "/api/scan", data=b"x" * (config.MAX_BODY_BYTES + 1),
            content_type="application/json")
        assert response.status_code == 413

    def test_non_json_body_rejected(self, client):
        response = client.post("/api/scan", data="not json",
                               content_type="application/json")
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "INVALID_JSON"

    def test_error_bodies_leak_no_tracebacks(self, client):
        response = client.post("/api/scan", json={"mode": "server", "authorization": True,
                                                  "target": "!!"})
        assert response.status_code == 400
        body = response.get_data(as_text=True)
        assert "Traceback" not in body
        assert ".py" not in body


class TestHealthMetadata:
    def test_health_reports_v2_1(self, client):
        data = client.get("/api/health").get_json()
        assert data["version"] == "2.5.0"
        assert data["checks_registered"] == 18
        assert "rate_limit_per_minute" in data
        assert "max_concurrent_scans" in data

    def test_static_assets_served(self, client):
        for path in ("/css/styles.css", "/css/themes.css", "/js/app.js",
                     "/js/scanner-ui.js", "/assets/favicon.svg"):
            assert client.get(path).status_code == 200, path

    def test_authorization_checkbox_in_ui(self, client):
        html = client.get("/").get_data(as_text=True)
        assert 'id="authorizeScan"' in html
        assert "Authorization confirmation" in html
