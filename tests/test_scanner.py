"""Tests for scan orchestration: server scan (scripted transport), demo
profiles and browser-mode imports. No real network access is performed."""
from __future__ import annotations

import hashlib
import json

import pytest

from backend import config, safe_transport, scanner, scoring, storage
from backend.safe_transport import ConnectionFailure, FetchOutcome, TLSFailure
from backend.target_validation import TargetValidationError

from conftest import sr

HARDENED_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=()"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
]

TLS_OK = {"verified": True, "cert_error": None, "not_after": "2027-06-01", "days_left": 400}


def outcome(url="https://example.com/", status=200, headers=None,
            set_cookies=None, chain=None, tls=None):
    resp = sr(url, status=status, headers=list(headers if headers is not None
                                              else HARDENED_HEADERS), tls=tls if tls is not None else TLS_OK)
    if chain is None:
        chain = [{"url": url, "status": status, "location": None,
                  "resolved_ip": "93.184.216.34",
                  "resolved_ips": ["93.184.216.34"], "decision": "final"}]
    return FetchOutcome(request_url=chain[0]["url"], final_url=url,
                        response=resp, redirect_chain=chain,
                        set_cookies=list(set_cookies or []))


@pytest.fixture()
def patched_fetch(monkeypatch):
    """Replace the transport with a scriptable fake; returns the set target."""
    holder = {"outcome": outcome()}

    def fake(target_raw, limits=None, **kwargs):
        return holder["outcome"]

    monkeypatch.setattr(safe_transport, "fetch_validated", fake)
    return holder


class TestServerScan:
    def test_hardened_target_scores_high(self, patched_fetch):
        record = scanner.run_server_scan("https://example.com")
        assert record["mode"] == "server"
        assert record["http_status"] == 200
        assert record["score"] >= 90
        assert record["score_applicable"] is True
        assert record["grade"] in ("A+", "A")
        ids = [c["id"] for c in record["checks"]]
        assert "HDR-001" in ids and "HDR-003" in ids and "TLS-001" in ids
        assert record["counts"]["high"] == 0

    def test_weak_target_scores_low(self, patched_fetch):
        patched_fetch["outcome"] = outcome(headers=[("Content-Type", "text/html")])
        record = scanner.run_server_scan("https://example.com")
        assert record["counts"]["high"] >= 1  # CSP missing
        assert record["score"] < 70

    def test_cookies_flagged_without_values(self, patched_fetch):
        patched_fetch["outcome"] = outcome(set_cookies=["sessionid=TOPSECRET; Path=/"])
        record = scanner.run_server_scan("https://example.com")
        evidence = " ".join(c["evidence"] for c in record["checks"])
        assert "sessionid" in evidence
        assert "TOPSECRET" not in evidence
        assert any(c["id"] == "COOKIE-002" and c["severity"] == "Medium"
                   for c in record["checks"])

    def test_redirect_chain_recorded_with_decisions(self, patched_fetch):
        chain = [
            {"url": "http://example.com/", "status": 301,
             "location": "https://example.com/", "resolved_ip": "93.184.216.34",
             "resolved_ips": ["93.184.216.34"], "decision": "followed"},
            {"url": "https://example.com/", "status": 200, "location": None,
             "resolved_ip": "93.184.216.34", "resolved_ips": ["93.184.216.34"],
             "decision": "final"},
        ]
        patched_fetch["outcome"] = outcome(url="https://example.com/", chain=chain)
        record = scanner.run_server_scan("http://example.com")
        assert len(record["redirect_chain"]) == 2
        assert record["redirect_chain"][0]["status"] == 301
        assert record["redirect_chain"][0]["decision"] == "followed"
        assert record["target"] == "http://example.com/"
        assert record["final_url"] == "https://example.com/"

    def test_persisted_to_history(self, patched_fetch):
        record = scanner.run_server_scan("https://example.com")
        assert storage.get_scan(record["id"])["id"] == record["id"]

    def test_authorization_recorded(self, patched_fetch):
        record = scanner.run_server_scan("https://example.com")
        assert record["authorization_confirmed"] is True

    def test_evidence_digest_present_and_deterministic(self, patched_fetch):
        record = scanner.run_server_scan("https://example.com")
        digest = record["evidence"]
        assert digest["algorithm"] == "sha256"
        assert len(digest["hash"]) == 64
        # Recomputing the canonical digest over the same observation set must
        # produce the same hash.
        canonical = {
            "product": record["product"], "version": record["version"],
            "target": record["target"], "final_url": record["final_url"],
            "timestamp": record["timestamp"], "http_status": record["http_status"],
            "headers": sorted({k.lower(): v for k, v in HARDENED_HEADERS}.items()),
            "redirect_chain": record["redirect_chain"],
        }
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)
        assert hashlib.sha256(blob.encode("utf-8")).hexdigest() == digest["hash"]

    def test_connection_error_raises_scan_error(self, monkeypatch):
        def boom(target_raw, limits=None, **kwargs):
            raise ConnectionFailure("connection refused", url="https://example.com/")

        monkeypatch.setattr(safe_transport, "fetch_validated", boom)
        with pytest.raises(scanner.ScanError) as exc:
            scanner.run_server_scan("https://example.com")
        assert exc.value.code == "CONNECTION_FAILED"

    def test_tls_failure_produces_high_record(self, monkeypatch):
        def boom(target_raw, limits=None, **kwargs):
            raise TLSFailure("certificate verify failed",
                             url="https://example.com/", resolved_ips=["93.184.216.34"])

        monkeypatch.setattr(safe_transport, "fetch_validated", boom)
        record = scanner.run_server_scan("https://example.com")
        assert record["tls"]["verified"] is False
        assert any(c["id"] == "TLS-002" and c["severity"] == "High"
                   for c in record["checks"])
        assert record["score"] == 85  # single High deduction

    def test_private_target_rejection_propagates(self, monkeypatch):
        def boom(target_raw, limits=None, **kwargs):
            raise TargetValidationError("PRIVATE_TARGET_BLOCKED", "loopback")

        monkeypatch.setattr(safe_transport, "fetch_validated", boom)
        with pytest.raises(TargetValidationError):
            scanner.run_server_scan("http://127.0.0.1:9000/")

    def test_body_metadata_recorded(self, patched_fetch):
        resp = sr("https://example.com/", status=200, headers=HARDENED_HEADERS,
                  tls=TLS_OK, body_bytes_read=8192, body_truncated=True)
        patched_fetch["outcome"] = FetchOutcome(
            request_url="https://example.com/", final_url="https://example.com/",
            response=resp,
            redirect_chain=[{"url": "https://example.com/", "status": 200,
                             "location": None, "resolved_ip": "93.184.216.34",
                             "resolved_ips": ["93.184.216.34"], "decision": "final"}])
        record = scanner.run_server_scan("https://example.com")
        assert record["body_bytes_read"] == 8192
        assert record["body_truncated"] is True


class TestDemoScan:
    def test_known_profiles(self):
        for profile in ("demo-mixed", "demo-good", "demo-poor"):
            record = scanner.run_demo_scan(profile, persist=False)
            assert record["mode"] == "demo"
            assert record["checks"]
            assert 0 <= record["score"] <= 100

    def test_demo_scores_follow_model(self):
        for profile in scanner.DEMO_PROFILES:
            record = scanner.run_demo_scan(profile, persist=False)
            assert record["score"] == scoring.compute_score(record["checks"])

    def test_unknown_profile(self):
        with pytest.raises(scanner.ScanError) as exc:
            scanner.run_demo_scan("demo-nope")
        assert exc.value.code == "UNKNOWN_PROFILE"

    def test_demo_no_request_target(self):
        record = scanner.run_demo_scan("demo-mixed", persist=False)
        assert record["target"] == "https://training.example.test"
        assert "authorization_confirmed" not in record  # demo makes no request


class TestBrowserImport:
    def test_import_and_persist(self):
        result = {
            "target": "https://example.com/",
            "http_status": 200,
            "duration_ms": 88,
            "observed": 3,
            "checks": [{"id": "LIVE-001", "severity": "High", "name": "CSP not exposed"}],
        }
        record = scanner.import_browser_result(result)
        assert record["mode"] == "browser"
        assert record["score"] is None
        assert record["grade"] is None
        assert record["score_applicable"] is False
        assert record["checks"][0]["severity"] == "Info"
        assert record["authorization_confirmed"] is True
        assert storage.get_scan(record["id"]) is not None

    def test_severity_sanitized(self):
        result = {"target": "https://example.com/",
                  "checks": [{"id": "LIVE-X", "severity": "bogus"}]}
        record = scanner.import_browser_result(result, persist=False)
        assert record["checks"][0]["severity"] == "Info"

    def test_check_cap(self):
        checks = [{"id": f"LIVE-{i}", "severity": "Info"} for i in range(500)]
        result = {"target": "https://example.com/", "checks": checks}
        record = scanner.import_browser_result(result, persist=False)
        assert len(record["checks"]) == 100  # config.MAX_BROWSER_CHECKS

    def test_missing_target_rejected(self):
        with pytest.raises(scanner.ScanError) as exc:
            scanner.import_browser_result({"checks": []})
        assert exc.value.code == "INVALID_RESULT"

    def test_non_dict_rejected(self):
        with pytest.raises(scanner.ScanError):
            scanner.import_browser_result("nope")
