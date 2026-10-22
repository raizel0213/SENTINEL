"""Tests for the security check registry (synthetic response contexts)."""
from __future__ import annotations

import pytest

from backend import security_checks as sc
from backend.security_checks import ScanContext, parse_set_cookie, run_all_checks


def ctx(**overrides) -> ScanContext:
    base = dict(
        target_url="https://example.com/",
        final_url="https://example.com/",
        scheme="https",
        status_code=200,
        headers={},
        set_cookies=[],
        cookies=[],
        redirect_chain=[{"url": "https://example.com/", "status": 200, "location": None}],
        tls={"verified": True, "cert_error": None, "not_after": "2027-01-01", "days_left": 300},
        duration_ms=50,
    )
    base.update(overrides)
    return ScanContext(**base)


def by_id(findings, cid):
    return next(f for f in findings if f["id"] == cid)


class TestRegistry:
    def test_eighteen_checks_registered(self):
        assert len(sc.REGISTRY) == 18

    def test_unique_ids(self):
        ids = [c.id for c in sc.REGISTRY]
        assert len(ids) == len(set(ids))

    def test_finding_shape(self):
        required = {"id", "severity", "name", "header", "status",
                    "evidence", "description", "impact", "fix", "docs"}
        findings = run_all_checks(ctx())
        assert findings, "a default context must produce findings"
        for finding in findings:
            assert required.issubset(finding.keys())

    def test_metadata(self):
        meta = sc.registry_metadata()
        assert len(meta) == len(sc.REGISTRY)
        assert {"id", "name", "category", "description"} == set(meta[0].keys())


class TestCsp:
    def test_missing_is_high(self):
        finding = by_id(run_all_checks(ctx()), "HDR-001")
        assert finding["severity"] == "High"

    def test_present_is_pass(self):
        finding = by_id(run_all_checks(
            ctx(headers={"Content-Security-Policy": "default-src 'self'"})), "HDR-001")
        assert finding["severity"] == "Pass"

    def test_report_only_is_medium(self):
        finding = by_id(run_all_checks(
            ctx(headers={"Content-Security-Policy-Report-Only": "default-src 'self'"})), "HDR-001")
        assert finding["severity"] == "Medium"

    def test_unsafe_inline_is_medium(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline'"})), "HDR-002")
        assert finding["severity"] == "Medium"

    def test_wildcard_script_is_medium(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Content-Security-Policy": "script-src *"})), "HDR-002")
        assert finding["severity"] == "Medium"

    def test_missing_base_uri_is_low(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Content-Security-Policy": "default-src 'self'"})), "HDR-002")
        assert finding["severity"] == "Low"

    def test_strict_policy_passes_weakness_check(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Content-Security-Policy":
                "default-src 'self'; object-src 'none'; base-uri 'self'"})), "HDR-002")
        assert finding["severity"] == "Pass"


class TestHsts:
    def test_missing_on_https_is_medium(self):
        finding = by_id(run_all_checks(ctx()), "HDR-003")
        assert finding["severity"] == "Medium"

    def test_not_applicable_on_http(self):
        finding = by_id(run_all_checks(ctx(scheme="http")), "HDR-003")
        assert finding["severity"] == "Info"

    def test_short_max_age_is_low(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Strict-Transport-Security": "max-age=86400"})), "HDR-003")
        assert finding["severity"] == "Low"

    def test_full_policy_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"})), "HDR-003")
        assert finding["severity"] == "Pass"


class TestHeaderControls:
    def test_xcto_missing_is_low(self):
        assert by_id(run_all_checks(ctx()), "HDR-004")["severity"] == "Low"

    def test_xcto_nosniff_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "X-Content-Type-Options": "nosniff"})), "HDR-004")
        assert finding["severity"] == "Pass"

    def test_xcto_wrong_value_is_low(self):
        finding = by_id(run_all_checks(ctx(headers={
            "X-Content-Type-Options": "nonsniff"})), "HDR-004")
        assert finding["severity"] == "Low"

    def test_no_framing_defense_is_medium(self):
        assert by_id(run_all_checks(ctx()), "HDR-005")["severity"] == "Medium"

    def test_xfo_sameorigin_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "X-Frame-Options": "SAMEORIGIN"})), "HDR-005")
        assert finding["severity"] == "Pass"

    def test_frame_ancestors_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Content-Security-Policy": "frame-ancestors 'none'"})), "HDR-005")
        assert finding["severity"] == "Pass"

    def test_referrer_missing_is_low(self):
        assert by_id(run_all_checks(ctx()), "HDR-006")["severity"] == "Low"

    def test_referrer_unsafe_url_is_medium(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Referrer-Policy": "unsafe-url"})), "HDR-006")
        assert finding["severity"] == "Medium"

    def test_referrer_strict_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Referrer-Policy": "strict-origin-when-cross-origin"})), "HDR-006")
        assert finding["severity"] == "Pass"

    def test_permissions_policy_missing_is_low(self):
        assert by_id(run_all_checks(ctx()), "HDR-007")["severity"] == "Low"

    def test_permissions_policy_present_is_pass(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Permissions-Policy": "camera=()"})), "HDR-007")
        assert finding["severity"] == "Pass"

    def test_server_version_is_low(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Server": "nginx/1.24.0"})), "HDR-008")
        assert finding["severity"] == "Low"

    def test_server_generic_is_info(self):
        finding = by_id(run_all_checks(ctx(headers={
            "Server": "nginx"})), "HDR-008")
        assert finding["severity"] == "Info"

    def test_x_powered_by_is_low(self):
        finding = by_id(run_all_checks(ctx(headers={
            "X-Powered-By": "Express"})), "HDR-009")
        assert finding["severity"] == "Low"

    def test_xss_protection_is_info(self):
        finding = by_id(run_all_checks(ctx(headers={
            "X-XSS-Protection": "1; mode=block"})), "HDR-010")
        assert finding["severity"] == "Info"

    def test_cache_control_missing_is_info(self):
        assert by_id(run_all_checks(ctx()), "HDR-011")["severity"] == "Info"

    def test_coop_missing_is_info(self):
        assert by_id(run_all_checks(ctx()), "HDR-012")["severity"] == "Info"


class TestCookies:
    def cookies_ctx(self, *set_cookies):
        cookies = [parse_set_cookie(raw) for raw in set_cookies]
        return ctx(set_cookies=list(set_cookies), cookies=cookies)

    def test_no_cookies_is_not_applicable_not_a_pass(self):
        finding = by_id(run_all_checks(ctx()), "COOKIE-001")
        assert finding["severity"] == "Info"
        assert finding["outcome"] == "not_applicable"

    def test_missing_secure_is_medium(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "sid=redacted; Path=/; HttpOnly")), "COOKIE-001")
        assert finding["severity"] == "Medium"
        assert "sid" in finding["evidence"]

    def test_secure_flag_pass(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "sid=redacted; Path=/; Secure; HttpOnly; SameSite=Lax")), "COOKIE-001")
        assert finding["severity"] == "Pass"

    def test_session_cookie_without_httponly_is_medium(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "sessionid=redacted; Path=/; Secure")), "COOKIE-002")
        assert finding["severity"] == "Medium"

    def test_nonsession_cookie_without_httponly_is_low(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "theme=dark; Path=/; Secure")), "COOKIE-002")
        assert finding["severity"] == "Low"

    def test_missing_samesite_is_low(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "sid=redacted; Path=/; Secure; HttpOnly")), "COOKIE-003")
        assert finding["severity"] == "Low"

    def test_cookie_values_never_recorded(self):
        finding = by_id(run_all_checks(self.cookies_ctx(
            "sid=SECRETVALUE123; Path=/; Secure")), "COOKIE-001")
        assert "SECRETVALUE123" not in finding["evidence"]


class TestTls:
    def test_https_is_pass(self):
        assert by_id(run_all_checks(ctx()), "TLS-001")["severity"] == "Pass"

    def test_http_is_high(self):
        finding = by_id(run_all_checks(ctx(scheme="http",
            final_url="http://example.com/")), "TLS-001")
        assert finding["severity"] == "High"

    def test_http_to_https_upgrade_noted(self):
        context = ctx(redirect_chain=[
            {"url": "http://example.com/", "status": 301, "location": "https://example.com/"},
            {"url": "https://example.com/", "status": 200, "location": None},
        ])
        finding = by_id(run_all_checks(context), "TLS-001")
        assert "redirect" in finding["evidence"].lower()

    def test_verified_cert_is_pass(self):
        assert by_id(run_all_checks(ctx()), "TLS-002")["severity"] == "Pass"

    def test_failed_verification_is_high(self):
        context = ctx(tls={"verified": False, "cert_error": "self signed certificate",
                           "not_after": None, "days_left": None})
        assert by_id(run_all_checks(context), "TLS-002")["severity"] == "High"

    def test_expiry_healthy_is_pass(self):
        assert by_id(run_all_checks(ctx()), "TLS-003")["severity"] == "Pass"

    def test_expiry_imminent_is_medium(self):
        context = ctx(tls={"verified": True, "cert_error": None,
                           "not_after": "2026-02-01", "days_left": 10})
        assert by_id(run_all_checks(context), "TLS-003")["severity"] == "Medium"

    def test_expiry_unknown_skips(self):
        context = ctx(tls={"verified": True, "cert_error": "metadata unavailable",
                           "not_after": None, "days_left": None})
        with pytest.raises(StopIteration):
            by_id(run_all_checks(context), "TLS-003")


class TestParseSetCookie:
    def test_flags(self):
        parsed = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
        assert parsed["name"] == "sid"
        assert parsed["secure"] is True
        assert parsed["httponly"] is True
        assert parsed["samesite"] == "Strict"
        assert parsed["session_like"] is True

    def test_plain_cookie(self):
        parsed = parse_set_cookie("theme=dark; Path=/")
        assert parsed["secure"] is False
        assert parsed["httponly"] is False
        assert parsed["samesite"] is None
        assert parsed["session_like"] is False


def test_csp_weakness_check_is_explicitly_not_applicable_when_csp_missing():
    finding = by_id(run_all_checks(ctx()), "HDR-002")
    assert finding["outcome"] == "not_applicable"
    assert finding["severity"] == "Info"


def test_unrecognized_referrer_policy_is_not_misreported_as_browser_default():
    finding = by_id(run_all_checks(ctx(headers={"Referrer-Policy": "made-up-policy"})), "HDR-006")
    assert finding["status"] == "Invalid"
    assert finding["outcome"] == "informational"


def test_referrer_policy_uses_last_recognized_token():
    finding = by_id(run_all_checks(ctx(headers={"Referrer-Policy": "unsafe-url, strict-origin-when-cross-origin"})), "HDR-006")
    assert finding["severity"] == "Pass"
    assert "strict-origin-when-cross-origin" in finding["evidence"]


def test_malformed_permissions_policy_is_not_passed_solely_for_presence():
    finding = by_id(run_all_checks(ctx(headers={"Permissions-Policy": "camera"})), "HDR-007")
    assert finding["status"] == "Invalid"
    assert finding["severity"] == "Low"


def test_invalid_x_frame_options_value_is_not_reported_as_absent():
    finding = by_id(run_all_checks(ctx(headers={"X-Frame-Options": "ALLOW-ALL"})), "HDR-005")
    assert finding["status"] == "Invalid"
    assert "header is present" in finding["description"]

def test_invalid_coop_value_is_not_passed_just_for_presence():
    finding = by_id(run_all_checks(ctx(headers={"Cross-Origin-Opener-Policy": "allow-everything"})), "HDR-012")
    assert finding["status"] == "Invalid"
    assert finding["severity"] == "Info"

def test_unsafe_none_coop_is_observation_not_pass():
    finding = by_id(run_all_checks(ctx(headers={"Cross-Origin-Opener-Policy": "unsafe-none"})), "HDR-012")
    assert finding["severity"] == "Info"
    assert finding["outcome"] == "informational"

def test_duplicate_hsts_max_age_is_flagged_as_invalid():
    finding = by_id(run_all_checks(ctx(headers={"Strict-Transport-Security": "max-age=31536000; max-age=10"})), "HDR-003")
    assert finding["status"] == "Invalid"
