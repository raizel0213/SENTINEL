"""SENTINEL local API + static frontend server.

Run from the project root:
    python -m backend.app          (recommended)
    python backend/app.py          (also supported)

The same process serves:
    * the frontend (frontend/) as static files
    * the JSON API under /api/*
    * generated reports under /api/scans/<id>/report

v2.3.0 security model:
    * real scans (server + browser modes) require an explicit JSON boolean
      ``authorization: true`` - enforced here, independently of the UI;
    * no CORS headers are emitted and cross-origin API calls are rejected
      (the app is a same-origin, localhost service - remote pages must not
      be able to drive or read it);
    * strict security headers (CSP, XCTO, framing, referrer policy) are set
      on every response;
    * scans are rate limited per client and bounded by a concurrency gate.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from flask import Flask, Response, jsonify, request, send_from_directory

try:
    from . import config, report_generator, scanner, security_checks, storage, target_validation
except ImportError:  # pragma: no cover - direct script execution
    import config
    import report_generator
    import scanner
    import security_checks
    import storage
    import target_validation

STARTED = time.time()
log = logging.getLogger("sentinel")

TARGET_ERROR_STATUS = {
    "PRIVATE_TARGET_BLOCKED": 403,
    "REDIRECT_LOOP": 502,
    "TOO_MANY_REDIRECTS": 502,
    "INVALID_REDIRECT": 400,
    "SCAN_TIMEOUT": 504,
    "TLS_VERIFICATION_FAILED": 502,
}
SCAN_ERROR_STATUS = {
    "CONNECTION_FAILED": 502,
    "UNKNOWN_PROFILE": 400,
    "INVALID_RESULT": 400,
}

# Scan modes that contact a target (directly from this backend, or by the
# user's browser on behalf of this page) require the authorization field.
NETWORK_MODES = {"server", "browser"}


class RateLimiter:
    """Minimal fixed-window per-client limiter (in-memory, single process)."""

    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        self._hits: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        limit = config.RATE_LIMIT_PER_MINUTE
        now = time.monotonic()
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] >= self.window:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


RATE_LIMITER = RateLimiter()
SCAN_GATE = threading.BoundedSemaphore(config.MAX_CONCURRENT_SCANS)


def _error(status: int, code: str, message: str):
    return jsonify({"error": {"code": code, "message": message}}), status


def _authorization_error(body: dict):
    """Enforce the explicit authorization confirmation (backend-side).

    Missing or malformed values are a bad request (400); an explicit
    ``false`` is a refusal (403). Demo mode never reaches this check
    because it performs no request.
    """
    if "authorization" not in body:
        return _error(
            400, "AUTHORIZATION_INVALID",
            "Real scans require an explicit 'authorization' field set to true. "
            "Confirm in the UI that you own the target or have permission to assess it.",
        )
    value = body["authorization"]
    if not isinstance(value, bool):
        return _error(
            400, "AUTHORIZATION_INVALID",
            "'authorization' must be a JSON boolean (true), not a string or number.",
        )
    if value is False:
        return _error(
            403, "AUTHORIZATION_REQUIRED",
            "Scan refused: the authorization confirmation was not given.",
        )
    return None


def _same_origin_guard():
    """Restrict the local service to loopback Host names and same-origin calls.

    Host validation is applied to reads as well as writes: DNS rebinding can
    make a remote-controlled hostname resolve to loopback while the browser
    sends that hostname in Host/Origin. Never treat arbitrary Host values as
    trusted merely because they reached this local process.
    """
    try:
        host = (urlsplit("//" + (request.host or "")).hostname or "").lower().rstrip(".")
        host_port = urlsplit("//" + (request.host or "")).port
    except ValueError:
        return _error(400, "INVALID_HOST", "Malformed Host header.")

    # Only names that resolve as loopback by definition are accepted. Do not
    # add arbitrary hostnames here: doing so reintroduces DNS-rebinding risk.
    allowed_hosts = {"localhost", "127.0.0.1", "::1"}
    configured_host = (config.HOST or "").strip().lower().rstrip(".")
    if configured_host in allowed_hosts:
        allowed_hosts.add(configured_host)

    if host not in allowed_hosts:
        return _error(403, "HOST_NOT_ALLOWED",
                      "SENTINEL only accepts requests addressed to localhost.")

    # On the real server, accept only its configured port. The Flask test
    # client omits the port in Host, so a missing port is allowed for tests
    # and local WSGI setups; an explicitly different port is not.
    if host_port is not None and host_port != config.PORT:
        return _error(403, "HOST_NOT_ALLOWED",
                      "The Host port does not match the configured SENTINEL port.")

    if not request.path.startswith("/api/"):
        return None

    origin = request.headers.get("Origin")
    if not origin:
        return None  # command-line tools and same-origin non-browser clients

    try:
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme not in ("http", "https")
            or not parsed_origin.netloc
            or parsed_origin.username is not None
            or parsed_origin.password is not None
            or parsed_origin.path not in ("", "/")
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("invalid origin")
        origin_host = (parsed_origin.hostname or "").lower().rstrip(".")
        origin_port = parsed_origin.port
    except ValueError:
        return _error(403, "CROSS_ORIGIN_BLOCKED",
                      "Malformed or foreign origins are not accepted.")

    # Compare the normalized origin authority with the request authority.
    # Explicit default ports are normalized so http://localhost:80 and
    # http://localhost are equivalent, while different non-default ports
    # remain distinct.
    request_scheme = request.scheme.lower()
    request_port = host_port or (443 if request_scheme == "https" else 80)
    effective_origin_port = origin_port or (443 if parsed_origin.scheme == "https" else 80)
    if (
        origin_host not in allowed_hosts
        or origin_host != host
        or effective_origin_port != request_port
        or parsed_origin.scheme != request_scheme
    ):
        return _error(
            403, "CROSS_ORIGIN_BLOCKED",
            "This SENTINEL instance only accepts same-origin requests.",
        )
    return None


def create_app() -> Flask:
    # Static files are served through explicit routes below instead of
    # Flask's built-in catch-all static rule: a "/<path>" wildcard would
    # shadow API method errors (GET on POST-only routes returned 404 via the
    # static view) and serve any file under frontend/ that happens to exist.
    app = Flask(config.PRODUCT, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_BODY_BYTES

    app.before_request(_same_origin_guard)

    @app.after_request
    def _security_headers(response: Response) -> Response:
        # No CORS headers are emitted on purpose: this is a same-origin,
        # localhost service. Remote pages must not be able to call it.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", config.APP_CSP)
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.route("/")
    def index():
        return send_from_directory(str(config.FRONTEND_DIR), "index.html")

    @app.get("/css/<path:filename>")
    @app.get("/js/<path:filename>")
    @app.get("/assets/<path:filename>")
    def static_assets(filename: str):
        """Serve the frontend's local assets (path traversal is handled by
        send_from_directory, which refuses anything outside the folder)."""
        kind = request.path.lstrip("/").split("/", 1)[0]
        response = send_from_directory(str(config.FRONTEND_DIR / kind), filename)
        response.headers.setdefault("Cache-Control", "no-cache")
        return response

    # --- system ----------------------------------------------------------

    @app.get("/api/health")
    def health():
        try:
            history_count = storage.count_scans()
        except Exception:  # noqa: BLE001 - health must not fail on storage issues
            history_count = None
        return jsonify({
            "status": "ok",
            "product": config.PRODUCT,
            "version": config.VERSION,
            "checks_registered": len(security_checks.REGISTRY),
            "history_records": history_count,
            "allow_private_targets": config.ALLOW_PRIVATE_TARGETS,
            "rate_limit_per_minute": config.RATE_LIMIT_PER_MINUTE,
            "max_concurrent_scans": config.MAX_CONCURRENT_SCANS,
            "uptime_s": int(time.time() - STARTED),
        })

    @app.get("/api/checks")
    def checks():
        return jsonify({
            "product": config.PRODUCT,
            "version": config.VERSION,
            "count": len(security_checks.REGISTRY),
            "checks": security_checks.registry_metadata(),
        })

    # --- scanning ----------------------------------------------------------

    @app.post("/api/scan")
    def scan():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return _error(400, "INVALID_JSON", "Request body must be a JSON object.")
        mode = str(body.get("mode") or "server").lower()

        # Backend-enforced authorization: independent of any frontend state.
        # Demo mode performs no request and stays available without it.
        if mode in NETWORK_MODES:
            auth_error = _authorization_error(body)
            if auth_error is not None:
                return auth_error

        if not RATE_LIMITER.allow(request.remote_addr or "local"):
            return _error(429, "RATE_LIMITED",
                          "Too many scan requests from this client. Retry in a minute.")

        acquired = SCAN_GATE.acquire(blocking=False)
        if not acquired:
            return _error(503, "SCAN_BUSY",
                          "Another scan is already in progress. Wait for it to finish.")
        try:
            if mode == "server":
                record = scanner.run_server_scan(str(body.get("target") or ""))
            elif mode == "demo":
                record = scanner.run_demo_scan(
                    str(body.get("profile") or "demo-mixed"),
                    persist=bool(body.get("persist", True)),
                )
            elif mode == "browser":
                record = scanner.import_browser_result(body.get("result") or {})
            else:
                return _error(400, "UNKNOWN_MODE",
                              f"Unknown mode '{mode}'. Expected server, demo or browser.")
        except target_validation.TargetValidationError as exc:
            status = TARGET_ERROR_STATUS.get(exc.code, 400)
            return _error(status, exc.code, str(exc))
        except scanner.ScanError as exc:
            status = SCAN_ERROR_STATUS.get(exc.code, 500)
            return _error(status, exc.code, str(exc))
        finally:
            if acquired:
                SCAN_GATE.release()
        return jsonify(record)

    # --- history -----------------------------------------------------------

    @app.get("/api/scans")
    def scans():
        items = storage.list_scans()
        return jsonify({"count": len(items), "items": items})

    @app.get("/api/scans/<scan_id>")
    def scan_detail(scan_id: str):
        record = storage.get_scan(scan_id)
        if record is None:
            return _error(404, "NOT_FOUND", f"No scan record with id '{scan_id}'.")
        return jsonify(record)

    @app.delete("/api/scans/<scan_id>")
    def scan_delete(scan_id: str):
        if not storage.delete_scan(scan_id):
            return _error(404, "NOT_FOUND", f"No scan record with id '{scan_id}'.")
        return jsonify({"deleted": 1, "id": scan_id})

    @app.delete("/api/scans")
    def scans_clear():
        return jsonify({"deleted": storage.clear_scans()})

    # --- reports -----------------------------------------------------------

    @app.get("/api/scans/<scan_id>/report")
    def scan_report(scan_id: str):
        record = storage.get_scan(scan_id)
        if record is None:
            return _error(404, "NOT_FOUND", f"No scan record with id '{scan_id}'.")
        fmt = (request.args.get("format") or "json").lower()
        try:
            content, mimetype, filename = report_generator.generate(record, fmt)
        except ValueError:
            return _error(400, "UNKNOWN_FORMAT",
                          f"Unknown report format '{fmt}'. Expected json, csv, md or html.")
        disposition = "inline" if fmt == "html" else "attachment"
        return Response(
            content,
            mimetype=mimetype,
            headers={"Content-Disposition": f"{disposition}; filename=\"{filename}\""},
        )

    # --- error handling ------------------------------------------------------

    @app.errorhandler(404)
    def not_found(_exc):
        if request.path.startswith("/api/"):
            return _error(404, "NOT_FOUND", "Unknown API endpoint.")
        return Response("Not found\n", mimetype="text/plain"), 404

    @app.errorhandler(405)
    def bad_method(_exc):
        return _error(405, "METHOD_NOT_ALLOWED", "Method not allowed for this endpoint.")

    @app.errorhandler(413)
    def too_large(_exc):
        return _error(413, "PAYLOAD_TOO_LARGE", "Request body exceeds the size limit.")

    @app.errorhandler(400)
    def bad_request(_exc):
        return _error(400, "BAD_REQUEST", "The request could not be parsed.")

    @app.errorhandler(500)
    def server_error(exc):  # pragma: no cover - safety net
        log.exception("Unhandled error: %s", exc)
        return _error(500, "INTERNAL_ERROR", "Unexpected server error.")

    return app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config.ensure_dirs()
    app = create_app()
    print(f"\n  SENTINEL {config.VERSION} \u2014 {config.TAGLINE}")
    print(f"  UI + API:    http://{config.HOST}:{config.PORT}")
    print(f"  History DB:  {config.DB_PATH}")
    guard = "DISABLED (public targets only)" if not config.ALLOW_PRIVATE_TARGETS \
        else "ENABLED (lab mode - private targets allowed)"
    print(f"  SSRF guard:  {guard}")
    print(f"  Scan limits: {config.MAX_REDIRECTS} redirects · {config.SCAN_DEADLINE:g}s budget · "
          f"{config.RATE_LIMIT_PER_MINUTE}/min · {config.MAX_CONCURRENT_SCANS} concurrent")
    print("  Real scans require the authorization confirmation (UI checkbox or "
          "'authorization': true).")
    print("  Scan only targets you own or are authorized to assess.\n")
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
