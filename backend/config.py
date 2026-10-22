"""SENTINEL runtime configuration.

Every tunable lives here and can be overridden with environment variables so
the same code works on a laptop, in a lab, or in CI.

Environment variables:
    SENTINEL_HOST                bind address (default 127.0.0.1)
    SENTINEL_PORT                bind port (default 5050)
    SENTINEL_ALLOW_PRIVATE       "1"/"true" to permit scanning private/loopback
                                 hosts (lab mode) - see target_validation.py
    SENTINEL_DB                  path to the SQLite history database
    SENTINEL_MAX_HISTORY         maximum stored scan records (default 200)
    SENTINEL_CONNECT_TIMEOUT     TCP connect timeout in seconds (default 5)
    SENTINEL_READ_TIMEOUT        socket read timeout in seconds (default 10)
    SENTINEL_DNS_TIMEOUT         DNS resolution timeout in seconds (default 5)
    SENTINEL_MAX_REDIRECTS       redirect hops followed per scan (default 5)
    SENTINEL_SCAN_DEADLINE       overall per-scan budget in seconds (default 60)
    SENTINEL_MAX_RESPONSE_BYTES  response bytes consumed before closing (default 65536)
    SENTINEL_ALLOWED_PORTS       comma-separated port allowlist (default 80,443,8080,8443)
    SENTINEL_MAX_CONCURRENT      concurrent scans (default 2; extras get 503)
    SENTINEL_RATE_LIMIT          scans per minute per client (default 12)
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = BASE_DIR / "data"

PRODUCT = "SENTINEL"
VERSION = "2.5.0"
TAGLINE = "Automated Web Security Scanner & Evidence Workstation"

# --- Server -------------------------------------------------------------
HOST = os.environ.get("SENTINEL_HOST", "127.0.0.1")
PORT = int(os.environ.get("SENTINEL_PORT", "5050"))

# --- Scanner behaviour ---------------------------------------------------
# Guard rail: by default the scanner refuses to request private, loopback,
# link-local, reserved or otherwise non-public hosts (SSRF protection).
# Set SENTINEL_ALLOW_PRIVATE=1 to scan your own lab targets (e.g. localhost).
ALLOW_PRIVATE_TARGETS = os.environ.get("SENTINEL_ALLOW_PRIVATE", "").strip().lower() in {
    "1", "true", "yes", "on",
}

CONNECT_TIMEOUT = float(os.environ.get("SENTINEL_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT = float(os.environ.get("SENTINEL_READ_TIMEOUT", "10"))
DNS_TIMEOUT = float(os.environ.get("SENTINEL_DNS_TIMEOUT", "5"))
MAX_REDIRECTS = int(os.environ.get("SENTINEL_MAX_REDIRECTS", "5"))
SCAN_DEADLINE = float(os.environ.get("SENTINEL_SCAN_DEADLINE", "60"))
MAX_RESPONSE_BYTES = int(os.environ.get("SENTINEL_MAX_RESPONSE_BYTES", "65536"))

ALLOWED_PORTS = frozenset(
    int(p) for p in
    os.environ.get("SENTINEL_ALLOWED_PORTS", "80,443,8080,8443").split(",")
    if p.strip().isdigit()
) or frozenset({80, 443, 8080, 8443})

MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("SENTINEL_MAX_CONCURRENT", "2")))
RATE_LIMIT_PER_MINUTE = max(1, int(os.environ.get("SENTINEL_RATE_LIMIT", "12")))

USER_AGENT = (
    f"{PRODUCT}/{VERSION} (+educational security-header scanner; "
    "local use only; scan only authorized targets)"
)

# Content-Security-Policy for the UI served by this app (strict, self-only).
APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)

# --- History -------------------------------------------------------------
MAX_HISTORY = int(os.environ.get("SENTINEL_MAX_HISTORY", "200"))
DB_PATH = Path(os.environ.get("SENTINEL_DB", str(DATA_DIR / "sentinel.db")))

# --- API limits ----------------------------------------------------------
MAX_BODY_BYTES = 1_000_000
MAX_BROWSER_CHECKS = 100          # max findings accepted in browser-mode imports
MAX_STRING_LENGTH = 8_000         # max characters kept per imported field


def ensure_dirs() -> None:
    """Create runtime directories (data dir for the SQLite database)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
