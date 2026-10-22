"""SENTINEL backend package.

Modules:
    app               Flask application (API + static frontend server)
    scanner           Scan orchestration (server scan, demo profiles, browser import)
    security_checks   Registry of passive HTTP security-configuration checks
    scoring           Educational scoring model
    report_generator  JSON / CSV / Markdown / printable-HTML reports
    target_validation URL validation and SSRF guard rails
    storage           SQLite scan-history persistence
    config            Runtime configuration (env-overridable)
"""

__all__ = [
    "app",
    "scanner",
    "security_checks",
    "scoring",
    "report_generator",
    "target_validation",
    "storage",
    "config",
]
