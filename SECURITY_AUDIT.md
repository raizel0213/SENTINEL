# SENTINEL 2.5.0 — Evidence Accuracy Upgrade

## Summary

This release builds on the existing v2.3.0 transport and local API hardening. It focuses on making the scanner's output more honest and easier to interpret, rather than expanding the scan's intrusiveness.

## Accuracy changes

- Added an explicit `outcome` field distinct from severity: `finding`, `pass`, `informational`, `inconclusive`, `not_tested`, and `not_applicable`.
- Added registry-aware assessment coverage. Missing registry checks count as not tested; not-applicable checks are excluded from the denominator; inconclusive checks reduce coverage.
- Browser-mode imports are unscored and their observations are marked inconclusive for server-side control assessment. Browser coverage is reported as not applicable.
- The CSP weakness check now explicitly reports not applicable when no enforced CSP is available, instead of silently omitting a registry check.
- Cookie-attribute checks no longer report a pass merely because no cookie was observed on a single response.
- Referrer-Policy evaluation recognizes valid comma-separated fallback policies and does not label every unknown value as a browser default.
- Permissions-Policy, X-Frame-Options, and COOP checks now flag some obviously malformed or unrecognized values instead of passing solely because a header exists.
- HSTS evaluation flags duplicate `max-age` directives.
- The dashboard's headline metric now counts potential findings rather than every record; reports include outcome and coverage information.

## Existing protections retained

- Local API Host/Origin validation
- Manual redirect validation and pinned transport protections
- CSV spreadsheet formula-injection mitigation
- HTML documentation-link scheme validation and output escaping
- Authorization confirmation and private-target restrictions

## Validation performed

- Python compilation: passed for backend and tests.
- JavaScript syntax checks: passed for all frontend JavaScript files using Node.js.
- Selected pure tests: **95 passed** across scoring, security-check logic, and report generation using a temporary test fixture.
- Targeted integration smoke tests: passed for 18 registry checks, coverage calculation, all four report formats, and unscored/inconclusive browser imports.
- Complete application test suite: **not run successfully in this environment** because Flask is unavailable and package downloads are blocked. Run `python -m pip install -r backend/requirements-dev.txt` and `python -m pytest tests/ -q` in the project's normal environment before relying on this release for live assessments.

## Known limitations

- Permissions-Policy validation is a lightweight syntax sanity check, not a complete standards parser.
- Scoring remains an educational severity-deduction heuristic; coverage is shown separately and the score is not a certification or quantitative risk measure.
- A passive single-response review cannot assess all routes, application logic, access controls, or exploitability.
