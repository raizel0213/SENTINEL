# SENTINEL 2.5.0 — Validation Report

**Purpose:** This report separates checks executed during packaging from checks that require the project's runtime dependencies. It must not be read as a claim that the full application suite passed.

## Packaging-environment checks

| Validation | Result | Notes |
| --- | --- | --- |
| Python compilation | Passed | `python -m compileall -q backend tests` |
| JavaScript syntax | Passed | `node --check` over each file in `frontend/js/` |
| Selected pure tests | 41 passed | Scoring and report-generator tests were copied to an isolated temporary test directory with a minimal fixture to avoid importing the Flask-dependent project `conftest.py`; this is not the full suite |
| Registry/demo/report smoke checks | Passed | 18 registry entries; demo-mixed score matched scoring function; JSON, CSV, Markdown, and HTML reports generated |
| Full pytest suite | Not completed in this packaging environment | Flask is not installed and package installation could not reach the package index |
| Live server / browser UI | Not verified here | Requires Flask and an interactive browser |
| External target scan | Not performed as part of packaging | Use only a target you own or have explicit permission to assess |

## Required local verification before final evaluation

Run these commands from the extracted `SENTINEL` directory in a Python 3.10+ environment with package installation available:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements-dev.txt
python -m compileall -q backend tests
python -m pytest tests/ -v
python -m backend.app
```

Then open `http://127.0.0.1:5050`, run a Demo profile, inspect one finding, and export a report. Do not describe the complete suite as passing unless the command finishes successfully and the result is reviewed.

## Design-level validation notes

- The suite contains unit tests for scoring and security checks, transport/redirect tests, target-validation tests, API and authorization tests, report tests, and frontend asset checks.
- Real scans require an explicit authorization confirmation and are constrained by URL/port and destination-IP policy.
- Demo profiles are canned training records and do not make network requests.
- Scoring is an educational heuristic. Explicit `inconclusive` and `not_applicable` outcomes are excluded from score deductions; legacy records without an outcome preserve the legacy severity-based behavior.
- A single-response scan cannot establish exploitability or represent every route, user role, or infrastructure node.

## Transparency statement

Static checks and selected pure tests can catch syntax, scoring, and report-generation issues but do not prove runtime correctness or the absence of security defects. The instructor demonstration and full local test run are the final verification steps before relying on this build.
