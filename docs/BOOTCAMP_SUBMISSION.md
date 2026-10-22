# SENTINEL — Bootcamp Project Submission

**Release:** 2.5.0  
**Project type:** Python / Flask cybersecurity application  
**Category:** Passive web security configuration assessment and evidence reporting

## 1. Project overview

SENTINEL is a local web application that performs a bounded, passive review of observable HTTP security configuration. It evaluates selected response headers, cookie attributes, HTTPS usage, and basic TLS certificate status. Each check produces a result with an outcome and supporting evidence; the application summarizes findings and exports reports for review.

The goal is to help a learner or junior analyst understand what a single HTTP response reveals about security configuration, how to record evidence, and how to communicate remediation steps. SENTINEL is not intended to replace a full vulnerability assessment, penetration test, or compliance audit.

## 2. Problem statement

Web security headers and transport settings are often discussed individually, while beginner assessments may lack a repeatable way to capture observations, separate evidence from assumptions, and communicate remediation. SENTINEL packages a limited set of checks into a repeatable workflow with local history and exportable results.

## 3. Objectives

- Inspect a target's observable HTTP security configuration with a single bounded request.
- Evaluate a defined registry of 18 checks across headers, cookies, and transport/TLS metadata.
- Distinguish potential findings, passes, informational observations, inconclusive checks, skipped checks, and not-applicable checks.
- Explain each potential finding and suggest a remediation.
- Preserve local scan history and export JSON, CSV, Markdown, or printable HTML reports.
- Apply basic safety controls: explicit authorization confirmation, URL/port validation, private-address protections, redirect validation, rate limits, and a loopback-only local API.

## 4. Technology stack

- **Python 3.10+** — scanner logic, validation, scoring, evidence/report generation, and persistence.
- **Flask 3+** — local HTTP API and static frontend serving.
- **Vanilla JavaScript, HTML, CSS** — dashboard and client interactions; no frontend build step.
- **SQLite** — local scan history.
- **pytest** — automated unit, API, transport, authorization, and asset tests.

## 5. Architecture and workflow

1. The operator starts the local application and opens the dashboard.
2. For a real scan, the operator confirms they own the target or have permission to assess it.
3. The backend validates the URL, scheme, port, DNS result, and destination policy.
4. The transport follows redirects manually and revalidates each destination before connecting.
5. The scanner captures the final response's observable headers, cookie attributes, and basic TLS metadata.
6. The check registry evaluates the evidence; the scoring module calculates an educational heuristic score for supported server/demo results.
7. The application stores the record locally and can export the findings and supporting evidence.

## 6. How to run the demonstration

From the extracted `SENTINEL` directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements-dev.txt
python -m backend.app
```

Open `http://127.0.0.1:5050` in a browser. If you only want to demonstrate the interface and report workflow, choose a **Demo** profile; demo profiles do not make network requests. For a live assessment, use only a site you own or have explicit permission to assess, leave private-target protections enabled unless conducting a controlled local lab, and confirm authorization in the interface.

Run automated tests in the same environment:

```bash
python -m pytest tests/ -v
```

## 7. Demonstration plan (about 5 minutes)

1. **Introduce the scope (30 seconds):** explain that SENTINEL is a passive, single-response configuration checker, not an exploit tool.
2. **Show the dashboard (45 seconds):** point out execution modes, potential findings, coverage, and the distinction between findings and other records.
3. **Run a demo profile (45 seconds):** use it to show the UI without sending traffic to an external target.
4. **Inspect a finding (60 seconds):** explain the observed evidence, impact, severity, and suggested fix. Clarify that a missing header is not proof of exploitability.
5. **Show the report (45 seconds):** export a report and describe how evidence is retained for review.
6. **Explain safety controls and limitations (60 seconds):** discuss authorization confirmation, private-address protections, redirect checks, and the limits of a single request.

## 8. Scoring methodology

For compatibility with earlier versions, the score starts at 100 and deducts 25 for each Critical, 15 for each High, 8 for each Medium, and 3 for each Low result, clamped to 0–100. Informational and Pass records have no deduction. The score is a teaching heuristic; it is not a validated risk metric, industry rating, or certification. Review individual evidence and coverage instead of interpreting the score alone.

## 9. Security and responsible-use controls

- Real scans require explicit authorization confirmation in both UI and API.
- The default target policy blocks private/loopback and other disallowed destinations; redirect destinations are revalidated.
- The local API is designed for loopback use and rejects foreign Host/Origin contexts.
- Rate and concurrency limits bound scan load.
- Reports neutralize spreadsheet-formula-like CSV cells and escape report content.
- Cookie values are not intentionally retained; cookie checks use names and attributes.

These controls reduce risk but do not guarantee the application is free of defects. The built-in Flask server is for local educational use and should not be exposed publicly.

## 10. Limitations and future work

- One request and the final response do not represent every route, role, method, or infrastructure node on a website.
- Browser mode is CORS-limited and therefore unscored for server-side configuration.
- Permissions-Policy validation is a lightweight sanity check, not a complete standards parser.
- TLS checks do not audit cipher suites, protocol versions, or the complete server TLS configuration.
- The scoring model is heuristic and should not be treated as quantitative risk.
- Future work could add repeatable fixture-based integration tests, broader standards-aware policy parsing, and multi-route assessment with explicit safe scope controls.

## 11. What I learned / skills demonstrated

This project demonstrates practical work across Python application development, HTTP and TLS concepts, security-header evaluation, input validation, redirect and destination controls, evidence handling, local persistence, report generation, frontend/backend integration, automated testing, and communicating limitations responsibly.

## 12. Suggested oral-review questions

- Why is a missing security header a potential weakness rather than proof of a vulnerability?
- Why does browser mode not receive the same score as server mode?
- Why must each redirect destination be validated before the next connection?
- What does the evidence digest establish, and what does it not establish?
- Why are cookie values excluded from reports?
- Why is the score called an educational heuristic?
- What would need to change to assess multiple routes or application logic safely?

## 13. Submission integrity note

Before submitting, run the full test suite on a machine with the dependencies installed, review the project files, and ensure you can explain the implementation and demonstrate it yourself. The validation report documents what was checked in the packaging environment and what remains unverified.
