# SENTINEL — Short Instructor Demo

**Length:** 4–6 minutes. Use a demo profile if time or network permissions are limited.

### Opening (30 seconds)
"SENTINEL is a local, passive web security configuration scanner. It records observable evidence from a bounded HTTP response and offers remediation guidance. It does not exploit targets or prove exploitability."

### Demonstrate (2–3 minutes)
1. Open the dashboard and point out the selected execution mode and authorization notice.
2. Run a Demo profile for a safe, repeatable walkthrough.
3. Select a finding and read its evidence, impact, and recommended fix.
4. Explain how findings differ from Pass, Info, Inconclusive, and Not applicable outcomes.
5. Export a report and show that the report can be used for review or remediation tracking.

### Explain engineering decisions (1–2 minutes)
- Real scans require explicit authorization confirmation.
- Redirect destinations are validated separately; a safe initial URL does not make every redirect safe.
- Browser-mode observations are CORS-filtered, so they cannot reliably prove that server headers are absent.
- Cookie values are not needed for attribute checks and should not be included in evidence.
- The score is a documented educational heuristic, not a certification or quantitative risk measure.

### Close (30 seconds)
"The main limitation is scope: this is a single-response configuration review. It does not crawl every route, test application logic, or replace a full security assessment."
