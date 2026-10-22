# SENTINEL 2.5.0 — Submission Checklist

Use this checklist immediately before submission.

- [ ] Extract the project ZIP into a clean directory.
- [ ] Create a virtual environment and install `backend/requirements-dev.txt`.
- [ ] Run `python -m pytest tests/ -v`; resolve failures before describing tests as passing.
- [ ] Start the app with `python -m backend.app` and open `http://127.0.0.1:5050`.
- [ ] Run a Demo profile to demonstrate the dashboard without contacting an external target.
- [ ] Export at least one report and verify it opens.
- [ ] If demonstrating a live scan, use only a target you own or have explicit permission to assess.
- [ ] Review `docs/BOOTCAMP_SUBMISSION.md`, `docs/METHODOLOGY.md`, and `docs/SECURITY.md`.
- [ ] Be ready to explain one finding, the score model, coverage, and the main limitations.
- [ ] Do not claim a complete test pass unless the full suite actually passes on your machine.
