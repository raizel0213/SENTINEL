"""SENTINEL educational scoring model.

The contract is inherited from SENTINEL 1.x so methodology stays comparable:

    score = clamp(100 - SUM(penalty(severity)), 0, 100)

    penalties:  Critical 25 | High 15 | Medium 8 | Low 3 | Info 0 | Pass 0

The score is a learning and review aid, NOT an industry rating or a
certification. See docs/METHODOLOGY.md for the full rationale.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

WEIGHTS: Dict[str, int] = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Info": 0,
    "Pass": 0,
}

ORDER: List[str] = ["Critical", "High", "Medium", "Low", "Info", "Pass"]

GRADE_BANDS = ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F"))

SCORING_MODEL_TEXT = (
    "Starts at 100 and deducts 25 per Critical, 15 per High, 8 per Medium and "
    "3 per Low finding; Info and Pass records deduct nothing. The result is "
    "clamped to 0-100. This is an educational heuristic, not a certification."
)


def severity_rank(severity: str) -> int:
    """Sort position for a severity label (Critical first, Pass last)."""
    label = str(severity or "Info")
    return ORDER.index(label) if label in ORDER else len(ORDER)


def compute_score(checks: Iterable[dict]) -> int:
    """Apply the deduction model and clamp the result to 0-100."""
    total = 0
    for check in checks:
        # New records carry an explicit outcome. Only a confirmed rule-based
        # potential finding should affect the heuristic score; an inconclusive
        # or not-applicable check must not create a penalty just because a
        # severity label was attached during error handling. Legacy records
        # without outcome retain the historical severity-based behavior.
        outcome = check.get("outcome")
        if outcome is not None and str(outcome).lower() != "finding":
            continue
        total += WEIGHTS.get(str(check.get("severity", "Info")), 0)
    return max(0, min(100, 100 - total))


def grade_for(score: int) -> str:
    """Map a 0-100 score onto an educational letter grade."""
    for floor, grade in GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def counts_for(checks: Iterable[dict]) -> Dict[str, int]:
    """Return both the legacy severity histogram and explicit outcome counts."""
    out = {
        "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
        "info": 0, "pass": 0, "findings": 0, "passes": 0,
        "informational": 0, "inconclusive": 0, "not_tested": 0,
        "not_applicable": 0,
    }
    for check in checks:
        out["total"] += 1
        severity = str(check.get("severity", "Info")).lower()
        if severity in out and severity not in {"findings", "passes", "informational", "inconclusive", "not_tested", "not_applicable"}:
            out[severity] += 1
        outcome = str(check.get("outcome") or "").lower()
        if outcome not in {"finding", "pass", "informational", "inconclusive", "not_tested", "not_applicable"}:
            # Compatibility for legacy records created before outcome was added.
            if severity == "pass":
                outcome = "pass"
            elif severity in {"critical", "high", "medium", "low"}:
                outcome = "finding"
            else:
                outcome = "informational"
        if outcome == "finding":
            out["findings"] += 1
        elif outcome == "pass":
            out["passes"] += 1
        else:
            out[outcome] += 1
    return out


def assessment_summary(checks: Iterable[dict], registered_checks: int | None = None) -> Dict[str, int | None]:
    """Summarize coverage without treating inapplicable checks as passes.

    When a registry size is supplied, omitted registry checks count as not
    tested. Coverage is the share of applicable registry checks with a
    conclusive evaluation (finding, pass, or informational observation).
    Inconclusive and unreturned checks lower coverage; not-applicable checks
    are excluded from the denominator.
    """
    materialized = list(checks)
    counts = counts_for(materialized)
    registry_size = max(0, int(registered_checks)) if registered_checks is not None else counts["total"]
    missing_from_result = max(0, registry_size - counts["total"])
    not_tested = counts["not_tested"] + missing_from_result
    applicable = max(0, registry_size - counts["not_applicable"])
    conclusive = counts["findings"] + counts["passes"] + counts["informational"]
    coverage = min(100, round((conclusive / applicable) * 100)) if applicable > 0 else None
    return {
        "checks_registered": registered_checks,
        "checks_returned": counts["total"],
        "applicable_checks": applicable,
        "conclusive_checks": conclusive,
        "coverage_percent": coverage,
        "findings": counts["findings"],
        "passes": counts["passes"],
        "informational": counts["informational"],
        "inconclusive": counts["inconclusive"],
        "not_tested": not_tested,
        "not_applicable": counts["not_applicable"],
    }
