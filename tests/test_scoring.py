"""Tests for the educational scoring model."""
from __future__ import annotations

from backend import scoring


def check(severity: str) -> dict:
    return {"severity": severity}


class TestComputeScore:
    def test_perfect_score(self):
        assert scoring.compute_score([]) == 100

    def test_high_deducts_15(self):
        assert scoring.compute_score([check("High")]) == 85

    def test_medium_deducts_8(self):
        assert scoring.compute_score([check("Medium")]) == 92

    def test_low_deducts_3(self):
        assert scoring.compute_score([check("Low")]) == 97

    def test_info_and_pass_free(self):
        assert scoring.compute_score([check("Info"), check("Pass")]) == 100

    def test_critical_deducts_25(self):
        assert scoring.compute_score([check("Critical")]) == 75

    def test_demo_mixed_maths(self):
        # demo-mixed: High + Medium + Low + Pass
        assert scoring.compute_score([check("High"), check("Medium"), check("Low"), check("Pass")]) == 74

    def test_clamped_at_zero(self):
        checks = [check("Critical")] * 5
        assert scoring.compute_score(checks) == 0

    def test_unknown_severity_treated_as_info(self):
        assert scoring.compute_score([check("Bogus")]) == 100

    def test_inconclusive_high_does_not_deduct(self):
        assert scoring.compute_score([{"severity": "High", "outcome": "inconclusive"}]) == 100

    def test_not_applicable_high_does_not_deduct(self):
        assert scoring.compute_score([{"severity": "High", "outcome": "not_applicable"}]) == 100

    def test_explicit_finding_deducts(self):
        assert scoring.compute_score([{"severity": "High", "outcome": "finding"}]) == 85


class TestGrades:
    def test_band_edges(self):
        assert scoring.grade_for(100) == "A+"
        assert scoring.grade_for(95) == "A+"
        assert scoring.grade_for(94) == "A"
        assert scoring.grade_for(85) == "A"
        assert scoring.grade_for(84) == "B"
        assert scoring.grade_for(70) == "B"
        assert scoring.grade_for(55) == "C"
        assert scoring.grade_for(40) == "D"
        assert scoring.grade_for(39) == "F"
        assert scoring.grade_for(0) == "F"


class TestCounts:
    def test_histogram(self):
        counts = scoring.counts_for([check("High"), check("High"), check("Low"), check("Pass")])
        assert counts["total"] == 4
        assert counts["high"] == 2
        assert counts["low"] == 1
        assert counts["pass"] == 1
        assert counts["medium"] == 0

    def test_empty(self):
        assert scoring.counts_for([])["total"] == 0


class TestSeverityRank:
    def test_ordering(self):
        ranks = [scoring.severity_rank(s) for s in
                 ["Pass", "Info", "Low", "Medium", "High", "Critical"]]
        assert ranks == sorted(ranks, reverse=True)


class TestAssessmentSummary:
    def test_counts_outcomes_separately_from_severity(self):
        checks = [
            {"severity": "High", "outcome": "finding"},
            {"severity": "Pass", "outcome": "pass"},
            {"severity": "Info", "outcome": "not_applicable"},
            {"severity": "Info", "outcome": "inconclusive"},
        ]
        summary = scoring.assessment_summary(checks, registered_checks=4)
        assert summary["checks_registered"] == 4
        assert summary["findings"] == 1
        assert summary["passes"] == 1
        assert summary["not_applicable"] == 1
        assert summary["inconclusive"] == 1
        assert summary["coverage_percent"] == 67

    def test_empty_assessment_has_no_coverage(self):
        summary = scoring.assessment_summary([], registered_checks=18)
        assert summary["coverage_percent"] == 0
        assert summary["checks_returned"] == 0
        assert summary["not_tested"] == 18

    def test_legacy_records_are_counted(self):
        summary = scoring.assessment_summary([check("High"), check("Pass")])
        assert summary["findings"] == 1
        assert summary["passes"] == 1
        assert summary["coverage_percent"] == 100


def test_partial_registry_results_lower_coverage():
    summary = scoring.assessment_summary([check("High"), check("Pass")], registered_checks=10)
    assert summary["coverage_percent"] == 20
    assert summary["not_tested"] == 8
