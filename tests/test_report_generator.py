"""Tests for the report generator (JSON, CSV, Markdown, HTML)."""
from __future__ import annotations

import csv
import io
import json

import pytest

from backend import report_generator as rg


@pytest.fixture()
def finalized_record(sample_record):
    from backend import scoring
    sample_record["counts"] = scoring.counts_for(sample_record["checks"])
    sample_record["score"] = scoring.compute_score(sample_record["checks"])
    sample_record["grade"] = scoring.grade_for(sample_record["score"])
    return sample_record


class TestJson:
    def test_valid_json_with_metadata(self, finalized_record):
        data = json.loads(rg.build_json(finalized_record))
        assert data["id"] == finalized_record["id"]
        assert "report_metadata" in data
        assert "score_model" in data["report_metadata"]


class TestCsv:
    def test_header_and_rows(self, finalized_record):
        content = rg.build_csv(finalized_record)
        lines = content.lstrip("\ufeff").strip().split("\r\n")
        assert lines[0] == ",".join(f'"{k}"' for k in rg.CSV_KEYS)
        assert len(lines) == 1 + len(finalized_record["checks"])

    def test_quotes_escaped(self, finalized_record):
        finalized_record["checks"][0]["evidence"] = 'He said "nosniff"'
        content = rg.build_csv(finalized_record)
        assert '""nosniff""' in content

    @pytest.mark.parametrize("payload", [
        "=1+1", "+SUM(A1:A2)", "-2+3", "@SUM(A1:A2)",
        '  =HYPERLINK("https://evil.example")',
        "\t=cmd|' /C calc'!A0",
    ])
    def test_formula_like_cells_neutralized(self, finalized_record, payload):
        finalized_record["checks"][0]["evidence"] = payload
        content = rg.build_csv(finalized_record)
        # Parse CSV first: embedded quotes are correctly doubled by csv.writer,
        # so searching the serialized CSV string is not a reliable assertion.
        rows = list(csv.reader(io.StringIO(content.lstrip("\ufeff"))))
        evidence_index = rg.CSV_KEYS.index("evidence")
        assert rows[1][evidence_index] == "'" + payload


class TestMarkdown:
    def test_core_sections(self, finalized_record):
        content = rg.build_markdown(finalized_record)
        assert "# SENTINEL" in content
        assert "## Findings overview" in content
        assert "## Finding details" in content
        assert "## Limitations" in content
        assert "HDR-001" in content
        assert "85/100 (grade A)" in content

    def test_pipes_escaped(self, finalized_record):
        finalized_record["checks"][0]["name"] = "A | B"
        content = rg.build_markdown(finalized_record)
        assert "A \\| B" in content


class TestHtml:
    def test_standalone_document(self, finalized_record):
        content = rg.build_html(finalized_record)
        assert content.startswith("<!doctype html>")
        assert "HDR-001" in content
        assert "Print / Save as PDF" in content

    def test_html_escaped(self, finalized_record):
        finalized_record["checks"][0]["name"] = "<script>alert(1)</script>"
        content = rg.build_html(finalized_record)
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content

    def test_severity_classes(self, finalized_record):
        content = rg.build_html(finalized_record)
        assert "sev high" in content or "sev pass" in content

    def test_javascript_reference_not_rendered_as_link(self, finalized_record):
        finalized_record["checks"][0]["docs"] = "javascript:alert(1)"
        content = rg.build_html(finalized_record)
        assert 'href="javascript:alert(1)"' not in content
        assert "Reference: javascript:alert(1)" in content

    def test_only_https_reference_becomes_link(self, finalized_record):
        finalized_record["checks"][0]["docs"] = "https://docs.example.test/path"
        content = rg.build_html(finalized_record)
        assert 'href="https://docs.example.test/path"' in content

    def test_credentials_in_reference_not_linked(self, finalized_record):
        finalized_record["checks"][0]["docs"] = "https://user:pass@evil.example/"
        content = rg.build_html(finalized_record)
        assert 'href="https://user:pass@evil.example/"' not in content


class TestGenerate:
    def test_each_format(self, finalized_record):
        for fmt in ("json", "csv", "md", "html"):
            content, mimetype, filename = rg.generate(finalized_record, fmt)
            assert content
            assert mimetype == rg.MIME[fmt]
            assert filename.endswith("." + fmt)
            assert finalized_record["id"] in filename

    def test_csv_filename_uses_findings_prefix(self, finalized_record):
        _, _, filename = rg.generate(finalized_record, "csv")
        assert filename.startswith("sentinel-findings-")

    def test_unknown_format_raises(self, finalized_record):
        with pytest.raises(ValueError):
            rg.generate(finalized_record, "xml")


def test_browser_mode_is_explicitly_unscored():
    from backend import report_generator
    import json

    record = {
        "mode": "browser", "target": "https://example.com/",
        "score": None, "grade": None, "score_applicable": False,
        "checks": [], "limitations": [], "counts": {"total": 0},
    }
    report = json.loads(report_generator.build_json(record))
    assert report["report_metadata"]["score_model"].startswith("Not applicable")
    assert "Not applicable (browser mode is unscored)" in report_generator.build_markdown(record)
    assert "N/A" in report_generator.build_html(record)
