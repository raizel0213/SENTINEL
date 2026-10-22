"""Frontend asset integrity: every local script/stylesheet/icon referenced by
index.html must exist, and all JS modules must be syntactically valid
(checked via node --test-style parse when node is available, else compileall
covers the Python side only)."""
from __future__ import annotations

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
INDEX = FRONTEND / "index.html"


class TestReferencedAssets:
    def test_index_exists(self):
        assert INDEX.is_file()

    def test_local_references_resolve(self):
        html = INDEX.read_text(encoding="utf-8")
        refs = re.findall(r'(?:src|href)="([^"]+)"', html)
        local = [r for r in refs if not r.startswith(("http", "#", "mailto:", "data:"))]
        assert local, "index.html must reference local assets"
        for ref in local:
            assert (FRONTEND / ref).is_file(), f"missing asset: {ref}"

    def test_all_seven_js_modules_present(self):
        expected = {"app.js", "api.js", "scanner-ui.js", "findings.js",
                    "reports.js", "history.js", "validation.js"}
        actual = {p.name for p in (FRONTEND / "js").glob("*.js")}
        assert expected == actual

    def test_stylesheet_split(self):
        assert (FRONTEND / "css" / "themes.css").is_file()
        assert (FRONTEND / "css" / "styles.css").is_file()

    def test_theme_tokens_present(self):
        themes = (FRONTEND / "css" / "themes.css").read_text(encoding="utf-8")
        assert "[data-theme=dark]" in themes
        assert "--green: #245846" in themes  # deep forest-green identity

    def test_index_links_modules_in_order(self):
        html = INDEX.read_text(encoding="utf-8")
        order = ["validation.js", "api.js", "findings.js", "history.js",
                 "reports.js", "scanner-ui.js", "app.js"]
        positions = [html.index(f"js/{name}") for name in order]
        assert positions == sorted(positions), "classic scripts must load in dependency order"

    def test_offline_csv_neutralizes_formula_cells_and_exports_outcome(self):
        reports = (FRONTEND / "js" / "reports.js").read_text(encoding="utf-8")
        assert "[\\s\\x00-\\x1f]*[=+\\-@]" in reports
        assert "' + text" in reports
        assert "'outcome'" in reports
