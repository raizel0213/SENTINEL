"""SENTINEL report generation.

Four formats share one record:
    json  - complete machine-readable report (metadata + record)
    csv   - findings table for spreadsheets
    md    - human-readable report for repositories and review docs
    html  - standalone, print-styled page (print to PDF from the browser)
"""
from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json
import re
from urllib.parse import urlsplit
from typing import Any, Dict, Tuple

try:
    from . import config, scoring
except ImportError:  # pragma: no cover - direct script execution
    import config
    import scoring


CSV_KEYS = ["id", "severity", "outcome", "name", "header", "status",
            "evidence", "description", "impact", "fix", "docs"]

MIME = {
    "json": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
}

EXT = {"json": "json", "csv": "csv", "md": "md", "html": "html"}


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def build_json(record: Dict[str, Any]) -> str:
    report = dict(record)
    report["report_metadata"] = {
        "generated_at": _utcnow(),
        "score_model": ("Not applicable: CORS-filtered browser visibility cannot support a reliable score."
                        if record.get("mode") == "browser" else scoring.SCORING_MODEL_TEXT),
        "assessment": record.get("assessment", {}),
        "note": "Educational heuristic - not a certification or a full vulnerability assessment.",
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


_CSV_FORMULA_PREFIX = re.compile(r"^[\s\x00-\x1f]*[=+\-@]")


def _csv_safe_cell(value: Any) -> str:
    """Neutralize formula-like cells before exporting data to spreadsheets.

    CSV quoting protects delimiters, not spreadsheet formula evaluation. Add
    a leading apostrophe when the first meaningful character is a formula
    trigger, including when whitespace/control characters precede it.
    """
    text = str(value if value is not None else "")
    if _CSV_FORMULA_PREFIX.match(text):
        return "'" + text
    return text


def build_csv(record: Dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(CSV_KEYS)
    for check in record.get("checks") or []:
        writer.writerow([_csv_safe_cell(check.get(key, "")) for key in CSV_KEYS])
    return "\ufeff" + buffer.getvalue()



def _safe_reference_url(value: Any) -> str | None:
    """Return a safe HTTPS documentation URL, or None for untrusted input."""
    if not isinstance(value, str) or not value or any(ord(ch) < 0x20 for ch in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        _ = parsed.port  # force malformed-port validation
        return value
    except ValueError:
        return None


def _md(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def build_markdown(record: Dict[str, Any]) -> str:
    counts = record.get("counts") or {}
    coverage_value = (record.get("assessment") or {}).get("coverage_percent")
    coverage_display = "N/A" if coverage_value is None else f"{coverage_value}%"
    lines: list[str] = [
        "# SENTINEL \u2014 Security Configuration Report",
        "",
        f"- **Target:** {_md(record.get('target'))}",
        f"- **Final URL:** {_md(record.get('final_url'))}",
        f"- **Execution mode:** {_md(record.get('mode_label'))}",
        f"- **Timestamp:** {_md(record.get('timestamp'))}",
        f"- **HTTP status:** {_md(record.get('http_status'))}",
        f"- **Duration:** {_md(record.get('duration_ms'))} ms",
        f"- **Score:** {'Not applicable (browser mode is unscored)' if record.get('mode') == 'browser' else str(record.get('score')) + '/100 (grade ' + str(record.get('grade')) + ')'}",
        f"- **Check records:** {counts.get('total', 0)}",
        f"- **Potential findings:** {counts.get('findings', sum(1 for c in (record.get('checks') or []) if str(c.get('severity', '')).lower() in {'critical', 'high', 'medium', 'low'}))}",
        f"- **High / critical findings:** {counts.get('high', 0) + counts.get('critical', 0)}",
        f"- **Assessment coverage:** {coverage_display}",
        "",
        "> " + ("Browser-mode observations are not scored because CORS-filtered visibility cannot establish server-side absence or policy effectiveness."
                 if record.get("mode") == "browser" else scoring.SCORING_MODEL_TEXT),
        "",
        "## Findings overview",
        "",
        "| ID | Outcome | Severity | Check | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in record.get("checks") or []:
        lines.append(
            f"| {_md(check.get('id'))} | {_md(check.get('outcome', 'informational'))} | "
            f"{_md(check.get('severity'))} | {_md(check.get('name'))} | {_md(check.get('status'))} |"
        )

    lines += ["", "## Finding details", ""]
    for check in record.get("checks") or []:
        lines += [
            f"### {check.get('id')} \u2014 {check.get('name')}",
            "",
            f"*Severity:* {check.get('severity')} \u00b7 *Header:* {check.get('header')} \u00b7 "
            f"*Status:* {check.get('status')}",
            "",
            "**Summary**",
            "",
            _md(check.get("description")),
            "",
            "**Potential impact**",
            "",
            _md(check.get("impact")),
            "",
            "**Observed evidence**",
            "",
            "```",
            str(check.get("evidence") or ""),
            "```",
            "",
            "**Recommended remediation**",
            "",
            _md(check.get("fix")),
            "",
            f"Reference: {check.get('docs')}",
            "",
        ]

    lines += ["## Limitations", ""]
    for item in record.get("limitations") or []:
        lines.append(f"- {item}")
    lines += [
        "",
        "---",
        "",
        f"Generated by SENTINEL {record.get('version', config.VERSION)} on "
        f"{_utcnow()}. Local, passive, educational tool \u2014 scan only targets "
        "you own or are authorized to assess.",
    ]
    return "\n".join(lines)


_SEV_CLASS = {"critical": "critical", "high": "high", "medium": "medium",
              "low": "low", "info": "info", "pass": "pass"}


def build_html(record: Dict[str, Any]) -> str:
    esc = lambda v: html.escape(str(v if v is not None else ""))  # noqa: E731
    counts = record.get("counts") or {}
    coverage_value = (record.get("assessment") or {}).get("coverage_percent")
    coverage_display = "N/A" if coverage_value is None else f"{coverage_value}%"

    def sev_class(sev: Any) -> str:
        return _SEV_CLASS.get(str(sev or "info").lower(), "info")

    rows = []
    for check in record.get("checks") or []:
        rows.append(
            "<tr><td>{sid}</td><td><span class='sev {cls}'>{sev}</span></td>"
            "<td>{name}<div class='meta'>{hid} \u00b7 {status} \u00b7 outcome: {outcome}</div></td></tr>".format(
                sid=esc(check.get("id")),
                cls=sev_class(check.get("severity")),
                sev=esc(str(check.get("severity")).upper()),
                name=esc(check.get("name")),
                hid=esc(check.get("header")),
                status=esc(check.get("status")),
                outcome=esc(check.get("outcome", "informational")),
            )
        )

    details = []
    for check in record.get("checks") or []:
        raw_docs = check.get("docs")
        safe_docs = _safe_reference_url(raw_docs)
        if safe_docs:
            docs_markup = '<a href="{url}" rel="noopener noreferrer" target="_blank">{label}</a>'.format(
                url=esc(safe_docs), label=esc(raw_docs)
            )
        else:
            docs_markup = esc(raw_docs) if raw_docs else "No trusted HTTPS reference supplied."
        details.append(
            """
<section class="finding">
  <h3>{sid} \u2014 {name}</h3>
  <div class="tags"><span class="sev {cls}">{sev}</span><span class="tag">{status}</span>
  <span class="tag">{hid}</span></div>
  <h4>Summary</h4><p>{desc}</p>
  <h4>Potential impact</h4><p>{impact}</p>
  <h4>Evaluation outcome</h4><p>{outcome}</p>
  <h4>Observed evidence</h4><pre>{evidence}</pre>
  <h4>Recommended remediation</h4><p>{fix}</p>
  <p class="docs">Reference: {docs_markup}</p>
</section>""".format(
                sid=esc(check.get("id")), name=esc(check.get("name")),
                cls=sev_class(check.get("severity")),
                sev=esc(str(check.get("severity")).upper()),
                status=esc(check.get("status")), hid=esc(check.get("header")),
                outcome=esc(check.get("outcome", "informational")),
                desc=esc(check.get("description")), impact=esc(check.get("impact")),
                evidence=esc(check.get("evidence")), fix=esc(check.get("fix")),
                docs_markup=docs_markup,
            )
        )

    limitations = "".join(
        f"<li>{esc(item)}</li>" for item in record.get("limitations") or []
    )

    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL report \u2014 {target}</title>
<style>
:root{{--canvas:#f3f2ee;--paper:#fff;--paper-2:#faf9f6;--ink:#20221f;--muted:#73766f;
--line:#deded5;--green:#245846;--green-soft:#e6efe9;--red:#a53e37;--red-soft:#f8e9e7;
--amber:#94631d;--amber-soft:#f8f0dc;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--canvas);color:var(--ink);font:13px/1.55 var(--sans);padding:26px}}
.sheet{{max-width:900px;margin:0 auto;background:var(--paper);border:1px solid var(--line);padding:30px 34px}}
header{{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;border-bottom:2px solid var(--green);padding-bottom:14px;margin-bottom:18px}}
.brand{{font-weight:750;letter-spacing:.12em;font-size:15px}}
.brand small{{display:block;color:var(--muted);font:10px var(--mono);letter-spacing:.04em;margin-top:3px}}
h1{{font-size:21px;margin:0 0 4px;letter-spacing:-.03em}}
.meta{{font:11px var(--mono);color:var(--muted)}}
.score{{border:2px solid var(--green);color:var(--green);border-radius:50%;width:64px;height:64px;display:grid;place-items:center;font:700 16px var(--mono)}}
.metrics{{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);margin-bottom:20px}}
.metrics div{{padding:10px 12px;border-right:1px solid var(--line)}}
.metrics div:last-child{{border:0}}
.metrics .label{{font:9px var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
.metrics .value{{font-size:18px;font-weight:650}}
table{{width:100%;border-collapse:collapse;margin-bottom:20px}}
th{{text-align:left;font:10px var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--paper-2);padding:8px 10px;border-bottom:1px solid var(--line)}}
td{{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
.meta{{font:10px var(--mono);color:var(--muted);margin-top:2px}}
.sev{{display:inline-block;padding:2px 6px;border:1px solid var(--line);font:10px var(--mono);text-transform:uppercase;border-radius:2px}}
.sev.high,.sev.critical{{color:var(--red);background:var(--red-soft)}}
.sev.medium{{color:var(--amber);background:var(--amber-soft)}}
.sev.low,.sev.info{{color:var(--muted);background:var(--paper-2)}}
.sev.pass{{color:var(--green);background:var(--green-soft)}}
.tag{{display:inline-block;padding:2px 6px;border:1px solid var(--line);font:10px var(--mono);color:var(--muted);border-radius:2px}}
.finding{{border-top:1px solid var(--line);padding:13px 0}}
.finding h3{{margin:0 0 7px;font-size:14px}}
.finding h4{{font:10px var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:12px 0 4px}}
.finding p{{margin:0}}
pre{{font:11px/1.6 var(--mono);background:var(--paper-2);border:1px solid var(--line);padding:9px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--muted)}}
.docs a{{color:var(--green);overflow-wrap:anywhere}}
.tags{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px}}
footer{{border-top:1px solid var(--line);margin-top:22px;padding-top:12px;color:var(--muted);font-size:10px}}
footer ul{{margin:6px 0 0;padding-left:18px}}
.toolbar{{max-width:900px;margin:0 auto 12px;text-align:right}}
.toolbar button{{font:12px var(--sans);padding:7px 12px;border:1px solid var(--line-dark);background:var(--paper);border-radius:3px;cursor:pointer}}
@media(max-width:640px){{body{{padding:8px}}.sheet{{padding:18px 14px}}.metrics{{grid-template-columns:repeat(2,1fr)}}header{{flex-direction:column}}}}
@media print{{body{{padding:0;background:#fff}}.toolbar{{display:none}}.sheet{{border:0}}}}
</style>
</head>
<body>
<div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="sheet">
<header>
  <div>
    <div class="brand">SENTINEL<small>SECURITY CONFIGURATION REPORT \u00b7 {version}</small></div>
    <h1>{target}</h1>
    <div class="meta">mode: {mode} \u00b7 {timestamp} \u00b7 HTTP {status} \u00b7 {dur} ms</div>
  </div>
  <div class="score">{score}</div>
</header>
<div class="metrics">
  <div><div class="label">Score / grade</div><div class="value">{score}/100 {grade}</div></div>
  <div><div class="label">Potential findings</div><div class="value">{total}</div></div>
  <div><div class="label">High / critical</div><div class="value">{high}</div></div>
  <div><div class="label">Headers observed</div><div class="value">{observed}</div></div>
  <div><div class="label">Check coverage</div><div class="value">{coverage}</div></div>
</div>
<table>
<thead><tr><th style="width:90px">ID</th><th style="width:110px">Severity</th><th>Check</th></tr></thead>
<tbody>{rows}</tbody>
</table>
{details}
<footer>
  <strong>Limitations</strong>
  <ul>{limitations}</ul>
  <p style="margin-top:10px">{model}</p>
</footer>
</div>
</body>
</html>""".format(
        target=esc(record.get("target")),
        version=esc(record.get("version", config.VERSION)),
        mode=esc(record.get("mode_label")),
        timestamp=esc(record.get("timestamp")),
        status=esc(record.get("http_status")),
        dur=esc(record.get("duration_ms")),
        score=esc("N/A" if record.get("mode") == "browser" else record.get("score")),
        grade=esc("Unscored" if record.get("mode") == "browser" else record.get("grade")),
        total=counts.get("findings", sum(1 for c in (record.get("checks") or []) if str(c.get("severity", "")).lower() in {"critical", "high", "medium", "low"})),
        high=counts.get("high", 0) + counts.get("critical", 0),
        observed=esc(record.get("observed")),
        coverage=esc(coverage_display),
        rows="".join(rows),
        details="".join(details),
        limitations=limitations,
        model=esc("Browser-mode observations are not scored because CORS-filtered visibility cannot establish server-side absence or policy effectiveness."
                  if record.get("mode") == "browser" else scoring.SCORING_MODEL_TEXT),
    )


def generate(record: Dict[str, Any], fmt: str) -> Tuple[str, str, str]:
    """Return (content, mimetype, filename) for a report format."""
    fmt = (fmt or "").lower()
    builders = {"json": build_json, "csv": build_csv,
                "md": build_markdown, "html": build_html}
    builder = builders.get(fmt)
    if builder is None:
        raise ValueError(f"Unknown report format '{fmt}'.")
    prefix = "sentinel-findings" if fmt == "csv" else "sentinel-report"
    filename = f"{prefix}-{str(record.get('id') or 'scan')}-{_stamp()}.{EXT[fmt]}"
    return builder(record), MIME[fmt], filename
