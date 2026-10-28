from __future__ import annotations

import html
import json
from pathlib import Path

from local_appsec_lab import __version__
from local_appsec_lab.models import Report
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir
from local_appsec_lab.utilities.redaction import redact


def shareable(report: Report) -> Report:
    """Generalize local operator/root metadata; retain measured evidence and IDs."""

    def generalize(value):
        if isinstance(value, dict):
            return {k: generalize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [generalize(v) for v in value]
        if isinstance(value, str):
            return value.replace(report.repository, "/assessed-project")
        return value

    data = generalize(report.model_dump())
    if data["authorization"]:
        data["authorization"]["user"] = "authorized-operator"
    data["environment"]["metadata_policy"] = (
        "Repository/operator metadata generalized; measured findings unchanged. Review before sharing."
    )
    return Report.model_validate(data)


def sarif(report: Report) -> dict:
    rules = sorted({f.rule for f in report.findings})
    results = []
    for finding in report.findings:
        if finding.state in {"false_positive", "not_reproduced", "not_tested", "blocked"}:
            continue
        result = {
            "ruleId": finding.rule,
            "ruleIndex": rules.index(finding.rule),
            "level": "error"
            if finding.state == "confirmed" and finding.severity in {"high", "critical"}
            else "warning"
            if finding.state == "candidate"
            else "note",
            "message": {"text": f"[{finding.state}] {finding.title}: {finding.observed}"},
            "partialFingerprints": {"appsecLab/v1": finding.fingerprint},
            "properties": {
                "state": finding.state,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "cvss": finding.cvss,
            },
        }
        if finding.source:
            from urllib.parse import quote

            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(finding.source.path, safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.source.line,
                            "endLine": max(finding.source.line, finding.source.end_line),
                        },
                    }
                }
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.product,
                        "version": __version__,
                        "rules": [
                            {"id": rule, "shortDescription": {"text": rule}} for rule in rules
                        ],
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": report.status == "complete"}],
                "properties": {
                    "run_id": report.run_id,
                    "coverage": [c.model_dump() for c in report.checks],
                },
            }
        ],
    }


def markdown(report: Report) -> str:
    # Escape Markdown syntax from repository-controlled strings as well as HTML.
    def esc(value) -> str:
        text = html.escape(str(value))
        for c in "\\`*_{}[]()#+!|":
            text = text.replace(c, "\\" + c)
        return text.replace("\n", " ")

    lines = [
        f"# {esc(report.product)} assessment",
        "",
        f"Run: {report.run_id} · Mode: {report.mode} · Status: **{report.status}**",
        "",
        f"Repository: {esc(report.repository)}",
        f"Revision: {esc(report.revision)}",
        f"Started: {report.started} · Duration: {report.duration_seconds:.2f}s",
        f"Execution strategy: {report.execution_strategy}",
        "",
        "## Measured results",
        "",
    ]
    lines.extend(f"- {esc(key)}: {esc(value)}" for key, value in report.metrics.items())
    component_rows = report.architecture.get("assessment", {}).get("components", [])
    if component_rows:
        lines.extend(
            [
                "",
                "## Component coverage",
                "",
                "Startup classification is a source hint. Test completion is measured separately above.",
                "",
                "| Component | Kind | Runtime action | Reason |",
                "|---|---|---|---|",
            ]
        )
        for row in component_rows:
            lines.append(
                "| "
                + " | ".join(esc(row[key]) for key in ("id", "kind", "runtime_action", "reason"))
                + " |"
            )
    lines.extend(["", "## Findings", ""])
    for f in report.findings:
        lines.extend(
            [
                f"### {esc(f.title)}",
                "",
                f"{f.id} · {f.severity} potential severity · {f.state} · confidence: {f.confidence}",
                "",
                f"Location: {esc(f.source.path + ':' + str(f.source.line) if f.source else f.endpoint or f.service)}",
                f"Rule: {esc(f.rule)} · {esc(f.cwe or 'no CWE mapping')}",
                "",
                esc(f.description),
                "",
                f"Root cause: {esc(f.root_cause)}",
                f"Expected: {esc(f.expected)}",
                f"Observed: {esc(f.observed)}",
                f"Severity rationale: {esc(f.severity_reason)}",
                "",
                "Evidence:",
                "```json",
                json.dumps(redact(f.evidence), indent=2),
                "```",
                "Verification:",
                "```json",
                json.dumps(redact(f.verification), indent=2),
                "```",
                f"Remediation: {esc(f.remediation)}",
                f"Regression: {esc(f.regression)}",
                "CVSS v4 (explicit vector only): " + esc(json.dumps(f.cvss))
                if f.cvss
                else "CVSS v4: not assigned; no supported vector supplied.",
                "Engineering guidance:",
                "```json",
                json.dumps(redact(f.remediation_details), indent=2),
                "```",
                f"Limitations: {esc('; '.join(f.limitations))}",
                "",
            ]
        )
    lines.extend(
        [
            "## Coverage",
            "",
            "| Test | Category | Status | Target | Reason |",
            "|---|---|---|---|---|",
        ]
    )
    lines.extend(
        f"| {esc(c.id)} | {esc(c.category)} | {c.status} | {esc(c.target)} | {esc(c.reason)} |"
        for c in report.checks
    )
    lines.extend(["", "## Limitations", ""] + [f"- {esc(x)}" for x in report.limitations])
    lines.extend(["", "No findings does not establish security or complete coverage.", ""])
    return "\n".join(lines)


def html_report(report: Report) -> str:
    def esc(x):
        return html.escape(str(x), quote=True)

    cards = []
    for f in report.findings:
        evidence = json.dumps(
            redact(
                {
                    "evidence": f.evidence,
                    "verification": f.verification,
                    "cvss": f.cvss,
                    "engineering_guidance": f.remediation_details,
                }
            ),
            indent=2,
        )
        cards.append(
            f'<article data-state="{f.state}" data-severity="{f.severity}"><p class="tag">{f.severity.upper()} · {f.state} · {esc(f.id)}</p><h2>{esc(f.title)}</h2><p>{esc(f.description)}</p><dl><dt>Location</dt><dd>{esc(f.source.path + ":" + str(f.source.line) if f.source else f.endpoint or f.service)}</dd><dt>Root cause</dt><dd>{esc(f.root_cause)}</dd><dt>Expected</dt><dd>{esc(f.expected)}</dd><dt>Observed</dt><dd>{esc(f.observed)}</dd><dt>Remediation</dt><dd>{esc(f.remediation)}</dd><dt>Regression</dt><dd>{esc(f.regression)}</dd><dt>Limitations</dt><dd>{esc("; ".join(f.limitations))}</dd></dl><details><summary>Evidence and independent verification</summary><pre>{esc(evidence)}</pre></details></article>'
        )
    severity_counts = "".join(
        f'<span class="tag">{severity}: {sum(f.severity == severity for f in report.findings)} &nbsp;</span>'
        for severity in ["critical", "high", "medium", "low", "informational"]
    )
    rows = "".join(
        f"<tr><td>{esc(c.id)}</td><td>{esc(c.category)}</td><td>{c.status}</td><td>{esc(c.target)}</td><td>{esc(c.reason)}</td></tr>"
        for c in report.checks
    )
    metrics = "".join(
        f"<div><strong>{esc(v)}</strong><span>{esc(k.replace('_', ' '))}</span></div>"
        for k, v in report.metrics.items()
    )
    component_rows = report.architecture.get("assessment", {}).get("components", [])
    component_table = ""
    if component_rows:
        component_table = (
            "<h2>Component coverage</h2><table><tr><th>Component</th><th>Kind</th><th>Runtime action</th><th>Reason</th></tr>"
            + "".join(
                "<tr>"
                + "".join(
                    "<td>" + esc(row[key]) + "</td>"
                    for key in ("id", "kind", "runtime_action", "reason")
                )
                + "</tr>"
                for row in component_rows
            )
            + "</table>"
        )
    limitations = "".join(f"<li>{esc(x)}</li>" for x in report.limitations)
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-appsec-report'; base-uri 'none'; form-action 'none'"><title>{esc(report.product)} assessment</title><style>
:root{{color-scheme:light dark;font:16px/1.6 system-ui;background:#101725;color:#e6edf7}}body{{max-width:1100px;margin:auto;padding:40px 24px}}h1{{font-size:2.8rem;line-height:1.15}}.eyebrow,.tag{{color:#7ee0c2;font-size:.85rem;letter-spacing:.06em}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}.metrics div,article{{background:#192438;border:1px solid #33435e;border-radius:12px;padding:22px;margin:14px 0}}.metrics strong{{display:block;font-size:2rem}}.metrics span{{font-size:.85rem;color:#bdcbe0}}h2{{font-size:1.25rem}}dd{{margin:0 0 12px}}dt{{color:#9cb0ce}}pre{{overflow:auto;max-height:450px;background:#0a111e;padding:16px;font-size:.8rem}}table{{border-collapse:collapse;width:100%;font-size:.85rem}}td,th{{text-align:left;border-bottom:1px solid #33435e;padding:10px}}.scroll{{overflow-x:auto}}select{{padding:8px;border-radius:6px;background:#192438;color:#fff}}[hidden]{{display:none}}footer{{color:#9cb0ce;margin-top:30px}}
</style><header><p class="eyebrow">LOCAL EVIDENCE · EXPLICIT SCOPE</p><h1>{esc(report.product)}</h1><p>Application security assessment · {report.mode} · {report.status}</p><p>{esc(report.repository)}<br>Run {report.run_id} · {esc(report.started)} · {report.duration_seconds:.1f}s<br>{esc(report.execution_strategy)}</p></header><section class="metrics">{metrics}</section><h2>Findings</h2><p>{component_table}{severity_counts}</p><label>Filter status <select id="filter"><option value="all">All findings</option><option>confirmed</option><option>candidate</option><option>informational</option><option>blocked</option><option>not_reproduced</option></select></label><main>{"".join(cards)}</main><h2>Test coverage</h2><div class="scroll"><table><thead><tr><th>Test</th><th>Category</th><th>Status</th><th>Target</th><th>Reason</th></tr></thead><tbody>{rows}</tbody></table></div><h2>Limitations</h2><ul>{limitations}</ul><footer>No findings does not establish security or complete coverage. This report works offline and contains no external resources.</footer><script nonce="appsec-report">document.getElementById('filter').addEventListener('change',function(){{document.querySelectorAll('article').forEach(a=>a.hidden=this.value!=='all'&&a.dataset.state!==this.value)}})</script></html>"""


def render(report: Report, output: Path, formats: list[str] | None = None) -> dict[str, str]:
    output = private_dir(output)
    formats = formats or ["json", "markdown", "html", "sarif"]
    result = {}
    for format in formats:
        extension = {"json": "json", "markdown": "md", "html": "html", "sarif": "sarif"}[format]
        destination = inside(output, Path(f"report.{extension}"))
        if format in {"json", "sarif"}:
            atomic_json(
                destination, redact(report.model_dump() if format == "json" else sarif(report))
            )
        else:
            destination.write_text(
                markdown(report) if format == "markdown" else html_report(report), encoding="utf-8"
            )
            destination.chmod(0o600)
        result[format] = str(destination)
    return result


def compare(old: Report, new: Report) -> dict:
    before, after = (
        {f.fingerprint: f for f in old.findings},
        {f.fingerprint: f for f in new.findings},
    )
    absent = sorted(before.keys() - after.keys())
    return {
        "old_run": old.run_id,
        "new_run": new.run_id,
        "new": sorted(after.keys() - before.keys()),
        "absent_requires_review": absent,
        "resolved": [
            k
            for k in absent
            if old.mode == new.mode
            and new.status == "complete"
            and {c.id for c in old.checks if c.status == "completed"}
            <= {c.id for c in new.checks if c.status == "completed"}
        ],
        "unchanged": [
            k
            for k in before.keys() & after.keys()
            if (before[k].severity, before[k].state, before[k].confidence)
            == (after[k].severity, after[k].state, after[k].confidence)
        ],
        "changed": [
            k
            for k in before.keys() & after.keys()
            if (before[k].severity, before[k].state, before[k].confidence)
            != (after[k].severity, after[k].state, after[k].confidence)
        ],
        "reopened": [
            k
            for k in before.keys() & after.keys()
            if before[k].state in {"not_reproduced", "false_positive"}
            and after[k].state in {"confirmed", "candidate"}
        ],
        "coverage_changes": {
            c.id: c.status
            for c in new.checks
            if c.id not in {x.id for x in old.checks}
            or next(x.status for x in old.checks if x.id == c.id) != c.status
        },
        "no_longer_executable": [
            c.id
            for c in new.checks
            if c.status in {"blocked", "not_tested", "failed"}
            and any(o.id == c.id and o.status == "completed" for o in old.checks)
        ],
        "caution": "Absence is only a resolution candidate; review coverage and verify the original behavior.",
    }
