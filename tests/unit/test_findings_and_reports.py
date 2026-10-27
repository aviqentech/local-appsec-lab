import json
from pathlib import Path

import jsonschema

from local_appsec_lab.configuration import Config
from local_appsec_lab.discovery import inspect
from local_appsec_lab.engine import scan
from local_appsec_lab.integrations import ToolAdapter
from local_appsec_lab.models import Finding, Report, Source
from local_appsec_lab.reporting import compare, html_report, render, sarif
from local_appsec_lab.scanners import dependencies, scan_source
from local_appsec_lab.verification import deduplicate, verify

ROOT = Path(__file__).resolve().parents[2]


def example():
    return Finding(
        rule="test",
        title="<script>alert(1)</script>",
        category="source",
        severity="high",
        severity_reason="Potential only",
        source=Source(path="safe.py", line=1, end_line=1, excerpt="pass"),
        description="Synthetic",
        expected="reject",
        observed="candidate",
    )


def report(finding):
    return Report(
        run_id="synthetic",
        product="Lab",
        repository="/synthetic",
        revision="none",
        started="2026-01-01",
        finished="2026-01-01",
        duration_seconds=0,
        mode="review",
        status="partial",
        environment={},
        architecture={},
        findings=[finding],
    )


def test_fingerprints_dedup_and_html_escaping(tmp_path):
    finding = example()
    copy = finding.model_copy(deep=True)
    copy.source.line = 10
    result = deduplicate([finding, copy], "/repo")
    assert len(result) == 1 and len(result[0].fingerprint) == 64
    html = html_report(report(result[0]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    outputs = render(report(result[0]), tmp_path / "reports")
    assert all(Path(p).is_file() for p in outputs.values())
    for name, data in [
        ("report", report(result[0]).model_dump()),
        ("sarif-2.1.0", sarif(report(result[0]))),
    ]:
        jsonschema.validate(
            data, json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text())
        )


def test_source_candidate_and_secure_negative(fixture_project):
    insecure = fixture_project("unsupported")
    secure = fixture_project("negative-controls")
    results, _ = scan_source(insecure, inspect(insecure))
    assert len(results) == 1 and results[0].rule == "shell-command"
    assert verify(results[0], insecure, Config(), None).state == "candidate"
    assert scan_source(secure, inspect(secure))[0] == []


def test_independent_source_change(tmp_path):
    (tmp_path / "safe.py").write_text("pass")
    finding = example()
    finding.source.sha256 = "old-hash"
    assert verify(finding, tmp_path, Config(), None).state == "not_reproduced"


def test_dependency_snapshot(tmp_path):
    (tmp_path / "requirements.txt").write_text("example==1.2.3\n")
    (tmp_path / "advisories.json").write_text(
        json.dumps(
            {
                "updated": "2026-01-01",
                "advisories": [
                    {
                        "id": "SYNTHETIC-1",
                        "name": "example",
                        "ecosystem": "PyPI",
                        "versions": ["1.2.3"],
                    }
                ],
            }
        )
    )
    findings, checks = dependencies(tmp_path, inspect(tmp_path), "advisories.json")
    assert len(findings) == 1 and findings[0].state == "candidate"
    assert "2026-01-01" in checks[0].reason


def test_tool_normalization_and_provenance(tmp_path):
    (tmp_path / "safe.py").write_text("pass")
    adapter = ToolAdapter("semgrep")
    result = adapter.normalize_results(
        {
            "results": [
                {
                    "path": "safe.py",
                    "check_id": "synthetic-rule",
                    "start": {"line": 1},
                    "extra": {"message": "synthetic"},
                }
            ]
        },
        tmp_path,
    )
    assert result[0].provenance == "semgrep" and result[0].state == "candidate"


def test_compare_does_not_resolve_on_partial():
    finding = example().identify("/repo")
    before = report(finding)
    after = report(finding)
    after.findings = []
    diff = compare(before, after)
    assert len(diff["absent_requires_review"]) == 1 and diff["resolved"] == []


def test_source_only_engine_has_real_locations(fixture_project):
    root = fixture_project("unsupported")
    result, paths = scan(root, root, Config())
    assert any(f.source.path == "unsafe.py" for f in result.findings)
    assert result.metrics["services_started"] == 0 and result.metrics["cleanup_completed"]
    assert all(Path(p).exists() for p in paths.values())


def test_shareable_export_retains_evidence_and_removes_root():
    from local_appsec_lab.reporting import shareable

    original = report(example().identify("/synthetic"))
    exported = shareable(original)
    assert exported.repository == "/assessed-project"
    assert exported.findings == original.findings
    assert exported.metrics == original.metrics
    assert original.repository == "/synthetic"
