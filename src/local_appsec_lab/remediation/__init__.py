from __future__ import annotations

from pathlib import Path

from local_appsec_lab.authorization import plan_digest
from local_appsec_lab.configuration import Config
from local_appsec_lab.models import Finding


def enrich(finding: Finding, root: Path, inventory: dict) -> None:
    """Explain the actual evidence and stack without asserting an unproved root cause."""
    from local_appsec_lab.utilities.files import read_text

    frameworks = inventory.get("frameworks", [])
    location = finding.source.path if finding.source else finding.endpoint or "repository"
    detail = {
        "affected_component": location,
        "root_cause": finding.root_cause,
        "impact": finding.severity_reason,
        "recommended_fix": finding.remediation,
        "regression": finding.regression,
        "framework_context": frameworks,
        "compatibility": "Review existing callers and deployment controls; run application regression tests before release.",
        "verification": "Repeat the recorded check with the same synthetic fixtures and verify both the denied actor and allowed owner controls.",
        "alternative_mitigation": "Constrain the affected interface while a source correction is reviewed; deployment controls need independent validation.",
        "references": [],
    }
    if finding.cwe and finding.cwe.startswith("CWE-") and finding.cwe[4:].isdigit():
        detail["references"].append(
            "https://cwe.mitre.org/data/definitions/" + finding.cwe[4:] + ".html"
        )
    if finding.source:
        text = read_text(root, finding.source.path)
        detail["source_files"] = [finding.source.path]
        detail["source_lines"] = [finding.source.line, finding.source.end_line]
        if "sql" in finding.rule.lower():
            driver = "psycopg" if "psycopg" in text else "sqlite3" if "sqlite3" in text else None
            detail["suggested_change"] = (
                "Keep the SQL template constant and bind input with %s placeholders and a separate parameter tuple."
                if driver == "psycopg"
                else "Keep the SQL template constant and bind input with ? placeholders and a separate parameter tuple."
                if driver == "sqlite3"
                else "Use the parameter-binding API of the database driver identified in this file; verify its placeholder syntax before editing."
            )
            if finding.rule.startswith("dataflow:"):
                finding.root_cause = "Bounded source analysis traced request-derived data into SQL construction; runtime applicability still needs validation."
            detail["compatibility"] = (
                "Preserve identifier allowlists and query result shape; test quotes, Unicode, nulls and ordinary owner requests."
            )
        elif finding.rule.startswith("boundary:"):
            detail["suggested_change"] = (
                "Apply the resource ownership or role check before the recorded operation; derive identity from the authenticated server context."
            )
    detail["root_cause"] = finding.root_cause
    finding.remediation_details = {**finding.remediation_details, **detail}


def regression(
    finding: Finding,
    config: Config,
    directory: Path,
    root: Path | None = None,
    run_id: str = "latest",
) -> str | None:
    """Produce an executable CLI regression, retaining no synthetic credentials."""
    if not finding.rule.startswith("boundary:"):
        return None
    scenario = next((s for s in config.scenarios if s.id == finding.rule.split(":", 1)[1]), None)
    if not scenario:
        return None
    destination = directory / f"test_{finding.id.replace('-', '_').lower()}.py"
    source = f'''"""Requires a fresh explicit local execution authorization via the CLI.
Run with the repository's original appsec-lab.yaml; never targets arbitrary URLs.
"""
import json
import subprocess
import sys


def test_access_boundary():
    result = subprocess.run([sys.executable, "-m", "local_appsec_lab", "verify",
                             "--project", {str(root or Path.cwd())!r},
                             "--run", {run_id!r}, "--finding", {finding.id!r}, "--authorize",
                             "--plan-digest", {plan_digest(config)!r}],
                            capture_output=True, text=True)
    data = json.loads(result.stdout)
    finding = data["finding"]
    assert finding["state"] == "not_reproduced", finding["state"]
'''
    destination.write_text(source)
    destination.chmod(0o600)
    return destination.name
