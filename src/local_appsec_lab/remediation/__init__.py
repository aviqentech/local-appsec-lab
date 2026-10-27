from __future__ import annotations

from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.models import Finding


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
                             "--run", {run_id!r}, "--finding", {finding.id!r}, "--authorize"],
                            capture_output=True, text=True)
    data = json.loads(result.stdout)
    finding = data["finding"]
    assert finding["state"] == "not_reproduced", finding["state"]
'''
    destination.write_text(source)
    destination.chmod(0o600)
    return destination.name
