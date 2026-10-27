import json
import subprocess
import sys
from pathlib import Path

import pytest


def cli(root, *arguments):
    return subprocess.run(
        [sys.executable, "-m", "local_appsec_lab", "--project", str(root), *arguments],
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "command",
    [
        ["--help"],
        ["doctor"],
        ["inspect"],
        ["plan"],
        ["config", "validate"],
        ["skills", "doctor"],
        ["status"],
        ["runs"],
        ["clean"],
    ],
)
def test_documented_read_commands(tmp_path, command):
    result = cli(tmp_path, *command)
    assert result.returncode == 0, result.stderr
    if command != ["--help"]:
        json.loads(result.stdout)


def test_init_scan_report_compare_and_authorization(tmp_path):
    assert cli(tmp_path, "init").returncode == 0
    assert cli(tmp_path, "init").returncode == 3
    rejected = cli(tmp_path, "scan", "--mode", "local-active")
    assert rejected.returncode == 4 and "authorize" in rejected.stderr
    (tmp_path / "unsafe.py").write_text(
        "import subprocess\nsubprocess.run(user_input, shell=True)\n"
    )
    first = cli(tmp_path, "scan")
    assert first.returncode == 2
    run = json.loads(first.stdout)["run_id"]
    assert cli(tmp_path, "report", "--run", run, "--format", "html").returncode == 0
    second = cli(tmp_path, "scan")
    assert second.returncode == 2
    another = json.loads(second.stdout)["run_id"]
    diff = cli(tmp_path, "compare", run, another)
    assert diff.returncode == 0
    assert len(json.loads(diff.stdout)["unchanged"]) == 1
    assert cli(tmp_path, "verify", "--run", run, "--finding", "missing").returncode == 3


def test_malicious_readme_is_inert(fixture_project):
    root = fixture_project("malicious-instructions")
    result = cli(root, "scan")
    assert result.returncode == 2
    assert not (root / "SHOULD_NEVER_EXIST").exists()
    report = json.loads(Path(json.loads(result.stdout)["outputs"]["json"]).read_text())
    assert report["metrics"]["http_requests"] == 0 and report["metrics"]["services_started"] == 0
