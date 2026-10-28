import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


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


def test_native_init_configures_review_without_running_source(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "server.js").write_text('require("fs").writeFileSync("EXECUTED", "yes")')
    result = cli(tmp_path, "init", "--native-host", "codex")
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    config_text = (tmp_path / "appsec-lab.yaml").read_text()
    config = yaml.safe_load(config_text)
    assert config["ai"]["strategy"] == "native"
    assert config["limits"]["model_tokens"] > 0
    assert config["execution"]["command"] == ["node", "server.js"]
    assert "# Project configuration:" in config_text
    assert not output["authorized"] and not output["live_testing"]["ready"]
    assert "--allow-model-requests" in output["next_steps"][-1]["command"]
    assert not (tmp_path / "EXECUTED").exists()
    assert not (tmp_path / ".appsec-lab").exists()
    assert cli(tmp_path, "config", "validate").returncode == 0
    assert cli(tmp_path, "init").returncode == 3
    assert (tmp_path / "appsec-lab.yaml").read_text() == config_text


@pytest.mark.parametrize(
    "flags",
    [
        ["--native-host", "codex", "--allow-model-requests"],
        ["--allow-model-requests"],
    ],
)
def test_model_flags_cannot_silently_run_deterministic_review(tmp_path, flags):
    result = cli(tmp_path, "scan", "--mode", "review", *flags)
    assert result.returncode == 3
    assert "ai.strategy" in result.stderr
    assert not (tmp_path / ".appsec-lab").exists()


def test_next_builds_excluded_and_child_init_is_scoped(tmp_path):
    (tmp_path / ".next").mkdir()
    (tmp_path / ".next" / "generated.js").write_text('app.get("/generated")')
    child = tmp_path / "api"
    child.mkdir()
    assert cli(tmp_path, "init", "--native-host", "codex").returncode == 0
    assert cli(child, "init").returncode == 0
    assert (
        yaml.safe_load((child / "appsec-lab.yaml").read_text())["ai"]["strategy"] == "deterministic"
    )
    inventory = json.loads(cli(tmp_path, "inspect").stdout)
    assert not any(".next" in p for p in inventory["files"])
