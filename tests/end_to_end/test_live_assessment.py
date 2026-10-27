import json
import socket
from pathlib import Path

import jsonschema
import pytest

from local_appsec_lab.configuration import load
from local_appsec_lab.engine import scan
from local_appsec_lab.findings import RunStore

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.runtime
@pytest.mark.parametrize("fixture", ["javascript-api", "python-api"])
def test_real_application_full_workflow(runtime_ready, fixture_project, free_port, fixture):
    root = fixture_project(fixture)
    config = load(root)
    config.execution.port = free_port
    result, outputs = scan(root, root, config, "local-active", True)
    assert result.metrics["services_started"] == 1
    assert result.metrics["http_requests"] >= 10
    confirmed = [f for f in result.findings if f.state == "confirmed"]
    assert len(confirmed) == 1 and confirmed[0].rule == "boundary:vulnerable-cross-user"
    assert not any(f.rule == "boundary:secure-cross-user" for f in result.findings)
    assert confirmed[0].verification[-1]["new_observation"]["violation"]
    assert confirmed[0].evidence[0]["owner"]["marker_present"]
    assert result.metrics["cleanup_completed"]
    assert list((root / ".appsec-lab/cache").iterdir()) == []
    with socket.socket() as probe:
        probe.settimeout(0.2)
        assert probe.connect_ex(("127.0.0.1", free_port)) != 0
    for name, schema in [("json", "report"), ("sarif", "sarif-2.1.0")]:
        jsonschema.validate(
            json.loads(Path(outputs[name]).read_text()),
            json.loads((ROOT / "schemas" / f"{schema}.schema.json").read_text()),
        )
    store = RunStore(root / ".appsec-lab")
    assert store.read(result.run_id).run_id == result.run_id
    store.close()


@pytest.mark.runtime
def test_fix_reverification_preserves_disagreement(runtime_ready, fixture_project, free_port):
    root = fixture_project()
    config = load(root)
    config.execution.port = free_port
    result, _ = scan(root, root, config, "local-active", True)
    finding = next(f for f in result.findings if f.state == "confirmed")
    source = root / "server.js"
    text = source.read_text()
    text = text.replace(
        "return actor ? send(200,{owner:'alice',data:'SYNTHETIC_ALICE_RECORD_42'})",
        "return actor === 'alice' ? send(200,{owner:'alice',data:'SYNTHETIC_ALICE_RECORD_42'})",
    )
    source.write_text(text)
    fixed, _ = scan(root, root, config, "local-active", True, reverify=finding)
    current = fixed.findings[0]
    assert current.state == "not_reproduced"
    assert current.verification[-1]["previous_state"] == "confirmed"
    assert current.fingerprint == finding.fingerprint
    assert not any(c.id in {s.id for s in config.scenarios} for c in fixed.checks)


@pytest.mark.runtime
def test_cli_cancellation_cleans_owned_runtime(runtime_ready, fixture_project, free_port):
    import signal
    import subprocess
    import sys
    import time
    import yaml

    root = fixture_project()
    data = yaml.safe_load((root / "appsec-lab.yaml").read_text())
    data["execution"]["port"] = free_port
    data["limits"]["requests_per_second"] = 1
    (root / "appsec-lab.yaml").write_text(yaml.safe_dump(data))
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "local_appsec_lab",
            "scan",
            "--project",
            str(root),
            "--mode",
            "local-active",
            "--authorize",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if list(root.glob(".appsec-lab/runs/*/runtime.json")):
            break
        if process.poll() is not None:
            raise AssertionError("CLI exited before cancellation")
        time.sleep(0.05)
    try:
        process.send_signal(signal.SIGINT)
        output, errors = process.communicate(timeout=10)
        assert process.returncode == 130, errors.decode()
        assert json.loads(output)["status"] == "cancelled"
        assert list((root / ".appsec-lab/cache").iterdir()) == []
        with socket.socket() as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", free_port)) != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
