import json
import os
import subprocess

import pytest

from local_appsec_lab.configuration import load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.engine import clean
from local_appsec_lab.errors import RuntimeFailure, ScopeError
from local_appsec_lab.isolation import mac_profile
from local_appsec_lab.network import Budget
from local_appsec_lab.runtime import Runtime
from local_appsec_lab.findings import RunStore


@pytest.mark.runtime
def test_network_and_file_boundary(runtime_ready, fixture_project, free_port, tmp_path):
    root = fixture_project()
    config = load(root)
    config.execution.port = free_port
    import socket

    canary = socket.socket()
    canary.bind(("127.0.0.1", 0))
    canary.listen()
    canary.settimeout(0.3)
    config.execution.environment = {"CANARY_PORT": str(canary.getsockname()[1])}
    state = root / ".appsec-lab"
    store = RunStore(state)
    runtime = Runtime(root, state, "boundary-proof", config, inspect(root))
    try:
        client = runtime.start(Budget(config.limits))
        response = client.request("/egress-probe")
        assert json.loads(response.body)["egress"] == "denied"
        with pytest.raises(TimeoutError):
            canary.accept()
    finally:
        runtime.stop()
        store.close()
        canary.close()
    assert list((state / "cache").iterdir()) == []


@pytest.mark.runtime
def test_profile_exact_root_is_non_recursive(runtime_ready, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("SYNTHETIC_CANARY")
    profile = scratch / "policy.sb"
    profile.write_text(mac_profile(scratch, scratch, "/bin/cat", 8765))
    for target, expected in [(outside, False), (scratch / "inside", True)]:
        if expected:
            target.write_text("SYNTHETIC_CANARY")
        with (scratch / "out").open("wb") as output, (scratch / "err").open("wb") as errors:
            result = subprocess.run(
                ["sandbox-exec", "-f", str(profile), "/bin/cat", str(target)],
                stdout=output,
                stderr=errors,
            )
        assert (result.returncode == 0) == expected


@pytest.mark.runtime
def test_port_collision_and_no_unrelated_process_kill(runtime_ready, fixture_project, free_port):
    import socket

    root = fixture_project()
    config = load(root)
    config.execution.port = free_port
    server = socket.socket()
    server.bind(("127.0.0.1", free_port))
    server.listen()
    state = root / ".appsec-lab"
    store = RunStore(state)
    runtime = Runtime(root, state, "collision", config, inspect(root))
    try:
        with pytest.raises(RuntimeFailure):
            runtime.start(Budget(config.limits))
        assert server.getsockname()[1] == free_port
    finally:
        runtime.stop()
        store.close()
        server.close()


def test_cleanup_rejects_unowned_resource(tmp_path):
    root = tmp_path
    state = root / ".appsec-lab"
    store = RunStore(state)
    run = state / "runs/fake"
    run.mkdir()
    (run / "runtime.json").write_text(
        json.dumps(
            {
                "owner": "another-tool",
                "scratch": str(tmp_path),
                "pid": os.getpid(),
                "stopped": False,
            }
        )
    )
    with pytest.raises(ScopeError):
        clean(root, load(root))
    assert run.exists()
    store.close()


@pytest.mark.docker
def test_docker_python_bridge(fixture_project, free_port):
    import shutil
    from local_appsec_lab.configuration import Config
    from local_appsec_lab.engine import scan

    if not shutil.which("docker"):
        pytest.skip("Docker missing")
    try:
        info = subprocess.run(
            ["docker", "image", "inspect", "python:3.13-slim"], capture_output=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("Docker unavailable")
    if info.returncode:
        pytest.skip("Docker daemon/image unavailable; never pull implicitly")
    root = fixture_project("multi-service")
    config = Config(
        execution={"backend": "docker", "command": ["python", "server.py"], "port": free_port}
    )
    result, _ = scan(root, root, config, "local-passive", True)
    assert result.metrics["services_started"] == 1 and result.metrics["cleanup_completed"]
