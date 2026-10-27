"""Real container assessments; never download dependencies from the engine."""

import json
import os
import shutil
import socket
import subprocess

import pytest

from local_appsec_lab.configuration import load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.engine import scan
from local_appsec_lab.findings import RunStore
from local_appsec_lab.network import Budget
from local_appsec_lab.runtime import Runtime


@pytest.fixture
def runtime_image():
    image = os.environ.get("APPSEC_TEST_IMAGE")
    if not image:
        pytest.skip("Set APPSEC_TEST_IMAGE to an explicitly prebuilt Python/Node/Flask image")
    assert shutil.which("docker"), "The requested Docker test requires Docker"
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=10)
    assert result.returncode == 0, "The requested test image must already be cached"
    return image


@pytest.mark.docker
@pytest.mark.parametrize("fixture", ["javascript-api", "python-api"])
def test_container_active_assessment(runtime_image, fixture_project, free_port, fixture):
    root = fixture_project(fixture)
    config = load(root)
    config.execution.backend = "docker"
    config.execution.image = runtime_image
    config.execution.port = free_port
    result, _ = scan(root, root, config, "local-active", True)
    assert result.metrics["services_started"] == 1
    assert result.metrics["http_requests"] >= 10
    confirmed = [finding for finding in result.findings if finding.state == "confirmed"]
    assert len(confirmed) == 1 and confirmed[0].rule == "boundary:vulnerable-cross-user"
    assert confirmed[0].verification[-1]["new_observation"]["violation"]
    assert not any(f.rule == "boundary:secure-cross-user" for f in result.findings)
    assert result.metrics["cleanup_completed"]
    assert list((root / ".appsec-lab/cache").iterdir()) == []
    manifest = json.loads(next(root.glob(".appsec-lab/runs/*/runtime.json")).read_text())
    assert manifest["stopped"]
    check = subprocess.run(
        [*manifest["docker_base"], "inspect", manifest["owner"]], capture_output=True, timeout=10
    )
    assert check.returncode != 0 and b"no such" in check.stderr.lower()


@pytest.mark.docker
def test_container_cannot_reach_host_loopback(runtime_image, fixture_project, free_port):
    root = fixture_project()
    config = load(root)
    config.execution.backend = "docker"
    config.execution.image = runtime_image
    config.execution.port = free_port
    state = root / ".appsec-lab"
    with socket.socket() as canary:
        canary.bind(("127.0.0.1", 0))
        canary.listen()
        canary.settimeout(0.3)
        config.execution.environment = {"CANARY_PORT": str(canary.getsockname()[1])}
        store = RunStore(state)
        runtime = Runtime(root, state, "docker-egress-proof", config, inspect(root))
        try:
            client = runtime.start(Budget(config.limits))
            assert json.loads(client.request("/egress-probe").body)["egress"] == "denied"
            with pytest.raises(TimeoutError):
                canary.accept()
        finally:
            runtime.stop()
            store.close()
        assert runtime.cleaned and not runtime.scratch.exists()
