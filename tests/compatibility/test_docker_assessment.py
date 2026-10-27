"""Real container assessments; never download dependencies from the engine."""

import json
import os
import shutil
import socket
import subprocess

import pytest

from local_appsec_lab.authorization import plan_digest
from local_appsec_lab.configuration import load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.engine import scan
from local_appsec_lab.findings import RunStore
from local_appsec_lab.isolation import docker_control, local_image
from local_appsec_lab.network import Budget
from local_appsec_lab.runtime import Runtime


@pytest.fixture
def runtime_image():
    image = os.environ.get("APPSEC_TEST_IMAGE")
    if not image:
        pytest.skip("Set APPSEC_TEST_IMAGE to an explicitly prebuilt Python/Node/Flask image")
    assert shutil.which("docker"), "The requested Docker test requires Docker"
    base, env = docker_control()
    local_image(base, env, image)
    return image


@pytest.mark.docker
@pytest.mark.parametrize("fixture", ["javascript-api", "python-api"])
def test_container_active_assessment(runtime_image, fixture_project, free_port, fixture):
    root = fixture_project(fixture)
    config = load(root)
    config.execution.backend = "docker"
    config.execution.image = runtime_image
    config.execution.port = free_port
    result, _ = scan(root, root, config, "local-active", True, reviewed_plan=plan_digest(config))
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


@pytest.mark.docker
def test_application_cannot_open_observer_protocol(runtime_image, fixture_project, free_port):
    from local_appsec_lab.configuration import Config

    root = fixture_project("multi-service")
    (root / "server.py").write_text("""import os
from http.server import HTTPServer, BaseHTTPRequestHandler
try:
    fd = os.open('/proc/' + str(os.getppid()) + '/fd/1', os.O_WRONLY)
except PermissionError:
    denied = True
else:
    os.close(fd)
    denied = False
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if denied else 500)
        self.end_headers()
        self.wfile.write(b'observer-protected' if denied else b'failed')
HTTPServer(('127.0.0.1', int(os.environ['PORT'])), Handler).serve_forever()
""")
    config = Config(
        execution={
            "backend": "docker",
            "image": runtime_image,
            "command": ["python", "server.py"],
            "port": free_port,
        }
    )
    store = RunStore(root / ".appsec-lab")
    runtime = Runtime(root, store.state, "observer-boundary", config, inspect(root))
    try:
        client = runtime.start(Budget(config.limits))
        assert client.request("/health").body == b"observer-protected"
    finally:
        runtime.stop()
        store.close()
    assert runtime.cleaned
