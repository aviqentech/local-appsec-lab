from pathlib import Path
import platform
import shutil
import socket

import pytest

from local_appsec_lab.isolation import sandbox_probe

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def private_cache_key(tmp_path, monkeypatch):
    import uuid

    monkeypatch.setenv(
        "APPSEC_CACHE_KEY_FILE", str(tmp_path.parent / ("analysis-" + uuid.uuid4().hex + ".key"))
    )


@pytest.fixture
def fixture_project(tmp_path):
    def copy(name="javascript-api"):
        destination = tmp_path / name
        shutil.copytree(
            ROOT / "tests" / "fixtures" / name,
            destination,
            ignore=shutil.ignore_patterns(".appsec-lab", "__pycache__"),
        )
        return destination.resolve()

    return copy


@pytest.fixture
def free_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


@pytest.fixture
def runtime_ready():
    if platform.system() != "Darwin":
        pytest.skip("Live macOS runtime suite; Docker has a separate integration test")
    from local_appsec_lab.configuration import Config

    if not sandbox_probe(Config(execution={"backend": "macos"}))["available"]:
        pytest.skip("OS sandbox unavailable inside nested sandbox")
    if not shutil.which("node"):
        pytest.skip("Node runtime missing")
