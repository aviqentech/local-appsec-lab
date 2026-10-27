import os
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from local_appsec_lab.authorization import plan_digest
from local_appsec_lab.configuration import Config
from local_appsec_lab.engine import scan


def test_experimental_bubblewrap_bridge(fixture_project, free_port):
    if platform.system() != "Linux" or not os.environ.get("APPSEC_TEST_BWRAP"):
        pytest.skip("Explicit native Linux bubblewrap validation only")
    assert shutil.which("bwrap"), "The explicit test requires bubblewrap to be installed"
    probe = ["bwrap", "--unshare-all"]
    for path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(path).exists():
            probe += ["--ro-bind", path, path]
    result = subprocess.run([*probe, "/usr/bin/true"], capture_output=True, timeout=10)
    if result.returncode:
        pytest.skip("Runner blocks bubblewrap namespaces: " + result.stderr.decode()[:500])
    root = fixture_project("multi-service")
    config = Config(
        execution={"backend": "bubblewrap", "command": ["python", "server.py"], "port": free_port}
    )
    result, _ = scan(root, root, config, "local-passive", True, reviewed_plan=plan_digest(config))
    assert result.metrics["services_started"] == 1
    assert result.metrics["cleanup_completed"]
