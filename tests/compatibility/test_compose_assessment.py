import json
import os
import subprocess

import pytest

from local_appsec_lab.configuration import load
from local_appsec_lab.engine import scan
from local_appsec_lab.errors import ScopeError
from local_appsec_lab.runtime.compose import definition


def test_compose_refuses_privilege_and_host_mounts(tmp_path):
    config = load(tmp_path)
    config.execution.compose_file = "compose.yaml"
    for field in [
        "privileged: true",
        'volumes: ["/:/host"]',
        "network_mode: host",
        "env_file: .env",
    ]:
        (tmp_path / "compose.yaml").write_text(
            "services:\n  api:\n    image: synthetic\n    " + field + "\n"
        )
        with pytest.raises(ScopeError):
            definition(tmp_path, config)


@pytest.mark.docker
def test_real_disposable_database_assessment(fixture_project, free_port):
    if not os.environ.get("APPSEC_TEST_COMPOSE"):
        pytest.skip("Explicit real database image validation only")
    root = fixture_project("database-api")
    config = load(root)
    config.execution.port = free_port
    config.execution.migrations = {
        "api": [
            "python",
            "-c",
            "import os, psycopg; c = psycopg.connect(os.environ['DATABASE_URL']); assert c.execute('SELECT count(*) FROM records').fetchone()[0] == 1; c.close()",
        ]
    }
    result, _ = scan(root, root, config, "local-active", True)
    assert result.metrics["services_started"] == 2, [
        (c.id, c.reason) for c in result.checks if c.status in {"failed", "blocked"}
    ]
    assert result.metrics["cleanup_completed"]
    confirmed = [f for f in result.findings if f.state == "confirmed"]
    assert len(confirmed) == 1 and confirmed[0].rule == "boundary:vulnerable-cross-user"
    assert not any(f.rule == "boundary:secure-cross-user" for f in result.findings)
    manifest = json.loads(next(root.glob(".appsec-lab/runs/*/runtime.json")).read_text())
    assert manifest["stopped"]
    for resource in manifest["resources"]:
        check = subprocess.run(
            [*manifest["docker_base"], resource["kind"], "inspect", resource["name"]],
            capture_output=True,
            timeout=10,
        )
        assert check.returncode != 0
    assert list((root / ".appsec-lab/cache").iterdir()) == []
