import os

import pytest
from pydantic import ValidationError

from local_appsec_lab.configuration import BrowserWorkflow, load
from local_appsec_lab.engine import scan


def test_browser_mutations_require_disposable_rollback():
    with pytest.raises(ValidationError):
        BrowserWorkflow(
            id="unsafe", path="/", allowed_mutations=[{"method": "POST", "path": "/record"}]
        )


@pytest.mark.docker
def test_real_browser_workflow(fixture_project, free_port):
    image = os.environ.get("APPSEC_TEST_BROWSER_IMAGE")
    if not image:
        pytest.skip("Explicit preloaded browser image validation only")
    root = fixture_project("frontend")
    config = load(root)
    config.execution.backend = "docker"
    config.execution.image = image
    config.execution.port = free_port
    config.limits.processes = 128
    config.limits.memory_mb = 1024
    config.limits.storage_mb = 256
    config.browser = True
    config.browser_workflows = [
        BrowserWorkflow(
            id="rendered-page",
            path="/html-secure",
            steps=[{"action": "expect_text", "selector": "h1", "value": "Local security fixture"}],
        )
    ]
    result, _ = scan(root, root, config, "local-active", True)
    checks = [c for c in result.checks if c.id.startswith("browser:")]
    assert checks and checks[0].status == "completed", [
        (c.status, c.reason, c.observations) for c in checks
    ]
    observation = checks[0].observations[0]
    assert observation["screenshot_bytes"] > 0 and len(observation["screenshot_sha256"]) == 64
    assert observation["artifact_policy"].startswith("hash-only")
    assert result.metrics["browser_workflows"] == 1 and result.metrics["cleanup_completed"]
