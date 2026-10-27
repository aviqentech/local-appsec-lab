import json
import os
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError

from local_appsec_lab.agents.native import bounded_run
from local_appsec_lab.authorization import authorize
from local_appsec_lab.configuration import Config
from local_appsec_lab.discovery import inspect
from local_appsec_lab.dynamic_tests.adaptive import run as adaptive
from local_appsec_lab.errors import BudgetExceeded, ScopeError
from local_appsec_lab.models import Check
from local_appsec_lab.network import Response
from local_appsec_lab.utilities.files import read_text
from local_appsec_lab.utilities.redaction import redact


@pytest.mark.parametrize("key", ["refresh_token", "password", "api_key"])
def test_json_credentials_are_redacted_before_model_context(key):
    assert "DUMMY_VALUE_123456" not in redact(json.dumps({key: "DUMMY_VALUE_123456"}))
    assert (
        "DUMMY_VALUE_123456"
        not in redact({"source": json.dumps({key: "DUMMY_VALUE_123456"})})["source"]
    )


def test_custom_state_excluded_from_discovery_and_approval(tmp_path):
    (tmp_path / "app.py").write_text("pass")
    config = Config(output="./assessment-state/")
    approval = authorize(tmp_path, tmp_path, config, "local-active", "test", True)
    state = tmp_path / config.output
    state.mkdir()
    (state / "oauth.json").write_text('{"refresh_token":"DUMMY_CREDENTIAL"}')
    assert inspect(tmp_path, config.output)["files"] == ["app.py"]
    approval.validate_scope(tmp_path, config, "local-active", "test")
    with pytest.raises(ValidationError):
        Config(output=".")


def test_pipe_stall_obeys_timeout_during_prompt_write(tmp_path):
    started = time.monotonic()
    with pytest.raises(BudgetExceeded):
        bounded_run(
            [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
            "x" * 500000,
            tmp_path,
            {"PATH": os.environ.get("PATH", "")},
            0.2,
        )
    assert time.monotonic() - started < 4


def test_adaptive_proposals_cannot_expand_scope_or_repeat_checks():
    class Client:
        paths = []

        def request(self, path, headers):
            self.paths.append(path)
            return Response(200, {}, b"synthetic", False)

    client = Client()
    proposals = [
        {"path": path, "category": category}
        for path, category in [
            ("http://example.invalid/", "headers"),
            ("/unlisted", "headers"),
            ("/known", "authentication"),
            ("/done", "headers"),
            ("/known", "headers"),
            ("/known", "headers"),
        ]
    ]
    results = adaptive(
        client,
        proposals,
        [{"path": "/known", "method": "GET"}, {"path": "/done", "method": "GET"}],
        [Check(id="done", category="headers", target="/done", status="completed")],
        "local-active",
        ["headers"],
        True,
    )
    assert client.paths == ["/known"]
    assert sum(c.status == "blocked" for c in results) == 3
    assert sum(c.status == "completed" for c in results) == 1


def test_source_directory_symlink_cannot_redirect_read(tmp_path):
    outside = tmp_path / "outside"
    root = tmp_path / "root"
    outside.mkdir()
    root.mkdir()
    (outside / "private.txt").write_text("PRIVATE_CANARY")
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation requires Windows developer mode or equivalent permission")
    with pytest.raises(ScopeError):
        read_text(root, "linked/private.txt")


@pytest.mark.skipif(os.name != "nt", reason="Native Windows junction contract")
def test_windows_junction_is_not_a_source_directory(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "private.txt").write_text("PRIVATE_CANARY")
    linked = root / "linked"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(linked), str(outside)], capture_output=True
    )
    assert result.returncode == 0
    try:
        assert inspect(root)["files"] == []
        with pytest.raises(ScopeError):
            read_text(root, "linked/private.txt")
    finally:
        linked.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Native Windows private ACL contract")
def test_windows_artifacts_have_protected_user_system_acl(tmp_path):
    from local_appsec_lab.utilities.files import private_dir
    from local_appsec_lab.utilities.windows_files import current_sid

    directory = private_dir(tmp_path / "private-state")
    env = dict(os.environ, APPSEC_ACL_TEST_PATH=str(directory))
    script = """$acl = Get-Acl -LiteralPath $env:APPSEC_ACL_TEST_PATH
@{protected=$acl.AreAccessRulesProtected; identities=@($acl.Access | ForEach-Object {$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value})} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        env=env,
        timeout=20,
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["protected"]
    assert set(value["identities"]) == {"S-1-5-18", current_sid()}
