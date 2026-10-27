import time
import pytest
from local_appsec_lab.authorization import plan_digest
from local_appsec_lab.authorization import authorize
from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import AuthorizationError


def test_modes_and_authorization(tmp_path):
    config = Config()
    assert authorize(tmp_path, tmp_path, config, "review", "run", False) is None
    with pytest.raises(AuthorizationError):
        authorize(tmp_path, tmp_path, config, "local-passive", "run", False)
    with pytest.raises(AuthorizationError):
        authorize(tmp_path, tmp_path, config, "local-active", "run", False)
    record = authorize(
        tmp_path, tmp_path, config, "local-active", "run", True, reviewed_plan=plan_digest(config)
    )
    record.validate_scope(tmp_path, config, "local-active", "run")


@pytest.mark.parametrize("change", ["expiry", "source", "config", "run", "mode"])
def test_bound_approval(tmp_path, change):
    config = Config()
    record = authorize(
        tmp_path, tmp_path, config, "local-active", "run", True, reviewed_plan=plan_digest(config)
    )
    mode, run = "local-active", "run"
    if change == "expiry":
        record.expires_at = time.time() - 1
    if change == "source":
        (tmp_path / "new.py").write_text("print(1)")
    if change == "config":
        config.execution.port += 1
    if change == "run":
        run = "another"
    if change == "mode":
        mode = "local-passive"
    with pytest.raises(AuthorizationError):
        record.validate_scope(tmp_path, config, mode, run)


def test_workspace_and_existing_manifest(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    with pytest.raises(AuthorizationError):
        authorize(tmp_path, nested, Config(), "local-active", "x", True)
    config = Config(
        execution={"existing_url": "http://127.0.0.1:8765", "existing_identity": "synthetic"}
    )
    with pytest.raises(AuthorizationError):
        authorize(tmp_path, tmp_path, config, "local-active", "x", True)
