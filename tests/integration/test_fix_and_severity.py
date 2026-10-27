import json

import pytest

from local_appsec_lab.errors import AuthorizationError, ConfigError, ScopeError
from local_appsec_lab.intelligence.severity import calculate
from local_appsec_lab.remediation.patches import apply, prepare
from local_appsec_lab.scanners import scan_source
from local_appsec_lab.utilities.files import private_dir


def test_explicit_cvss4_vector_and_missing_metrics():
    result = calculate(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "synthetic explicit vector",
    )
    assert result["score"] == 9.3 and result["severity"] == "critical"
    with pytest.raises(ConfigError):
        calculate("CVSS:4.0/AV:N", "incomplete")


def test_fix_preparation_apply_consent_and_rollback(tmp_path):
    path = tmp_path / "app.py"
    original = b'app.run(host="127.0.0.1", debug=True)\n'
    path.write_bytes(original)
    state = private_dir(tmp_path / ".appsec-lab")
    findings, _ = scan_source(tmp_path, {"files": ["app.py"]}, ["configuration"])
    finding = findings[0].identify(str(tmp_path))
    plan = prepare(tmp_path, state, finding)
    assert path.read_bytes() == original and plan["state"] == "prepared"
    assert "debug=False" in (state / "fixes" / plan["id"] / "change.patch").read_text()
    with pytest.raises(AuthorizationError):
        apply(tmp_path, state, plan["id"], False)
    apply(tmp_path, state, plan["id"], True)
    assert b"debug=False" in path.read_bytes()
    assert scan_source(tmp_path, {"files": ["app.py"]}, ["configuration"])[0] == []
    apply(tmp_path, state, plan["id"], True, rollback=True)
    assert path.read_bytes() == original
    assert (
        json.loads((state / "fixes" / plan["id"] / "plan.json").read_text())["state"]
        == "rolled_back"
    )


def test_fix_refuses_source_drift_and_tampered_bundle(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("app.run(debug=True)\n")
    state = private_dir(tmp_path / ".appsec-lab")
    finding = scan_source(tmp_path, {"files": ["app.py"]}, ["configuration"])[0][0]
    plan = prepare(tmp_path, state, finding)
    path.write_text("# unrelated user edit\napp.run(debug=True)\n")
    with pytest.raises((ScopeError, ConfigError)):
        apply(tmp_path, state, plan["id"], True)
