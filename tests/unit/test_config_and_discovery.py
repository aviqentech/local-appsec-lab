import json

import pytest
from pydantic import ValidationError

from local_appsec_lab.configuration import Execution, Limits, Scenario, load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.errors import ConfigError


@pytest.mark.parametrize("value", [0, -1, 1001])
def test_request_budget_bounds(value):
    with pytest.raises(ValidationError):
        Limits(max_requests=value)


@pytest.mark.parametrize(
    "key", ["PATH", "HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "NODE_OPTIONS"]
)
def test_environment_overrides(key):
    with pytest.raises(ValidationError):
        Execution(environment={key: "unsafe"})


def test_unknown_config_and_yaml_object(tmp_path):
    (tmp_path / "appsec-lab.yaml").write_text("authorization: true")
    with pytest.raises(ConfigError):
        load(tmp_path)
    (tmp_path / "appsec-lab.yaml").write_text("!!python/object/apply:os.system [echo nope]")
    with pytest.raises(ConfigError):
        load(tmp_path)


def test_cli_precedence(tmp_path):
    (tmp_path / "appsec-lab.yaml").write_text("limits: {max_requests: 20}\nfail_on: low")
    config = load(tmp_path, overrides={"fail_on": "critical"})
    assert config.fail_on == "critical" and config.limits.max_requests == 20


def test_state_change_requires_contract():
    with pytest.raises(ValidationError):
        Scenario(id="mutation", path="/record", category="validation", method="POST")
    assert Scenario(
        id="mutation",
        path="/record",
        category="validation",
        method="POST",
        disposable=True,
        rollback_path="/record",
    ).disposable


def test_boundary_requires_marker():
    with pytest.raises(ValidationError):
        Scenario(id="ownership", path="/record", category="authorization")


def test_javascript_and_python_detection(fixture_project):
    node = inspect(fixture_project())
    python = inspect(fixture_project("python-api"))
    assert "JavaScript" in node["languages"] and len(node["routes"]) == 8
    assert node["services"][0]["command"] == ["node", "server.js"]
    assert "Flask" in python["frameworks"] and "pip" in python["package_managers"]
    assert any(r["path"] == "/records/secure/42" for r in python["routes"])


def test_compose_graph_and_unsupported(fixture_project):
    compose = inspect(fixture_project("multi-service"))
    assert "database" in compose["service_graph"]["api"]
    unsupported = inspect(fixture_project("unsupported"))
    assert "Kotlin" in unsupported["languages"]


@pytest.mark.parametrize(
    "name,framework",
    [
        ("next", "Next.js"),
        ("react", "React"),
        ("vite", "Vite"),
        ("vue", "Vue"),
        ("nuxt", "Nuxt"),
        ("@angular/core", "Angular"),
        ("express", "Express"),
        ("@nestjs/core", "NestJS"),
        ("fastify", "Fastify"),
        ("@sveltejs/kit", "SvelteKit"),
    ],
)
def test_framework_manifest_detection(tmp_path, name, framework):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: "1.0.0"}}))
    assert framework in inspect(tmp_path)["frameworks"]


def test_locked_dependencies(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/example": {"version": "1.2.3"}}})
    )
    (tmp_path / "requirements.txt").write_text("Flask==3.1.3\n")
    deps = inspect(tmp_path)["dependencies"]
    assert {(d["name"], d["version"]) for d in deps} == {("example", "1.2.3"), ("Flask", "3.1.3")}
