import subprocess
import time

import pytest
from pydantic import ValidationError

from local_appsec_lab.agents import assignments, validate_results
from local_appsec_lab.configuration import Config, Execution, Limits, Scenario, load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.dynamic_tests import run, scenario_observation
from local_appsec_lab.errors import BudgetExceeded, RollbackFailure, RuntimeFailure
from local_appsec_lab.findings import RunStore
from local_appsec_lab.isolation import docker_control
from local_appsec_lab.models import Finding, Source
from local_appsec_lab.network import Budget, Response
from local_appsec_lab.runtime import Runtime
from local_appsec_lab.verification import verify


def boundary_finding():
    return Finding(
        rule="boundary:synthetic",
        title="synthetic",
        category="authentication",
        severity="high",
        severity_reason="synthetic policy",
        description="synthetic",
        expected="denied",
        observed="candidate",
    )


def test_model_rule_cannot_dispatch_active_verification(tmp_path):
    (tmp_path / "app.py").write_text("pass")
    task = next(
        t
        for t in assignments(tmp_path, inspect(tmp_path), Config(categories=["input_data_flow"]))
        if t["role"] == "data_flow"
    )
    finding = boundary_finding()
    finding.category = "input_data_flow"
    finding.source = Source(path="app.py", line=1, end_line=1)
    result = validate_results(tmp_path, task, [finding.model_dump()])[0]
    assert result.rule.startswith("model:data_flow:boundary:")
    assert result.provenance == "ai:data_flow" and result.state == "candidate"


@pytest.mark.parametrize(
    "mode,categories,provenance",
    [
        ("local-passive", ("authentication",), "builtin"),
        ("local-active", (), "builtin"),
        ("local-active", ("authentication",), "ai:api"),
    ],
)
def test_verifier_final_policy_gate(tmp_path, mode, categories, provenance):
    config = Config(
        scenarios=[
            {
                "id": "synthetic",
                "path": "/record",
                "category": "authentication",
                "marker": "SYNTHETIC",
                "owner_headers": {"X-Test-User": "alice"},
            }
        ]
    )

    class ForbiddenClient:
        def request(self, *args, **kwargs):
            raise AssertionError("Policy gate bypass")

    finding = boundary_finding()
    finding.provenance = provenance
    verify(finding, tmp_path, config, ForbiddenClient(), mode, categories)
    assert finding.state == "blocked"


def test_authentication_500_is_not_confirmed_bypass():
    class FakeClient:
        budget = Budget(Limits())
        calls = 0

        def request(self, *args, **kwargs):
            self.budget.claim()
            self.calls += 1
            return Response(
                200 if self.calls == 1 else 500,
                {},
                b"SYNTHETIC" if self.calls == 1 else b"error",
                False,
            )

    scenario = Scenario(
        id="synthetic",
        path="/record",
        category="authentication",
        marker="SYNTHETIC",
        owner_headers={"X-Test-User": "alice"},
    )
    assert not scenario_observation(FakeClient(), scenario)["violation"]


def test_mutation_reserves_rollback_before_any_request():
    class FakeClient:
        budget = Budget(Limits(max_requests=2))

        def request(self, *args, **kwargs):
            raise AssertionError("Mutation before reservation")

    scenario = Scenario(
        id="synthetic",
        path="/record",
        category="validation",
        method="POST",
        disposable=True,
        rollback_path="/record",
    )
    with pytest.raises(BudgetExceeded):
        scenario_observation(FakeClient(), scenario)


def test_rollback_failure_stops_all_later_scenarios():
    seen = []

    class FakeClient:
        budget = Budget(Limits(requests_per_second=10))

        def request(self, path, headers=None, method="GET", body=None):
            self.budget.claim()
            seen.append((method, path))
            return Response(
                500 if method == "DELETE" else 200,
                {"content-type": "application/json"},
                b"{}",
                False,
            )

    config = Config(
        scenarios=[
            {
                "id": "first",
                "path": "/record",
                "category": "validation",
                "method": "POST",
                "disposable": True,
                "rollback_path": "/record",
            },
            {"id": "later", "path": "/must-not-run", "category": "validation"},
        ]
    )
    with pytest.raises(RollbackFailure):
        run(FakeClient(), config, [], "local-active", ["validation"])
    assert ("DELETE", "/record") in seen and not any(path == "/must-not-run" for _, path in seen)


def test_rate_limit_cannot_sleep_beyond_deadline():
    budget = Budget(Limits(duration_seconds=5, requests_per_second=0.000001))
    budget.last_request = time.monotonic()
    started = time.monotonic()
    with pytest.raises(BudgetExceeded):
        budget.claim()
    assert time.monotonic() - started < 0.1


@pytest.mark.parametrize("name", ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"])
def test_app_environment_cannot_redirect_host_docker(name):
    with pytest.raises(ValidationError):
        Execution(environment={name: "untrusted"})


def test_docker_control_pins_local_daemon_and_ignores_ambient_override(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://unapproved.invalid:2375")
    observed = []

    def local(args, **kwargs):
        observed.append(kwargs["env"])
        return subprocess.CompletedProcess(args, 0, b"unix:///synthetic/docker.sock\n", b"")

    monkeypatch.setattr(subprocess, "run", local)
    base, env = docker_control()
    assert base == ["docker", "--host", "unix:///synthetic/docker.sock"]
    assert "DOCKER_HOST" not in observed[0]
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, 0, b"tcp://unapproved.invalid:2375\n", b""
        ),
    )
    with pytest.raises(RuntimeFailure):
        docker_control()


def test_repo_config_cannot_select_model_credential():
    with pytest.raises(ValidationError):
        Config(ai={"api_key_env": "UNRELATED_CREDENTIAL"})


@pytest.mark.runtime
def test_cleanup_surviving_child_after_leader_exit(runtime_ready, fixture_project, free_port):
    root = fixture_project()
    config = load(root)
    config.execution.backend = "macos"
    config.execution.port = free_port
    source = root / "server.js"
    source.write_text("""const http=require('node:http');const cp=require('node:child_process');
const child=cp.spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
const server=http.createServer((req,res)=>{res.end('healthy');if(req.url==='/exit')setTimeout(()=>process.exit(0),20)});
server.listen(Number(process.env.PORT),'127.0.0.1');
""")
    state = root / ".appsec-lab"
    store = RunStore(state)
    runtime = Runtime(root, state, "child-cleanup", config, inspect(root))
    try:
        client = runtime.start(Budget(config.limits))
        client.request("/exit")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not runtime.cleaned:
            time.sleep(0.1)
        runtime.stop()
        assert runtime.cleaned and not runtime._group_alive()
        assert not runtime.scratch.exists()
    finally:
        runtime.stop()
        store.close()


@pytest.mark.runtime
def test_passive_runtime_never_grants_mutation_capability(
    runtime_ready, fixture_project, free_port
):
    root = fixture_project()
    config = load(root)
    config.execution.backend = "macos"
    config.execution.port = free_port
    config.scenarios.append(
        Scenario(
            id="mutation",
            path="/record",
            category="validation",
            method="POST",
            disposable=True,
            rollback_path="/record",
        )
    )
    state = root / ".appsec-lab"
    store = RunStore(state)
    runtime = Runtime(root, state, "passive-capabilities", config, inspect(root))
    try:
        client = runtime.start(Budget(config.limits))
        assert client.allowed_mutations == set()
    finally:
        runtime.stop()
        store.close()


def test_expiry_is_checked_at_every_request_claim():
    budget = Budget(Limits(), expires_at=time.time() - 1)
    with pytest.raises(BudgetExceeded):
        budget.claim()


def test_failed_owner_baseline_never_sends_actor_request():
    class FakeClient:
        budget = Budget(Limits())
        calls = 0

        def request(self, *args, **kwargs):
            self.budget.claim()
            self.calls += 1
            return Response(401, {}, b"not seeded", False)

    client = FakeClient()
    scenario = Scenario(
        id="synthetic",
        path="/record",
        category="authentication",
        marker="SYNTHETIC",
        owner_headers={"X-Test-User": "alice"},
    )
    observation = scenario_observation(client, scenario)
    assert not observation["owner_precondition"] and not observation["violation"]
    assert client.calls == 1


def test_identical_synthetic_identities_are_invalid():
    with pytest.raises(ValidationError):
        Scenario(id="same-actor", path="/record", category="authorization", marker="SYNTHETIC")


def test_yaml_alias_and_error_input_redaction(tmp_path):
    (tmp_path / "appsec-lab.yaml").write_text("version: 1\nscenarios: &a [*a]")
    from local_appsec_lab.errors import ConfigError

    with pytest.raises(ConfigError):
        load(tmp_path)
    (tmp_path / "appsec-lab.yaml").write_text('limits: {max_requests: "SYNTHETIC_SECRET_INPUT"}')
    with pytest.raises(ConfigError) as caught:
        load(tmp_path)
    assert "limits.max_requests" in str(caught.value)
    assert "SYNTHETIC_SECRET_INPUT" not in str(caught.value)
