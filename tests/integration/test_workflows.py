import os

import pytest

from local_appsec_lab.authorization import plan_digest
from local_appsec_lab.configuration import Config, StatefulWorkflow
from local_appsec_lab.dynamic_tests.fuzz import cases
from local_appsec_lab.dynamic_tests.workflows import observe
from local_appsec_lab.engine import scan
from local_appsec_lab.errors import BudgetExceeded, RollbackFailure
from local_appsec_lab.network import Budget, Response


def workflow(secure=False):
    return StatefulWorkflow(
        id="secure" if secure else "vulnerable",
        synthetic=True,
        disposable=True,
        identities={"owner": {"X-Test-User": "alice"}, "actor": {"X-Test-User": "bob"}},
        steps=[
            {
                "id": "create",
                "path": "/records",
                "method": "POST",
                "expected_status": [201],
                "capture": {"record": "/id"},
            },
            {
                "id": "release",
                "path": "/records/{{record}}/" + ("secure-release" if secure else "release"),
                "method": "POST",
                "identity": "actor",
                "expected_status": [403],
                "marker": "SYNTHETIC_RELEASED",
                "security_assertion": True,
            },
            {
                "id": "state",
                "path": "/records/{{record}}",
                "expected_status": [200],
                "marker": "SYNTHETIC_RECORD",
            },
        ],
        rollback={
            "id": "rollback",
            "path": "/records/{{record}}",
            "method": "DELETE",
            "expected_status": [200],
        },
    )


def test_workflow_reserves_before_mutation_and_halts_failed_rollback():
    class Client:
        allowed_mutations = set()
        budget = Budget(Config(limits={"max_requests": 3}).limits)

        def request(self, *args):
            pytest.fail("No request before complete workflow reservation")

    with pytest.raises(BudgetExceeded):
        observe(Client(), workflow())

    class FailingClient:
        allowed_mutations = set()
        budget = Budget(Config(limits={"max_requests": 10}).limits)

        def request(self, path, headers, method, body):
            self.budget.claim()
            return Response(
                500 if method == "DELETE" else 201 if path == "/records" else 403,
                {},
                b'{"id":42}',
                False,
            )

    with pytest.raises(RollbackFailure):
        observe(FailingClient(), workflow())


def test_fuzz_cases_are_invalid_small_and_bounded():
    import jsonschema

    schema = {"type": "integer", "minimum": 1, "maximum": 10}
    valid, invalid = cases(schema, 3)
    assert jsonschema.Draft202012Validator(schema).is_valid(valid)
    assert len(invalid) == 3 and all(
        not jsonschema.Draft202012Validator(schema).is_valid(x) for x in invalid
    )
    assert max(len(str(value)) for value in invalid) <= 129


@pytest.mark.docker
def test_real_stateful_and_fuzz_controls(fixture_project, free_port):
    image = os.environ.get("APPSEC_TEST_IMAGE")
    if not image:
        pytest.skip("Explicit preloaded runtime image required")
    root = fixture_project("stateful-api")
    config = Config(
        execution={
            "backend": "docker",
            "image": image,
            "command": ["python", "server.py"],
            "port": free_port,
        },
        limits={"requests_per_second": 10, "processes": 64},
        workflows=[workflow(), workflow(True)],
        fuzz_targets=[
            {
                "id": "secure",
                "path": "/validate",
                "parameter": "count",
                "input_schema": {"type": "integer", "minimum": 1, "maximum": 10},
            },
            {
                "id": "vulnerable",
                "path": "/validate-vulnerable",
                "parameter": "count",
                "input_schema": {"type": "integer", "minimum": 1, "maximum": 10},
            },
        ],
    )
    report, _ = scan(root, root, config, "local-active", True, reviewed_plan=plan_digest(config))
    assert report.metrics["cleanup_completed"] and report.metrics["services_started"] == 1
    assert [f.rule for f in report.findings if f.state == "confirmed"] == [
        "workflow:vulnerable:release"
    ]
    assert not any(f.rule.startswith(("workflow:secure:", "fuzz:secure")) for f in report.findings)
    assert any(f.rule == "fuzz:vulnerable" and f.state == "candidate" for f in report.findings)
