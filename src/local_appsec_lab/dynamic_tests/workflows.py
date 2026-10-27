"""Explicit synthetic state machines; values stay in memory and rollback is reserved first."""

import json
import re
from urllib.parse import quote

from local_appsec_lab.errors import ConfigError, LabError, RollbackFailure
from local_appsec_lab.models import Check, Finding


def render(value, variables, path=False):
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    if not isinstance(value, str):
        return value

    def replace(match):
        if match[1] not in variables:
            raise ConfigError("Workflow variable has not been captured")
        result = str(variables[match[1]])
        return quote(result, safe="") if path else result

    return re.sub(r"\{\{([a-z][a-z0-9_]{0,31})\}\}", replace, value)


def observe(client, workflow):
    variables, observations, violations = {}, [], []
    original = set(client.allowed_mutations)

    def request(step):
        path = render(step.path, variables, path=True)
        client.allowed_mutations = {(step.method, path)} if step.method != "GET" else set()
        return client.request(
            path,
            render(workflow.identities[step.identity], variables),
            step.method,
            render(step.body, variables),
        )

    with client.budget.reserve(len(workflow.steps) + 1):
        try:
            for step in workflow.steps:
                response = request(step)
                matched = response.status in step.expected_status
                marker = bool(
                    step.marker and step.marker.encode() in response.body and not response.truncated
                )
                observation = {
                    "step": step.id,
                    "method": step.method,
                    "path_template": step.path,
                    "expected_status": step.expected_status,
                    "matched": matched,
                    "security_assertion": step.security_assertion,
                    "response": response.evidence(step.marker),
                }
                observations.append(observation)
                if (
                    step.security_assertion
                    and not matched
                    and marker
                    and 200 <= response.status < 300
                ):
                    violations.append(step.id)
                elif not matched and not step.security_assertion:
                    return {"baseline": False, "steps": observations, "violations": []}
                if step.capture:
                    data = json.loads(response.body)
                    for name, pointer in step.capture.items():
                        value = data
                        for key in pointer.split("/")[1:]:
                            value = value[int(key)] if isinstance(value, list) else value[key]
                        if (
                            not isinstance(value, (str, int))
                            or isinstance(value, bool)
                            or len(str(value)) > 256
                        ):
                            raise ConfigError("Workflow captured value exceeds the scalar budget")
                        variables[name] = value
            return {"baseline": True, "steps": observations, "violations": violations}
        finally:
            try:
                response = request(workflow.rollback)
                if response.status not in workflow.rollback.expected_status:
                    raise RollbackFailure(
                        "Synthetic workflow rollback returned an unexpected status"
                    )
            except (LabError, OSError, KeyError, ValueError) as exc:
                raise RollbackFailure(
                    "Synthetic workflow rollback failed; stop dynamic testing"
                ) from exc
            finally:
                client.allowed_mutations = original


def run(client, config, mode, categories, owned):
    findings, checks = [], []
    for workflow in config.workflows:
        check = Check(id="workflow:" + workflow.id, category=workflow.category, status="not_tested")
        if mode != "local-active" or workflow.category not in categories or not owned:
            check.reason = "Stateful workflows require an owned disposable runtime and active category authorization"
            checks.append(check)
            continue
        try:
            observation = observe(client, workflow)
            check.status = "completed" if observation["baseline"] else "blocked"
            check.reason = "Explicit synthetic workflow; captured values retained only in memory"
            check.observations = [observation]
            for step in observation["violations"]:
                findings.append(
                    Finding(
                        rule="workflow:" + workflow.id + ":" + step,
                        title="Synthetic workflow policy violated: " + step,
                        category=workflow.category,
                        severity="high",
                        severity_reason="A disallowed synthetic operation returned the configured protected success marker.",
                        description="The configured workflow baseline succeeded but a security transition assertion failed.",
                        expected="The explicit workflow transition and principal policy is enforced.",
                        observed="Unexpected success status and protected inert marker at step "
                        + step,
                        evidence=[observation],
                        remediation="Enforce principal and state preconditions transactionally before this operation.",
                        regression="Replay this workflow with the same owner/actor controls after the correction.",
                        limitations=[
                            "The expected business policy and synthetic fixtures are explicitly developer supplied."
                        ],
                    )
                )
        except RollbackFailure:
            raise
        except (LabError, OSError, KeyError, ValueError) as exc:
            check.status, check.reason = "blocked", type(exc).__name__
        checks.append(check)
    return findings, checks
