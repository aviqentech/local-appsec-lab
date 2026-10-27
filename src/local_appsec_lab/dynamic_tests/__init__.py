from __future__ import annotations

import time
from urllib.parse import quote

from local_appsec_lab.configuration import Config, Scenario
from local_appsec_lab.errors import LabError, RollbackFailure
from local_appsec_lab.models import Check, Finding, now
from local_appsec_lab.network import Client


def scenario_observation(client: Client, scenario: Scenario) -> dict:
    count = 3 if scenario.method != "GET" else 2
    with client.budget.reserve(count):
        return _scenario_observation(client, scenario)


def _scenario_observation(client: Client, scenario: Scenario) -> dict:
    started = time.monotonic()
    try:
        owner = client.request(
            scenario.path, scenario.owner_headers, scenario.method, scenario.body
        )
        owner_precondition = owner.status == scenario.owner_status and (
            not scenario.marker or scenario.marker.encode() in owner.body
        )
        if not owner_precondition:
            return {
                "test_id": scenario.id,
                "category": scenario.category,
                "method": scenario.method,
                "path": scenario.path,
                "timestamp": now(),
                "owner": owner.evidence(scenario.marker),
                "actor": {"not_executed": "Owner baseline failed"},
                "owner_precondition": False,
                "expected_status": scenario.expected_status,
                "violation": False,
                "duration_seconds": time.monotonic() - started,
            }
        actor = client.request(
            scenario.path, scenario.actor_headers, scenario.method, scenario.body
        )
        owner_ok = owner.status == scenario.owner_status and (
            not scenario.marker or scenario.marker.encode() in owner.body
        )
        violation = owner_ok and actor.status not in scenario.expected_status
        if scenario.category in {
            "authorization",
            "tenant_isolation",
            "business_logic",
            "authentication",
        }:
            violation = (
                violation
                and 200 <= actor.status < 300
                and actor.status == scenario.owner_status
                and bool(scenario.marker and scenario.marker.encode() in actor.body)
                and not actor.truncated
            )
        return {
            "test_id": scenario.id,
            "category": scenario.category,
            "method": scenario.method,
            "path": scenario.path,
            "timestamp": now(),
            "owner": owner.evidence(scenario.marker),
            "actor": actor.evidence(scenario.marker),
            "owner_precondition": owner_ok,
            "expected_status": scenario.expected_status,
            "violation": violation,
            "actor_identity": "configured-synthetic-actor",
            "duration_seconds": time.monotonic() - started,
            "limitations": "Expected policy and fixture ownership are supplied by the developer.",
        }
    finally:
        if scenario.method != "GET" and scenario.rollback_path:
            try:
                result = client.request(scenario.rollback_path, scenario.owner_headers, "DELETE")
            except (OSError, LabError) as exc:
                raise RollbackFailure(
                    "Scenario rollback failed; all dynamic work must stop"
                ) from exc
            if result.status not in {200, 204, 404}:
                raise RollbackFailure("Scenario rollback failed; all dynamic work must stop")


def run(
    client: Client, config: Config, routes: list[dict], mode: str, allowed_categories: list[str]
) -> tuple[list[Finding], list[Check]]:
    findings, checks = [], []
    paths = sorted(
        {
            config.execution.health_path,
            *[
                r["path"]
                for r in routes
                if r["method"] == "GET" and not any(c in r["path"] for c in ("{", ":", "*", "<"))
            ],
        }
    )[:10]
    if not set(allowed_categories) & {"headers", "cors", "session"}:
        paths = []
    for path in paths:
        started = time.monotonic()
        try:
            response = client.request(path)
            checks.append(
                Check(
                    id="response:" + path,
                    category="headers",
                    status="completed",
                    target=path,
                    duration_seconds=time.monotonic() - started,
                    observations=[response.evidence()],
                )
            )
            if response.status != 200:
                continue
            missing = [
                header
                for header in ["x-content-type-options", "content-security-policy"]
                if header not in response.headers
            ]
            is_html = "text/html" in response.headers.get("content-type", "")
            if missing and is_html:
                findings.append(
                    Finding(
                        rule="response-headers",
                        title="Browser defense headers absent",
                        category="headers",
                        severity="low",
                        severity_reason="Missing browser defense in depth; no script injection is established.",
                        confidence="high",
                        state="informational",
                        endpoint=path,
                        description="An HTML response omitted common browser defense headers.",
                        expected="Set a suitable CSP and X-Content-Type-Options: nosniff.",
                        observed="Missing: " + ", ".join(missing),
                        evidence=[response.evidence()],
                        remediation="Apply headers at the application or trusted proxy; test compatibility.",
                        limitations=["Deployment reverse-proxy headers may differ."],
                    )
                )
            cookies = response.headers.get("set-cookie", "")
            if cookies:
                flags = {
                    "httponly": "httponly" in cookies.lower(),
                    "samesite": "samesite=" in cookies.lower(),
                    "secure": "; secure" in cookies.lower(),
                }
                checks.append(
                    Check(
                        id="cookie-flags:" + path,
                        category="session",
                        status="completed",
                        target=path,
                        observations=[flags],
                    )
                )
            if "cors" in allowed_categories:
                cors = client.request(path, {"Origin": "https://appsec-lab.invalid"})
                origin = cors.headers.get("access-control-allow-origin")
                if (
                    origin == "https://appsec-lab.invalid"
                    and cors.headers.get("access-control-allow-credentials", "").lower() == "true"
                ):
                    findings.append(
                        Finding(
                            rule="cors-reflection",
                            title="Credentialed CORS reflects synthetic origin",
                            category="cors",
                            severity="medium",
                            severity_reason="A synthetic untrusted origin was granted credentialed browser access; sensitive-data impact needs review.",
                            state="candidate",
                            endpoint=path,
                            cwe="CWE-942",
                            description="The local response reflected an arbitrary synthetic origin and enabled credentials.",
                            expected="Allow only trusted origins for credentialed requests.",
                            observed="Synthetic origin reflected with allow-credentials=true.",
                            evidence=[cors.evidence()],
                            remediation="Use an exact trusted-origin allowlist and appropriate Vary: Origin.",
                            limitations=[
                                "Authenticated sensitive response accessibility is not established."
                            ],
                        )
                    )
                checks.append(
                    Check(
                        id="cors:" + path,
                        category="cors",
                        status="completed",
                        target=path,
                        observations=[cors.evidence()],
                    )
                )
        except RollbackFailure:
            raise
        except (OSError, LabError) as exc:
            checks.append(
                Check(
                    id="response:" + path,
                    category="headers",
                    status="blocked",
                    target=path,
                    reason=str(exc),
                )
            )
    for scenario in config.scenarios:
        if mode != "local-active" or scenario.category not in allowed_categories:
            checks.append(
                Check(
                    id=scenario.id,
                    category=scenario.category,
                    status="not_tested",
                    target=scenario.path,
                    reason="Requires approved local-active category",
                )
            )
            continue
        try:
            observation = scenario_observation(client, scenario)
            checks.append(
                Check(
                    id=scenario.id,
                    category=scenario.category,
                    status="completed" if observation["owner_precondition"] else "blocked",
                    reason=""
                    if observation["owner_precondition"]
                    else "Owner baseline did not satisfy the configured synthetic fixture contract",
                    target=scenario.path,
                    duration_seconds=observation["duration_seconds"],
                    observations=[observation],
                )
            )
            if observation["violation"]:
                findings.append(
                    Finding(
                        rule="boundary:" + scenario.id,
                        title="Synthetic access policy violated: " + scenario.id,
                        category=scenario.category,
                        severity="high"
                        if scenario.category in {"authorization", "tenant_isolation"}
                        else "medium",
                        severity_reason="The configured lower-trust synthetic actor received the prohibited fixture response.",
                        confidence="high",
                        cwe="CWE-862" if scenario.category != "validation" else "CWE-20",
                        endpoint=scenario.path,
                        description="The owner baseline succeeded and the disallowed synthetic request received an unexpected response.",
                        expected=f"Actor response status in {scenario.expected_status}; protected record inaccessible.",
                        observed="Actor received the configured synthetic resource or disallowed response.",
                        evidence=[observation],
                        remediation="Enforce the configured ownership/role/input policy at the server-side resource boundary.",
                        regression=f"Run `appsec-lab verify --finding <id> --authorize` after fixing scenario {scenario.id}; actor must be denied.",
                        limitations=[
                            "Conclusion depends on the explicitly configured synthetic users, records and expected policy."
                        ],
                    )
                )
        except RollbackFailure:
            raise
        except (OSError, LabError) as exc:
            checks.append(
                Check(
                    id=scenario.id,
                    category=scenario.category,
                    status="blocked",
                    target=scenario.path,
                    reason=str(exc),
                )
            )
    return findings, checks


def fuzz_validation(
    client: Client, path: str, parameter: str, expected_statuses: list[int], maximum: int = 3
) -> list[dict]:
    """Small deterministic malformed-input set; only explicitly configured read-only fields."""
    values = ["", "appsec-lab-invalid", "x" * 128][: min(maximum, 3)]
    return [
        {
            "input_bytes": len(value),
            "secure": (
                result := client.request(
                    path
                    + ("&" if "?" in path else "?")
                    + quote(parameter, safe="")
                    + "="
                    + quote(value, safe="")
                )
            ).status
            in expected_statuses,
            "response": result.evidence(),
        }
        for value in values
    ]
