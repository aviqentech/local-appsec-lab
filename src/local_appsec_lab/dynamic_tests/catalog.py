from __future__ import annotations

from typing import Literal

from pydantic import Field

from local_appsec_lab.models import Model
from local_appsec_lab.scanners import RULES


class TestDefinition(Model):
    schema_version: Literal[1] = 1
    id: str
    title: str
    category: str
    cwe: str | None = None
    preconditions: list[str]
    required_fixtures: list[str] = Field(default_factory=list)
    supported_targets: list[str]
    authorization: str
    mode: str
    expected_secure_behavior: str
    observation: str
    verification: str
    cleanup: str
    timeout_seconds: int = 3
    resource_budget: str
    limitations: list[str]


def catalog() -> list[dict]:
    result = []
    for rule, (category, _severity, cwe, title, fix) in RULES.items():
        result.append(
            TestDefinition(
                id="source:" + rule,
                title=title,
                category=category,
                cwe=cwe,
                preconditions=["A supported source/configuration file exists"],
                supported_targets=["source"],
                authorization="workspace read only",
                mode="review",
                expected_secure_behavior=fix,
                observation="Python AST or bounded syntactic pattern",
                verification="Fresh source read; never confirm exploitability from a pattern",
                cleanup="No target resources created",
                timeout_seconds=60,
                resource_budget="10,000 files / 50 MB repository; 1 MB per file",
                limitations=["No whole-program input provenance or deployment proof"],
            ).model_dump()
        )
    for category in [
        "authentication",
        "authorization",
        "tenant_isolation",
        "validation",
        "business_logic",
    ]:
        result.append(
            TestDefinition(
                id="synthetic:" + category,
                title="Configured synthetic " + category + " policy",
                category=category,
                cwe="CWE-862" if category in {"authorization", "tenant_isolation"} else None,
                preconditions=[
                    "Healthy authorized service",
                    "Explicit expected policy",
                    "Owner baseline succeeds",
                ],
                required_fixtures=[
                    "Synthetic actors and records",
                    "Protected response marker for access tests",
                ],
                supported_targets=[
                    "owned local HTTP service",
                    "explicitly approved existing local identity",
                ],
                authorization="Unexpired local-active approval including this category",
                mode="local-active",
                expected_secure_behavior="Lower-trust request satisfies configured denial/status policy",
                observation="Bounded owner and actor requests; hashes, status and synthetic marker only",
                verification="Independent repeat; validation status alone remains a candidate",
                cleanup="Reserved DELETE rollback for mutations, then owned runtime destruction",
                resource_budget="2 requests/read-only or 3/mutation including rollback; reservation before execution",
                limitations=[
                    "Developer-supplied fixture and policy assumptions",
                    "No inferred business-state machine",
                ],
            ).model_dump()
        )
    for identifier, category, title, targets, mode, observation, verification in [
        (
            "python-dataflow",
            "input_data_flow",
            "Bounded interprocedural Python provenance",
            ["Python source"],
            "review",
            "AST request-to-sink summaries, at most 100,000 nodes, 200 finding outputs",
            "Fresh source context; conservative candidates only",
        ),
        (
            "offline-tools",
            "dependencies",
            "Optional offline scanner adapters",
            ["source", "lockfiles"],
            "review",
            "Semgrep, OSV-Scanner or Trivy structured output and version/data provenance",
            "Source/dependency evidence validated; no exploit confirmation",
        ),
        (
            "stateful-workflow",
            "business_logic",
            "Explicit synthetic state workflow",
            ["owned disposable service"],
            "local-active",
            "Ordered identities, scalar capture, assertion and reserved DELETE rollback",
            "Fresh complete sequence and cleanup with protected control",
        ),
        (
            "scalar-fuzz",
            "validation",
            "Bounded scalar-schema properties",
            ["explicit local GET field"],
            "local-active",
            "Valid control before at most eight malformed small cases",
            "Status-only discrepancies remain candidates",
        ),
        (
            "chromium-workflow",
            "browser",
            "Isolated browser policy workflow",
            ["owned Docker/Compose service"],
            "local-active",
            "Parent-brokered HTTP, configured assertions, screenshot digest only",
            "Browser observations do not independently establish exploitability",
        ),
        (
            "adaptive-get",
            "headers",
            "Parent-gated adaptive response checks",
            ["known GET route"],
            "local-active",
            "At most four new approved header/CORS/error checks from model proposals",
            "Concrete parent checks; proposals cannot expand scope or mutate state",
        ),
    ]:
        result.append(
            TestDefinition(
                id=identifier,
                title=title,
                category=category,
                preconditions=[
                    "Explicit supported configuration and prerequisites",
                    "Required category/scope authorization",
                ],
                supported_targets=targets,
                authorization="Read-only review"
                if mode == "review"
                else "Unexpired active approval and owned runtime",
                mode=mode,
                expected_secure_behavior="Configured security policy and corresponding protected control hold",
                observation=observation,
                verification=verification,
                cleanup="Owned runtime/lease cleanup; reserve rollback before state changes",
                timeout_seconds=60,
                resource_budget="Run request/time/storage/model limits and module-specific bounded work",
                limitations=[
                    "Supported explicit workflow only; blocked or untested prerequisites remain visible"
                ],
            ).model_dump()
        )
    return result
