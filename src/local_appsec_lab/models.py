from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Mode = Literal["review", "local-passive", "local-active"]
State = Literal[
    "candidate",
    "confirmed",
    "not_reproduced",
    "false_positive",
    "informational",
    "blocked",
    "not_tested",
]
Severity = Literal["critical", "high", "medium", "low", "informational"]
SEVERITIES = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def now() -> str:
    return datetime.now(UTC).isoformat()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Source(Model):
    path: str
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str = ""
    sha256: str = ""


class Finding(Model):
    schema_version: Literal[1] = 1
    id: str = ""
    fingerprint: str = ""
    rule: str
    title: str
    category: str
    severity: Severity
    severity_reason: str
    confidence: Literal["low", "medium", "high"] = "medium"
    state: State = "candidate"
    cwe: str | None = None
    source: Source | None = None
    endpoint: str | None = None
    service: str = "app"
    description: str
    root_cause: str = "Exact source-level cause is not established by the available evidence."
    expected: str
    observed: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    verification: list[dict[str, Any]] = Field(default_factory=list)
    remediation: str = ""
    regression: str = ""
    limitations: list[str] = Field(default_factory=list)
    provenance: str = "builtin"

    def identify(self, repository: str) -> Finding:
        location = self.source.path if self.source else self.endpoint
        # Include source expression, not line number, to survive unrelated line shifts.
        anchor = self.source.excerpt.strip() if self.source else self.endpoint
        if self.source and (not anchor or "[REDACTED]" in anchor):
            anchor = f"{anchor}:{self.source.line}"
        self.fingerprint = digest(
            [repository, self.rule, self.service, location, anchor, self.endpoint]
        )
        self.id = "LAB-" + self.fingerprint[:16]
        return self


class Check(Model):
    id: str
    category: str
    status: Literal["completed", "blocked", "not_applicable", "not_tested", "failed"]
    reason: str = ""
    target: str = "repository"
    duration_seconds: float = 0
    observations: list[dict[str, Any]] = Field(default_factory=list)


class Report(Model):
    schema_version: Literal[1] = 1
    run_id: str
    product: str
    repository: str
    revision: str
    started: str
    finished: str
    duration_seconds: float
    mode: Mode
    status: Literal["complete", "partial", "cancelled", "failed"]
    environment: dict[str, Any]
    architecture: dict[str, Any]
    authorization: dict[str, Any] | None = None
    execution_strategy: str = "deterministic-workers"
    findings: list[Finding] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    jobs: list[dict[str, Any]] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
