from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, ValidationError, model_validator

from local_appsec_lab.errors import ConfigError
from local_appsec_lab.models import Model, Severity
from local_appsec_lab.utilities.files import read_text
from local_appsec_lab.utilities.yaml import safe_yaml

CONFIG_FILE = "appsec-lab.yaml"


class Limits(Model):
    duration_seconds: int = Field(default=300, ge=5, le=3600)
    max_requests: int = Field(default=100, ge=1, le=1000)
    requests_per_second: float = Field(default=2, gt=0, le=10)
    response_bytes: int = Field(default=65_536, ge=256, le=1_048_576)
    log_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    storage_mb: int = Field(default=64, ge=8, le=512)
    memory_mb: int = Field(default=512, ge=128, le=2048)
    processes: int = Field(default=32, ge=4, le=128)
    cpus: float = Field(default=1, gt=0, le=4)
    max_concurrent: int = Field(default=2, ge=1, le=4)
    retries: int = Field(default=0, ge=0, le=2)
    model_tokens: int = Field(default=0, ge=0, le=1_000_000)
    model_calls: int = Field(default=16, ge=1, le=64)
    model_cost_usd: float = Field(default=0, ge=0, le=20)
    max_findings: int = Field(default=500, ge=10, le=2000)


class Execution(Model):
    backend: Literal["auto", "docker", "macos", "bubblewrap"] = "auto"
    command: list[str] = Field(default_factory=list, max_length=32)
    service: str | None = None
    port: int = Field(default=8765, ge=1024, le=65535)
    health_path: str = "/health"
    startup_timeout: int = Field(default=20, ge=1, le=180)
    # Image must already exist locally. No implicit pulls or builds.
    image: str = "python:3.13-slim"
    environment: dict[str, str] = Field(default_factory=dict)
    existing_url: str | None = None
    existing_identity: str | None = None
    compose_file: str | None = None
    seeds: dict[str, str] = Field(default_factory=dict, max_length=8)
    migrations: dict[str, list[str]] = Field(default_factory=dict, max_length=8)
    dependency_lock: str | None = None
    use_dependencies: bool = True

    @model_validator(mode="after")
    def safe_environment(self) -> Execution:
        forbidden = (
            "LD_",
            "DYLD_",
            "PYTHON",
            "NODE_",
            "OPENSSL_",
            "PATH",
            "HOME",
            "BASH",
            "ENV",
            "DOCKER_",
            "CONTAINER_",
        )
        for key, value in self.environment.items():
            if key.startswith(forbidden) or "\x00" in key + value:
                raise ValueError(
                    "Interpreter, loader and ambient environment overrides are prohibited"
                )
        return self


class Scenario(Model):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    path: str
    category: Literal[
        "authorization", "authentication", "validation", "business_logic", "tenant_isolation"
    ]
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    owner_headers: dict[str, str] = Field(default_factory=dict)
    actor_headers: dict[str, str] = Field(default_factory=dict)
    owner_status: int = Field(default=200, ge=100, le=599)
    expected_status: list[int] = Field(default_factory=lambda: [401, 403, 404], min_length=1)
    marker: str | None = None
    body: dict | None = None
    disposable: bool = False
    synthetic: bool = True
    rollback_path: str | None = None

    @model_validator(mode="after")
    def state_contract(self) -> Scenario:
        if self.method != "GET" and (
            not self.disposable or not self.rollback_path or not self.synthetic
        ):
            raise ValueError(
                "State-changing scenarios require synthetic disposable data and rollback_path"
            )
        if (
            self.category
            in {"authorization", "tenant_isolation", "business_logic", "authentication"}
            and not self.marker
        ):
            raise ValueError("Boundary tests require an expected synthetic response marker")
        if (
            self.category in {"authorization", "tenant_isolation", "authentication"}
            and self.owner_headers == self.actor_headers
        ):
            raise ValueError("Owner and lower-trust actor identities must differ")
        return self


class Tools(Model):
    semgrep: bool = False
    osv_scanner: bool = False
    trivy: bool = False
    advisory_snapshot: str | None = None
    advisory_max_age_days: int = Field(default=7, ge=1, le=365)
    backend: Literal["auto", "macos", "bubblewrap", "docker"] = "auto"
    images: dict[Literal["semgrep", "osv-scanner", "trivy"], str] = Field(default_factory=dict)


class AI(Model):
    strategy: Literal["deterministic", "host", "http", "native"] = "deterministic"
    endpoint: str | None = None
    model: str | None = None
    context_bytes: int = Field(default=12_000, ge=1000, le=32_000)


class BrowserStep(Model):
    action: Literal["fill", "click", "goto", "expect_text", "expect_path"]
    selector: str = Field(default="body", max_length=256)
    value: str = Field(default="", max_length=1024)


class BrowserMutation(Model):
    method: Literal["POST", "PUT", "PATCH", "DELETE"]
    path: str


class BrowserWorkflow(Model):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    steps: list[BrowserStep] = Field(default_factory=list, max_length=20)
    max_requests: int = Field(default=8, ge=1, le=30)
    allowed_mutations: list[BrowserMutation] = Field(default_factory=list, max_length=8)
    rollback_path: str | None = None
    synthetic: bool = True
    disposable: bool = False

    @model_validator(mode="after")
    def policy(self):
        if not self.synthetic or (
            self.allowed_mutations and (not self.disposable or not self.rollback_path)
        ):
            raise ValueError("Browser mutations need synthetic disposable data and rollback")
        from local_appsec_lab.network import safe_path

        for path in [
            self.path,
            *[m.path for m in self.allowed_mutations],
            *([self.rollback_path] if self.rollback_path else []),
        ]:
            safe_path(path)
        for step in self.steps:
            if step.action in {"goto", "expect_path"}:
                safe_path(step.value)
        return self


class WorkflowStep(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    identity: str = "owner"
    body: dict | None = None
    expected_status: list[int] = Field(default_factory=lambda: [200], min_length=1, max_length=10)
    marker: str | None = Field(default=None, max_length=256)
    capture: dict[str, str] = Field(default_factory=dict, max_length=5)
    security_assertion: bool = False


class StatefulWorkflow(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    category: Literal["business_logic", "authorization", "tenant_isolation", "authentication"] = (
        "business_logic"
    )
    identities: dict[str, dict[str, str]]
    steps: list[WorkflowStep] = Field(min_length=1, max_length=12)
    rollback: WorkflowStep
    synthetic: Literal[True]
    disposable: Literal[True]

    @model_validator(mode="after")
    def state_policy(self):
        import re
        from local_appsec_lab.network import safe_path

        if self.rollback.method != "DELETE":
            raise ValueError("Workflow rollback must be an explicit DELETE")
        for step in [*self.steps, self.rollback]:
            safe_path(step.path)
            if step.identity not in self.identities or any(
                not 100 <= code <= 599 for code in step.expected_status
            ):
                raise ValueError("Workflow identity/status is invalid")
            if step.security_assertion and not step.marker:
                raise ValueError("Security assertions need an inert synthetic response marker")
            if any(
                not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", key)
                or not re.fullmatch(r"/[A-Za-z0-9_/-]{1,128}", pointer)
                for key, pointer in step.capture.items()
            ):
                raise ValueError("Workflow captures require named, bounded JSON pointers")
        return self


class FuzzTarget(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    path: str
    parameter: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
    input_schema: dict = Field(default_factory=lambda: {"type": "integer"})
    max_cases: int = Field(default=3, ge=1, le=8)
    expected_invalid_status: list[int] = Field(
        default_factory=lambda: [400, 422], min_length=1, max_length=10
    )
    expected_valid_status: list[int] = Field(
        default_factory=lambda: [200], min_length=1, max_length=10
    )

    @model_validator(mode="after")
    def bounded_schema(self):
        from local_appsec_lab.network import safe_path

        safe_path(self.path)
        if any(
            not 100 <= code <= 599
            for code in self.expected_valid_status + self.expected_invalid_status
        ):
            raise ValueError("Fuzz expected statuses must be HTTP status codes")
        import jsonschema

        try:
            jsonschema.Draft202012Validator.check_schema(self.input_schema)
        except jsonschema.SchemaError as exc:
            raise ValueError("Fuzz input_schema must be a valid JSON schema") from exc
        if set(self.input_schema) - {
            "type",
            "minimum",
            "maximum",
            "minLength",
            "maxLength",
            "enum",
        } or self.input_schema.get("type") not in {"integer", "string", "boolean"}:
            raise ValueError("Fuzz schemas support bounded scalar fields only")
        for name in ("minimum", "maximum", "minLength", "maxLength"):
            value = self.input_schema.get(name)
            if value is not None and (not isinstance(value, int) or abs(value) > 128):
                raise ValueError("Fuzz boundaries must be small integers within 128")
        if "enum" in self.input_schema and (
            len(self.input_schema["enum"]) > 10
            or any(
                not isinstance(v, (str, int, bool)) or len(str(v)) > 128
                for v in self.input_schema["enum"]
            )
        ):
            raise ValueError("Fuzz enum exceeds the scalar input budget")
        return self


class Config(Model):
    version: Literal[1] = 1
    product_name: str = Field(default="Local AppSec Lab", min_length=1, max_length=80)
    execution: Execution = Field(default_factory=Execution)
    limits: Limits = Field(default_factory=Limits)
    scenarios: list[Scenario] = Field(default_factory=list, max_length=30)
    tools: Tools = Field(default_factory=Tools)
    ai: AI = Field(default_factory=AI)
    output: str = ".appsec-lab"
    fail_on: Severity = "high"
    categories: list[str] = Field(default_factory=list)
    offline: bool = True
    cvss_vectors: dict[str, str] = Field(default_factory=dict, max_length=100)
    browser: bool = False
    browser_workflows: list[BrowserWorkflow] = Field(default_factory=list, max_length=10)
    workflows: list[StatefulWorkflow] = Field(default_factory=list, max_length=10)
    fuzz_targets: list[FuzzTarget] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def output_scope(self):
        path = Path(self.output)
        if (
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or any(ord(c) < 32 for c in self.output)
        ):
            raise ValueError("output must be a dedicated project-relative state subdirectory")
        self.output = path.as_posix()
        return self


def merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        result[key] = (
            merge(result[key], value)
            if isinstance(value, dict) and isinstance(result.get(key), dict)
            else value
        )
    return result


def load(root: Path, config_path: str | None = None, overrides: dict | None = None) -> Config:
    try:
        user_path = Path.home() / ".config" / "local-appsec-lab" / "config.yaml"
        data = {}
        if user_path.is_file() and not user_path.is_symlink():
            data = safe_yaml(read_text(user_path.parent, user_path.name)) or {}
        path = config_path or CONFIG_FILE
        if config_path or (root / path).exists():
            project = safe_yaml(read_text(root, path)) or {}
            if not isinstance(project, dict):
                raise ConfigError("Configuration must be a YAML mapping")
            data = merge(data, project)
        return Config.model_validate(merge(data, overrides or {}))
    except ValidationError as exc:
        fields = sorted(
            {".".join(str(p) for p in e["loc"]) for e in exc.errors(include_input=False)}
        )
        raise ConfigError(
            "Invalid configuration fields: "
            + ", ".join(fields)
            + "; see schemas/config.schema.json"
        ) from exc
    except (OSError, yaml.YAMLError, TypeError, ValueError) as exc:
        # Do not echo Pydantic/YAML input values: they may contain credentials.
        raise ConfigError(
            f"Invalid configuration ({type(exc).__name__}); check YAML syntax and mapping types"
        ) from exc


def template() -> str:
    return (
        "# Execution and active testing require CLI authorization for each run.\n"
        + yaml.safe_dump(Config().model_dump(), sort_keys=False)
    )
