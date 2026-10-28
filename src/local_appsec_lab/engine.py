from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from local_appsec_lab import __version__
from local_appsec_lab.agents import HTTPProvider, ROLES, assignments, validate_results
from local_appsec_lab.authorization import authorize, plan_digest
from local_appsec_lab.configuration import Config
from local_appsec_lab.discovery import inspect
from local_appsec_lab.discovery.components import assessment
from local_appsec_lab.discovery.source_links import attach_sources
from local_appsec_lab.dynamic_tests import run as dynamic_scan
from local_appsec_lab.dynamic_tests.catalog import catalog
from local_appsec_lab.errors import (
    ConfigError,
    AuthorizationError,
    BudgetExceeded,
    LabError,
    RuntimeFailure,
    ScopeError,
)
from local_appsec_lab.findings import RunStore
from local_appsec_lab.integrations import ToolAdapter
from local_appsec_lab.intelligence.cache import AnalysisCache
from local_appsec_lab.intelligence.dataflow import analyze as analyze_dataflow
from local_appsec_lab.isolation import sandbox_probe, docker_control
from local_appsec_lab.models import Check, Finding, Report, SEVERITIES, digest, now
from local_appsec_lab.network import Budget
from local_appsec_lab.remediation import regression
from local_appsec_lab.reporting import render
from local_appsec_lab.runtime import Runtime, resolve_command
from local_appsec_lab.scanners import dependencies, scan_source
from local_appsec_lab.scheduling import Scheduler
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_text
from local_appsec_lab.utilities.redaction import redact
from local_appsec_lab.verification import deduplicate, verify


def state_path(root: Path, config: Config) -> Path:
    # Output cannot be used to overwrite arbitrary files outside the CLI workspace.
    return inside(root, Path(config.output))


def startup_summary(root: Path, config: Config, inventory: dict) -> dict:
    try:
        if config.execution.existing_url:
            runtime = {
                "supported": bool(config.execution.existing_identity),
                "service": config.execution.service or ".",
                "backend": "existing",
                "reason": "Existing service requires explicit manifest approval and matching health identity",
            }
        elif config.execution.compose_file:
            from local_appsec_lab.runtime.compose import definition

            services, selected = definition(root, config)
            runtime = {
                "supported": True,
                "backend": "compose",
                "selected_service": selected,
                "services": list(services),
                "images": [service["image"] for service in services.values()],
                "network": "internal bridge with isolated gateway; no published ports",
                "disposable_databases": True,
                "seeds": config.execution.seeds,
                "migrations": config.execution.migrations,
            }
        else:
            command, service = resolve_command(config, inventory)
            runtime = {"command": command, "service": service, "supported": True}
    except LabError as exc:
        runtime = {"supported": False, "reason": str(exc)}
    return runtime


def plan(root: Path, config: Config, mode: str = "local-active") -> dict:
    root = root.resolve(strict=True)
    inventory = inspect(root, config.output)
    runtime = startup_summary(root, config, inventory)
    existing = None
    if config.execution.existing_url:
        existing = digest(
            {
                "url": config.execution.existing_url,
                "identity": config.execution.existing_identity,
                "repository": str(root.resolve()),
            }
        )
    return {
        "schema_version": 1,
        "plan_digest": plan_digest(config),
        "repository": str(root.resolve()),
        "architecture": inventory,
        "assessment": assessment(inventory, config, mode, runtime),
        "startup": runtime,
        "backend": config.execution.backend,
        "permissions": [
            "source-read",
            "explicit execution authorization for passive/active modes",
            "synthetic policy tests only in active mode",
        ],
        "environment_names": sorted(config.execution.environment),
        "network": {
            "application_egress": "denied except its approved private/loopback service",
            "scanner_target": f"127.0.0.1:{config.execution.port}",
            "redirects": "denied",
            "remote_dependencies": "never implicitly installed",
        },
        "categories": config.categories
        or sorted(
            {
                c
                for role, values in ROLES.items()
                if role not in {"coordinator", "verifier", "remediation"}
                for c in values
            }
        ),
        "test_catalog": catalog(),
        "health_path": config.execution.health_path,
        "synthetic_scenarios": redact([s.model_dump() for s in config.scenarios]),
        "backend_status": sandbox_probe(config),
        "limits": config.limits.model_dump(),
        "cleanup": [
            "stop owned process groups/labelled containers",
            "remove exact owned source copy",
            "retain redacted report and event history",
        ],
        "existing_manifest_digest": existing,
        "model_endpoint": config.ai.endpoint,
        "model_auth_source": "Only the explicit --model-key-env CLI option selects a credential; repository config cannot select one",
        "model_disclosure": "HTTP strategy transmits only the selected, redacted source context to the configured endpoint and requires separate CLI consent"
        if config.ai.strategy == "http"
        else "Native authenticated CLI workers transmit bounded redacted context after separate consent; vendor usage/cost caps vary"
        if config.ai.strategy == "native"
        else "No programmatic model requests configured",
        "limitations": [
            "No implicit package installation or repository lifecycle hooks; locked setup requires explicit authorization and network consent.",
            "Compose execution uses a constrained generated environment, preloaded images and disposable owned services; arbitrary project semantics are unsupported.",
        ],
    }


def doctor(root: Path, config: Config) -> dict:
    from local_appsec_lab.install import host_locations

    try:
        isolation = sandbox_probe(config)
    except (OSError, subprocess.TimeoutExpired):
        isolation = {"available": False, "remediation": "Check isolation backend permissions"}
    return {
        "version": __version__,
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "permissions": {
            "workspace_readable": os.access(root, os.R_OK),
            "workspace_writable": os.access(root, os.W_OK),
        },
        "isolation": isolation,
        "executables": {
            name: shutil.which(name)
            for name in ["git", "docker", "bwrap", "node", "semgrep", "osv-scanner", "trivy"]
        },
        "skills": host_locations(Path.home()),
        "project_skills": host_locations(root),
        "ai": {
            "strategy": config.ai.strategy,
            "authentication_setup": "explicit --model-key-env only",
            "optional": True,
        },
        "remediation": [
            "Use review mode when isolation is unavailable.",
            "Install optional scanners separately; enable them explicitly in tools.",
            "Preload required dependencies/images in a trusted provisioning step.",
        ],
    }


def revision(root: Path) -> str:
    # Never invoke repository hooks, pagers, or aliases.
    try:
        result = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "rev-parse", "HEAD"],
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", ""),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            },
            capture_output=True,
            timeout=3,
        )
        return result.stdout.decode().strip() if result.returncode == 0 else "unversioned"
    except (OSError, subprocess.TimeoutExpired):
        return "unversioned"


def exit_code(report: Report, config: Config) -> int:
    if report.status == "cancelled":
        return 130
    if any(
        f.state == "confirmed" and SEVERITIES[f.severity] >= SEVERITIES[config.fail_on]
        for f in report.findings
    ):
        return 1
    if report.metrics.get("runtime_startup_failed"):
        return 5
    return 2 if report.status == "partial" else 0


def scan(
    root: Path,
    workspace: Path,
    config: Config,
    mode: str = "review",
    acknowledged: bool = False,
    existing_digest: str | None = None,
    allow_model: bool = False,
    model_price: float = 0,
    host_results: str | None = None,
    reverify: Finding | None = None,
    model_key_env: str | None = None,
    native_host: str | None = None,
    native_model: str | None = None,
    native_auth_dir: Path | None = None,
    reviewed_plan: str | None = None,
) -> tuple[Report, dict]:
    started, clock = now(), time.monotonic()
    root = root.resolve(strict=True)
    if native_host and config.ai.strategy != "native":
        raise ConfigError(
            "--native-host requires ai.strategy: native in the selected project's configuration. "
            "Edit appsec-lab.yaml and set a positive limits.model_tokens budget; parent configs are not inherited."
        )
    if allow_model and config.ai.strategy == "deterministic":
        raise ConfigError(
            "--allow-model-requests would be ignored with ai.strategy: deterministic. "
            "Configure ai.strategy: native or http with positive model budgets."
        )
    run_id = uuid.uuid4().hex
    approval = authorize(
        root, workspace, config, mode, run_id, acknowledged, existing_digest, reviewed_plan
    )
    if mode == "review" and config.scenarios and reverify and reverify.rule.startswith("boundary:"):
        raise AuthorizationError("Dynamic finding verification requires an authorized dynamic mode")
    if config.ai.strategy == "http" and not allow_model:
        raise AuthorizationError(
            "HTTP AI review requires --allow-model-requests and explicit token/cost budgets"
        )
    if config.ai.strategy == "native" and (not allow_model or not native_host):
        raise AuthorizationError(
            "Native review needs --allow-model-requests and an explicit --native-host"
        )
    inventory = inspect(root, config.output)
    state = state_path(root, config)
    if (
        native_auth_dir
        and native_auth_dir.resolve().is_relative_to(root)
        and not native_auth_dir.resolve().is_relative_to(state)
    ):
        raise ScopeError(
            "Native login directories inside the project must be under its excluded state directory"
        )
    store = RunStore(state)
    from local_appsec_lab.agents.knowledge import SharedKnowledge

    knowledge = SharedKnowledge(store, run_id, inventory)
    analysis_cache = AnalysisCache(state, root, inventory)
    runtime_type = Runtime
    if config.execution.compose_file:
        from local_appsec_lab.runtime.compose import ComposeRuntime

        runtime_type = ComposeRuntime
    runtime = runtime_type(
        root, state, run_id, config, inventory, mode, tuple(approval.categories) if approval else ()
    )
    budget = Budget(config.limits, approval.expires_at if approval else None)
    checks, findings, jobs, limitations = [], [], [], list(inventory["limitations"])
    provider = None
    runtime_failed, cancelled = False, False
    store.status(
        run_id,
        {"state": "running", "stage": "source", "pid": os.getpid(), "started": started, "jobs": []},
    )
    if approval:
        atomic_json(state / "runs" / run_id / "authorization.json", approval.model_dump())
    client = None
    strategy = "deterministic-workers"
    try:

        def progress(value):
            store.status(
                run_id,
                {
                    "state": "running",
                    "stage": "source",
                    "pid": os.getpid(),
                    "started": started,
                    "elapsed_seconds": time.monotonic() - clock,
                    "jobs": value,
                },
            )

        scheduler = Scheduler(
            config.limits.max_concurrent,
            min(60, config.limits.duration_seconds),
            config.limits.retries,
            progress,
        )
        for role, categories in ROLES.items():
            if role in {"coordinator", "verifier", "remediation", "supply_chain"}:
                continue
            selected = [c for c in categories if not config.categories or c in config.categories]
            if selected:
                scheduler.add(
                    "source:" + role,
                    role,
                    lambda selected=selected: analysis_cache.source(
                        selected, lambda: scan_source(root, inventory, selected)
                    ),
                )
        if not config.categories or "input_data_flow" in config.categories:
            scheduler.add(
                "dataflow",
                "data_flow",
                lambda: analysis_cache.source(
                    ["__interprocedural_dataflow__"], lambda: analyze_dataflow(root, inventory)
                ),
            )
        scheduler.add(
            "dependencies",
            "supply_chain",
            lambda: dependencies(
                root,
                inventory,
                config.tools.advisory_snapshot
                or (
                    (Path(config.output) / "advisories/osv.json").as_posix()
                    if (state / "advisories/osv.json").is_file()
                    else None
                ),
                config.tools.advisory_max_age_days,
            ),
        )
        for name, enabled in [
            ("semgrep", config.tools.semgrep),
            ("osv-scanner", config.tools.osv_scanner),
            ("trivy", config.tools.trivy),
        ]:
            if enabled:
                adapter = ToolAdapter(name)
                scheduler.add(
                    "tool:" + name,
                    "external_tool",
                    lambda adapter=adapter: adapter.run(root, state, config),
                )
        source_results = asyncio.run(scheduler.run())
        source_jobs = scheduler.snapshot()
        for found, covered in source_results.values():
            findings.extend(found)
            checks.extend(covered if isinstance(covered, list) else [covered])
        knowledge.publish("source-analysis", findings, checks)
        scheduler = Scheduler(
            config.limits.max_concurrent,
            min(120, config.limits.duration_seconds),
            config.limits.retries,
            progress,
        )
        tasks = (
            assignments(root, inventory, config) if config.ai.strategy != "deterministic" else []
        )
        for task in tasks:
            task["shared_knowledge"] = knowledge.context(task["categories"])
        if config.ai.strategy in {"http", "native"}:
            if config.ai.strategy == "native":
                from local_appsec_lab.agents.native import NativeProvider

                provider = NativeProvider(
                    config,
                    allow_model,
                    native_host,
                    state,
                    native_model,
                    native_auth_dir,
                    model_key_env,
                    root,
                )
            else:
                provider = HTTPProvider(config, allow_model, model_price, model_key_env)
            provider.deadline = min(
                provider.deadline, budget.started + config.limits.duration_seconds
            )
            strategy = config.ai.strategy + "-model-and-deterministic-workers"
            for task in tasks:
                scheduler.add(
                    "model:" + task["id"],
                    task["role"],
                    lambda task=task: provider.review(root, task),
                    config.ai.strategy + "-model",
                )
        elif config.ai.strategy == "host":
            strategy = (
                "host-results-and-deterministic-workers"
                if host_results
                else "deterministic-workers; host tasks exported, not executed"
            )
            task_dir = private_dir(state / "runs" / run_id / "tasks")
            for task in tasks:
                atomic_json(task_dir / (task["id"] + ".json"), task)
            if host_results:
                imported = json.loads(read_text(root, host_results))
                for entry in imported:
                    task = next((t for t in tasks if t["id"] == entry.get("task_id")), None)
                    if (
                        not task
                        or entry.get("repository_fingerprint") != task["repository_fingerprint"]
                    ):
                        raise ScopeError(
                            "Host results do not match the current assigned repository context"
                        )
                    findings.extend(validate_results(root, task, entry["findings"]))
            else:
                checks.append(
                    Check(
                        id="host-ai",
                        category="ai_review",
                        status="not_tested",
                        reason="Tasks exported for native host delegation; no independent AI execution claimed",
                    )
                )
        results = asyncio.run(scheduler.run())
        jobs = source_jobs + scheduler.snapshot()
        for identifier, result in results.items():
            if identifier.startswith("model:"):
                findings.extend(result)
            else:
                found, covered = result
                findings.extend(found)
                checks.extend(covered if isinstance(covered, list) else [covered])
        for job in jobs:
            if job["state"] != "completed":
                checks.append(
                    Check(
                        id=job["id"],
                        category="worker",
                        status="failed",
                        reason=job["error"] or job["state"],
                    )
                )
        # Remove worker-local excluded-rule records; retain one truthful check per rule.
        check_index = {}
        for check in checks:
            if check.id not in check_index or check.status == "completed":
                check_index[check.id] = check
        checks = list(check_index.values())
        knowledge.publish("specialist-analysis", findings, checks)
        if mode != "review":
            approval.validate_scope(root, config, mode, run_id)
            store.status(
                run_id,
                {
                    "state": "running",
                    "stage": "runtime",
                    "pid": os.getpid(),
                    "started": started,
                    "jobs": jobs,
                },
            )
            try:
                client = runtime.start(budget)
                checks.append(
                    Check(
                        id="runtime-health",
                        category="runtime",
                        status="completed",
                        observations=[
                            {
                                "backend": runtime.backend,
                                "owned": runtime.started,
                                "port": config.execution.port,
                            }
                        ],
                    )
                )
                if not reverify:
                    observed, dynamic_checks = dynamic_scan(
                        client, config, inventory["routes"], mode, approval.categories
                    )
                    findings.extend(observed)
                    checks.extend(dynamic_checks)
                    from local_appsec_lab.dynamic_tests.fuzz import run as fuzz_scan
                    from local_appsec_lab.dynamic_tests.workflows import run as workflow_scan

                    for operation in (fuzz_scan, workflow_scan):
                        arguments = [client, config, mode, approval.categories]
                        if operation is workflow_scan:
                            arguments.append(runtime.started)
                        observed, covered = operation(*arguments)
                        findings.extend(observed)
                        checks.extend(covered)
            except (RuntimeFailure, OSError) as exc:
                runtime_failed = True
                checks.append(
                    Check(
                        id="runtime-health", category="runtime", status="blocked", reason=str(exc)
                    )
                )
                checks.append(
                    Check(
                        id="dynamic",
                        category="dynamic",
                        status="not_tested",
                        reason="Application could not be safely launched/identified",
                    )
                )
        else:
            checks.append(
                Check(
                    id="dynamic",
                    category="dynamic",
                    status="not_tested",
                    reason="Source-only review mode",
                )
            )
        if reverify:
            findings = [reverify.model_copy(deep=True)]
        attach_sources(root, inventory, findings)
        findings = deduplicate(findings, str(root))
        if len(findings) > config.limits.max_findings:
            total = len(findings)
            findings = findings[: config.limits.max_findings]
            checks.append(
                Check(
                    id="finding-budget",
                    category="analysis",
                    status="blocked",
                    reason=f"Finding budget reached ({config.limits.max_findings}/{total}); narrow the selected categories or project",
                )
            )
        ai_exhausted = False
        for finding in findings:
            if approval and time.time() >= approval.expires_at:
                finding.state = "blocked"
                finding.verification.append({"conclusion": "Approval expired before verification"})
            else:
                verify(
                    finding,
                    root,
                    config,
                    client,
                    mode,
                    tuple(approval.categories) if approval else (),
                    runtime.started,
                )
                if provider and not ai_exhausted and hasattr(provider, "verify") and finding.source:
                    try:
                        verdict = provider.verify(root, finding)
                        finding.verification.append(verdict)
                        if verdict.get("remediation"):
                            finding.remediation = verdict["remediation"]
                        if verdict.get("regression"):
                            finding.regression = verdict["regression"]
                        if (
                            finding.severity in {"high", "critical"}
                            and verdict.get("conclusion") == "supported"
                        ):
                            finding.remediation_details["ai_review"] = provider.remediate(
                                root, finding
                            )
                    except BudgetExceeded as exc:
                        ai_exhausted = True
                        checks.append(
                            Check(
                                id="ai-verification-budget",
                                category="ai_verification",
                                status="blocked",
                                reason=str(exc),
                            )
                        )
                    except LabError as exc:
                        checks.append(
                            Check(
                                id="ai-verifier:" + finding.id,
                                category="ai_verification",
                                status="blocked",
                                reason=str(exc),
                            )
                        )
        if not reverify and (config.browser or config.browser_workflows):
            if client and approval:
                from local_appsec_lab.dynamic_tests.browser import run_browser

                checks.extend(run_browser(runtime, client, config, mode, approval.categories))
            else:
                checks.append(
                    Check(
                        id="browser",
                        category="browser",
                        status="not_tested",
                        reason="Browser requires an authorized running service",
                    )
                )
        if (
            not reverify
            and provider
            and getattr(provider, "proposals", None)
            and client
            and approval
        ):
            from local_appsec_lab.dynamic_tests.adaptive import run as explore

            routes = list(inventory["routes"])
            for check in checks:
                if check.id.startswith("browser:"):
                    for observation in check.observations:
                        routes.extend(
                            {"path": path, "method": "GET", "source": "browser-navigation"}
                            for path in observation.get("routes", [])
                        )
            checks.extend(
                explore(
                    client,
                    provider.proposals,
                    routes,
                    checks,
                    mode,
                    approval.categories,
                    runtime.started,
                )
            )
        for category in [
            "authentication",
            "authorization",
            "session",
            "csrf",
            "sensitive_response",
            "validation",
            "error_handling",
            "file_upload",
            "business_logic",
            "tenant_isolation",
            "ai_security",
        ]:
            if not any(c.category == category and c.status == "completed" for c in checks):
                checks.append(
                    Check(
                        id="coverage:" + category,
                        category=category,
                        status="not_tested",
                        reason="No applicable implemented check or configured synthetic scenario executed",
                    )
                )
        from local_appsec_lab.intelligence.severity import calculate
        from local_appsec_lab.remediation import enrich

        for finding in findings:
            if finding.rule in config.cvss_vectors:
                finding.cvss = calculate(
                    config.cvss_vectors[finding.rule], "explicit project configuration"
                )
            enrich(finding, root, inventory)
    except KeyboardInterrupt:
        cancelled = True
        checks.append(
            Check(
                id="cancellation",
                category="runtime",
                status="blocked",
                reason="Cancelled; owned resources cleaned",
            )
        )
    except LabError as exc:
        checks.append(
            Check(id="policy-or-budget", category="execution", status="blocked", reason=str(exc))
        )
    finally:
        runtime.stop()
    findings = deduplicate(findings, str(root))[: config.limits.max_findings]
    known_secrets = (
        tuple(getattr(runtime, "secrets", ()))
        + tuple(v for v in config.execution.environment.values() if len(v) > 3)
        + tuple(
            v
            for scenario in config.scenarios
            for headers in (scenario.owner_headers, scenario.actor_headers)
            for v in headers.values()
            if len(v) > 3
        )
    )
    atomic_json(
        state / "runs" / run_id / "diagnostics.json",
        {
            "backend": runtime.backend,
            "failure": runtime.failure,
            "log": redact(bytes(runtime.log).decode(errors="replace"), known_secrets),
            "log_bytes_retained": len(runtime.log),
            "log_byte_limit": config.limits.log_bytes,
        },
    )
    if runtime.failure:
        checks.append(
            Check(id="runtime-budget", category="runtime", status="blocked", reason=runtime.failure)
        )
    limitations.extend(
        [
            "Syntactic source checks remain candidates; manual data-flow and deployment review is required.",
            "Deterministic workers and verification are not independent AI reviewers.",
            "No current advisory coverage without a supplied offline snapshot or a successful optional scanner.",
            "State-changing scenarios rely on explicitly configured disposable synthetic fixtures.",
            "Data-flow analysis is bounded and conservative; unsupported dynamic dispatch and languages need specialist review. Mobile emulation and automatic business-policy inference are not provided.",
        ]
    )
    if runtime.backend == "macos":
        limitations.append(
            "macOS is for reviewed source only: numeric process-argument sysctls can expose same-user host process metadata/environment despite Seatbelt. Use Docker for untrusted code. It uses a per-port host-loopback sandbox, not a private network namespace. Aggregate RSS/process/storage limits are monitored; Docker provides stronger resource isolation. Daemonizing startup programs are unsupported."
        )
    inventory["assessment"] = assessment(
        inventory,
        config,
        mode,
        startup_summary(root, config, inventory),
        started=runtime.started,
        requests=budget.requests,
        completed=True,
    )
    if mode != "review":
        for component in inventory["assessment"]["components"]:
            if component["runtime_action"] == "not_selected":
                checks.append(
                    Check(
                        id="component:" + component["id"],
                        category="component_runtime",
                        status="not_tested",
                        target=component["id"],
                        reason=component["reason"],
                    )
                )
    metrics = {
        "source_files_inspected": len(inventory["files"]),
        "dependencies_identified": len(inventory["dependencies"]),
        "services_identified": len(inventory["services"]),
        "services_started": getattr(runtime, "services_started", int(runtime.started)),
        "routes_discovered": len(inventory["routes"]),
        "routes_tested": len(
            {c.target for c in checks if c.id.startswith("response:") and c.status == "completed"}
        ),
        "http_requests": budget.requests,
        "browser_workflows": sum(
            c.id.startswith("browser:") and c.status == "completed" for c in checks
        ),
        "stateful_workflows": sum(
            c.id.startswith("workflow:") and c.status == "completed" for c in checks
        ),
        "fuzz_properties": sum(
            c.id.startswith("fuzz:") and c.status == "completed" for c in checks
        ),
        "adaptive_new_coverage": sum(
            c.id.startswith("adaptive:") and c.status == "completed" for c in checks
        ),
        "dynamic_checks_completed": sum(
            c.status == "completed"
            and (
                c.id.startswith(("response:", "cors:")) or c.id in {s.id for s in config.scenarios}
            )
            for c in checks
        ),
        "worker_assignments_completed": sum(j["state"] == "completed" for j in jobs),
        "candidate_findings": sum(f.state == "candidate" for f in findings),
        "confirmed_findings": sum(f.state == "confirmed" for f in findings),
        "false_positives": sum(f.state == "false_positive" for f in findings),
        "blocked_checks": sum(c.status in {"blocked", "failed"} for c in checks),
        "not_tested_checks": sum(c.status == "not_tested" for c in checks),
        "runtime_startup_failed": runtime_failed,
        "cleanup_completed": runtime.cleaned,
        "model_tokens_reserved": provider.tokens if provider else 0,
        "model_cost_upper_bound_usd": provider.cost
        if provider and config.ai.strategy == "http"
        else None
        if provider
        else 0,
        "model_calls": getattr(provider, "calls", 0),
        "model_reported_tokens": provider.actual_tokens
        if provider and provider.usage_reported
        else None,
        "model_reported_cost_usd": getattr(provider, "reported_cost", None),
        "native_hard_token_cap": False if config.ai.strategy == "native" else None,
        "analysis_cache_hits": analysis_cache.hits,
        "analysis_cache_misses": analysis_cache.misses,
        "analysis_cache_verified": bool(analysis_cache.seal_key),
    }
    status = (
        "cancelled"
        if cancelled
        else "partial"
        if any(c.status in {"blocked", "failed", "not_tested"} for c in checks)
        else "complete"
    )
    report = Report(
        run_id=run_id,
        product=config.product_name,
        repository=str(root),
        revision=revision(root),
        started=started,
        finished=now(),
        duration_seconds=time.monotonic() - clock,
        mode=mode,
        status=status,
        environment={
            "os": platform.system(),
            "python": sys.version.split()[0],
            "engine": __version__,
            "backend": runtime.backend,
        },
        architecture=inventory,
        authorization=approval.model_dump() if approval else None,
        execution_strategy=strategy,
        findings=findings,
        checks=checks,
        jobs=jobs,
        metrics=metrics,
        limitations=limitations,
    )
    report = Report.model_validate(redact(report.model_dump()))
    knowledge.publish(
        "finished",
        findings,
        checks,
        {"backend": runtime.backend, "started": runtime.started, "cleaned": runtime.cleaned},
    )
    store.save(report)
    directory = private_dir(state / "reports" / run_id)
    outputs = render(report, directory)
    for finding in findings:
        regression(finding, config, directory, root, run_id)
    store.status(
        run_id,
        {
            "state": status,
            "stage": "finished",
            "started": started,
            "duration_seconds": report.duration_seconds,
            "jobs": jobs,
            "outputs": outputs,
        },
    )
    store.close()
    return report, outputs


def clean(root: Path, config: Config) -> list[dict]:
    state = state_path(root, config)
    from local_appsec_lab.runtime.leases import recover

    result = recover(state)
    if not (state / "runs").exists():
        return result
    for directory in (state / "runs").iterdir():
        if directory.is_symlink() or not directory.is_dir():
            continue
        manifest = directory / "runtime.json"
        if not manifest.is_file():
            continue
        data = json.loads(read_text(state, manifest.relative_to(state).as_posix()))
        name = "appsec-lab-" + directory.name
        if data.get("owner") != name:
            raise ScopeError("Cleanup ownership manifest mismatch")
        scratch = inside(state, Path(data["scratch"]))
        if scratch.parent != state / "cache" or not scratch.name.startswith(name + "-"):
            raise ScopeError("Cleanup path is not an owned runtime")
        if not data.get("stopped"):
            pid = data["pid"]
            if data["backend"] == "compose":
                from local_appsec_lab.runtime.compose import cleanup_resources

                base, control_env = docker_control()
                if data.get("docker_base") != base:
                    raise ScopeError("Docker context changed; refusing cross-daemon cleanup")
                cleanup_resources(base, control_env, name, data["resources"])
            elif data["backend"] == "docker":
                base, control_env = docker_control()
                recorded = data.get("docker_base")
                if recorded != base:
                    raise ScopeError(
                        "Docker context changed since launch; refusing cross-daemon cleanup"
                    )
                label = subprocess.run(
                    [
                        *base,
                        "inspect",
                        "--format",
                        '{{index .Config.Labels "appsec-lab.owner"}}',
                        name,
                    ],
                    env=control_env,
                    capture_output=True,
                    timeout=5,
                )
                if label.stdout.decode().strip() == name:
                    removed = subprocess.run(
                        [*base, "rm", "-f", name], env=control_env, capture_output=True, timeout=10
                    )
                    if removed.returncode:
                        raise ScopeError("Owned container cleanup failed; preserving scratch")
                elif label.returncode and b"no such" not in label.stderr.lower():
                    raise ScopeError("Cannot establish container state; preserving scratch")
            elif os.name == "posix":
                identity = (
                    subprocess.run(
                        ["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="],
                        capture_output=True,
                        timeout=3,
                    )
                    .stdout.decode()
                    .strip()
                )
                if identity:
                    if identity != data["identity"] or os.getpgid(pid) != pid:
                        raise ScopeError(
                            "Process ownership no longer matches; refusing to signal it"
                        )
                    os.killpg(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        try:
                            os.kill(pid, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.1)
                    else:
                        raise ScopeError("Owned process has not exited; preserving scratch")
                else:
                    groups = subprocess.run(
                        ["ps", "-axo", "pgid=,stat="], capture_output=True, timeout=3
                    )
                    if any(
                        parts[0] == str(pid).encode() and not parts[1].startswith(b"Z")
                        for line in groups.stdout.splitlines()
                        if len(parts := line.split()) >= 2
                    ):
                        raise ScopeError(
                            "Leader is gone and group ownership cannot be revalidated; preserving scratch"
                        )
            data["stopped"] = True
            atomic_json(manifest, data)
        if scratch.exists():
            shutil.rmtree(scratch)
        result.append({"run_id": directory.name, "cleaned": True})
    return result
