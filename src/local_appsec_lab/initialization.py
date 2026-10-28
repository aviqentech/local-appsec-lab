"""Prepare a reviewable project configuration without executing target code."""

from pathlib import Path

from local_appsec_lab.configuration import CONFIG_FILE, Config, template
from local_appsec_lab.discovery import inspect
from local_appsec_lab.errors import ConfigError, LabError
from local_appsec_lab.runtime import resolve_command
from local_appsec_lab.utilities.files import inside, read_bytes


def review_budget(file_count: int | None, source_bytes: int | None) -> dict:
    """Starter scheduling budgets; project size does not establish complete coverage."""
    if file_count is None or source_bytes is None:
        size, tokens, calls, seconds = "unknown", 200_000, 12, 300
    elif file_count > 500 or source_bytes > 10_000_000:
        size, tokens, calls, seconds = "large", 1_000_000, 32, 900
    elif file_count > 100 or source_bytes > 1_000_000:
        size, tokens, calls, seconds = "medium", 500_000, 24, 600
    else:
        size, tokens, calls, seconds = "small", 200_000, 12, 300
    return dict(
        project_size=size,
        source_files=file_count,
        source_bytes=source_bytes,
        model_tokens=tokens,
        model_calls=calls,
        duration_seconds=seconds,
    )


def initialize(root: Path, native_host: str | None = None) -> dict:
    destination = inside(root, Path(CONFIG_FILE))
    if destination.exists():
        raise ConfigError(
            "Configuration already exists; edit appsec-lab.yaml, then run config validate and plan. "
            "No files overwritten"
        )
    config = Config()
    if native_host:
        config.ai.strategy = "native"
        config.ai.context_bytes = 6000
    notes = []
    detected = {}
    budget = review_budget(None, None)
    try:
        inventory = inspect(root, config.output)
        binary = set(inventory.get("binary_files", []))
        source_files = [p for p in inventory["files"] if p not in binary]
        budget = review_budget(
            len(source_files), sum(len(read_bytes(root, p)) for p in source_files)
        )
        detected = {
            "languages": sorted(inventory["languages"]),
            "frameworks": sorted(inventory["frameworks"]),
            "services": [s["id"] for s in inventory["services"]],
        }
        try:
            command, directory = resolve_command(config, inventory)
            config.execution.command = command
            config.execution.service = directory
            detected["startup"] = {"command": command, "service": directory}
        except LabError as exc:
            notes.append(str(exc))
    except LabError as exc:
        notes.append("Project discovery incomplete: " + str(exc))
    if native_host:
        for field in ("model_tokens", "model_calls", "duration_seconds"):
            setattr(config.limits, field, budget[field])
    notes.extend(
        [
            "Review execution.command, service directory, port and health_path before live testing.",
            "Prepare the runtime image and application dependencies; init does not install or start them.",
            "Configure synthetic users and API scenarios; init cannot infer the intended access policy.",
            "Browser testing requires browser: true, browser_workflows and a Playwright/Chromium runtime.",
        ]
    )
    if native_host:
        notes.append(
            "Authenticate the selected host CLI separately. Init sends no model requests. "
            "Native vendor token/cost limits are not uniformly enforceable."
        )
    # Exclusive creation preserves an existing configuration, including concurrent initialization.
    with destination.open("x", encoding="utf-8") as stream:
        stream.write(template(config))
    ignore = inside(root, Path(".gitignore"))
    existing = ignore.read_text() if ignore.exists() else ""
    if ".appsec-lab/" not in existing:
        ignore.write_text(existing + "\n# Private security assessments\n.appsec-lab/\n")
    project = ["--project", str(root)]
    scan = ["appsec-lab", "scan", *project, "--mode", "review"]
    if native_host:
        scan.extend(["--native-host", native_host, "--allow-model-requests"])
    return {
        "configuration": str(destination),
        "authorized": False,
        "ai_strategy": config.ai.strategy,
        "configured_settings": {
            "file": str(destination),
            "ai": config.ai.model_dump(),
            "limits": config.limits.model_dump(),
            "sizing": budget,
            "sizing_applied": bool(native_host),
            "edit_instructions": (
                "Edit ai and limits in this appsec-lab.yaml to suit your needs. Then run config "
                "validate and plan again. These starter budgets do not guarantee complete coverage."
            ),
        },
        "detected": detected,
        "configuration_scope": (
            "This file applies only to this --project directory. Child project scans do not "
            "inherit it; initialize each selected service directory."
        ),
        "ai_setup": (
            "Native strategy and explicit budgets configured; model consent is still required per scan."
            if native_host
            else "Deterministic review configured. To enable AI later, edit ai.strategy to native and "
            "limits.model_tokens/model_calls, then select --native-host with --allow-model-requests."
        ),
        "live_testing": {"ready": False, "remaining_setup": notes},
        "next_steps": [
            {"action": "Edit the generated configuration", "file": str(destination)},
            {
                "action": "Validate configuration",
                "command": ["appsec-lab", "config", "validate", *project],
            },
            {"action": "Review the plan", "command": ["appsec-lab", "plan", *project]},
            {"action": "Run source review", "command": scan},
        ],
        "documentation": "https://github.com/aviqentech/local-appsec-lab/blob/main/docs/configuration.md",
    }
