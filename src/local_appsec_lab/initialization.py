"""Prepare a reviewable project configuration without executing target code."""

from pathlib import Path

from local_appsec_lab.configuration import CONFIG_FILE, Config, template
from local_appsec_lab.discovery import inspect
from local_appsec_lab.errors import ConfigError, LabError
from local_appsec_lab.runtime import resolve_command
from local_appsec_lab.utilities.files import inside


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
        config.limits.model_tokens = 200_000
        config.limits.model_calls = 6
    notes = []
    detected = {}
    try:
        inventory = inspect(root, config.output)
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
