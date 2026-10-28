"""Explain component boundaries and applicable checks without executing source."""

from pathlib import PurePosixPath


def components(inventory: dict) -> list[dict]:
    groups: dict[str, dict] = {}

    def group(directory: str, kind: str = "library_or_unknown") -> dict:
        return groups.setdefault(
            directory,
            dict(
                id=directory,
                project=directory,
                kind=kind,
                evidence=[],
                startup_candidates=[],
                dependencies=[],
                files=[],
                runtime_candidate=False,
            ),
        )

    for service in inventory["services"]:
        directory = PurePosixPath(service["source"]).parent.as_posix()
        if service["kind"] == "compose":
            key = service["source"] + "#" + service["id"]
            item = group(key, "compose_service")
            item["project"] = directory
            item["service"] = service["id"]
            item["compose_file"] = service["source"]
            item["dependencies"] = service["dependencies"]
            image = str(service.get("image") or "").split("/")[-1].split(":")[0].split("@")[0]
            item["kind"] = (
                "supporting_service"
                if image
                in {
                    "postgres",
                    "redis",
                    "mysql",
                    "mariadb",
                    "mongo",
                    "minio",
                }
                else "compose_service"
            )
            item["runtime_candidate"] = True
        else:
            item = group(directory)
            item["kind"] = "application"
            command = service.get("command") or []
            scripts = service.get("scripts")
            if not command and isinstance(scripts, dict):
                script = next(
                    (s for s in ("start", "dev") if isinstance(scripts.get(s), str)), None
                )
                if script:
                    command = ["npm", "run", script]
            if command and command not in item["startup_candidates"]:
                item["startup_candidates"].append(command)
            item["runtime_candidate"] = bool(item["startup_candidates"])
        item["evidence"].append(service["source"])
    manifests = {"pyproject.toml", "Cargo.toml", "go.mod", "pom.xml", "composer.json", "Gemfile"}
    for path in inventory["files"]:
        if PurePosixPath(path).name in manifests:
            group(PurePosixPath(path).parent.as_posix())["evidence"].append(path)
    if inventory.get("project_type") == "static_website":
        group(".")["kind"] = "static_frontend"
        groups["."]["runtime_candidate"] = True
        groups["."]["evidence"].append("index.html")
    directories = sorted((key for key in groups if "#" not in key), key=len, reverse=True)
    binaries = set(inventory.get("binary_files", []))
    infra = {p.split(":workspaces")[0] for p in inventory["infrastructure"]}
    for path in inventory["files"]:
        parts = PurePosixPath(path).parts
        if path in infra or path.startswith(".github/workflows/"):
            item = group("@infrastructure", "infrastructure")
            item["project"] = "."
        elif parts[0] in {"docs", "documentation"} or PurePosixPath(path).suffix.lower() in {
            ".md",
            ".rst",
        }:
            item = group("@documentation", "documentation")
            item["project"] = "."
        elif path in binaries:
            item = group("@assets", "assets")
            item["project"] = "."
        else:
            owner = next((p for p in directories if p == "." or path.startswith(p + "/")), None)
            if owner is None:
                owner = parts[0] if len(parts) > 1 else "."
            item = group(owner)
        item["files"].append(path)
    for item in groups.values():
        item["file_count"] = len(item["files"])
        item["evidence"] = sorted(set(item["evidence"]))
        if item["kind"] == "application":
            framework_names = {
                name
                for name, sources in inventory["frameworks"].items()
                if any(PurePosixPath(p).parent.as_posix() == item["project"] for p in sources)
            }
            if framework_names.intersection(
                {"Next.js", "React", "Vue", "Nuxt", "Vite", "Angular", "SvelteKit"}
            ):
                item["kind"] = "frontend"
            elif framework_names.intersection(
                {"Flask", "FastAPI", "Django", "Express", "Fastify", "NestJS", "Starlette"}
            ):
                item["kind"] = "api"
            item["reason"] = (
                "Source declares a startup candidate; image, dependencies, port and health still need validation."
                if item["runtime_candidate"]
                else "Application manifest found, but no supported startup candidate was identified."
            )
        elif item["kind"] == "supporting_service":
            item["reason"] = (
                "Database/cache/storage dependency; start only inside a reviewed disposable service group."
            )
        elif item["kind"] == "compose_service":
            item["reason"] = (
                "Compose declaration found; constrained Compose validation is required before startup."
            )
        elif item["kind"] == "static_frontend":
            item["reason"] = (
                "Static pages need a reviewed web server and browser runtime for live tests."
            )
        else:
            item["reason"] = (
                "No HTTP startup identified; review source/configuration without inventing a runtime."
            )
    return sorted(groups.values(), key=lambda c: c["id"])


def assessment(
    inventory: dict,
    config,
    mode: str,
    startup: dict,
    started: bool = False,
    requests: int = 0,
    completed: bool = False,
) -> dict:
    """Route a requested mode to components. A startup candidate is never marked ready."""
    selected_directory = startup.get("service")
    compose_services = set(startup.get("services", [])) if config.execution.compose_file else set()
    selected_ids = {
        c["id"]
        for c in inventory.get("components", [])
        if (
            (
                config.execution.compose_file
                and c.get("compose_file") == config.execution.compose_file
                and c.get("service") in compose_services
            )
            or (not config.execution.compose_file and c["id"] == selected_directory)
        )
    }
    rows = []
    for component in inventory.get("components", []):
        selected = component["id"] in selected_ids
        applicable = component["runtime_candidate"] or bool(
            selected
            and startup.get("supported")
            and (config.execution.command or config.execution.existing_url)
        )
        if mode == "review":
            action, reason = (
                "source_only",
                "The request selects source review; no application execution.",
            )
        elif not applicable:
            action, reason = "source_only", component["reason"]
        elif not startup.get("supported"):
            action, reason = "blocked", startup.get("reason", "Startup is unsupported.")
        elif not selected:
            action, reason = (
                "not_selected",
                (
                    "Runtime candidate is outside the selected startup profile; needs its own service plan."
                ),
            )
        else:
            action, reason = (
                "planned",
                (
                    "Selected for bounded execution after plan approval; prerequisites can still block startup."
                ),
            )
        if completed and action == "planned":
            action = "started" if started else "not_started"
            reason = (
                "Owned runtime started; consult measured test coverage."
                if started
                else (
                    "No successful startup recorded; consult blocked checks and runtime diagnostics."
                )
            )
        support = component["kind"] == "supporting_service"
        rows.append(
            dict(
                id=component["id"],
                project=component["project"],
                kind=component["kind"],
                file_count=component["file_count"],
                runtime_candidate=applicable,
                runtime_action=action,
                reason=reason,
                source_review="inventory_only"
                if component["kind"] == "assets"
                else "bounded_source_checks",
                applicable_live_checks=(
                    []
                    if mode == "review" or not applicable or support
                    else ["http_responses"]
                    + (["synthetic_api_scenarios"] if mode == "local-active" else [])
                ),
                browser="configured" if selected and config.browser_workflows else "not_configured",
                execution_target=selected and not support,
            )
        )
    return dict(
        requested_mode=mode,
        components=rows,
        execution_policy="Only the selected reviewed runtime profile executes; other components are explicitly accounted for.",
        measured_http_requests=requests if completed else None,
        limitations=[
            "Recognition and startup declarations do not prove runnability or complete source coverage.",
            "A CLI scan runs one service/profile or one constrained Compose group; the skill coordinates independent scopes.",
            "Synthetic access policies, database seeds and browser workflows require actual project-specific configuration.",
        ],
    )
