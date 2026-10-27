"""Generate a constrained Compose environment; never execute project Compose as-is."""

from __future__ import annotations

import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import RuntimeFailure, ScopeError
from local_appsec_lab.isolation import docker_control, local_image
from local_appsec_lab.network import Budget
from local_appsec_lab.runtime import BridgeClient, Runtime
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_bytes, read_text
from local_appsec_lab.utilities.yaml import safe_yaml


FORBIDDEN = {
    "privileged",
    "devices",
    "device_cgroup_rules",
    "network_mode",
    "pid",
    "ipc",
    "cap_add",
    "external_links",
    "extra_hosts",
    "configs",
    "secrets",
    "extends",
    "env_file",
    "develop",
    "provider",
}


def definition(root: Path, config: Config) -> tuple[dict, str]:
    value = safe_yaml(read_text(root, config.execution.compose_file))
    services = value.get("services") if isinstance(value, dict) else None
    if not isinstance(services, dict) or not 1 <= len(services) <= 8:
        raise ScopeError("Compose requires 1–8 explicit services")
    for name, service in services.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", name) or not isinstance(service, dict):
            raise ScopeError("Invalid Compose service identity")
        if FORBIDDEN.intersection(service):
            raise ScopeError("Compose requests forbidden host/privilege/config access")
        if service.get("volumes"):
            raise ScopeError(
                "Project Compose host/volume mounts are not executed; use configured disposable seeds"
            )
        if not isinstance(service.get("image"), str) or "${" in service["image"]:
            raise ScopeError("Every Compose service needs an explicit preloaded image")
        if service.get("entrypoint"):
            raise ScopeError("Project entrypoint overrides are unsupported")
    selected = config.execution.service
    if selected is None:
        candidates = [
            name for name, service in services.items() if not database_type(service["image"])
        ]
        if len(candidates) != 1:
            raise RuntimeFailure("Select execution.service for a multi-application Compose project")
        selected = candidates[0]
    if selected not in services or database_type(services[selected]["image"]):
        raise ScopeError("The selected HTTP service must be an application")
    return services, selected


def database_type(image: str) -> str | None:
    base = image.split("@")[0].split(":")[0].removeprefix("docker.io/library/")
    return base if base in {"postgres", "redis"} else None


class ComposeRuntime(Runtime):
    def __init__(self, root, state, run_id, config, inventory, mode="local-passive", categories=()):
        super().__init__(root, state, run_id, config, inventory, mode, categories)
        self.backend = "compose"
        self.resources = []
        self.network = self.name + "-network"
        self.compose_path = None
        self.secrets = ()
        self.services_started = 0

    def control(self, args, *, input=None, timeout=30):
        from local_appsec_lab.agents.native import bounded_run
        from local_appsec_lab.errors import BudgetExceeded

        try:
            output, _ = bounded_run(
                [*self.docker_base, *args], input or b"", self.root, self.control_env, timeout
            )
            return output
        except (RuntimeFailure, BudgetExceeded) as exc:
            from local_appsec_lab.utilities.redaction import redact

            diagnostic = redact(
                getattr(exc, "diagnostic", b"").decode(errors="replace"), self.secrets
            )
            self.log.extend(
                diagnostic.encode()[: max(0, self.config.limits.log_bytes - len(self.log))]
            )
            raise RuntimeFailure(
                "Owned Docker/Compose operation failed; inspect image, capability and readiness prerequisites"
            ) from exc

    def manifest_value(self, stopped=False):
        return {
            "owner": self.name,
            "backend": "compose",
            "pid": self.process.pid if self.process else None,
            "docker_base": self.docker_base,
            "scratch": str(self.scratch),
            "resources": self.resources,
            "network": self.network,
            "stopped": stopped,
            "identity": "owned-labels",
        }

    def start(self, budget: Budget):
        services, selected = definition(self.root, self.config)
        self.docker_base, self.control_env = docker_control()
        version = json.loads(self.control(["version", "--format", "{{json .Server}}"]))
        if int(version["Version"].split(".")[0]) < 28:
            raise RuntimeFailure("Compose isolation needs Docker Engine 28+ isolated gateway mode")
        self.scratch = Path(
            tempfile.mkdtemp(prefix=self.name + "-", dir=private_dir(self.state / "cache"))
        )
        source = self.scratch / "source"
        source.mkdir()
        for relative in self.inventory["files"]:
            if relative == "appsec-lab.yaml":
                continue
            target = inside(source, Path(relative))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(read_bytes(self.root, relative))
            target.chmod(0o644)
        for path in [source, *source.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
        password = secrets.token_hex(16)
        self.secrets = (password,)
        documents = {}
        self.resources = [{"kind": "network", "name": self.network}]
        for name, original in services.items():
            image = local_image(self.docker_base, self.control_env, original["image"])
            kind = database_type(original["image"])
            container = self.name + "-" + name
            self.resources.append({"kind": "container", "name": container})
            service = {
                "image": image,
                "container_name": container,
                "pull_policy": "never",
                "labels": {"appsec-lab.owner": self.name},
                "networks": ["lab"],
                "dns": ["127.0.0.1"],
                "user": "65534:65534",
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "cpus": self.config.limits.cpus / max(1, len(services)),
                "mem_limit": f"{self.config.limits.memory_mb // len(services)}m",
                "pids_limit": self.config.limits.processes,
                "tmpfs": [
                    f"/tmp:rw,noexec,nosuid,uid=65534,gid=65534,size={self.config.limits.storage_mb}m"
                ],
                "logging": {
                    "driver": "local",
                    "options": {
                        "max-size": str(self.config.limits.log_bytes),
                        "max-file": "1",
                        "compress": "false",
                    },
                },
            }
            if kind == "postgres":
                service.update(
                    {
                        "environment": {
                            "POSTGRES_USER": "synthetic",
                            "POSTGRES_PASSWORD": password,
                            "POSTGRES_DB": "synthetic",
                            "PGDATA": "/tmp/pgdata",
                            "PGHOST": "/var/run/postgresql",
                        },
                    }
                )
                service["tmpfs"].append(
                    "/var/run/postgresql:rw,noexec,nosuid,uid=65534,gid=65534,mode=3775,size=1m"
                )
            elif kind == "redis":
                service["command"] = [
                    "redis-server",
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                    "--dir",
                    "/tmp",
                ]
            else:
                env = original.get("environment", {})
                if not isinstance(env, dict):
                    raise ScopeError("Compose environments must be explicit mappings")
                clean = {}
                if name == selected:
                    env = {**env, **self.config.execution.environment}
                for key, value in env.items():
                    if not isinstance(value, (str, int, bool)) or "${" in str(value):
                        raise ScopeError("Compose environment interpolation is prohibited")
                    value = str(value)
                    if "://" in value:
                        parsed = urlsplit(value)
                        if parsed.hostname not in services:
                            raise ScopeError(
                                "Compose environment points outside the disposable service graph"
                            )
                        target_kind = database_type(services[parsed.hostname]["image"])
                        if target_kind == "postgres":
                            value = f"postgresql://synthetic:{password}@{parsed.hostname}:5432/synthetic"
                        elif target_kind == "redis":
                            value = f"redis://{parsed.hostname}:6379/0"
                        else:
                            raise ScopeError(
                                "Review application-to-application connection configuration explicitly"
                            )
                    clean[key] = value
                from local_appsec_lab.configuration import Execution

                Execution(environment=clean)
                clean.update(
                    {
                        "HOME": "/tmp",
                        "HOST": "127.0.0.1" if name == selected else "0.0.0.0",
                        "PORT": str(self.config.execution.port),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    }
                )
                command = (
                    self.config.execution.command
                    if name == selected and self.config.execution.command
                    else original.get("command")
                )
                if (
                    not isinstance(command, list)
                    or not command
                    or not all(isinstance(arg, str) for arg in command)
                ):
                    raise ScopeError(
                        "Application Compose commands must be explicit argument arrays"
                    )
                if Path(command[0]).name not in {
                    "python",
                    "python3",
                    "node",
                    "npm",
                    "pnpm",
                    "yarn",
                    "uvicorn",
                    "flask",
                }:
                    raise ScopeError("Unsupported Compose application executable")
                service.update(
                    {
                        "environment": clean,
                        "working_dir": "/app",
                        "volumes": [
                            {
                                "type": "bind",
                                "source": str(source),
                                "target": "/app",
                                "read_only": True,
                            },
                            {
                                "type": "bind",
                                "source": str(Path(__file__).parent / "bridge.py"),
                                "target": "/bridge.py",
                                "read_only": True,
                            },
                        ],
                    }
                )
                if name == selected:
                    from local_appsec_lab.runtime.setup import prepared

                    bundle = prepared(self.root, self.state, self.config, image)
                    if bundle:
                        installed, manager = bundle
                        if manager == "pip":
                            service["environment"]["PYTHONPATH"] = "/deps"
                        else:
                            (source / "node_modules").mkdir(exist_ok=True)
                        service["volumes"].append(
                            {
                                "type": "bind",
                                "source": str(
                                    installed if manager == "pip" else installed / "node_modules"
                                ),
                                "target": "/deps" if manager == "pip" else "/app/node_modules",
                                "read_only": True,
                            }
                        )
                if name == selected:
                    service.update(
                        {
                            "entrypoint": ["python", "-I", "/bridge.py"],
                            "command": [json.dumps(command), str(self.config.execution.port)],
                            "stdin_open": True,
                        }
                    )
                else:
                    service["command"] = command
            documents[name] = service
            if name == selected and (self.config.browser or self.config.browser_workflows):
                service["security_opt"].append(
                    "seccomp=" + str(Path(__file__).parent.parent / "data/browser-seccomp.json")
                )
                service["volumes"].append(
                    {
                        "type": "bind",
                        "source": str(Path(__file__).parent / "browser_worker.py"),
                        "target": "/browser_worker.py",
                        "read_only": True,
                    }
                )
        self.compose_path = self.scratch / "compose.yaml"
        self.compose_path.write_text(
            yaml.safe_dump(
                {
                    "services": documents,
                    "networks": {"lab": {"name": self.network, "external": True}},
                },
                sort_keys=False,
            )
        )
        atomic_json(self.manifest, self.manifest_value())
        self.control(
            [
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--label",
                "appsec-lab.owner=" + self.name,
                self.network,
            ]
        )
        compose = ["compose", "--project-name", self.name, "--file", str(self.compose_path)]
        dependencies = [name for name in services if name != selected]
        if dependencies:
            self.control(
                [*compose, "up", "--detach", "--no-build", "--pull", "never", *dependencies],
                timeout=self.config.execution.startup_timeout,
            )
        for name, service in services.items():
            kind = database_type(service["image"])
            if not kind:
                continue
            command = (
                ["pg_isready", "-h", "127.0.0.1", "-U", "synthetic", "-d", "synthetic"]
                if kind == "postgres"
                else ["redis-cli", "ping"]
            )
            deadline = time.monotonic() + self.config.execution.startup_timeout
            while True:
                result = subprocess.run(
                    [*self.docker_base, "exec", self.name + "-" + name, *command],
                    env=self.control_env,
                    capture_output=True,
                    timeout=3,
                )
                if result.returncode == 0:
                    break
                if time.monotonic() > deadline:
                    diagnostic = subprocess.run(
                        [*self.docker_base, "logs", "--tail", "30", self.name + "-" + name],
                        env=self.control_env,
                        capture_output=True,
                        timeout=5,
                    )
                    from local_appsec_lab.utilities.redaction import redact

                    self.log.extend(
                        redact(
                            (diagnostic.stdout + diagnostic.stderr).decode(errors="replace"),
                            self.secrets,
                        ).encode()[: self.config.limits.log_bytes]
                    )
                    raise RuntimeFailure("Disposable database readiness timeout")
                budget.remaining()
                time.sleep(0.2)
            seed = self.config.execution.seeds.get(name)
            if seed:
                if kind != "postgres":
                    raise ScopeError("SQL seeds require an owned disposable PostgreSQL service")
                self.control(
                    [
                        "exec",
                        "-i",
                        "--user",
                        "65534:65534",
                        self.name + "-" + name,
                        "psql",
                        "--host",
                        "/var/run/postgresql",
                        "--username",
                        "synthetic",
                        "--dbname",
                        "synthetic",
                        "--set",
                        "ON_ERROR_STOP=1",
                    ],
                    input=read_bytes(self.root, seed),
                    timeout=20,
                )
        for name, command in self.config.execution.migrations.items():
            if (
                name not in services
                or database_type(services[name]["image"])
                or not command
                or Path(command[0]).name
                not in {"python", "python3", "node", "npm", "alembic", "flask"}
            ):
                raise ScopeError("Invalid disposable migration command")
            migration = {"kind": "container", "name": self.name + "-migration-" + name}
            self.resources.append(migration)
            atomic_json(self.manifest, self.manifest_value())
            try:
                self.control(
                    [
                        *compose,
                        "run",
                        "--rm",
                        "--name",
                        migration["name"],
                        "--no-deps",
                        "--entrypoint",
                        command[0],
                        name,
                        *command[1:],
                    ],
                    timeout=min(60, self.config.limits.duration_seconds),
                )
            finally:
                cleanup_resources(self.docker_base, self.control_env, self.name, [migration])
        self.control([*compose, "create", "--no-build", "--pull", "never", selected])
        self.process = subprocess.Popen(
            [*self.docker_base, "start", "--attach", "--interactive", self.name + "-" + selected],
            env=self.control_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        atomic_json(self.manifest, self.manifest_value())
        threading.Thread(target=self._drain, args=(self.process.stdout, True), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.process.stderr, False), daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()
        try:
            ready = self.output.get(timeout=10)
        except queue.Empty as exc:
            raise RuntimeFailure("Compose bridge did not initialize") from exc
        if not ready.get("ready"):
            raise RuntimeFailure("Invalid Compose bridge initialization")
        scenarios = [
            s
            for s in self.config.scenarios
            if self.mode == "local-active" and s.category in self.categories
        ]
        mutations = {(s.method, s.path) for s in scenarios if s.method != "GET"} | {
            ("DELETE", s.rollback_path) for s in scenarios if s.rollback_path
        }
        client = BridgeClient(self, budget, mutations)
        deadline = time.monotonic() + self.config.execution.startup_timeout
        while time.monotonic() < deadline:
            try:
                if client.request(self.config.execution.health_path).status == 200:
                    self.started = True
                    self.services_started = len(services)
                    return client
            except (OSError, RuntimeFailure):
                pass
            time.sleep(0.1)
        raise RuntimeFailure("Compose application readiness timeout")

    def _stop_owned(self):
        if self.stopped.is_set():
            return
        self.stopped.set()
        try:
            cleanup_resources(self.docker_base, self.control_env, self.name, self.resources)
            if self.process:
                self.process.wait(timeout=5)
            if self.manifest.exists():
                atomic_json(self.manifest, self.manifest_value(True))
            if self.scratch and self.scratch.exists():
                shutil.rmtree(self.scratch)
            self.cleaned = True
        except (OSError, subprocess.TimeoutExpired, RuntimeFailure, ScopeError) as exc:
            self.failure = "Compose cleanup incomplete: " + type(exc).__name__
            self.cleaned = False


def cleanup_resources(base, env, owner, resources):
    for resource in sorted(resources, key=lambda r: r["kind"] == "network"):
        kind, name = resource["kind"], resource["name"]
        if kind not in {"container", "network"} or not name.startswith(owner + "-"):
            raise ScopeError("Invalid owned Compose resource")
        template = (
            '{{index .Config.Labels "appsec-lab.owner"}}'
            if kind == "container"
            else '{{index .Labels "appsec-lab.owner"}}'
        )
        result = subprocess.run(
            [*base, kind, "inspect", "--format", template, name],
            env=env,
            capture_output=True,
            timeout=5,
        )
        if result.returncode:
            if b"no such" in result.stderr.lower() or b"not found" in result.stderr.lower():
                continue
            raise RuntimeFailure("Cannot establish Compose cleanup ownership")
        if result.stdout.decode().strip() != owner:
            raise ScopeError("Refusing to remove foreign Compose resource")
        result = subprocess.run(
            [*base, kind, "rm", *(["--force"] if kind == "container" else []), name],
            env=env,
            capture_output=True,
            timeout=10,
        )
        if result.returncode:
            raise RuntimeFailure("Owned Compose resource removal failed")
