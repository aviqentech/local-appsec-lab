from __future__ import annotations

import base64
import json
import os
import platform
import queue
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import RuntimeFailure, ScopeError
from local_appsec_lab.isolation import backend, command_for, docker_control
from local_appsec_lab.network import Budget, Client, Response, safe_path
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_bytes


def child_limits(config: Config):
    def apply():
        import resource

        resource.setrlimit(
            resource.RLIMIT_CPU, (config.limits.duration_seconds, config.limits.duration_seconds)
        )
        resource.setrlimit(
            resource.RLIMIT_FSIZE, (config.limits.log_bytes, config.limits.log_bytes)
        )
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if platform.system() == "Linux":
            memory = config.limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))

    return apply


def resolve_command(config: Config, inventory: dict) -> tuple[list[str], str]:
    service = config.execution.service
    candidates = [
        s
        for s in inventory["services"]
        if s.get("command") and (service is None or s["id"] == service)
    ]
    if config.execution.command:
        command = list(config.execution.command)
        directory = service or "."
    elif len(candidates) == 1:
        command = list(candidates[0]["command"])
        directory = str(Path(candidates[0]["source"]).parent)
    else:
        raise RuntimeFailure(
            "Startup is ambiguous or unsupported; set execution.command and execution.service after reviewing plan"
        )
    if not command or Path(command[0]).name not in {
        "python",
        "python3",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "uvicorn",
        "flask",
    }:
        raise RuntimeFailure(
            "Startup executable is unsupported; use a reviewed Python/Node entry point"
        )
    if any("\x00" in arg for arg in command):
        raise RuntimeFailure("Invalid startup arguments")
    return command, directory


class BridgeClient(Client):
    def __init__(self, runtime: Runtime, budget: Budget, mutations: set):
        super().__init__(
            f"http://127.0.0.1:{runtime.config.execution.port}",
            runtime.config.execution.port,
            budget,
            mutations,
        )
        self.runtime = runtime

    def request(
        self, path: str, headers: dict | None = None, method: str = "GET", body: dict | None = None
    ) -> Response:
        safe_path(path)
        if method not in {"GET", "HEAD"} and (method, path) not in self.allowed_mutations:
            raise ScopeError("Unapproved mutation")
        if headers and any(
            k.lower()
            in {"host", "connection", "transfer-encoding", "content-length", "proxy-authorization"}
            or "\r" in k + v
            or "\n" in k + v
            for k, v in headers.items()
        ):
            raise ScopeError("Unsafe headers")
        data = json.dumps(body) if body is not None else None
        if data and len(data) > 4096:
            raise ScopeError("Oversized body")
        self.budget.claim()
        result = self.runtime.exchange(
            {
                "path": path,
                "headers": headers or {},
                "method": method,
                "body": data,
                "limit": self.budget.limits.response_bytes,
                "timeout": min(3, self.budget.remaining()),
            }
        )
        if "error" in result:
            raise RuntimeFailure(f"Isolated HTTP request failed: {result['error']}")
        if 300 <= result["status"] < 400:
            raise ScopeError("Redirect refused")
        content = base64.b64decode(result["body"])
        maximum = self.budget.limits.response_bytes
        return Response(
            result["status"],
            {k.lower(): v for k, v in result["headers"].items()},
            content[:maximum],
            len(content) > maximum,
        )


class Runtime:
    def __init__(
        self,
        root: Path,
        state: Path,
        run_id: str,
        config: Config,
        inventory: dict,
        mode: str = "local-passive",
        categories: tuple[str, ...] = (),
    ):
        self.root, self.state, self.run_id = root, state, run_id
        self.config, self.inventory = config, inventory
        self.mode, self.categories = mode, categories
        self.docker_base: list[str] = []
        self.control_env: dict[str, str] = {}
        self.process: subprocess.Popen | None = None
        self.scratch: Path | None = None
        self.backend = "none"
        self.name = "appsec-lab-" + run_id
        self.output: queue.Queue = queue.Queue(maxsize=4)
        self.rpc_lock = threading.Lock()
        self.stopped = threading.Event()
        self.stop_lock = threading.Lock()
        self.failure: str | None = None
        self.started = False
        self.cleaned = False
        self.log = bytearray()
        self.manifest = state / "runs" / run_id / "runtime.json"

    def start(self, budget: Budget) -> Client:
        execution = self.config.execution
        if execution.existing_url:
            if not execution.existing_identity:
                raise RuntimeFailure("Existing service requires a declared identity")
            client = Client(execution.existing_url, execution.port, budget)
            response = client.request(execution.health_path)
            if response.headers.get("x-appsec-lab-identity") != execution.existing_identity:
                raise RuntimeFailure("Existing service identity challenge failed")
            return client
        command, directory = resolve_command(self.config, self.inventory)
        selected = backend(self.config)
        self.scratch = Path(
            tempfile.mkdtemp(prefix=self.name + "-", dir=private_dir(self.state / "cache"))
        )
        source = self.scratch / "source"
        source.mkdir(mode=0o700)
        for relative in self.inventory["files"]:
            if relative == "appsec-lab.yaml":
                continue
            destination = inside(source, Path(relative))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(read_bytes(self.root, relative))
        cwd = inside(source, Path(directory))
        if not cwd.is_dir():
            raise RuntimeFailure("Selected service directory does not exist")
        if selected != "docker":
            if command[0] in {"python", "python3"}:
                command[0] = sys.executable
            else:
                binary = shutil.which(command[0])
                if not binary:
                    raise RuntimeFailure(f"Missing runtime: {command[0]}")
                command[0] = binary
        if selected == "macos":
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", execution.port))
                except OSError as exc:
                    raise RuntimeFailure(
                        "Configured port is occupied; no existing service will be tested"
                    ) from exc
        actual_command = command
        if selected == "bubblewrap":
            bridge = source / "_appsec_bridge.py"
            shutil.copyfile(Path(__file__).parent / "bridge.py", bridge)
            actual_command = [
                sys.executable,
                "-I",
                str(bridge),
                json.dumps(command),
                str(execution.port),
            ]
        if selected == "docker":
            self.docker_base, self.control_env = docker_control()
            # Host parent remains private; the container's non-root UID must read the source mount.
            for entry in [source, *source.rglob("*")]:
                entry.chmod(0o755 if entry.is_dir() else 0o644)
        args, self.backend = command_for(
            self.config, self.scratch, cwd, actual_command, self.name, self.docker_base
        )
        # The original environment is deliberately not inherited.
        env = {
            "PATH": os.pathsep.join(
                filter(
                    None,
                    [
                        str(Path(sys.executable).parent),
                        "/usr/bin",
                        "/bin",
                        "/usr/local/bin",
                        "/opt/homebrew/bin",
                    ],
                )
            ),
            "HOME": str(self.scratch),
            "TMPDIR": str(self.scratch),
            "LANG": "C.UTF-8",
            "PORT": str(execution.port),
            "HOST": "127.0.0.1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "OPENSSL_CONF": "/dev/null",
            **execution.environment,
        }
        self.process = subprocess.Popen(
            args,
            cwd=cwd,
            env=self.control_env if self.backend == "docker" else env,
            stdin=subprocess.PIPE if self.backend != "macos" else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            preexec_fn=child_limits(self.config)
            if os.name == "posix" and self.backend == "macos"
            else None,
        )
        atomic_json(
            self.manifest,
            {
                "owner": self.name,
                "pid": self.process.pid,
                "backend": self.backend,
                "docker_base": self.docker_base,
                "scratch": str(self.scratch),
                "identity": self._process_identity(),
                "stopped": False,
            },
        )
        threading.Thread(target=self._drain, args=(self.process.stderr, False), daemon=True).start()
        threading.Thread(
            target=self._drain, args=(self.process.stdout, self.backend != "macos"), daemon=True
        ).start()
        threading.Thread(target=self._watch, daemon=True).start()
        scenarios = [
            s
            for s in self.config.scenarios
            if self.mode == "local-active" and s.category in self.categories
        ]
        mutations = {(s.method, s.path) for s in scenarios if s.method != "GET"}
        mutations |= {("DELETE", s.rollback_path) for s in scenarios if s.rollback_path}
        client = (
            Client(f"http://127.0.0.1:{execution.port}", execution.port, budget, mutations)
            if self.backend == "macos"
            else BridgeClient(self, budget, mutations)
        )
        if self.backend != "macos":
            try:
                message = self.output.get(timeout=10)
            except queue.Empty as exc:
                raise RuntimeFailure(
                    "Isolation bridge did not initialize; verify image contains Python/runtime"
                ) from exc
            if not message.get("ready"):
                raise RuntimeFailure("Invalid isolation bridge startup")
        deadline = time.monotonic() + execution.startup_timeout
        last_error = "not ready"
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeFailure(
                    "Application exited during startup; inspect runtime diagnostics and dependencies"
                )
            try:
                response = client.request(execution.health_path)
                if response.status == 200:
                    if self.backend == "macos":
                        self._confirm_listener()
                    self.started = True
                    data = json.loads(self.manifest.read_text())
                    data["identity"] = self._process_identity()
                    atomic_json(self.manifest, data)
                    return client
                last_error = f"health returned {response.status}"
            except (OSError, RuntimeFailure) as exc:
                last_error = type(exc).__name__
            time.sleep(0.1)
        raise RuntimeFailure(
            f"Application readiness timeout ({last_error}); check command and health_path"
        )

    def _confirm_listener(self) -> None:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-nP", f"-iTCP:{self.config.execution.port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            timeout=3,
        )
        pids = [int(p) for p in result.stdout.split() if p.isdigit()]
        if not pids or any(os.getpgid(p) != self.process.pid for p in pids):
            raise RuntimeFailure("Listening service does not belong to this run")

    def _process_identity(self) -> str:
        if os.name != "posix" or not self.process:
            return "live-handle-only"
        return (
            subprocess.run(
                ["ps", "-p", str(self.process.pid), "-o", "lstart=", "-o", "command="],
                capture_output=True,
                timeout=3,
            )
            .stdout.decode()
            .strip()
        )

    def _drain(self, stream, protocol: bool) -> None:
        if protocol:
            for line in iter(lambda: stream.readline(2_000_000), b""):
                try:
                    self.output.put(json.loads(line), timeout=1)
                except (ValueError, queue.Full):
                    self.failure = "Invalid or overflowing runtime protocol"
                    break
        else:
            while chunk := stream.read(4096):
                remaining = self.config.limits.log_bytes - len(self.log)
                if remaining > 0:
                    self.log.extend(chunk[:remaining])

    def _group_alive(self) -> bool:
        if not self.process or os.name != "posix":
            return bool(self.process and self.process.poll() is None)
        result = subprocess.run(["ps", "-axo", "pgid=,stat="], capture_output=True, timeout=3)
        return any(
            parts[0] == str(self.process.pid).encode() and not parts[1].startswith(b"Z")
            for line in result.stdout.splitlines()
            if len(parts := line.split()) >= 2
        )

    def _storage_size(self) -> int:
        import stat

        total, count = 0, 0
        for directory, dirs, names in os.walk(self.scratch, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
            for name in names:
                try:
                    info = os.stat(Path(directory) / name, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    count += 1
                    if count > 10000:
                        raise RuntimeFailure("Runtime file-count budget exceeded")
        return total

    def _watch(self) -> None:
        started = time.monotonic()
        try:
            while not self.stopped.wait(0.25):
                if self.process.poll() is not None:
                    # Stop surviving members of the owned group/container even if its leader exited.
                    self.stop()
                    return
                size = self._storage_size()
                if (
                    size > self.config.limits.storage_mb * 1024 * 1024
                    or time.monotonic() - started > self.config.limits.duration_seconds
                ):
                    raise RuntimeFailure("Runtime storage or wall-clock budget exceeded")
                if self.backend == "macos":
                    result = subprocess.run(
                        ["ps", "-axo", "pgid=,rss="], capture_output=True, timeout=3
                    )
                    group = [
                        parts
                        for line in result.stdout.splitlines()
                        if len(parts := line.split()) >= 2
                        and parts[0] == str(self.process.pid).encode()
                    ]
                    if (
                        len(group) > self.config.limits.processes
                        or sum(int(p[1]) for p in group) > self.config.limits.memory_mb * 1024
                    ):
                        raise RuntimeFailure("Runtime process or memory budget exceeded")
        except Exception as exc:
            self.failure = "Runtime watchdog: " + type(exc).__name__
            self.stop()

    def exchange(self, message: dict) -> dict:
        with self.rpc_lock:
            if not self.process or self.process.poll() is not None:
                raise RuntimeFailure("Runtime is no longer running")
            self.process.stdin.write((json.dumps(message) + "\n").encode())
            self.process.stdin.flush()
            try:
                return self.output.get(timeout=min(5, float(message.get("timeout", 3)) + 0.25))
            except queue.Empty as exc:
                raise RuntimeFailure("Runtime bridge timed out") from exc

    def stop(self) -> None:
        with self.stop_lock:
            self._stop_owned()

    def _stop_owned(self) -> None:
        if self.stopped.is_set():
            return
        self.stopped.set()
        try:
            if self.process:
                if self.backend == "docker":
                    result = subprocess.run(
                        [
                            *self.docker_base,
                            "inspect",
                            "--format",
                            '{{index .Config.Labels "appsec-lab.owner"}}',
                            self.name,
                        ],
                        env=self.control_env,
                        capture_output=True,
                        timeout=5,
                    )
                    if result.stdout.decode().strip() == self.name:
                        removed = subprocess.run(
                            [*self.docker_base, "rm", "-f", self.name],
                            env=self.control_env,
                            capture_output=True,
                            timeout=8,
                        )
                        if removed.returncode:
                            raise RuntimeFailure("Owned container could not be removed")
                    elif result.returncode and b"no such" not in result.stderr.lower():
                        raise RuntimeFailure("Cannot establish container cleanup state")
                if self.backend == "docker":
                    # The application belongs to the owned container. Once removed,
                    # reap only our client handle; its process group may already be gone.
                    if self.process.poll() is None:
                        self.process.terminate()
                elif os.name == "posix":
                    try:
                        os.killpg(self.process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    deadline = time.monotonic() + 3
                    while self._group_alive() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    if self._group_alive():
                        try:
                            os.killpg(self.process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        time.sleep(0.1)
                    if self._group_alive():
                        raise RuntimeFailure(
                            "Owned process group remains alive; preserving scratch"
                        )
                elif self.process.poll() is None:
                    self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            if self.manifest.exists():
                data = json.loads(self.manifest.read_text())
                data["stopped"] = True
                atomic_json(self.manifest, data)
            if self.scratch and self.scratch.exists():
                if self.scratch.parent == self.state / "cache" and self.scratch.name.startswith(
                    self.name + "-"
                ):
                    shutil.rmtree(self.scratch)
            self.cleaned = True
        except (OSError, RuntimeFailure, subprocess.TimeoutExpired) as exc:
            self.failure = "Cleanup incomplete: " + type(exc).__name__
            self.cleaned = False
