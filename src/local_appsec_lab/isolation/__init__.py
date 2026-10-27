from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import RuntimeFailure


def docker_control() -> tuple[list[str], dict[str, str]]:
    """Pin a trusted local daemon; application config never affects the host client."""
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home())}
    if os.name == "nt":
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "C:\\Windows")
        env["USERPROFILE"] = str(Path.home())
    result = subprocess.run(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        env=env,
        capture_output=True,
        timeout=5,
    )
    endpoint = result.stdout.decode().strip()
    if (
        result.returncode
        or not endpoint.startswith(("unix:///", "npipe://"))
        or any(ord(c) < 32 for c in endpoint)
    ):
        raise RuntimeFailure(
            "Only a trusted local Unix-socket/named-pipe Docker daemon is supported"
        )
    return ["docker", "--host", endpoint], env


def local_image(base: list[str], env: dict, reference: str) -> str:
    """Resolve a preloaded exact reference to content identity; never pull implicitly."""
    result = subprocess.run(
        [*base, "image", "inspect", reference, "--format", "{{.Id}}"],
        env=env,
        capture_output=True,
        timeout=10,
    )
    identity = result.stdout.decode().strip()
    if not result.returncode and re.fullmatch(r"sha256:[a-f0-9]{64}", identity):
        return identity
    # Some containerd image stores list a tag but reject tag inspection. Match
    # the exact tag/digest in the local inventory, then inspect its content ID.
    listing = subprocess.run(
        [*base, "image", "ls", "--digests", "--no-trunc", "--format", "{{json .}}"],
        env=env,
        capture_output=True,
        timeout=10,
    )
    if listing.returncode or len(listing.stdout) > 1_000_000:
        raise RuntimeFailure("Cannot read the bounded local image inventory")
    expected = (
        reference
        if ":" in reference.rsplit("/", 1)[-1] or "@" in reference
        else reference + ":latest"
    )
    matches = set()
    for line in listing.stdout.splitlines():
        item = json.loads(line)
        if (
            item["Repository"] + ":" + item["Tag"] == expected
            or item["Repository"] + "@" + item.get("Digest", "") == expected
        ):
            matches.add(item["ID"])
    if len(matches) == 1:
        identity = matches.pop()
        if re.fullmatch(r"sha256:[a-f0-9]{64}", identity):
            verified = subprocess.run(
                [*base, "image", "inspect", identity, "--format", "{{.Id}}"],
                env=env,
                capture_output=True,
                timeout=10,
            )
            if not verified.returncode and verified.stdout.decode().strip() == identity:
                return identity
    raise RuntimeFailure(
        "The exact runtime image is not preloaded or cannot be resolved; provision it explicitly"
    )


def backend(config: Config) -> str:
    requested = config.execution.backend
    if requested != "auto":
        return requested
    if shutil.which("docker"):
        return "docker"
    if platform.system() == "Linux" and shutil.which("bwrap"):
        return "bubblewrap"
    raise RuntimeFailure("No OS isolation backend available; use review mode or install Docker")


def mac_profile(scratch: Path, source: Path, executable: str, port: int) -> str:
    scratch, source = scratch.resolve(), source.resolve()

    def q(path: str | Path) -> str:
        return json.dumps(str(path))

    readonly = [
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/opt/homebrew/Cellar",
        "/opt/homebrew/opt",
        "/opt/homebrew/bin",
        str(Path(sys.prefix).resolve()),
        str(Path(sys.base_prefix).resolve()),
        str(source),
    ]
    reads = "\n".join(f"(allow file-read* (subpath {q(p)}))" for p in readonly)
    system_files = [
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/private/etc/services",
        "/private/etc/protocols",
        "/private/etc/localtime",
    ]
    reads += "\n" + "\n".join(f"(allow file-read* (literal {q(p)}))" for p in system_files)
    sysctls = "\n".join(
        f'(allow sysctl-read (sysctl-name "{name}"))'
        for name in (
            "hw.memsize",
            "hw.ncpu",
            "hw.availcpu",
            "hw.physicalcpu",
            "hw.physicalcpu_max",
            "hw.logicalcpu",
            "hw.logicalcpu_max",
            "hw.machine",
            "hw.model",
            "hw.pagesize",
            "hw.pagesize_compat",
            "hw.cachelinesize",
            "hw.optional.arm64",
            "kern.ostype",
            "kern.osrelease",
            "kern.version",
            "kern.hostname",
            "kern.osversion",
        )
    )
    return f"""(version 1)
(deny default)
(allow process-exec process-fork)
{sysctls}
(allow signal (target self))
(allow file-read-metadata)
(allow file-read* (literal "/"))
{reads}
(allow file-read* file-write* (subpath {q(scratch)}))
(allow file-write-data (literal "/dev/null"))
(allow network-bind (local ip "localhost:{port}"))
(allow network-inbound (local ip "localhost:{port}"))
(allow network-outbound (remote ip "localhost:{port}"))
"""


def command_for(
    config: Config,
    scratch: Path,
    source: Path,
    command: list[str],
    name: str,
    docker_base: list[str] | None = None,
    dependencies: tuple[Path, str] | None = None,
) -> tuple[list[str], str]:
    selected = backend(config)
    if selected == "macos":
        if platform.system() != "Darwin" or not shutil.which("sandbox-exec"):
            raise RuntimeFailure("macOS sandbox-exec is unavailable")
        profile = scratch / "sandbox.sb"
        profile.write_text(mac_profile(scratch, source, command[0], config.execution.port))
        return ["sandbox-exec", "-f", str(profile), *command], selected
    if selected == "bubblewrap":
        # A separate network namespace prevents host-loopback targets. Requests run via
        # the trusted bridge in that namespace; no host socket or home is mounted.
        if not shutil.which("bwrap"):
            raise RuntimeFailure("bubblewrap is unavailable")
        args = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        for path in ("/usr", "/bin", "/lib", "/lib64", "/opt", "/Library"):
            if Path(path).exists():
                args += ["--ro-bind", path, path]
        args += [
            "--ro-bind",
            str(source),
            str(source),
            "--bind",
            str(scratch),
            str(scratch),
            "--chdir",
            str(source),
            *command,
        ]
        return args, selected
    if selected == "docker":
        if not shutil.which("docker"):
            raise RuntimeFailure("Docker executable is unavailable")
        # The caller runs a bridge inside the container. No published ports or egress.
        limit = config.limits
        control_base, control_env = docker_control()
        image_identity = local_image(
            docker_base or control_base, control_env, config.execution.image
        )
        if "," in str(source):
            raise RuntimeFailure("Docker bind paths containing commas are unsupported")
        args = [
            *(docker_base or docker_control()[0]),
            "run",
            "--rm",
            "-i",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"appsec-lab.owner={name}",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            f"--cpus={limit.cpus}",
            f"--memory={limit.memory_mb}m",
            f"--pids-limit={limit.processes}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={limit.storage_mb}m",
            "--mount",
            f"type=bind,src={source},dst=/app,readonly",
            "--mount",
            f"type=bind,src={Path(__file__).parent.parent / 'runtime' / 'bridge.py'},dst=/bridge.py,readonly",
            "--workdir=/app",
            "--env=HOME=/tmp",
            "--env=PYTHONDONTWRITEBYTECODE=1",
            f"--env=PORT={config.execution.port}",
            "--env=HOST=127.0.0.1",
        ]
        for key, value in config.execution.environment.items():
            args += [f"--env={key}={value}"]
        if dependencies:
            installed, manager = dependencies
            if manager == "pip":
                args += [
                    "--mount",
                    f"type=bind,src={installed},dst=/deps,readonly",
                    "--env=PYTHONPATH=/deps",
                ]
            else:
                args += [
                    "--mount",
                    f"type=bind,src={installed / 'node_modules'},dst=/app/node_modules,readonly",
                ]
        if config.browser or config.browser_workflows:
            args += [
                "--mount",
                f"type=bind,src={Path(__file__).parent.parent / 'runtime' / 'browser_worker.py'},dst=/browser_worker.py,readonly",
                "--security-opt",
                f"seccomp={Path(__file__).parent.parent / 'data' / 'browser-seccomp.json'}",
            ]
        args += [
            "--entrypoint=python",
            image_identity,
            "-I",
            "/bridge.py",
            json.dumps(command),
            str(config.execution.port),
        ]
        return args, selected
    raise RuntimeFailure("Unsupported isolation backend")


def sandbox_probe(config: Config | None = None) -> dict:
    try:
        selected = backend(config or Config())
    except RuntimeFailure:
        selected = "none"
    status = {
        "backend": selected,
        "available": False,
        "remediation": "Install/start the selected isolation backend and preload its runtime",
    }
    try:
        if selected == "macos" and platform.system() == "Darwin" and shutil.which("sandbox-exec"):
            result = subprocess.run(
                [
                    "sandbox-exec",
                    "-p",
                    "(version 1)(allow default)(deny network*)",
                    "/usr/bin/true",
                ],
                capture_output=True,
                timeout=5,
            )
            status.update(
                {
                    "available": result.returncode == 0,
                    "remediation": "Run where macOS sandbox-exec is allowed; nested sandboxes may reject it",
                    "limits": "Reviewed source only: numeric process-argument sysctls can expose same-user host process metadata/environment despite Seatbelt. CPU/file limits enforced; aggregate RSS/process/storage monitored. Use Docker for untrusted code.",
                }
            )
        elif selected == "docker" and shutil.which("docker"):
            base, env = docker_control()
            result = subprocess.run(
                [*base, "info", "--format", "{{.OSType}} {{.ServerVersion}}"],
                env=env,
                capture_output=True,
                timeout=5,
            )
            status.update(
                {
                    "available": result.returncode == 0 and result.stdout.startswith(b"linux "),
                    "remediation": "Start a local Docker Linux-container engine; preload the required image",
                }
            )
        elif selected == "bubblewrap" and platform.system() == "Linux":
            args = ["bwrap", "--unshare-all", "--cap-drop", "ALL"]
            for path in ("/usr", "/bin", "/lib", "/lib64"):
                if Path(path).exists():
                    args.extend(["--ro-bind", path, path])
            result = subprocess.run([*args, "/usr/bin/true"], capture_output=True, timeout=5)
            status.update(
                {
                    "available": result.returncode == 0,
                    "remediation": "Use a host where the required user/network namespaces are permitted; do not disable host protections",
                }
            )
    except (OSError, subprocess.TimeoutExpired, RuntimeFailure):
        status["reason"] = (
            "Backend capability probe unavailable or timed out; source review remains available"
        )
    return status
