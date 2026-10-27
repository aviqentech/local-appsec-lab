"""Optional scanners run offline with explicit provenance and fail-closed isolation."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.isolation import docker_control, local_image, mac_profile
from local_appsec_lab.models import Check, Finding, Source
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_bytes
from local_appsec_lab.utilities.redaction import redact


class ToolAdapter:
    required_permissions = ["read repository", "write assigned scratch"]
    supported_targets = ["source", "lockfiles"]

    def __init__(self, name: str):
        self.name = name
        self.capabilities = {
            "semgrep": ["SAST"],
            "osv-scanner": ["dependency advisories"],
            "trivy": ["dependencies", "misconfiguration", "secrets"],
        }[name]
        self.executable = shutil.which(name)
        self.configuration = "offline; no implicit installation or database downloads"
        self.version = None

    @property
    def availability(self) -> bool:
        return bool(self.executable)

    def arguments(self, root: Path, executable=None, rules=None, cache=None) -> list[str]:
        executable = executable or self.executable
        if self.name == "semgrep":
            rules = rules or Path(__file__).parent.parent / "data" / "semgrep.yaml"
            return [
                executable,
                "scan",
                "--config",
                str(rules),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--no-rewrite-rule-ids",
                "--jobs",
                "1",
                str(root),
            ]
        if self.name == "osv-scanner":
            return [
                executable,
                "scan",
                "source",
                "--offline",
                "--no-ignore",
                "--no-call-analysis",
                "go,rust",
                "--no-resolve",
                "--config",
                "/dev/null",
                "--format",
                "json",
                "--recursive",
                str(root),
            ]
        return [
            executable,
            "filesystem",
            "--format",
            "json",
            "--skip-db-update",
            "--skip-check-update",
            "--skip-java-db-update",
            "--offline-scan",
            "--scanners",
            "vuln,misconfig,secret",
            "--config",
            "/dev/null",
            "--ignorefile",
            "/dev/null",
            "--cache-dir",
            str(cache or "/tmp/trivy"),
            "--cache-backend",
            "memory",
            str(root),
        ]

    def normalize_results(
        self, data: dict, root: Path, virtual_root: Path | None = None
    ) -> list[Finding]:
        def location(value):
            path = Path(value)
            if virtual_root and path.is_absolute():
                path = path.relative_to(virtual_root)
            return inside(root, path)

        results = []
        if self.name == "semgrep":
            for item in data.get("results", []):
                path = location(item["path"])
                results.append(
                    self._finding(
                        item["check_id"],
                        item.get("extra", {}).get("message", item["check_id"]),
                        path.relative_to(root).as_posix(),
                        item["start"]["line"],
                        {"engine": self.name, "check_id": item["check_id"]},
                    )
                )
        elif self.name == "trivy":
            for target in data.get("Results", []):
                path = location(target["Target"])
                for item in target.get("Vulnerabilities", []):
                    results.append(
                        self._finding(
                            item["VulnerabilityID"],
                            item.get("Title", item["VulnerabilityID"]),
                            path.relative_to(root).as_posix(),
                            1,
                            {
                                "package": item.get("PkgName"),
                                "installed": item.get("InstalledVersion"),
                                "fixed": item.get("FixedVersion"),
                            },
                        )
                    )
                for item in target.get("Misconfigurations", []):
                    results.append(
                        self._finding(
                            item["ID"],
                            item.get("Title", item["ID"]),
                            path.relative_to(root).as_posix(),
                            max(1, item.get("CauseMetadata", {}).get("StartLine", 1)),
                            {"engine": self.name, "rule": item["ID"]},
                        )
                    )
                for item in target.get("Secrets", []):
                    results.append(
                        self._finding(
                            item["RuleID"],
                            "Potential secret reported by Trivy",
                            path.relative_to(root).as_posix(),
                            max(1, item.get("StartLine", 1)),
                            {"engine": self.name, "secret": "[REDACTED]"},
                        )
                    )
        else:
            for target in data.get("results", []):
                path = location(target["source"]["path"])
                for package in target.get("packages", []):
                    for advisory in package.get("vulnerabilities", []):
                        results.append(
                            self._finding(
                                advisory["id"],
                                advisory.get("summary", advisory["id"]),
                                path.relative_to(root).as_posix(),
                                1,
                                {"advisory": advisory["id"], "package": package.get("package")},
                            )
                        )
        return results

    def _finding(self, rule: str, title: str, path: str, line: int, evidence: dict) -> Finding:
        return Finding(
            rule=f"{self.name}:{rule}",
            title=redact(title),
            category="dependencies" if self.name != "semgrep" else "source",
            severity="medium",
            severity_reason="External-tool candidate; impact and reachability require independent review.",
            source=Source(path=path, line=line, end_line=line),
            description="External offline scanner reported this candidate.",
            expected="The applicable security control is enforced.",
            observed="Tool result was normalized without automatic confirmation.",
            evidence=[redact(evidence)],
            provenance=self.name,
            remediation="Review the tool rule/advisory and apply the narrowest compatible correction.",
            limitations=["External-tool result is not independent proof of exploitability."],
        )

    def run(self, root: Path, state: Path, config: Config) -> tuple[list[Finding], Check]:
        from local_appsec_lab.agents.native import bounded_run
        from local_appsec_lab.discovery import inspect
        from local_appsec_lab.errors import LabError

        started = time.monotonic()
        check = Check(id="tool:" + self.name, category="external_tools", status="blocked")
        selected = config.tools.backend
        if selected == "auto":
            selected = (
                "macos"
                if platform.system() == "Darwin" and shutil.which("sandbox-exec")
                else "docker"
                if self.name in config.tools.images
                else "bubblewrap"
            )
        if selected != "docker" and not self.availability:
            check.reason = f"{self.name} is not installed; install a reviewed version separately"
            return [], check
        cache = private_dir(state / "tool-data" / self.name)
        rules = Path(__file__).parent.parent / "data" / "semgrep.yaml"
        from local_appsec_lab.runtime.leases import register, release, scratch_directory

        try:
            with scratch_directory(state, "tool-") as scratch:
                directory = str(scratch)
                source = scratch / "source"
                source.mkdir()
                for relative in inspect(root, config.output)["files"]:
                    destination = inside(source, Path(relative))
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(read_bytes(root, relative))
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": directory,
                    "TMPDIR": directory,
                    "SEMGREP_SEND_METRICS": "off",
                    "SEMGREP_ENABLE_VERSION_CHECK": "0",
                    "PYTHONNOUSERSITE": "1",
                    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache),
                    "OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY": str(cache),
                }
                arguments = self.arguments(source, cache=cache)
                wrapper = []
                control_env = env
                if selected == "macos":
                    if platform.system() != "Darwin" or not shutil.which("sandbox-exec"):
                        raise ValueError("macOS isolation is unavailable")
                    executable = Path(self.executable).resolve()
                    tool_prefix = (
                        executable.parent.parent
                        if executable.parent.name == "bin"
                        else executable.parent
                    )
                    profile = mac_profile(scratch, source, self.executable, 65534)
                    profile = "\n".join(
                        line
                        for line in profile.splitlines()
                        if not line.startswith("(allow network-")
                    )
                    for readonly in (tool_prefix, cache, rules):
                        profile += (
                            "\n(allow file-read* (subpath " + json.dumps(str(readonly)) + "))"
                        )
                    policy = scratch / "sandbox.sb"
                    policy.write_text(profile)
                    wrapper = ["sandbox-exec", "-f", str(policy)]
                elif selected == "bubblewrap":
                    if platform.system() != "Linux" or not shutil.which("bwrap"):
                        raise ValueError(
                            "bubblewrap is unavailable; configure a preloaded scanner Docker image"
                        )
                    wrapper = [
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
                    paths = {
                        Path(p)
                        for p in ("/usr", "/bin", "/lib", "/lib64", "/opt")
                        if Path(p).exists()
                    }
                    paths.update(
                        {Path(self.executable).resolve().parent.parent, rules.parent, cache}
                    )
                    for path in sorted(paths):
                        wrapper += ["--ro-bind", str(path), str(path)]
                    wrapper += ["--bind", directory, directory, "--chdir", directory]
                elif selected == "docker":
                    image = config.tools.images.get(self.name)
                    if not image:
                        raise ValueError(
                            "Set tools.images for this scanner to an explicitly preloaded image"
                        )
                    base, control_env = docker_control()
                    image_id = local_image(base, control_env, image)
                    for path in [source, *source.rglob("*"), cache, *cache.rglob("*")]:
                        if not path.is_symlink():
                            path.chmod(0o755 if path.is_dir() else 0o644)
                    name = "appsec-tool-" + os.urandom(8).hex()
                    wrapper = [
                        *base,
                        "run",
                        "--rm",
                        "--pull=never",
                        "--name",
                        name,
                        "--label",
                        "appsec-lab.owner=" + name,
                        "--network=none",
                        "--read-only",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges",
                        "--user=65534:65534",
                        "--memory=" + str(config.limits.memory_mb) + "m",
                        "--pids-limit=" + str(config.limits.processes),
                        "--cpus=" + str(config.limits.cpus),
                        "--tmpfs",
                        "/tmp:rw,noexec,nosuid,size=" + str(config.limits.storage_mb) + "m",
                        "--mount",
                        "type=bind,src=" + str(source) + ",dst=/source,readonly",
                        "--mount",
                        "type=bind,src=" + str(cache) + ",dst=/cache,readonly",
                        "--mount",
                        "type=bind,src=" + str(rules) + ",dst=/rules.yaml,readonly",
                        "--env=HOME=/tmp",
                        "--env=TMPDIR=/tmp",
                        "--env=SEMGREP_SEND_METRICS=off",
                        "--env=SEMGREP_ENABLE_VERSION_CHECK=0",
                        "--env=OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/cache",
                        "--env=OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY=/cache",
                        "--workdir=/tmp",
                        "--entrypoint="
                        + ("/osv-scanner" if self.name == "osv-scanner" else self.name),
                        image_id,
                    ]
                    arguments = self.arguments(
                        Path("/source"),
                        executable=self.name,
                        rules=Path("/rules.yaml"),
                        cache=Path("/cache"),
                    )[1:]
                else:
                    raise ValueError("Unsupported scanner isolation backend")
                if selected == "docker":
                    register(state, name, base, scratch)
                try:
                    version_args = wrapper + (
                        ["--version"] if selected == "docker" else [self.executable, "--version"]
                    )
                    version, _ = bounded_run(version_args, "", scratch, control_env, 30)
                    self.version = version.decode().strip()[:200]
                    output, _ = bounded_run(
                        wrapper + arguments,
                        "",
                        scratch,
                        control_env,
                        min(120, config.limits.duration_seconds),
                        accepted_codes=(0, 1),
                        limits=config.limits if selected != "docker" else None,
                    )
                    data = json.loads(output)
                    findings = self.normalize_results(
                        data, source, Path("/source") if selected == "docker" else None
                    )
                    check.status = "completed"
                    check.reason = (
                        self.name
                        + " "
                        + redact(version.decode().strip())[:200]
                        + "; offline "
                        + selected
                    )
                    check.observations = [
                        {
                            "version": redact(version.decode().strip())[:200],
                            "network": "denied",
                            "snapshot": "filtered source only",
                        }
                    ]
                    if self.name != "semgrep":
                        from local_appsec_lab.intelligence import snapshot_age

                        manifest = cache / "manifest.json"
                        if manifest.is_file():
                            intelligence = json.loads(manifest.read_text())
                            age = snapshot_age(intelligence)
                            check.observations.append(
                                {
                                    "database_updated": intelligence["updated"],
                                    "database_age_days": age,
                                }
                            )
                            if age > config.tools.advisory_max_age_days:
                                check.status = "blocked"
                                check.reason += (
                                    "; stale database: refresh required for current coverage"
                                )
                        else:
                            check.status = "blocked"
                            check.reason += (
                                "; database age unavailable: provision through tools update"
                            )
                    return findings, check
                finally:
                    if selected == "docker":
                        release(state, name)
        except (OSError, ValueError, KeyError, LabError, subprocess.TimeoutExpired) as exc:
            diagnostic = getattr(exc, "diagnostic", b"")
            atomic_json(
                cache / "last-error.json",
                {
                    "error": type(exc).__name__,
                    "diagnostic": redact(diagnostic.decode(errors="replace"))[:16000],
                },
            )
            check.status = "failed"
            check.reason = (
                self.name
                + ": "
                + type(exc).__name__
                + " ("
                + str(exc)[:160]
                + ")"
                + "; verify version, isolation and offline databases"
            )
            return [], check
        finally:
            check.duration_seconds = time.monotonic() - started

    def cleanup(self) -> None:
        """run() owns its TemporaryDirectory and process lifetime."""
