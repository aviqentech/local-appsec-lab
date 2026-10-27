"""Optional scanners run offline with explicit provenance and fail-closed isolation."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.isolation import mac_profile
from local_appsec_lab.models import Check, Finding, Source
from local_appsec_lab.utilities.files import inside
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

    @property
    def availability(self) -> bool:
        return bool(self.executable)

    def arguments(self, root: Path) -> list[str]:
        if self.name == "semgrep":
            rules = Path(__file__).parent.parent / "data" / "semgrep.yaml"
            return [
                self.executable,
                "scan",
                "--config",
                str(rules),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                str(root),
            ]
        if self.name == "osv-scanner":
            return [
                self.executable,
                "scan",
                "source",
                "--offline",
                "--format",
                "json",
                "--recursive",
                str(root),
            ]
        return [
            self.executable,
            "filesystem",
            "--format",
            "json",
            "--skip-db-update",
            "--skip-check-update",
            "--offline-scan",
            "--scanners",
            "vuln,misconfig,secret",
            str(root),
        ]

    def normalize_results(self, data: dict, root: Path) -> list[Finding]:
        results = []
        if self.name == "semgrep":
            for item in data.get("results", []):
                path = Path(item["path"])
                path = inside(root, path)
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
                path = inside(root, Path(target["Target"]))
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
                path = inside(root, Path(target["source"]["path"]))
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
        started = time.monotonic()
        check = Check(id="tool:" + self.name, category="external_tools", status="blocked")
        if not self.availability:
            check.reason = f"{self.name} is not installed; install separately after reviewing its license and version"
            return [], check
        if platform.system() != "Darwin" or not shutil.which("sandbox-exec"):
            check.reason = "This adapter requires the implemented macOS offline sandbox wrapper; other platforms retain built-in checks"
            return [], check
        with tempfile.TemporaryDirectory(prefix="tool-", dir=state / "cache") as directory:
            scratch = Path(directory)
            profile = scratch / "sandbox.sb"
            profile.write_text(
                mac_profile(scratch, root, self.executable, 65534)
                .replace('(allow network-bind (local ip "localhost:65534"))', "")
                .replace('(allow network-inbound (local ip "localhost:65534"))', "")
                .replace('(allow network-outbound (remote ip "localhost:65534"))', "")
            )
            env = {
                "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                "HOME": directory,
                "TMPDIR": directory,
                "SEMGREP_SEND_METRICS": "off",
            }
            try:
                version = subprocess.run(
                    ["sandbox-exec", "-f", str(profile), self.executable, "--version"],
                    env=env,
                    capture_output=True,
                    timeout=10,
                )
                with (
                    (scratch / "output.json").open("wb") as output,
                    (scratch / "stderr.log").open("wb") as errors,
                ):
                    from local_appsec_lab.runtime import child_limits

                    process = subprocess.Popen(
                        ["sandbox-exec", "-f", str(profile), *self.arguments(root)],
                        cwd=scratch,
                        env=env,
                        stdout=output,
                        stderr=errors,
                        start_new_session=True,
                        preexec_fn=child_limits(config),
                    )
                    try:
                        code = process.wait(timeout=min(60, config.limits.duration_seconds))
                    finally:
                        if process.poll() is None:
                            import signal

                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                data = json.loads((scratch / "output.json").read_text())
                if code not in {0, 1}:
                    raise ValueError("Tool failed")
                findings = self.normalize_results(data, root)
                check.status, check.reason = (
                    "completed",
                    f"{self.name} {redact(version.stdout.decode().strip())}; offline",
                )
                return findings, check
            except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
                check.status, check.reason = (
                    "failed",
                    f"{self.name}: {type(exc).__name__}; verify supported tool version and offline databases",
                )
                return [], check
            finally:
                check.duration_seconds = time.monotonic() - started

    def cleanup(self) -> None:
        """run() owns its TemporaryDirectory and process lifetime."""
