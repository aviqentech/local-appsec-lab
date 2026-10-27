from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from local_appsec_lab import __version__
from local_appsec_lab.errors import ConfigError
from local_appsec_lab.utilities.files import inside

TARGETS = {
    "claude": ".claude/skills",
    "codex": ".agents/skills",
    "cursor": ".cursor/skills",
    "gemini": ".gemini/skills",
    "generic": ".agents/skills",
}
INVOCATIONS = {
    "claude": "/local-appsec-lab",
    "codex": "$local-appsec-lab",
    "cursor": "/local-appsec-lab",
    "gemini": "Use the local-appsec-lab skill (check /skills)",
    "generic": "Read SKILL.md and run its bundled CLI helper",
}


def digest_tree(path: Path) -> dict[str, str]:
    result = {}
    for entry in sorted(path.rglob("*")):
        if entry.name == ".installation.json" or "__pycache__" in entry.parts:
            continue
        if entry.is_symlink():
            raise ConfigError("Installed files contain a symlink; refusing destructive update")
        if entry.is_file():
            result[entry.relative_to(path).as_posix()] = hashlib.sha256(
                entry.read_bytes()
            ).hexdigest()
    return result


def host_locations(base: Path) -> dict:
    return {
        name: {
            "path": str(base / relative / "local-appsec-lab"),
            "host_detected": bool(
                shutil.which(
                    {
                        "claude": "claude",
                        "codex": "codex",
                        "cursor": "cursor",
                        "gemini": "gemini",
                        "generic": "python",
                    }[name]
                )
            ),
            "installed": (base / relative / "local-appsec-lab" / "SKILL.md").is_file(),
        }
        for name, relative in TARGETS.items()
    }


def verify_owned(destination: Path) -> dict:
    if destination.is_symlink():
        raise ConfigError("Skill path is a symlink; remove it manually after reviewing its target")
    manifest = destination / ".installation.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise ConfigError("Existing skill has no ownership manifest; unrelated files preserved")
    data = json.loads(manifest.read_text())
    if data.get("owner") != "local-appsec-lab" or data.get("files") != digest_tree(destination):
        raise ConfigError(
            "Installed skill was modified; preserve/review changes before update or uninstall"
        )
    return data


def install(base: Path, targets: list[str], operation: str = "install") -> list[dict]:
    results = []
    base = base.resolve(strict=True)
    package = Path(__file__).parent
    repository_skill = package.parent.parent / "skill" / "local-appsec-lab"
    source_skill = repository_skill if repository_skill.is_dir() else package / "data" / "skill"
    if not source_skill.is_dir():
        raise ConfigError("Packaged skill resources missing; reinstall the distribution")
    for dependency in ("pydantic", "yaml", "jsonschema"):
        if not importlib.util.find_spec(dependency):
            raise ConfigError(
                "Install the CLI with pip first; installer never downloads dependencies implicitly"
            )
    seen = set()
    # Validate every destination before making any changes.
    destinations = []
    for target in targets:
        destination = inside(base, Path(TARGETS[target]) / "local-appsec-lab")
        if destination in seen:
            continue
        seen.add(destination)
        if destination.exists():
            verify_owned(destination)
        destinations.append((target, destination))
    for target, destination in destinations:
        if operation == "uninstall":
            if destination.exists():
                shutil.rmtree(destination)
            results.append({"target": target, "removed": True, "path": str(destination)})
            continue
        if operation == "doctor":
            data = verify_owned(destination)
            results.append(
                {
                    "target": target,
                    "valid": True,
                    "version": data["version"],
                    "path": str(destination),
                }
            )
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".appsec-install-", dir=destination.parent
        ) as temporary:
            staged = Path(temporary) / "skill"
            shutil.copytree(source_skill, staged)
            runtime = staged / "runtime" / "local_appsec_lab"
            shutil.copytree(package, runtime, ignore=shutil.ignore_patterns("__pycache__"))
            scripts = staged / "scripts"
            scripts.mkdir(exist_ok=True)
            launcher = scripts / "appsec_lab.py"
            launcher.write_text(
                'import sys\nfrom pathlib import Path\nsys.dont_write_bytecode = True\nsys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runtime"))\nfrom local_appsec_lab.cli import main\nraise SystemExit(main())\n'
            )
            (scripts / "python.json").write_text(
                json.dumps({"python": sys.executable, "platform": platform.system()})
            )
            check = subprocess.run(
                [sys.executable, "-I", str(launcher), "--help"], capture_output=True, timeout=10
            )
            if check.returncode:
                raise ConfigError(
                    "Staged runtime validation failed; previous installation preserved"
                )
            data = {
                "owner": "local-appsec-lab",
                "version": __version__,
                "python": sys.executable,
                "platform": platform.system(),
                "files": digest_tree(staged),
            }
            (staged / ".installation.json").write_text(json.dumps(data, indent=2))
            backup = Path(temporary) / "previous"
            if destination.exists():
                destination.rename(backup)
            try:
                staged.rename(destination)
            except OSError:
                if backup.exists():
                    backup.rename(destination)
                raise
        results.append(
            {
                "target": target,
                "path": str(destination),
                "version": __version__,
                "invocation": INVOCATIONS[target],
                "python": sys.executable,
                "helper": str(destination / "scripts" / "appsec_lab.py"),
            }
        )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Install/update/verify/remove the portable skill with its engine"
    )
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--global", dest="global_install", action="store_true")
    scope.add_argument("--project", type=Path)
    parser.add_argument("--target", choices=[*TARGETS, "all"], default="all")
    parser.add_argument(
        "--operation", choices=["install", "update", "doctor", "uninstall"], default="install"
    )
    args = parser.parse_args(argv)
    try:
        base = Path.home() if args.global_install else args.project
        selected = list(TARGETS) if args.target == "all" else [args.target]
        print(json.dumps(install(base, selected, args.operation), indent=2))
        return 0
    except (OSError, ValueError, ConfigError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
