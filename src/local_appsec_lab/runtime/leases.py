"""Crash-recoverable leases for ephemeral scanner and dependency containers."""

import json
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from local_appsec_lab.errors import RuntimeFailure, ScopeError
from local_appsec_lab.isolation import docker_control
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_text


@contextmanager
def scratch_directory(state: Path, prefix: str):
    directory = Path(tempfile.mkdtemp(prefix=prefix, dir=private_dir(state / "cache")))
    try:
        yield directory
    finally:
        if not (directory / ".owned-container.json").exists():
            shutil.rmtree(directory)


def register(state: Path, name: str, base: list[str], scratch: Path):
    if not re.fullmatch(r"appsec-(?:setup|tool)-[a-f0-9]{16}", name):
        raise ScopeError("Invalid ephemeral container ownership name")
    value = {"owner": name, "docker_base": base, "scratch": scratch.relative_to(state).as_posix()}
    atomic_json(state / "leases" / (name + ".json"), value)
    atomic_json(scratch / ".owned-container.json", value)


def release(state: Path, name: str):
    if not re.fullmatch(r"appsec-(?:setup|tool)-[a-f0-9]{16}", name):
        raise ScopeError("Invalid ephemeral container ownership name")
    manifest = state / "leases" / (name + ".json")
    value = json.loads(read_text(state, manifest.relative_to(state).as_posix()))
    base, env = docker_control()
    if value.get("owner") != name or value.get("docker_base") != base:
        raise ScopeError("Ephemeral cleanup ownership/daemon does not match")
    scratch = inside(state, Path(value["scratch"]))
    if scratch.parent != state / "cache" or not scratch.name.startswith(("tool-", "setup-")):
        raise ScopeError("Invalid ephemeral scratch identity")
    if scratch.exists():
        marker = json.loads(
            read_text(state, (scratch / ".owned-container.json").relative_to(state).as_posix())
        )
        if marker != value:
            raise ScopeError("Ephemeral scratch ownership marker does not match")
    result = subprocess.run(
        [
            *base,
            "container",
            "inspect",
            "--format",
            '{{index .Config.Labels "appsec-lab.owner"}}',
            name,
        ],
        env=env,
        capture_output=True,
        timeout=10,
    )
    if result.returncode:
        if b"no such" not in result.stderr.lower() and b"not found" not in result.stderr.lower():
            raise RuntimeFailure("Cannot establish ephemeral container state; lease retained")
    elif result.stdout.decode().strip() != name:
        raise ScopeError("Ephemeral name belongs to another owner; refusing cleanup")
    else:
        removed = subprocess.run(
            [*base, "rm", "--force", name], env=env, capture_output=True, timeout=10
        )
        if removed.returncode:
            raise RuntimeFailure("Ephemeral container cleanup failed; lease retained")
    (scratch / ".owned-container.json").unlink(missing_ok=True)
    manifest.unlink()
    return scratch


def recover(state: Path):
    directory = state / "leases"
    if not directory.exists():
        return []
    result = []
    for manifest in sorted(directory.glob("*.json")):
        scratch = release(state, manifest.stem)
        if scratch.exists():
            shutil.rmtree(scratch)
        result.append({"ephemeral": manifest.stem, "cleaned": True})
    return result
