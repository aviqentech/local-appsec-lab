"""Private, single-file fix bundles. Preparing a fix never changes application files."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from local_appsec_lab.errors import AuthorizationError, ConfigError, ScopeError
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_bytes, read_text


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git_state(root: Path, path: str) -> dict:
    if not (root / ".git").is_dir() or (root / ".git").is_symlink():
        return {
            "available": False,
            "target_dirty": False,
            "reason": "No ordinary repository metadata at project root; source hashes bind this fix",
        }
    for name in (".git/config", ".git/config.worktree"):
        if (root / name).exists() and re.search(
            r"(?im)^\s*\[\s*(?:include|filter)", read_text(root, name)
        ):
            return {
                "available": False,
                "target_dirty": False,
                "reason": "Git status skipped: repository filters/includes may execute or load external configuration; review the hash-bound diff",
            }
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
    }
    args = [
        "git",
        "--no-optional-locks",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesFile=" + os.devnull,
        "-c",
        "core.hooksPath=" + os.devnull,
    ]
    status = subprocess.run(
        [
            *args,
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=all",
            "--",
            path,
        ],
        cwd=root,
        env=env,
        capture_output=True,
        timeout=10,
    )
    return {
        "available": status.returncode == 0,
        "target_dirty": bool(status.stdout),
        "status": status.stdout.decode(errors="replace")[:1000],
    }


def disable_python_debug(before: bytes, finding) -> bytes | None:
    if finding.rule != "debug-mode" or not finding.source.path.endswith(".py"):
        return None
    tree = ast.parse(before)
    lines = before.splitlines(keepends=True)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "debug"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
            and node.value.lineno == finding.source.line
        ):
            value = node.value
            if value.lineno != value.end_lineno:
                continue
            line = lines[value.lineno - 1]
            if line[value.col_offset : value.end_col_offset] != b"True":
                continue
            lines[value.lineno - 1] = (
                line[: value.col_offset] + b"False" + line[value.end_col_offset :]
            )
            return b"".join(lines)
    return None


def prepare(root: Path, state: Path, finding, replacement: str | None = None) -> dict:
    if not finding.source:
        raise ConfigError(
            "A source-bound fix needs a current source location; review the finding's remediation guidance"
        )
    path = finding.source.path
    before = read_bytes(root, path)
    if (
        finding.source.sha256
        and sha(before.decode(errors="replace").encode()) != finding.source.sha256
    ):
        raise ConfigError("Source changed since this finding; rescan before preparing a fix")
    after = read_bytes(root, replacement) if replacement else disable_python_debug(before, finding)
    if after is None:
        raise ConfigError(
            "No validated automatic rewrite exists for this finding; provide a reviewed --replacement file to prepare a diff"
        )
    if before == after:
        raise ConfigError("Replacement does not change the selected source file")
    checks = []
    if path.endswith(".py"):
        ast.parse(after)
        checks.append({"check": "Python syntax", "status": "passed", "target_executed": False})
    elif path.endswith(".json"):
        json.loads(after)
        checks.append({"check": "JSON syntax", "status": "passed", "target_executed": False})
    else:
        raise ConfigError(
            "Fix preparation currently validates Python or JSON source; other languages require an external reviewed patch workflow"
        )
    from local_appsec_lab.scanners import RULES, scan_source

    with tempfile.TemporaryDirectory(
        prefix="fix-check-", dir=private_dir(state / "cache")
    ) as temporary:
        snapshot = Path(temporary)
        destination = snapshot / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(after)
        findings, _ = scan_source(snapshot, {"files": [path]}, [finding.category])
    still_matched = any(f.rule == finding.rule for f in findings)
    checks.append(
        {
            "check": "Fresh source rule rescan",
            "status": "not_applicable"
            if finding.rule not in RULES
            else "failed"
            if still_matched
            else "passed",
            "limitation": "Source rescan and syntax do not establish runtime security or application compatibility",
        }
    )
    if still_matched:
        raise ConfigError("The original source rule still matches the proposed replacement")
    identifier = uuid.uuid4().hex
    directory = private_dir(state / "fixes" / identifier)
    for name, content in [("before.source", before), ("after.source", after)]:
        (directory / name).write_bytes(content)
        (directory / name).chmod(0o600)
    patch = "".join(
        difflib.unified_diff(
            before.decode().splitlines(keepends=True),
            after.decode().splitlines(keepends=True),
            fromfile="a/" + path,
            tofile="b/" + path,
        )
    )
    (directory / "change.patch").write_text(patch)
    (directory / "change.patch").chmod(0o600)
    result = {
        "schema_version": 1,
        "id": identifier,
        "finding": finding.id,
        "rule": finding.rule,
        "path": path,
        "before_sha256": sha(before),
        "after_sha256": sha(after),
        "state": "prepared",
        "git": git_state(root, path),
        "validation": checks,
        "runtime_regression": "not_run",
        "regression_recommendation": finding.regression,
        "diff": str(directory / "change.patch"),
        "source_modified": False,
    }
    atomic_json(directory / "plan.json", result)
    return result


def replace_source(root: Path, path: str, data: bytes, expected: str) -> None:
    """Check the current object and atomically replace one file in its held directory."""
    relative = Path(path)
    destination = inside(root, relative)
    if sha(read_bytes(root, path)) != expected:
        raise ScopeError("Source changed after fix review; refusing to overwrite it")
    mode = destination.stat().st_mode & 0o777
    if os.name == "posix":
        parent = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = ".appsec-fix-" + uuid.uuid4().hex
        try:
            for part in [*root.parts[1:], *relative.parts[:-1]]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, relative.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)
    else:
        # Hold the complete parent chain against rename/junction replacement.
        from local_appsec_lab.utilities.windows_files import hold_parents

        with hold_parents(root, relative):
            if sha(read_bytes(root, path)) != expected:
                raise ScopeError("Source changed after fix review")
            fd, temporary = tempfile.mkstemp(prefix=".appsec-fix-", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, mode)
                os.replace(temporary, destination)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def apply(root: Path, state: Path, identifier: str, authorized: bool, rollback=False) -> dict:
    if not authorized:
        raise AuthorizationError(
            "Applying or rolling back a prepared fix needs explicit --authorize-fix after reviewing change.patch"
        )
    if len(identifier) != 32 or any(c not in "0123456789abcdef" for c in identifier):
        raise ConfigError("Invalid fix bundle identity")
    directory = state / "fixes" / identifier
    plan = json.loads(read_text(root, (directory / "plan.json").relative_to(root).as_posix()))
    if plan["state"] != ("applied" if rollback else "prepared"):
        raise ConfigError("Fix bundle is not in the required state")
    if not rollback and git_state(root, plan["path"])["target_dirty"]:
        raise ConfigError(
            "The selected file has unrelated Git changes; preserve or commit them before applying a fix"
        )
    before, after = ("after", "before") if rollback else ("before", "after")
    data = read_bytes(root, (directory / (after + ".source")).relative_to(root).as_posix())
    if sha(data) != plan[after + "_sha256"]:
        raise ScopeError("Fix bundle content changed; prepare a new reviewed fix")
    replace_source(root, plan["path"], data, plan[before + "_sha256"])
    plan.update({"state": "rolled_back" if rollback else "applied", "source_modified": True})
    atomic_json(directory / "plan.json", plan)
    return plan
