from __future__ import annotations

import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from local_appsec_lab.errors import ScopeError

EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".appsec-lab",
    "dist",
    "build",
    "__pycache__",
    ".agents",
    ".codex",
    ".claude",
    ".cursor",
    ".gemini",
    ".pytest_cache",
    ".ruff_cache",
    ".ssh",
    ".aws",
    ".azure",
    ".gcloud",
    ".docker",
    ".kube",
    ".gnupg",
}


def inside(root: Path, path: Path) -> Path:
    root = root.resolve(strict=True)
    candidate = path if path.is_absolute() else root / path
    if ".." in candidate.parts:
        raise ScopeError("Parent traversal is prohibited")
    cursor = candidate
    while cursor != root and cursor != cursor.parent:
        if cursor.is_symlink() or (
            cursor.exists() and getattr(cursor.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise ScopeError(f"Symlink is outside the trusted file contract: {cursor.name}")
        cursor = cursor.parent
    result = candidate.resolve()
    if not result.is_relative_to(root):
        raise ScopeError("Path escapes the authorized workspace")
    return result


def read_bytes(root: Path, relative: str, max_bytes: int = 1_000_000) -> bytes:
    from local_appsec_lab.scheduling import check_cancelled

    check_cancelled()
    # Open each directory relative to a held descriptor. A concurrent directory
    # replacement cannot redirect a later file open outside the selected root.
    root = Path(os.path.abspath(root))
    candidate = Path(relative)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root)
        except ValueError as exc:
            raise ScopeError("Path escapes the authorized workspace") from exc
    if not candidate.parts or ".." in candidate.parts:
        raise ScopeError("Parent traversal is prohibited")
    if os.name == "nt":
        from local_appsec_lab.utilities.windows_files import open_source

        fd = open_source(root, candidate)
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        directory_flags = flags | os.O_DIRECTORY
        directory = os.open(root.anchor, directory_flags)
        try:
            for part in [*root.parts[1:], *candidate.parts[:-1]]:
                child = os.open(part, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(candidate.name, flags, dir_fd=directory)
        except OSError as exc:
            raise ScopeError("Source changed or contains a symlink/unreadable directory") from exc
        finally:
            os.close(directory)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            raise ScopeError("Only bounded, regular, non-hard-linked source files may be read")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ScopeError("File grew beyond the read budget")
        return data
    finally:
        os.close(fd)


def read_text(root: Path, relative: str, max_bytes: int = 1_000_000) -> str:
    return read_bytes(root, relative, max_bytes).decode("utf-8", errors="replace")


@contextmanager
def directory_descriptor(path: Path):
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
        yield current
    except OSError as exc:
        raise ScopeError("Inventory directory changed or contains a symlink") from exc
    finally:
        os.close(current)


def inventory_walk(root):
    if os.name == "posix":
        with directory_descriptor(root) as descriptor:
            for directory, directories, names, current in os.fwalk(
                ".", dir_fd=descriptor, follow_symlinks=False
            ):
                yield root / directory, directories, names, current
    else:
        for directory, directories, names in os.walk(root, followlinks=False):
            yield Path(directory), directories, names, None


def files(
    root: Path, max_files: int = 10_000, max_total: int = 50_000_000, excluded_paths=()
) -> list[str]:
    result: list[str] = []
    total = 0
    excluded_paths = {Path(path).as_posix() for path in excluded_paths}
    for directory, dirs, names, descriptor in inventory_walk(root):

        def information(name, descriptor=descriptor, directory=directory):
            return (
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if descriptor is not None
                else (directory / name).lstat()
            )

        safe_directories = []
        for name in dirs:
            if (
                name in EXCLUDED
                or (directory / name).relative_to(root).as_posix() in excluded_paths
            ):
                continue
            try:
                info = information(name)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400:
                safe_directories.append(name)
        dirs[:] = sorted(safe_directories)
        for name in sorted(names):
            path = Path(directory) / name
            if (
                name.startswith(".env")
                or name
                in {".netrc", ".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519"}
                or name.endswith(
                    (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx", ".sqlite", ".sqlite3", ".db")
                )
            ):
                continue
            try:
                info = information(name)
            except FileNotFoundError:
                continue
            if getattr(info, "st_file_attributes", 0) & 0x400:
                continue  # Windows reparse points include junctions, not only symlinks.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_000_000:
                continue
            total += info.st_size
            if len(result) >= max_files or total > max_total:
                raise ScopeError(
                    "Repository inventory exceeds file/storage budget; select a smaller service"
                )
            result.append(path.relative_to(root).as_posix())
    return sorted(result)


def private_dir(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for parent in [*absolute.parents, absolute]:
        if parent.is_symlink() or (
            parent.exists() and getattr(parent.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise ScopeError("State directories and ancestors must not be symlinks/reparse points")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    if os.name == "nt":
        from local_appsec_lab.utilities.windows_files import secure_path

        secure_path(path)
    return path


def atomic_json(path: Path, data: Any) -> None:
    private_dir(path.parent)
    if path.is_symlink():
        raise ScopeError("Refusing to replace a symlink")
    fd, temp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
