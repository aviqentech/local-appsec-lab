from __future__ import annotations

import json
import os
import stat
import tempfile
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
        if cursor.is_symlink():
            raise ScopeError(f"Symlink is outside the trusted file contract: {cursor.name}")
        cursor = cursor.parent
    result = candidate.resolve()
    if not result.is_relative_to(root):
        raise ScopeError("Path escapes the authorized workspace")
    return result


def read_bytes(root: Path, relative: str, max_bytes: int = 1_000_000) -> bytes:
    path = inside(root, Path(relative))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
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


def files(root: Path, max_files: int = 10_000, max_total: int = 50_000_000) -> list[str]:
    result: list[str] = []
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in EXCLUDED and not (Path(directory) / d).is_symlink()
        )
        for name in sorted(names):
            path = Path(directory) / name
            if (
                path.is_symlink()
                or name.startswith(".env")
                or name
                in {".netrc", ".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_ed25519"}
                or name.endswith(
                    (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx", ".sqlite", ".sqlite3", ".db")
                )
            ):
                continue
            info = path.stat()
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
    if path.is_symlink():
        raise ScopeError("State directories must not be symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
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
