"""Cache seals live outside untrusted repositories, in private user cache state."""

import os
import platform
import stat
from pathlib import Path

from local_appsec_lab.errors import ScopeError
from local_appsec_lab.utilities.files import private_dir


def user_cache() -> Path:
    base = (
        Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
        if os.name == "nt"
        else Path.home() / "Library/Caches"
        if platform.system() == "Darwin"
        else Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    )
    return base


def key(root: Path) -> bytes | None:
    override = os.environ.get("APPSEC_CACHE_KEY_FILE")
    path = Path(override).absolute() if override else user_cache() / "local-appsec-lab/analysis-key"
    if path.resolve().is_relative_to(root.resolve()):
        return None  # A repository cannot supply the key that vouches for its own cached results.
    try:
        private_dir(path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        if os.name == "nt":
            from local_appsec_lab.utilities.windows_files import secure_path

            secure_path(path, directory=False)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or (os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077))
            ):
                return None
            value = stream.read(33)
        return value if len(value) == 32 else None
    except (OSError, ScopeError):
        return None  # Recompute source; never consume an unverifiable cached assessment.
