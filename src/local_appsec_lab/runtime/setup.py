"""Locked public-registry artifacts; installation itself runs with Docker networking disabled."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

from local_appsec_lab.errors import (
    AuthorizationError,
    BudgetExceeded,
    ConfigError,
    DependencyFailure,
)
from local_appsec_lab.integrations.provision import download
from local_appsec_lab.intelligence import NoRedirect
from local_appsec_lab.isolation import docker_control, local_image
from local_appsec_lab.models import digest, now
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_bytes, read_text


def inputs(root: Path, config) -> tuple[str, dict[str, bytes]]:
    from local_appsec_lab.discovery import inspect
    from local_appsec_lab.runtime import resolve_command

    _, directory = resolve_command(config, inspect(root, config.output))
    base = Path(directory)
    if config.execution.compose_file and not (root / base).is_dir():
        base = Path(".")
    requested = config.execution.dependency_lock
    names = (
        [requested]
        if requested
        else [
            (base / name).as_posix()
            for name in ("requirements.lock", "requirements.txt", "package-lock.json")
        ]
    )
    for name in names:
        if not name or not inside(root, Path(name)).is_file():
            continue
        if Path(name).name == "package-lock.json":
            return "npm", {
                "package-lock.json": read_bytes(root, name),
                "package.json": read_bytes(root, (Path(name).parent / "package.json").as_posix()),
            }
        return "pip", {"requirements.txt": read_bytes(root, name)}
    raise DependencyFailure(
        "No supported lockfile found; configure a hash-pinned requirements file or npm package-lock v2/v3"
    )


def coordinates(manager: str, data: dict[str, bytes]) -> list[dict]:
    if manager == "pip":
        text = data["requirements.txt"].decode().replace("\\\n", " ")
        result = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(
                r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s+((?:--hash=sha256:[a-f0-9]{64}\s*)+)",
                line,
            )
            if not match:
                raise ConfigError(
                    "Python setup requires exact versions and sha256 hashes for every dependency; URLs, options, editable installs and source builds are refused"
                )
            result.append(
                {
                    "name": match[1],
                    "version": match[2],
                    "hashes": re.findall(r"sha256:([a-f0-9]{64})", match[3]),
                }
            )
    else:
        lock = json.loads(data["package-lock.json"])
        if lock.get("lockfileVersion") not in {2, 3} or not isinstance(lock.get("packages"), dict):
            raise ConfigError("npm setup requires package-lock v2/v3")
        result = []
        for path, item in lock["packages"].items():
            if path == "":
                continue
            if not path.startswith("node_modules/") or ".." in Path(path).parts or item.get("link"):
                raise ConfigError(
                    "npm workspace links/local dependencies need an explicitly prepared image"
                )
            url = item.get("resolved", "")
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or parsed.hostname != "registry.npmjs.org"
                or parsed.port
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or not parsed.path.endswith(".tgz")
            ):
                raise ConfigError(
                    "npm setup only downloads integrity-pinned tarballs from registry.npmjs.org"
                )
            integrity = item.get("integrity", "")
            if not re.fullmatch(r"sha(?:256|512)-[A-Za-z0-9+/]+=*", integrity):
                raise ConfigError("Each npm package needs a sha256/sha512 integrity value")
            result.append({"url": url, "integrity": integrity})
    if not result or len(result) > 128:
        raise BudgetExceeded("Dependency setup requires 1–128 explicitly locked packages")
    return result


def tree_digest(directory: Path, maximum: int) -> str:
    digestor = hashlib.sha256()
    size, count = 0, 0
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        count += 1
        if count > 100000:
            raise BudgetExceeded("Installed dependency tree exceeds the file budget")
        digestor.update(relative.as_posix().encode())
        if path.is_symlink():
            if not path.resolve().is_relative_to(directory.resolve()):
                raise ConfigError("Installed package symlink escapes its isolated dependency tree")
            digestor.update(os.readlink(path).encode())
        elif path.is_file():
            if path.stat().st_nlink != 1:
                raise ConfigError("Installed package hardlinks are unsupported")
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    size += len(chunk)
                    if size > maximum:
                        raise BudgetExceeded("Installed dependencies exceed the storage budget")
                    digestor.update(chunk)
        elif not path.is_dir():
            raise ConfigError("Unsupported installed package file type")
    return digestor.hexdigest()


def prepared(root: Path, state: Path, config, image: str | None = None) -> tuple[Path, str] | None:
    if not config.execution.use_dependencies:
        return None
    try:
        manager, data = inputs(root, config)
    except DependencyFailure:
        return None
    if image is None:
        base, env = docker_control()
        image = image_identity(root, config, base, env)
    key = digest(
        [
            1,
            manager,
            image,
            {name: hashlib.sha256(value).hexdigest() for name, value in data.items()},
        ]
    )
    directory = state / "dependencies" / key
    if not (directory / "manifest.json").is_file():
        return None
    manifest = json.loads(
        read_text(root, (directory / "manifest.json").relative_to(root).as_posix())
    )
    installed = inside(root, directory / "installed")
    if manifest.get("key") != key or manifest.get("tree_sha256") != tree_digest(
        installed, config.limits.storage_mb * 1048576
    ):
        raise DependencyFailure("Prepared dependencies changed; run setup again before execution")
    return installed, manager


def image_identity(root, config, base, env):
    image = config.execution.image
    if config.execution.compose_file:
        from local_appsec_lab.runtime.compose import definition

        services, selected = definition(root, config)
        image = services[selected]["image"]
    return local_image(base, env, image)


def setup(root: Path, state: Path, config, authorized: bool, network: bool) -> dict:
    if not authorized:
        raise AuthorizationError(
            "Dependency installation requires --authorize; downloaded packages are installed only inside an isolated container"
        )
    manager, data = inputs(root, config)
    packages = coordinates(manager, data)
    base, env = docker_control()
    image = image_identity(root, config, base, env)
    key = digest(
        [
            1,
            manager,
            image,
            {name: hashlib.sha256(value).hexdigest() for name, value in data.items()},
        ]
    )
    target = private_dir(state / "dependencies" / key)
    if (target / "manifest.json").exists():
        prepared(root, state, config, image)
        return {"key": key, "manager": manager, "status": "reused", "network_requests": 0}
    if not network:
        raise AuthorizationError(
            "First setup needs --allow-network to fetch locked public package artifacts; no repository code or credentials are transmitted"
        )
    from local_appsec_lab.runtime.leases import register, release, scratch_directory

    with scratch_directory(state, "setup-") as scratch:
        downloads = scratch / "downloads"
        downloads.mkdir(mode=0o755)
        locked = scratch / "locked"
        locked.mkdir(mode=0o755)
        for name, content in data.items():
            (locked / name).write_bytes(content)
        total, requests, artifacts = 0, 0, []
        maximum = config.limits.storage_mb * 1048576
        for package in packages:
            if manager == "pip":
                from local_appsec_lab.utilities.tls import context

                url = (
                    "https://pypi.org/pypi/"
                    + quote(package["name"], safe="")
                    + "/"
                    + quote(package["version"], safe="")
                    + "/json"
                )
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=context()),
                    NoRedirect(),
                )
                with opener.open(url, timeout=15) as response:
                    raw = response.read(2_000_001)
                requests += 1
                if len(raw) > 2_000_000:
                    raise BudgetExceeded("Package metadata too large")
                candidates = [
                    item
                    for item in json.loads(raw)["urls"]
                    if item["filename"].endswith(".whl")
                    and item["digests"]["sha256"] in package["hashes"]
                ]
                if not candidates:
                    raise DependencyFailure(
                        "No locked binary wheel is available; source builds are never executed"
                    )
                for item in candidates:
                    parsed = urlsplit(item["url"])
                    if (
                        parsed.scheme != "https"
                        or parsed.hostname != "files.pythonhosted.org"
                        or parsed.username
                        or parsed.port
                        or Path(item["filename"]).name != item["filename"]
                    ):
                        raise ConfigError("Unexpected wheel origin or filename")
                    artifact = download(
                        item["url"],
                        downloads / item["filename"],
                        maximum - total,
                        expected_sha256=item["digests"]["sha256"],
                    )
                    artifacts.append(artifact)
                    total += artifact["bytes"]
                    requests += 1
            else:
                destination = downloads / (str(len(artifacts)) + ".tgz")
                artifact = download(package["url"], destination, maximum - total)
                algorithm, expected = package["integrity"].split("-", 1)
                computed = hashlib.new(algorithm, destination.read_bytes()).digest()
                if computed != base64.b64decode(expected, validate=True):
                    raise ConfigError("npm tarball integrity mismatch")
                artifacts.append(artifact)
                total += artifact["bytes"]
                requests += 1
            if requests > 256 or len(artifacts) > 256:
                raise BudgetExceeded("Package download request budget exceeded")
        installed = target / "installed"
        if installed.exists():
            # Failed/crashed installation: recover an owning container before replacing its output.
            from local_appsec_lab.runtime.leases import recover

            recover(state)
            if installed.is_symlink():
                raise ConfigError("Dependency output must be an ordinary directory")
            shutil.rmtree(installed)
        installed.mkdir(mode=0o777)
        installed.chmod(
            0o777
        )  # Private parent stays 0700; only the owned non-root container writes here.
        for path in [locked, downloads, *locked.iterdir(), *downloads.iterdir()]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        script = scratch / "installer.py"
        script.write_text("""import pathlib, shutil, subprocess, sys
def run(args): subprocess.run(args, check=True, stdin=subprocess.DEVNULL)
if sys.argv[1] == "pip":
    run([sys.executable, "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-input", "--no-index", "--require-hashes", "--only-binary=:all:", "--no-compile", "--find-links=/downloads", "--target=/deps", "-r", "/locked/requirements.txt"])
else:
    for name in ("package.json", "package-lock.json"): shutil.copyfile("/locked/" + name, "/deps/" + name)
    for path in sorted(pathlib.Path("/downloads").glob("*.tgz")):
        run(["npm", "cache", "add", str(path), "--ignore-scripts", "--offline", "--cache=/tmp/npm-cache"])
    run(["npm", "ci", "--ignore-scripts", "--offline", "--no-audit", "--no-fund", "--cache=/tmp/npm-cache"])
""")
        script.chmod(0o644)
        name = "appsec-setup-" + os.urandom(8).hex()
        args = [
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
            "--cpus=" + str(config.limits.cpus),
            "--pids-limit=" + str(config.limits.processes),
            "--ulimit",
            "fsize=" + str(maximum) + ":" + str(maximum),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=" + str(config.limits.storage_mb) + "m",
            "--mount",
            "type=bind,src=" + str(downloads) + ",dst=/downloads,readonly",
            "--mount",
            "type=bind,src=" + str(locked) + ",dst=/locked,readonly",
            "--mount",
            "type=bind,src=" + str(script) + ",dst=/installer.py,readonly",
            "--mount",
            "type=bind,src=" + str(installed) + ",dst=/deps",
            "--env=HOME=/tmp",
            "--workdir=/deps",
            "--entrypoint=python",
            image,
            "-I",
            "/installer.py",
            manager,
        ]
        from local_appsec_lab.agents.native import bounded_run

        register(state, name, base, scratch)

        def monitor():
            size, count = 0, 0
            for directory, _, names in os.walk(installed, followlinks=False):
                for filename in names:
                    path = Path(directory) / filename
                    count += 1
                    try:
                        size += path.lstat().st_size
                    except FileNotFoundError:
                        continue
                    if count > 100000 or size > maximum:
                        raise BudgetExceeded(
                            "Dependency installation exceeded its monitored file/storage budget"
                        )

        try:
            bounded_run(
                args, "", scratch, env, min(180, config.limits.duration_seconds), monitor=monitor
            )
            fingerprint = tree_digest(installed, maximum)
        finally:
            release(state, name)
        for path in [installed, *installed.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        result = {
            "schema_version": 1,
            "key": key,
            "manager": manager,
            "image": image,
            "installed": now(),
            "artifacts": artifacts,
            "tree_sha256": fingerprint,
            "network_requests": requests,
            "lifecycle_scripts": False,
            "source_builds": False,
            "install_network": "none",
        }
        atomic_json(target / "manifest.json", result)
        return result
