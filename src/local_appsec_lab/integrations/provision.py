"""Explicit database updates, separated from source execution and scanner runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from local_appsec_lab.errors import AuthorizationError, BudgetExceeded, ConfigError
from local_appsec_lab.intelligence import NoRedirect
from local_appsec_lab.models import now
from local_appsec_lab.utilities.files import atomic_json, private_dir


def download(
    url: str, destination: Path, maximum: int, *, expected_sha256=None, redirects=None
) -> dict:
    """Fixed caller-selected HTTPS endpoint; no ambient proxies, redirects or credentials."""
    from local_appsec_lab.utilities.tls import context

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context()),
        redirects or NoRedirect(),
    )
    started, size, digest = time.monotonic(), 0, hashlib.sha256()
    temporary = destination.with_suffix(destination.suffix + ".partial")
    private_dir(destination.parent)
    try:
        with opener.open(url, timeout=20) as response, temporary.open("xb") as stream:
            while chunk := response.read(65536):
                size += len(chunk)
                if size > maximum or time.monotonic() - started > 180:
                    raise BudgetExceeded("Database/package download budget exceeded")
                digest.update(chunk)
                stream.write(chunk)
        if expected_sha256 and digest.hexdigest() != expected_sha256:
            raise ConfigError("Downloaded artifact checksum does not match the locked hash")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {"url": url, "bytes": size, "sha256": digest.hexdigest()}


class RegistryRedirect(urllib.request.HTTPRedirectHandler):
    """The public mirror redirects blob requests within its own verified HTTPS origin."""

    def __init__(self):
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlsplit

        parsed = urlsplit(newurl)
        self.count += 1
        if (
            self.count > 3
            or parsed.scheme != "https"
            or parsed.hostname != "mirror.gcr.io"
            or parsed.username
            or parsed.password
            or parsed.port
        ):
            raise AuthorizationError("Unexpected OCI database redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def trivy_database(cache: Path) -> dict:
    from local_appsec_lab.utilities.tls import context

    origin = "https://mirror.gcr.io/v2/aquasec/trivy-db"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context()),
        NoRedirect(),
    )
    request = urllib.request.Request(
        origin + "/manifests/2", headers={"Accept": "application/vnd.oci.image.manifest.v1+json"}
    )
    with opener.open(request, timeout=20) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise BudgetExceeded("OCI database manifest exceeds its budget")
    manifest = json.loads(raw)
    layers = manifest.get("layers", [])
    if (
        len(layers) != 1
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", layers[0].get("digest", ""))
        or layers[0].get("size", 2**30) > 256_000_000
    ):
        raise ConfigError("Unsupported Trivy database OCI layer layout")
    digest = layers[0]["digest"]
    with tempfile.TemporaryDirectory(prefix="db-update-", dir=cache) as temporary:
        staging = Path(temporary)
        artifact = download(
            origin + "/blobs/" + digest,
            staging / "db.tar.gz",
            256_000_000,
            expected_sha256=digest[7:],
            redirects=RegistryRedirect(),
        )
        database = staging / "db"
        database.mkdir(mode=0o755)
        size, count, names, started = 0, 0, set(), time.monotonic()
        with tarfile.open(staging / "db.tar.gz", "r|gz") as archive:
            for member in archive:
                count += 1
                if (
                    count > 10
                    or not member.isfile()
                    or Path(member.name).name not in {"trivy.db", "metadata.json"}
                    or ".." in Path(member.name).parts
                ):
                    raise ConfigError("Database archive contains unexpected members")
                name = Path(member.name).name
                if name in names:
                    raise ConfigError("Duplicate database archive member")
                names.add(name)
                source = archive.extractfile(member)
                with source, (database / name).open("xb") as destination:
                    while chunk := source.read(65536):
                        size += len(chunk)
                        if size > 2_147_483_648 or time.monotonic() - started > 180:
                            raise BudgetExceeded("Database expansion exceeds 2 GiB or 180 seconds")
                        destination.write(chunk)
                (database / name).chmod(0o644)
        if names != {"trivy.db", "metadata.json"}:
            raise ConfigError("Incomplete Trivy database archive")
        metadata = json.loads((database / "metadata.json").read_text())
        previous = cache / (".previous-db-" + os.urandom(8).hex())
        current = cache / "db"
        try:
            if current.exists():
                os.replace(current, previous)
            os.replace(database, current)
        except Exception:
            if previous.exists() and not current.exists():
                os.replace(previous, current)
            raise
        finally:
            if previous.exists():
                shutil.rmtree(previous)
        return {
            "tool": "trivy",
            "updated": now(),
            "database": metadata,
            "artifact": artifact,
            "expanded_bytes": size,
            "updater": "verified OCI data only; no scanner execution",
        }


def update(state: Path, name: str, authorized: bool, ecosystems: list[str]) -> dict:
    if not authorized:
        raise AuthorizationError("Scanner database updates require --allow-network")
    cache = private_dir(state / "tool-data" / name)
    if name == "osv-scanner":
        if not ecosystems or set(ecosystems) - {
            "PyPI",
            "npm",
            "Go",
            "RubyGems",
            "Maven",
            "Packagist",
            "crates.io",
            "NuGet",
        }:
            raise ConfigError("Select supported OSV --ecosystem values explicitly")
        from urllib.parse import quote

        downloads = []
        for ecosystem in sorted(set(ecosystems)):
            # Current OSV-Scanner uses osv-scalibr; older compatible releases use osv-scanner.
            destination = cache / "osv-scalibr" / ecosystem / "all.zip"
            downloads.append(
                download(
                    "https://osv-vulnerabilities.storage.googleapis.com/"
                    + quote(ecosystem, safe="")
                    + "/all.zip",
                    destination,
                    256_000_000,
                )
            )
        result = {"tool": name, "updated": now(), "databases": downloads}
    elif name == "trivy":
        result = trivy_database(cache)
    else:
        raise ConfigError(
            "Semgrep uses bundled local rules; it has no live rule update in this command"
        )
    atomic_json(cache / "manifest.json", result)
    return result
