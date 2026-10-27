"""Fail a release if its files, metadata or archive contents do not match the project."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    name, version = project["name"], project["version"]
    normalized = name.replace("-", "_")
    expected = {f"{normalized}-{version}-py3-none-any.whl", f"{normalized}-{version}.tar.gz"}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=root / "dist")
    files = list(parser.parse_args().directory.glob("*"))
    if {path.name for path in files} != expected:
        raise SystemExit("dist/ must contain only the current wheel and source archive")
    forbidden = {".git", ".appsec-lab", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for path in files:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as archive:
                members = archive.namelist()
                metadata = archive.read(
                    next(n for n in members if n.endswith(".dist-info/METADATA"))
                )
        else:
            with tarfile.open(path) as archive:
                members = archive.getnames()
                member = archive.extractfile(f"{normalized}-{version}/PKG-INFO")
                if member is None:
                    raise SystemExit("Source archive metadata is missing")
                metadata = member.read()
        if any(
            set(Path(member).parts) & forbidden
            or Path(member).is_absolute()
            or ".." in Path(member).parts
            or member.endswith((".pyc", ".pyo", ".pypirc"))
            for member in members
        ):
            raise SystemExit("Archive contains private state, traversal paths or bytecode")
        headers = BytesParser().parsebytes(metadata)
        if headers["Name"] != name or headers["Version"] != version:
            raise SystemExit("Archive identity differs from pyproject.toml")
        if headers["License-Expression"] != "Apache-2.0":
            raise SystemExit("Archive license metadata is missing or inconsistent")
        if not any(member.endswith("/SKILL.md") for member in members):
            raise SystemExit("Bundled Agent Skill is missing")
        print(
            json.dumps(
                {
                    "file": path.name,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "bytes": path.stat().st_size,
                    "archive_members": len(members),
                }
            )
        )


if __name__ == "__main__":
    main()
