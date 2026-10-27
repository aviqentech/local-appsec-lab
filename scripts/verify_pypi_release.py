"""Compare registry files with validated CI artifacts, then install from PyPI alone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--artifacts", type=Path, default=Path("dist"))
    args = parser.parse_args()
    metadata = None
    for attempt in range(12):
        try:
            with urllib.request.urlopen(
                f"https://pypi.org/pypi/local-appsec-lab/{args.version}/json", timeout=20
            ) as response:
                metadata = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 404 or attempt == 11:
                raise
            time.sleep(5)
    if metadata is None or metadata["info"]["version"] != args.version:
        raise RuntimeError("Expected release is not visible on PyPI")
    files = {path.name: path for path in args.artifacts.iterdir() if path.is_file()}
    indexed = {item["filename"]: item for item in metadata["urls"]}
    if set(files) != set(indexed) or len(files) != 2:
        raise RuntimeError("PyPI file inventory differs from the validated release")
    for name, path in files.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != indexed[name]["digests"]["sha256"]:
            raise RuntimeError("Published file digest differs from the validated CI artifact")
    with tempfile.TemporaryDirectory(prefix="appsec-pypi-smoke-") as directory:
        base = Path(directory)
        subprocess.run([sys.executable, "-m", "venv", str(base / "environment")], check=True)
        python = base / "environment" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "--index-url",
                "https://pypi.org/simple",
                f"local-appsec-lab=={args.version}",
            ],
            check=True,
        )
        fixture = base / "fixture"
        fixture.mkdir()
        result = subprocess.run(
            [str(python), "-m", "local_appsec_lab", "--version"],
            cwd=fixture,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip() != args.version:
            raise RuntimeError("Installed CLI version differs from the published version")
        subprocess.run([str(python), "-m", "local_appsec_lab", "inspect"], cwd=fixture, check=True)
        for operation in ("install", "doctor", "uninstall"):
            subprocess.run(
                [
                    str(python),
                    "-m",
                    "local_appsec_lab.install",
                    "--project",
                    str(fixture),
                    "--target",
                    "all",
                    "--operation",
                    operation,
                ],
                cwd=fixture,
                check=True,
            )
    summary = {
        "version": args.version,
        "registry_digests": "matched",
        "fresh_pypi_install": "passed",
        "cli_and_all_skill_targets": "passed",
    }
    print(json.dumps(summary))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(
                f"Published and verified [local-appsec-lab {args.version}]"
                f"(https://pypi.org/project/local-appsec-lab/{args.version}/). "
                "Registry hashes, fresh installation and all skill installers passed.\n"
            )


if __name__ == "__main__":
    main()
