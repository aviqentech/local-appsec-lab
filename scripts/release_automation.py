"""Prepare collision-free releases from reviewed main; never publish unmerged PR code."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path

REPOSITORY = "aviqentech/local-appsec-lab"
PACKAGE = "local-appsec-lab"
REQUIRED_CI = {"test.yml", "container.yml", "lint.yml", "security.yml", "platform-capabilities.yml"}
VERSION_FILES = ["pyproject.toml", "src/local_appsec_lab/__init__.py", "README.md", "CHANGELOG.md"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_json(url: str, token: str | None = None):
    headers = {"Accept": "application/vnd.github+json" if token else "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=20) as response:
            data = response.read(2_000_001)
            if len(data) > 2_000_000:
                raise RuntimeError("Release metadata exceeds its response budget")
            return json.loads(data)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and url.startswith("https://pypi.org/pypi/"):
            return None
        raise


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def output(**values):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def merged_pr(pulls: list[dict], sha: str) -> int | None:
    for pull in pulls:
        if (
            pull.get("merged_at")
            and pull.get("merge_commit_sha") == sha
            and pull.get("base", {}).get("ref") == "main"
            and pull.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY
        ):
            return int(pull["number"])
    return None


def ci_state(runs: list[dict], sha: str) -> str:
    latest = {}
    for run in sorted(runs, key=lambda item: item["id"], reverse=True):
        name = run.get("path", "").split("@", 1)[0].rsplit("/", 1)[-1]
        if (
            name in REQUIRED_CI
            and name not in latest
            and run.get("head_sha") == sha
            and run.get("event") == "push"
            and run.get("head_branch") == "main"
        ):
            latest[name] = run
    if any(
        run["status"] == "completed" and run.get("conclusion") != "success"
        for run in latest.values()
    ):
        return "failed"
    if set(latest) == REQUIRED_CI and all(
        run["status"] == "completed" and run.get("conclusion") == "success"
        for run in latest.values()
    ):
        return "success"
    return "pending"


def next_version(current: str, published: list[str]) -> str:
    from packaging.version import InvalidVersion, Version

    if not re.fullmatch(r"\d+\.\d+\.\d+", current):
        raise ValueError("Automatic releases require a stable MAJOR.MINOR.PATCH source version")
    versions = []
    for item in published:
        try:
            versions.append(Version(item))
        except InvalidVersion:
            continue
    source = Version(current)
    if not versions or source > max(versions):
        return current  # Preserve an explicitly prepared higher minor/major version.
    highest = max(source, *versions)
    return f"{highest.major}.{highest.minor}.{highest.micro + 1}"


def set_version(root: Path, version: str, source: str, pull: int | None):
    p = root / "pyproject.toml"
    text, count = re.subn(
        r'(?m)^version = "[^"]+"$', f'version = "{version}"', p.read_text(), count=1
    )
    if count != 1 or tomllib.loads(text)["project"]["version"] != version:
        raise ValueError("Cannot update the project version unambiguously")
    p.write_text(text)
    p = root / "src/local_appsec_lab/__init__.py"
    text, count = re.subn(
        r'(?m)^__version__ = "[^"]+"$', f'__version__ = "{version}"', p.read_text()
    )
    if count != 1:
        raise ValueError("Cannot update the CLI version unambiguously")
    p.write_text(text)
    p = root / "README.md"
    p.write_text(
        re.sub(
            r"(\*\*Version )\d+\.\d+\.\d+( is experimental\.\*\*)",
            lambda match: match[1] + version + match[2],
            p.read_text(),
            count=1,
        )
    )
    p = root / "CHANGELOG.md"
    text = p.read_text()
    if not re.search(r"(?m)^## " + re.escape(version) + r"(?:\s|$)", text):
        date = datetime.now(UTC).date().isoformat()
        note = f"PR #{pull}" if pull is not None else "reviewed main"
        entry = f"## {version} — {date}\n\nReleased from {note}, source `{source}`.\n"
        if "## Unreleased\n" in text:
            text = text.replace("## Unreleased\n", "## Unreleased\n\n" + entry, 1)
        else:
            text = text.replace("# Changelog\n", "# Changelog\n\n" + entry, 1)
        p.write_text(text)


def current_main() -> str:
    return git("ls-remote", "origin", "refs/heads/main").split()[0]


def prepare():
    if (
        os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
    ):
        raise RuntimeError(
            "Release automation is restricted to the publication repository's main branch"
        )
    source = git("rev-parse", "HEAD")
    if source != os.environ["GITHUB_SHA"]:
        raise RuntimeError("Checkout does not match the triggering source revision")
    token = os.environ["GH_TOKEN"]
    api = f"https://api.github.com/repos/{REPOSITORY}"
    pull = None
    if os.environ["GITHUB_EVENT_NAME"] == "push":
        for attempt in range(8):
            pull = merged_pr(get_json(f"{api}/commits/{source}/pulls", token), source)
            if pull is not None:
                break
            if attempt < 7:
                time.sleep(2)
        if pull is None:
            output(eligible="false", publish="false")
            print("No merged main PR associated with this push; no automatic release")
            return
        deadline = time.monotonic() + 1500
        while True:
            if current_main() != source:
                output(eligible="false", publish="false")
                print(
                    "A newer main revision superseded this run; its release will include these changes"
                )
                return
            runs = get_json(f"{api}/actions/runs?head_sha={source}&event=push&per_page=100", token)[
                "workflow_runs"
            ]
            state = ci_state(runs, source)
            if state == "failed":
                raise RuntimeError("Required CI failed or was cancelled; release stopped")
            if state == "success":
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Required CI did not succeed within the release wait budget")
            time.sleep(15)
    if current_main() != source:
        raise RuntimeError("Main changed; rerun against the latest reviewed main")
    root = Path.cwd()
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    registry = get_json(f"https://pypi.org/pypi/{PACKAGE}/json")
    version = next_version(project["version"], list(registry["releases"]) if registry else [])
    set_version(root, version, source, pull)
    publish = (
        os.environ["GITHUB_EVENT_NAME"] == "push" or os.environ.get("RELEASE_PUBLISH") == "true"
    )
    output(eligible="true", publish=str(publish).lower(), version=version, source_sha=source)
    print(json.dumps({"version": version, "source": source, "merged_pr": pull, "publish": publish}))


def commit():
    source, version = os.environ["RELEASE_SOURCE_SHA"], os.environ["RELEASE_VERSION"]
    if git("rev-parse", "HEAD") != source or current_main() != source:
        raise RuntimeError("Main advanced during validation; no stale release will be published")
    if tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"] != version:
        raise RuntimeError("Validated version changed before the release commit")
    subprocess.run(["git", "config", "user.name", "aviqentech"], check=True)
    subprocess.run(
        ["git", "config", "user.email", "302154595+aviqentech@users.noreply.github.com"], check=True
    )
    subprocess.run(["git", "add", "--", *VERSION_FILES], check=True)
    if git("diff", "--cached", "--name-only"):
        subprocess.run(["git", "commit", "-m", f"chore: release {version} [skip ci]"], check=True)
        # No force push: concurrent merges abort before publication. GITHUB_TOKEN prevents loops.
        subprocess.run(["git", "push", "origin", "HEAD:refs/heads/main"], check=True)
    output(release_sha=git("rev-parse", "HEAD"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "commit"])
    args = parser.parse_args()
    {"prepare": prepare, "commit": commit}[args.operation]()


if __name__ == "__main__":
    main()
