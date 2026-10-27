import importlib.util
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_automation", ROOT / "scripts/release_automation.py"
)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


@pytest.mark.parametrize(
    "current,published,expected",
    [
        ("0.2.0", ["0.2.0"], "0.2.1"),
        ("0.2.0", ["0.2.0", "0.2.7"], "0.2.8"),
        ("0.3.0", ["0.2.7"], "0.3.0"),
        ("1.0.0", [], "1.0.0"),
        ("0.2.0", ["invalid", "0.3.0rc1"], "0.3.1"),
    ],
)
def test_versions_never_reuse_published_contents(current, published, expected):
    assert release.next_version(current, published) == expected


def test_prerelease_requires_explicit_release_policy():
    with pytest.raises(ValueError):
        release.next_version("0.3.0rc1", ["0.2.0"])


def test_only_actual_merges_into_owned_main_are_eligible():
    pull = {
        "number": 42,
        "merged_at": "2026-10-27",
        "merge_commit_sha": "abc",
        "base": {"ref": "main", "repo": {"full_name": release.REPOSITORY}},
    }
    assert release.merged_pr([pull], "abc") == 42
    assert release.merged_pr([{**pull, "merged_at": None}], "abc") is None
    assert release.merged_pr([pull], "other") is None
    assert release.merged_pr([{**pull, "base": {"ref": "develop"}}], "abc") is None


def test_ci_gate_needs_success_for_every_exact_source_workflow():
    runs = [
        {
            "id": index,
            "path": ".github/workflows/" + name,
            "head_sha": "source",
            "head_branch": "main",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
        }
        for index, name in enumerate(sorted(release.REQUIRED_CI))
    ]
    assert release.ci_state(runs, "source") == "success"
    assert release.ci_state(runs, "other") == "pending"
    assert release.ci_state(runs[:-1], "source") == "pending"
    assert (
        release.ci_state([{**runs[0], "id": 100, "conclusion": "failure"}, *runs], "source")
        == "failed"
    )
    assert (
        release.ci_state(
            [{**runs[0], "id": 100, "status": "in_progress", "conclusion": None}, *runs], "source"
        )
        == "pending"
    )


def test_bump_keeps_runtime_metadata_readme_and_unreleased_notes_consistent(tmp_path):
    (tmp_path / "src/local_appsec_lab").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    (tmp_path / "src/local_appsec_lab/__init__.py").write_text('__version__ = "0.2.0"\n')
    (tmp_path / "README.md").write_text("**Version 0.2.0 is experimental.**\n")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## Unreleased\n\n- Reviewed fix\n\n## 0.2.0\n"
    )
    release.set_version(tmp_path, "0.2.1", "abc", 42)
    assert tomllib.loads((tmp_path / "pyproject.toml").read_text())["project"]["version"] == "0.2.1"
    assert '__version__ = "0.2.1"' in (tmp_path / "src/local_appsec_lab/__init__.py").read_text()
    assert "Version 0.2.1" in (tmp_path / "README.md").read_text()
    changes = (tmp_path / "CHANGELOG.md").read_text()
    assert (
        changes.index("## Unreleased") < changes.index("## 0.2.1") < changes.index("- Reviewed fix")
    )
    release.set_version(tmp_path, "0.2.1", "abc", 42)
    assert (tmp_path / "CHANGELOG.md").read_text().count("## 0.2.1") == 1


def test_concurrent_merge_prevents_version_commit(monkeypatch):
    monkeypatch.setenv("RELEASE_SOURCE_SHA", "reviewed")
    monkeypatch.setenv("RELEASE_VERSION", "0.2.1")
    monkeypatch.setattr(release, "current_main", lambda: "newer-merge")
    with pytest.raises(RuntimeError, match="advanced"):
        release.commit()


def test_workflow_has_main_only_trigger_and_isolated_publisher():
    workflow = yaml.load(
        (ROOT / ".github/workflows/publish-pypi.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert "pull_request_target" not in workflow["on"]
    job = workflow["jobs"]["publish"]
    assert job["permissions"] == {"id-token": "write"}
    assert job["environment"]["name"] == "pypi"
    assert not any("actions/checkout" in step.get("uses", "") for step in job["steps"])
    assert workflow["jobs"]["verify"]["needs"] == ["build", "publish"]


def test_dry_run_plans_version_without_publishing_or_committing(tmp_path, monkeypatch):
    (tmp_path / "src/local_appsec_lab").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    (tmp_path / "src/local_appsec_lab/__init__.py").write_text('__version__ = "0.2.0"\n')
    (tmp_path / "README.md").write_text("**Version 0.2.0 is experimental.**\n")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n")
    monkeypatch.chdir(tmp_path)
    for key, value in {
        "GITHUB_REPOSITORY": release.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "reviewed",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GH_TOKEN": "dummy",
        "RELEASE_PUBLISH": "false",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(release, "git", lambda *args: "reviewed")
    monkeypatch.setattr(release, "current_main", lambda: "reviewed")
    monkeypatch.setattr(release, "get_json", lambda *args: {"releases": {"0.2.0": []}})
    release.prepare()
    values = (tmp_path / "outputs").read_text()
    assert "version=0.2.1" in values and "publish=false" in values


def test_direct_main_push_is_not_a_release(tmp_path, monkeypatch):
    for key, value in {
        "GITHUB_REPOSITORY": release.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": "direct",
        "GITHUB_EVENT_NAME": "push",
        "GH_TOKEN": "dummy",
        "GITHUB_OUTPUT": str(tmp_path / "outputs"),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(release, "git", lambda *args: "direct")
    monkeypatch.setattr(release, "get_json", lambda *args: [])
    monkeypatch.setattr(release.time, "sleep", lambda *args: None)
    release.prepare()
    assert (tmp_path / "outputs").read_text() == "eligible=false\npublish=false\n"


def test_installed_runtime_and_project_metadata_versions_match():
    from local_appsec_lab import __version__

    assert tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"] == __version__
