import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from local_appsec_lab.errors import ConfigError, ScopeError
from local_appsec_lab.install import install


@pytest.mark.parametrize("target", ["claude", "codex", "cursor", "gemini", "generic"])
def test_install_reinstall_doctor_uninstall(tmp_path, target):
    base = tmp_path / "project with spaces"
    base.mkdir()
    first = install(base, [target])[0]
    destination = Path(first["path"])
    assert (destination / "SKILL.md").is_file()
    assert install(base, [target], "update")[0]["version"] == "0.1.0"
    assert install(base, [target], "doctor")[0]["valid"]
    helper = subprocess.run(
        [sys.executable, "-I", str(destination / "scripts/appsec_lab.py"), "--version"],
        capture_output=True,
        text=True,
    )
    assert helper.returncode == 0 and helper.stdout.strip() == "0.1.0"
    install(base, [target], "uninstall")
    assert not destination.exists()


def test_foreign_modified_and_broken_symlinks_preserved(tmp_path):
    destination = tmp_path / ".agents/skills/local-appsec-lab"
    destination.mkdir(parents=True)
    (destination / "unrelated").write_text("preserve")
    with pytest.raises(ConfigError):
        install(tmp_path, ["codex"])
    assert (destination / "unrelated").read_text() == "preserve"
    shutil.rmtree(destination)
    install(tmp_path, ["codex"])
    (destination / "SKILL.md").write_text("modified by user")
    with pytest.raises(ConfigError):
        install(tmp_path, ["codex"], "uninstall")
    assert (destination / "SKILL.md").read_text() == "modified by user"
    shutil.rmtree(destination)
    try:
        destination.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises((ConfigError, ScopeError)):
        install(tmp_path, ["codex"])
    assert destination.is_symlink()


def test_global_paths_in_temporary_home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    from local_appsec_lab.install import main

    assert main(["--global", "--target", "all"]) == 0
    assert (tmp_path / ".claude/skills/local-appsec-lab/SKILL.md").exists()
    assert main(["--global", "--target", "all", "--operation", "doctor"]) == 0
    assert main(["--global", "--target", "all", "--operation", "uninstall"]) == 0
