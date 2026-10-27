import base64
import json

import pytest

from local_appsec_lab.errors import ConfigError
from local_appsec_lab.runtime.setup import coordinates, tree_digest


def test_setup_requires_locked_hashes_and_no_execution_sources():
    for entry in ("requests>=2", "-e .", "https://example.invalid/a.whl", "requests==2.19.1"):
        with pytest.raises(ConfigError):
            coordinates("pip", {"requirements.txt": entry.encode()})
    result = coordinates(
        "pip", {"requirements.txt": ("synthetic==1.0 --hash=sha256:" + "a" * 64).encode()}
    )
    assert result[0]["hashes"] == ["a" * 64]


def test_setup_rejects_foreign_registry_and_workspace_links():
    package = {
        "resolved": "https://example.invalid/module.tgz",
        "integrity": "sha512-" + base64.b64encode(b"synthetic").decode(),
    }
    lock = {"lockfileVersion": 3, "packages": {"node_modules/test": package}}
    with pytest.raises(ConfigError):
        coordinates("npm", {"package-lock.json": json.dumps(lock).encode()})
    package.update({"resolved": "https://registry.npmjs.org/test/-/test.tgz", "link": True})
    with pytest.raises(ConfigError):
        coordinates("npm", {"package-lock.json": json.dumps(lock).encode()})


def test_dependency_fingerprint_rejects_escape_and_changes(tmp_path):
    installed = tmp_path / "installed"
    installed.mkdir()
    path = installed / "module.py"
    path.write_text("SYNTHETIC=1")
    before = tree_digest(installed, 1024)
    path.write_text("SYNTHETIC=2")
    assert tree_digest(installed, 1024) != before
    try:
        (installed / "escape").symlink_to(tmp_path)
    except OSError:
        pytest.skip("Symlink creation needs Windows developer mode")
    with pytest.raises(ConfigError):
        tree_digest(installed, 1024)
