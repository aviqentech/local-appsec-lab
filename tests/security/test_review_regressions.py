import http.server
import importlib.util
import json
import os
import threading
from pathlib import Path

import pytest

from local_appsec_lab import cli, isolation
from local_appsec_lab.authorization import authorize, fingerprint, plan_digest
from local_appsec_lab.configuration import Config, Limits, load
from local_appsec_lab.discovery import inspect
from local_appsec_lab.dynamic_tests import run
from local_appsec_lab.engine import plan
from local_appsec_lab.errors import AuthorizationError, ScopeError
from local_appsec_lab.models import Finding
from local_appsec_lab.network import Budget, Client, Response, merge_headers, safe_path
from local_appsec_lab.remediation import regression
from local_appsec_lab.utilities.files import read_text


# --authorize is bound to the configuration that `plan` printed.


def test_authorize_requires_reviewed_plan_digest(tmp_path):
    config = Config()
    with pytest.raises(AuthorizationError, match="reviewed plan"):
        authorize(tmp_path, tmp_path, config, "local-active", "run", True)
    reviewed = plan_digest(config)
    # Repository configuration changed after review, e.g. to a weaker backend.
    weaker = Config(execution={"backend": "macos"})
    with pytest.raises(AuthorizationError, match="reviewed plan"):
        authorize(tmp_path, tmp_path, weaker, "local-active", "run", True, reviewed_plan=reviewed)
    assert authorize(
        tmp_path, tmp_path, config, "local-active", "run", True, reviewed_plan=reviewed
    )


def test_plan_prints_digest_and_cli_enforces_it(tmp_path, capsys):
    (tmp_path / "app.py").write_text("pass\n")
    (tmp_path / "appsec-lab.yaml").write_text("ai:\n  endpoint: https://model.invalid/v1\n")
    assert plan(tmp_path, load(tmp_path))["plan_digest"] == plan_digest(load(tmp_path))
    code = cli.main(["scan", "--project", str(tmp_path), "--mode", "local-passive", "--authorize"])
    assert code != 0
    assert "--plan-digest" in capsys.readouterr().err


def test_regression_script_carries_plan_digest(tmp_path):
    config = Config(
        scenarios=[
            {
                "id": "orders",
                "path": "/orders/1",
                "category": "authorization",
                "owner_headers": {"X-User": "owner"},
                "actor_headers": {"X-User": "actor"},
                "marker": "SYNTHETIC",
            }
        ]
    )
    finding = Finding(
        id="LAB-1",
        rule="boundary:orders",
        title="t",
        category="authorization",
        severity="high",
        severity_reason="r",
        description="d",
        expected="e",
        observed="o",
        remediation="r",
    )
    name = regression(finding, config, tmp_path, tmp_path, "run")
    assert plan_digest(config) in (tmp_path / name).read_text()


# The repository fingerprint hashes raw bytes.


def test_fingerprint_detects_binary_changes(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\xff")
    before = fingerprint(tmp_path)
    (tmp_path / "blob.bin").write_bytes(b"\xfe")
    assert fingerprint(tmp_path) != before


# The source copy stays read-only inside the writable scratch directory.


def test_bubblewrap_source_bind_follows_scratch_bind(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation.shutil, "which", lambda name: "/usr/bin/" + name)
    scratch = tmp_path / "scratch"
    source = scratch / "source"
    source.mkdir(parents=True)
    args, _ = isolation.command_for(
        Config(execution={"backend": "bubblewrap"}), scratch, source, ["app"], "lab"
    )
    writable = args.index("--bind")
    readonly = args.index("--ro-bind", writable)
    assert args[writable + 1] == str(scratch)
    assert args[readonly + 1] == str(source)


def test_macos_profile_denies_writes_to_source(tmp_path):
    scratch = tmp_path / "scratch"
    source = scratch / "source"
    source.mkdir(parents=True)
    profile = isolation.mac_profile(scratch, source, "python", 8765)
    allow = profile.index(
        f"(allow file-read* file-write* (subpath {json.dumps(str(scratch.resolve()))}))"
    )
    deny = profile.index(f"(deny file-write* (subpath {json.dumps(str(source.resolve()))}))")
    assert allow < deny  # later Seatbelt rules take precedence


# Request paths and repeated response headers.


@pytest.mark.parametrize("path", ["/a b", "/a\x7f", "/a\tb"])
def test_raw_whitespace_and_del_paths_are_scope_errors(path):
    with pytest.raises(ScopeError):
        safe_path(path)


def test_encoded_space_path_remains_allowed():
    assert safe_path("/a%20b") == "/a%20b"


def test_repeated_headers_are_kept():
    pairs = [("Set-Cookie", "a=1; HttpOnly"), ("Set-Cookie", "b=2"), ("Vary", "A"), ("vary", "B")]
    assert merge_headers(pairs) == {"set-cookie": "a=1; HttpOnly\nb=2", "vary": "A, B"}
    spec = importlib.util.spec_from_file_location(
        "bridge", Path(isolation.__file__).parent.parent / "runtime" / "bridge.py"
    )
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    assert bridge.headers(pairs) == merge_headers(pairs)


def test_client_returns_every_set_cookie():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Set-Cookie", "a=1; HttpOnly")
            self.send_header("Set-Cookie", "b=2")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        client = Client(f"http://127.0.0.1:{port}", port, Budget(Limits(requests_per_second=10)))
        assert client.request("/").headers["set-cookie"] == "a=1; HttpOnly\nb=2"
    finally:
        server.shutdown()


def test_cookie_flag_requires_every_cookie():
    class FakeClient:
        def request(self, path, headers=None):
            return Response(200, {"set-cookie": "a=1; HttpOnly\nb=2"}, b"", False)

    _, checks = run(FakeClient(), Config(), [], "local-passive", ["session"])
    flags = next(c for c in checks if c.id.startswith("cookie-flags:")).observations[0]
    assert flags["httponly"] is False


# Symlinks above an operator-chosen root are allowed; links inside it are not.


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_project_location_is_readable(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "app.py").write_text("pass\n")
    (real / "appsec-lab.yaml").write_text("fail_on: low\n")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    assert load(link).fail_on == "low"
    assert inspect(link)["files"] == ["app.py", "appsec-lab.yaml"]
    assert plan(link, Config())["plan_digest"] == plan_digest(Config())


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_home_config_is_readable(tmp_path, monkeypatch):
    real = tmp_path / "home-real"
    (real / ".config" / "local-appsec-lab").mkdir(parents=True)
    (real / ".config" / "local-appsec-lab" / "config.yaml").write_text("fail_on: low\n")
    home = tmp_path / "home"
    home.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    project = tmp_path / "project"
    project.mkdir()
    assert load(project).fail_on == "low"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_state_directory_is_still_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.json").write_text("{}")
    project = tmp_path / "project"
    project.mkdir()
    (project / ".appsec-lab").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ScopeError):
        read_text(project / ".appsec-lab", "report.json")
