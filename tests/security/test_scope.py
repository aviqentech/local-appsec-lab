import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from local_appsec_lab.configuration import Limits
from local_appsec_lab.errors import BudgetExceeded, ScopeError
from local_appsec_lab.network import Budget, Client, local_url, safe_path
from local_appsec_lab.utilities.files import files, inside, read_text
from local_appsec_lab.utilities.redaction import redact


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid:8765",
        "http://192.168.1.1:8765",
        "http://169.254.169.254:8765",
        "http://127.0.0.2:8765",
        "http://2130706433:8765",
        "http://0177.0.0.1:8765",
        "http://0x7f000001:8765",
        "http://127.0.0.1:8766",
        "http://user@127.0.0.1:8765",
        "http://127%2e0.0.1:8765",
        "http://[::ffff:127.0.0.1]:8765",
        "https://127.0.0.1:8765",
        "http://127.0.0.1:8765/#fragment",
        "http://127.0.0.1:8765\\@example.invalid",
        "http://127.0.0.1:8765/\nHeader:value",
    ],
)
def test_scope_rejects(url):
    with pytest.raises(ScopeError):
        local_url(url, {8765})


@pytest.mark.parametrize(
    "path",
    [
        "//example.invalid",
        "/../secret",
        "/%2e%2e/secret",
        "/%252e%252e/secret",
        "/x%0d%0aHost:bad",
        "https://example.invalid",
        "/a\\b",
    ],
)
def test_path_rejects(path):
    with pytest.raises(ScopeError):
        safe_path(path)


def test_loopback_literals_and_dns_pinning(monkeypatch):
    assert local_url("http://127.0.0.1:8765/health", {8765}) == ("127.0.0.1", 8765, "/health")
    assert local_url("http://[::1]:8765/", {8765})[0] == "::1"
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("192.0.2.1", 0))]
    )
    with pytest.raises(ScopeError):
        local_url("http://localhost:8765/", {8765})


def test_budget_and_mutations():
    budget = Budget(Limits(max_requests=1, requests_per_second=10))
    budget.claim()
    with pytest.raises(BudgetExceeded):
        budget.claim()
    client = Client("http://127.0.0.1:8765", 8765, Budget(Limits()))
    with pytest.raises(ScopeError):
        client.request("/record", method="DELETE")
    with pytest.raises(ScopeError):
        client.request("/record", headers={"Host": "example.invalid"})


def test_traversal_symlink_hardlink_and_sensitive_exclusion(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "safe.py").write_text("pass")
    outside = tmp_path / "outside"
    outside.write_text("synthetic")
    (source / ".env").write_text("secret=synthetic")
    with pytest.raises(ScopeError):
        inside(source, Path("../outside"))
    try:
        (source / "escape").symlink_to(outside)
    except OSError:
        pytest.skip("Symlinks unavailable")
    with pytest.raises(ScopeError):
        read_text(source, "escape")
    import os

    os.link(outside, source / "hardlink")
    with pytest.raises(ScopeError):
        read_text(source, "hardlink")
    assert files(source) == ["safe.py"]


def test_redaction_preserves_schema_but_removes_credentials():
    value = redact(
        {
            "authorization": {"limits": {"model_tokens": 42}},
            "headers": {"Authorization": "Bearer synthetictoken"},
            "text": "password=synthetic-secret",
        }
    )
    assert value["authorization"]["limits"]["model_tokens"] == 42
    assert value["headers"]["Authorization"] == "[REDACTED]"
    assert "synthetic-secret" not in json.dumps(value)


def test_redirect_and_proxy_rejection(monkeypatch, free_port):
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/never")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", free_port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    try:
        with pytest.raises(ScopeError):
            Client(f"http://127.0.0.1:{free_port}", free_port, Budget(Limits())).request(
                "/redirect"
            )
        assert hits == ["/redirect"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
