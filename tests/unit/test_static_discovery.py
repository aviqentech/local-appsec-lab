import pytest

from local_appsec_lab.discovery import inspect
from local_appsec_lab.discovery.context import References, hostname


def test_static_site_context(tmp_path):
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/stats.yml").write_text("steps:\n  - run: python update.py\n")
    (tmp_path / ".htaccess").write_text(
        "RewriteCond %{HTTPS} !=on\n"
        "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
        "RewriteCond %{THE_REQUEST} index\n"
        "RewriteRule ^index\\.html$ / [L,R=301]\n"
        'Header set Content-Security-Policy "connect-src https://api.example.com;"\n'
    )
    (tmp_path / "index.html").write_text(
        '<link rel="canonical" href="https://site.example.com/">'
        '<script type="application/ld+json">{"@context":"https://schema.org"}</script>'
        '<a href="https://github.com/org/repo">Code</a>'
        * 3
        + '<script src="/home.js?v=2"></script>'
        + '<script src="https://cdn.example.com/app.js"></script>'
    )
    for page in ("404", "privacy", "terms", "dpdp"):
        (tmp_path / f"{page}.html").write_text(
            "<p>Permission, authentication and payment terms.</p>"
        )
    (tmp_path / "home.js").write_text(
        "function getJSON(u){return fetch(u)};getJSON('https://api.example.com/repos/'+REPO);\n"
        "element.innerHTML = input;"
    )
    (tmp_path / "update.py").write_text(
        'import subprocess\ndef get(url):\n subprocess.run(["curl", url])\n'
        'get(f"https://api.example.com/repos/{REPO}")\n'
    )
    (tmp_path / "font.woff2").write_bytes(b"wOF2\x00permission authentication")
    result = inspect(tmp_path)
    assert result["project_type"] == "static_website"
    assert len(result["routes"]) == 6
    assert {"/", "/privacy.html", "/terms.html", "/dpdp.html"} <= {
        r["path"] for r in result["routes"]
    }
    assert result["ci_cd"] == ["GitHub Actions"]
    assert ".htaccess" in result["infrastructure"]
    rules = result["server_configuration"][0]["rewrite_rules"]
    assert rules[0]["dynamic_substitution"] and rules[0]["source_path"] is None
    assert rules[1]["source_path"] == "/index.html" and rules[1]["target_path"] == "/"
    assert rules[1]["conditional"]
    assert result["resource_graph"]["index.html"] == ["home.js"]
    assert {"index.html", "home.js", "update.py"} <= set(result["entry_points"])
    assert "font.woff2" in result["binary_files"] and "font.woff2" in result["files"]
    assert not {"font.woff2", "terms.html", "index.html"} & set(result["security_sensitive_files"])
    assert "home.js" in result["security_sensitive_files"]
    assert all(item["reasons"] for item in result["security_sensitive_details"])
    refs = result["external_references"]
    assert len(refs) == len({(r["host"], r["source"], r["kind"]) for r in refs})
    navigation = next(r for r in refs if r["kind"] == "navigation")
    assert navigation["occurrences"] == 3
    assert any(r["host"] == "schema.org" and r["kind"] == "schema_reference" for r in refs)
    integrations = result["external_integrations"]
    assert {(r["host"], r["source"]) for r in integrations} == {
        ("api.example.com", "home.js"),
        ("api.example.com", "update.py"),
        ("cdn.example.com", "index.html"),
    }
    assert all(r["host"] != "%{HTTP_HOST" and not r["host"].endswith(";") for r in refs)


@pytest.mark.parametrize(
    "url",
    [
        "https://%{HTTP_HOST}/",
        "https://api.example.com;/",
        "https://a..com/",
        "https://-host.com",
        "https://user:pass@example.com/",
        "https://localhost/",
        "https://[::1]/",
        "http://127.0.0.1/",
        "https://x.com:99999/",
        "https://bad_host.example/",
        "https://foo\\bar.example/",
    ],
)
def test_invalid_or_loopback_host(url):
    assert hostname(url) is None


def test_reference_deduplication_before_limit():
    refs = References()
    for _ in range(600):
        refs.add("https://API.EXAMPLE.COM/path?token=not-retained", "a.js", "network_call", 1)
    refs.add("https://other.example.com", "a.js", "network_call", 2)
    assert len(refs.items) == 2
    assert not refs.truncated
    assert "token" not in str(refs.items)
    for n in range(600):
        refs.add(f"https://host{n}.example.com", "a.js", "network_call", n)
    assert len(refs.items) == 512 and refs.truncated


def test_binary_and_non_utf8_do_not_create_routes(tmp_path):
    (tmp_path / "bad.txt").write_bytes(b'\xffapp.get("/fake")')
    (tmp_path / "image.png").write_bytes(b'app.get("/fake") authentication')
    assert inspect(tmp_path)["routes"] == []
    assert inspect(tmp_path)["security_sensitive_files"] == []


def test_malformed_markup_reports_partial_coverage(tmp_path):
    (tmp_path / "index.html").write_text("<![broken]>")
    assert inspect(tmp_path)["partially_parsed_markup"] == ["index.html"]


def test_infrastructure_assignment_includes_apache_source(tmp_path):
    from local_appsec_lab.agents import assignments
    from local_appsec_lab.configuration import Config

    (tmp_path / ".htaccess").write_text("Options -Indexes\n")
    tasks = assignments(tmp_path, inspect(tmp_path), Config())
    infrastructure = next(t for t in tasks if t["role"] == "infrastructure")
    assert infrastructure["context"][0]["path"] == ".htaccess"


def test_docs_and_application_html_are_not_deployed_static_routes(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "index.html").write_text("<p>Template</p>")
    assert inspect(tmp_path)["routes"] == []


def test_inline_code_is_reviewed_but_json_ld_is_not(tmp_path):
    (tmp_path / "index.html").write_text(
        '<script type="application/ld+json">{"permission":"eval(password)"}</script>'
        "<script>element.innerHTML = input;</script>"
    )
    signals = inspect(tmp_path)["security_sensitive_details"][0]["reasons"]
    assert [s["category"] for s in signals] == ["dom_sink"]
