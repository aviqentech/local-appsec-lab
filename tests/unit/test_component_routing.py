import json

from local_appsec_lab.configuration import Config
from local_appsec_lab.discovery import inspect
from local_appsec_lab.discovery.components import assessment
from local_appsec_lab.engine import plan, scan
from local_appsec_lab.reporting import markdown, html_report


def test_mixed_project_accounts_for_every_file(tmp_path):
    for directory in ("api", "ui", "shared", "docs", ".github/workflows"):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / "api/app.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (tmp_path / "api/requirements.txt").write_text("fastapi==0.100.0\n")
    (tmp_path / "ui/package.json").write_text(
        json.dumps(
            {
                "dependencies": {"react": "1.0.0"},
                "scripts": {"start": "next start"},
            }
        )
    )
    (tmp_path / "shared/pyproject.toml").write_text('[project]\nname="shared"\n')
    (tmp_path / "shared/helpers.py").write_text("def identity(x): return x\n")
    (tmp_path / "docs/readme.md").write_text("Docs")
    (tmp_path / ".github/workflows/ci.yml").write_text("name: ci\n")
    (tmp_path / "logo.png").write_bytes(b"\x00font")
    inventory = inspect(tmp_path)
    rows = {c["id"]: c for c in inventory["components"]}
    assert rows["api"]["kind"] == "api"
    assert rows["ui"]["kind"] == "frontend"
    assert rows["ui"]["startup_candidates"] == [["npm", "run", "start"]]
    assert rows["shared"]["kind"] == "library_or_unknown"
    owned = [p for c in rows.values() for p in c["files"]]
    assert sorted(owned) == inventory["files"] and len(owned) == len(set(owned))
    # Selecting an API does not imply that the frontend or shared library was started.
    config = Config(execution={"service": "api", "command": ["python", "app.py"]})
    startup = {"supported": True, "service": "api"}
    actions = {
        r["id"]: r for r in assessment(inventory, config, "local-active", startup)["components"]
    }
    assert actions["api"]["runtime_action"] == "planned"
    assert actions["ui"]["runtime_action"] == "not_selected"
    assert actions["shared"]["runtime_action"] == "source_only"
    assert actions["@infrastructure"]["runtime_action"] == "source_only"
    review = assessment(inventory, config, "review", startup)
    assert all(r["runtime_action"] == "source_only" for r in review["components"])


def test_compose_dependencies_are_supporting_services(fixture_project):
    inventory = inspect(fixture_project("multi-service"))
    rows = {r["id"]: r for r in inventory["components"]}
    assert rows["compose.yaml#database"]["kind"] == "supporting_service"
    config = Config(execution={"compose_file": "compose.yaml", "service": "api"})
    routing = assessment(
        inventory,
        config,
        "local-active",
        {
            "supported": True,
            "services": ["api", "database"],
        },
    )
    database = next(r for r in routing["components"] if r["id"] == "compose.yaml#database")
    assert database["runtime_action"] == "planned"
    assert not database["execution_target"] and database["applicable_live_checks"] == []


def test_missing_static_runtime_is_explained(tmp_path):
    (tmp_path / "index.html").write_text("<h1>Static</h1>")
    route = plan(tmp_path, Config())["assessment"]["components"][0]
    assert route["kind"] == "static_frontend"
    assert route["runtime_action"] == "blocked" and "Startup" in route["reason"]


def test_review_report_does_not_claim_live_work(fixture_project):
    root = fixture_project()
    report, _ = scan(root, root, Config(), "review")
    overview = report.architecture["assessment"]
    assert overview["measured_http_requests"] == 0
    assert all(c["runtime_action"] == "source_only" for c in overview["components"])
    assert "Component coverage" in markdown(report)
    assert "Component coverage" in html_report(report)


def test_runtime_result_is_not_inferred_from_candidate(fixture_project):
    inventory = inspect(fixture_project())
    config = Config()
    startup = {"supported": True, "service": "."}
    failed = assessment(inventory, config, "local-passive", startup, completed=True)
    assert (
        next(c for c in failed["components"] if c["id"] == ".")["runtime_action"] == "not_started"
    )
    passed = assessment(
        inventory, config, "local-passive", startup, completed=True, started=True, requests=4
    )
    assert next(c for c in passed["components"] if c["id"] == ".")["runtime_action"] == "started"
    assert passed["measured_http_requests"] == 4
