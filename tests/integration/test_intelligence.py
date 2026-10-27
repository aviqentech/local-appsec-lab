import json

import pytest

from local_appsec_lab.discovery import inspect
from local_appsec_lab.errors import AuthorizationError, BudgetExceeded
from local_appsec_lab.intelligence import refresh, status
from local_appsec_lab.intelligence.cache import AnalysisCache
from local_appsec_lab.scanners import scan_source


def test_cache_reuses_then_invalidates_source(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import pickle\npickle.loads(data)\n")
    inventory = inspect(tmp_path)
    cache = AnalysisCache(tmp_path / ".appsec-lab", tmp_path, inventory)
    expected = cache.source([], lambda: scan_source(tmp_path, inventory))
    reused = AnalysisCache(tmp_path / ".appsec-lab", tmp_path, inventory)
    actual = reused.source([], lambda: pytest.fail("Cache missed unchanged source"))
    assert reused.hits == 1 and len(expected[0]) == len(actual[0])
    source.write_text("value = 1\n")
    changed = AnalysisCache(tmp_path / ".appsec-lab", tmp_path, inspect(tmp_path))
    result = changed.source([], lambda: scan_source(tmp_path, inspect(tmp_path)))
    assert changed.misses == 1 and not result[0]


def test_advisory_consent_pagination_and_previous_snapshot(tmp_path):
    inventory = {
        "dependencies": [
            {"ecosystem": "PyPI", "name": "synthetic-package", "version": "1.0", "locked": True}
        ]
    }
    state = tmp_path / ".appsec-lab"
    with pytest.raises(AuthorizationError):
        refresh(tmp_path, state, inventory, False)
    seen = []

    def fetch(payload):
        seen.append(payload)
        if len(seen) == 1:
            return {"vulns": [{"id": "SYNTHETIC-1"}], "next_page_token": "next"}
        return {"vulns": [{"id": "SYNTHETIC-WITHDRAWN", "withdrawn": "2026-01-01"}]}

    result = refresh(tmp_path, state, inventory, True, fetch=fetch)
    assert result["requests"] == 2 and result["advisories"] == 1
    assert seen[1]["page_token"] == "next"
    assert status(tmp_path, result["snapshot"])["age_days"] < 1
    original = json.loads((tmp_path / result["snapshot"]).read_text())
    with pytest.raises(BudgetExceeded):
        refresh(tmp_path, state, inventory, True, fetch=fetch, max_requests=0)
    assert json.loads((tmp_path / result["snapshot"]).read_text()) == original


def test_forged_cache_cannot_suppress_source_findings(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import pickle\npickle.loads(data)\n")
    inventory = inspect(tmp_path)
    state = tmp_path / ".appsec-lab"
    original = AnalysisCache(state, tmp_path, inventory)
    expected, _ = original.source([], lambda: scan_source(tmp_path, inventory))
    cache_path = next((state / "analysis-cache").glob("*.json"))
    forged = json.loads(cache_path.read_text())
    forged["findings"] = []
    cache_path.write_text(json.dumps(forged))
    fresh = AnalysisCache(state, tmp_path, inventory)
    actual, _ = fresh.source([], lambda: scan_source(tmp_path, inventory))
    assert fresh.hits == 0 and fresh.misses == 1
    assert [finding.rule for finding in actual] == [finding.rule for finding in expected]


def test_scalar_fuzz_empty_string_control():
    from local_appsec_lab.dynamic_tests.fuzz import cases

    valid, malformed = cases({"type": "string", "maxLength": 0}, 3)
    assert valid == "" and malformed
