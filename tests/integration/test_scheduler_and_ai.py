import asyncio
import json
import threading
import time

import pytest

from local_appsec_lab.agents import HTTPProvider, assignments, validate_results
from local_appsec_lab.configuration import Config
from local_appsec_lab.discovery import inspect
from local_appsec_lab.errors import AuthorizationError, BudgetExceeded, ConfigError
from local_appsec_lab.scheduling import Scheduler


def test_real_concurrency_dedup_retries_and_failure():
    lock = threading.Lock()
    active = 0
    peak = 0
    attempts = 0

    def work():
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.03)
        with lock:
            active -= 1
        return 1

    def retry():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("synthetic")
        return 2

    def failure():
        raise ValueError("synthetic")

    scheduler = Scheduler(2, 1, 1)
    for i in range(5):
        scheduler.add(str(i), "different-scope", work)
    scheduler.add("0", "duplicate", failure)
    scheduler.add("retry", "supply-chain", retry)
    scheduler.add("failure", "api", failure)
    values = asyncio.run(scheduler.run())
    assert peak == 2 and values["0"] == 1 and values["retry"] == 2
    assert scheduler.jobs["retry"].attempts == 2 and scheduler.jobs["failure"].state == "failed"


def test_scheduler_timeout_and_cancellation():
    async def blocked():
        await asyncio.sleep(5)

    async def run():
        scheduler = Scheduler(1, 0.01)
        scheduler.add("timeout", "test", blocked)
        await scheduler.run()
        assert scheduler.jobs["timeout"].state == "failed"
        scheduler = Scheduler(1, 5)
        scheduler.add("cancel", "test", blocked)
        task = asyncio.create_task(scheduler.run())
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert scheduler.jobs["cancel"].state == "cancelled"

    asyncio.run(run())


def test_bounded_queue():
    scheduler = Scheduler()
    for i in range(64):
        scheduler.add(str(i), "bounded", lambda: None)
    with pytest.raises(ValueError):
        scheduler.add("overflow", "bounded", lambda: None)


def test_ai_requires_consent_and_budget(tmp_path):
    config = Config(
        ai={
            "strategy": "http",
            "endpoint": "https://model.example.invalid/v1/chat/completions",
            "model": "synthetic",
        }
    )
    with pytest.raises(AuthorizationError):
        HTTPProvider(config, False, 1)
    provider = HTTPProvider(config, True, 1)
    with pytest.raises(BudgetExceeded):
        provider.review(tmp_path, {"token_budget": 1024, "context": []})


def test_context_budget_and_untrusted_model_results(fixture_project):
    root = fixture_project("unsupported")
    config = Config(ai={"context_bytes": 1000})
    tasks = assignments(root, inspect(root), config)
    assert all(
        sum(len(c["untrusted_source"].encode()) for c in task["context"]) <= 1000 for task in tasks
    )
    task = next(t for t in tasks if t["role"] == "data_flow")
    with pytest.raises(ConfigError):
        validate_results(
            root,
            task,
            [
                {
                    "rule": "fake",
                    "title": "fake",
                    "category": "source",
                    "severity": "high",
                    "severity_reason": "fake",
                    "source": {"path": "../outside", "line": 1, "end_line": 1},
                    "description": "fake",
                    "expected": "fake",
                    "observed": "fake",
                }
            ],
        )


def test_http_provider_contract_with_mock_only(tmp_path, monkeypatch):
    # No real provider request. Validate the actual JSON adapter contract and accounting.
    config = Config(
        ai={
            "strategy": "http",
            "endpoint": "https://model.example.invalid/v1/chat/completions",
            "model": "synthetic",
        },
        limits={"model_tokens": 10000, "model_cost_usd": 1},
    )
    requests = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        consumed = False

        def read(self, n):
            if self.consumed:
                return b""
            self.consumed = True
            return json.dumps(
                {"choices": [{"message": {"content": '{"findings":[], "proposed_checks":[]}'}}]}
            ).encode()

    class Opener:
        def open(self, request, timeout):
            requests.append(json.loads(request.data))
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener())
    provider = HTTPProvider(config, True, 1)
    assert (
        provider.review(tmp_path, {"id": "test", "role": "api", "token_budget": 500, "context": []})
        == []
    )
    assert requests[0]["model"] == "synthetic" and provider.tokens > 0 and provider.cost > 0
