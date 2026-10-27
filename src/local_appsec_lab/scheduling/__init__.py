from __future__ import annotations

import asyncio
import inspect
import time
import threading
from contextvars import ContextVar
from collections.abc import Callable
from typing import Any

from local_appsec_lab.models import Model

_cancel = ContextVar("appsec_job_cancellation", default=None)


def check_cancelled():
    from local_appsec_lab.errors import BudgetExceeded

    event = _cancel.get()
    if event is not None and event.is_set():
        raise BudgetExceeded("Worker was cancelled or exceeded its time budget")


class Job(Model):
    id: str
    role: str
    state: str = "queued"
    attempts: int = 0
    duration_seconds: float = 0
    error: str | None = None
    strategy: str = "deterministic-worker"


class Scheduler:
    def __init__(
        self,
        concurrency: int = 2,
        timeout: float = 60,
        retries: int = 0,
        progress: Callable | None = None,
    ):
        if not 1 <= concurrency <= 4 or not 0 <= retries <= 2:
            raise ValueError("Invalid scheduler budget")
        self.concurrency, self.timeout, self.retries = concurrency, timeout, retries
        self.progress = progress or (lambda jobs: None)
        self.jobs: dict[str, Job] = {}
        self.tasks: dict[str, Callable] = {}

    def add(
        self, identifier: str, role: str, function: Callable, strategy: str = "deterministic-worker"
    ) -> None:
        if len(self.jobs) >= 64:
            raise ValueError("Bounded work queue is full")
        if identifier not in self.jobs:
            self.jobs[identifier] = Job(id=identifier, role=role, strategy=strategy)
            self.tasks[identifier] = function

    async def run(self) -> dict[str, Any]:
        semaphore = asyncio.Semaphore(self.concurrency)
        results: dict[str, Any] = {}

        async def execute(identifier: str):
            job = self.jobs[identifier]
            async with semaphore:
                started = time.monotonic()
                try:
                    for attempt in range(self.retries + 1):
                        job.state, job.attempts = "running", attempt + 1
                        self.progress(self.snapshot())
                        cancelled = threading.Event()
                        token = _cancel.set(cancelled)
                        pending = None
                        try:
                            fn = self.tasks[identifier]
                            operation = (
                                fn() if inspect.iscoroutinefunction(fn) else asyncio.to_thread(fn)
                            )
                            pending = asyncio.create_task(operation)
                            results[identifier] = await asyncio.wait_for(
                                asyncio.shield(pending), self.timeout
                            )
                            job.state = "completed"
                            break
                        except Exception as exc:
                            job.error = type(exc).__name__
                            job.state = "failed"
                        finally:
                            cancelled.set()
                            if pending and not pending.done():
                                if inspect.iscoroutinefunction(fn):
                                    pending.cancel()
                                try:
                                    await asyncio.wait_for(asyncio.shield(pending), 5)
                                except (Exception, asyncio.CancelledError):
                                    pending.cancel()
                            _cancel.reset(token)
                except asyncio.CancelledError:
                    job.state = "cancelled"
                    raise
                finally:
                    job.duration_seconds = time.monotonic() - started
                    self.progress(self.snapshot())

        await asyncio.gather(*(execute(identifier) for identifier in self.jobs))
        return results

    def snapshot(self) -> list[dict]:
        return [job.model_dump() for job in self.jobs.values()]
