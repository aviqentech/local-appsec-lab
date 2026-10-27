"""Parent-owned browser workflow execution using the same scoped HTTP client/budget."""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import threading
import time

from local_appsec_lab.configuration import Config
from local_appsec_lab.errors import (
    BudgetExceeded,
    LabError,
    RollbackFailure,
    RuntimeFailure,
    ScopeError,
)
from local_appsec_lab.models import Check
from local_appsec_lab.network import local_url, safe_path


def run_browser(runtime, client, config: Config, mode: str, categories) -> list[Check]:
    if mode != "local-active" or "browser" not in categories:
        return [
            Check(
                id="browser",
                category="browser",
                status="not_tested",
                reason="Browser workflows require active authorization for the browser category",
            )
        ]
    if runtime.backend not in {"docker", "compose"}:
        return [
            Check(
                id="browser",
                category="browser",
                status="blocked",
                reason="Browser execution requires the approved Docker runtime image with Playwright/Chromium and its seccomp policy",
            )
        ]
    if not config.browser_workflows:
        return [
            Check(
                id="browser",
                category="browser",
                status="not_tested",
                reason="Configure an explicit synthetic browser workflow",
            )
        ]
    results = []
    for workflow in config.browser_workflows:
        check = Check(
            id="browser:" + workflow.id, category="browser", target=workflow.path, status="blocked"
        )
        rollback = workflow.rollback_path
        reserved = workflow.max_requests + (1 if rollback else 0)
        original = set(client.allowed_mutations)
        try:
            if workflow.allowed_mutations and not runtime.started:
                raise ScopeError("Browser mutations require an owned disposable runtime")
            client.allowed_mutations = {
                (entry.method, entry.path) for entry in workflow.allowed_mutations
            }
            if rollback:
                client.allowed_mutations.add(("DELETE", rollback))
            with client.budget.reserve(reserved):
                try:
                    result = execute(runtime, client, workflow, config)
                    check.status = "completed" if result.get("passed") else "failed"
                    check.reason = (
                        "Real isolated Chromium session; each request passed through the scoped budget and policy gate"
                        if result.get("passed")
                        else "Browser assertion/startup failed: " + result.get("error", "unknown")
                    )
                    check.observations = [result]
                finally:
                    if rollback:
                        response = client.request(rollback, method="DELETE")
                        if response.status not in {200, 204, 404}:
                            raise RollbackFailure("Browser synthetic rollback failed")
        except RollbackFailure:
            raise
        except (LabError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
            check.reason = type(exc).__name__
        finally:
            client.allowed_mutations = original
        results.append(check)
    return results


def execute(runtime, client, workflow, config):
    container = runtime.name
    if runtime.backend == "compose":
        from local_appsec_lab.runtime.compose import definition

        _, selected = definition(runtime.root, config)
        container += "-" + selected
    origin = "http://127.0.0.1:" + str(config.execution.port)
    specification = {
        "url": origin + workflow.path,
        "origin": origin,
        "headers": workflow.headers,
        "steps": [step.model_dump() for step in workflow.steps],
    }
    args = [
        *runtime.docker_base,
        "exec",
        "--interactive",
        "--user",
        "65532:65532",
        container,
        "python",
        "-I",
        "/browser_worker.py",
        json.dumps(specification),
    ]
    process = subprocess.Popen(
        args,
        env=runtime.control_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    messages = queue.Queue(maxsize=4)
    errors = bytearray()
    overflow = threading.Event()

    def read():
        for line in iter(lambda: process.stdout.readline(2_000_000), b""):
            if len(line) > 1_000_000:
                overflow.set()
                return
            try:
                messages.put(json.loads(line), timeout=1)
            except (ValueError, queue.Full):
                overflow.set()
                return

    def stderr():
        while chunk := process.stderr.read(4096):
            remaining = 16384 - len(errors)
            if remaining > 0:
                errors.extend(chunk[:remaining])

    threading.Thread(target=read, daemon=True).start()
    threading.Thread(target=stderr, daemon=True).start()
    started = time.monotonic()
    wall_limit = min(60, client.budget.remaining() - (4 if workflow.rollback_path else 0))
    count = 0
    observations = []
    try:
        while time.monotonic() - started < wall_limit:
            client.budget.remaining()
            if overflow.is_set():
                raise BudgetExceeded("Browser protocol overflow")
            try:
                message = messages.get(timeout=0.25)
            except queue.Empty:
                if process.poll() is not None:
                    raise RuntimeFailure(
                        "Browser worker failed before producing a result; verify image, sandbox and resource limits"
                    ) from None
                continue
            if message.get("type") == "result":
                process.wait(timeout=5)
                message["http_observations"] = observations
                return message
            if message.get("type") != "request":
                raise ScopeError("Invalid browser protocol")
            count += 1
            if count > workflow.max_requests:
                raise BudgetExceeded("Browser request budget exceeded")
            reply = {"abort": True}
            try:
                _, _, path = local_url(message["url"], {config.execution.port})
                safe_path(path)
                method = message["method"]
                if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                    raise ScopeError("Browser method not approved")
                body = (
                    base64.b64decode(message["body"], validate=True)
                    if message.get("body")
                    else None
                )
                if body is not None and len(body) > 4096:
                    raise BudgetExceeded("Browser request body too large")
                headers = {
                    k: v
                    for k, v in message.get("headers", {}).items()
                    if k.lower()
                    in {
                        "accept",
                        "content-type",
                        "cookie",
                        "authorization",
                        "x-test-user",
                        "x-csrf-token",
                    }
                }
                response = client.request(path, method=method, headers=headers, body=body)
                observations.append(
                    {"request": count, "method": method, "response": response.evidence()}
                )
                if response.truncated:
                    raise BudgetExceeded("Browser response exceeded the scoped response budget")
                reply = {
                    "status": response.status,
                    "headers": {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower()
                        not in {
                            "content-length",
                            "transfer-encoding",
                            "content-encoding",
                            "connection",
                        }
                    },
                    "body": base64.b64encode(response.body).decode(),
                }
            except BudgetExceeded:
                raise
            except LabError:
                reply = {"abort": True}
            process.stdin.write((json.dumps(reply) + "\n").encode())
            process.stdin.flush()
        raise BudgetExceeded("Browser workflow duration exceeded")
    finally:
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if errors:
            from local_appsec_lab.utilities.redaction import redact

            diagnostic = redact(errors.decode(errors="replace"), getattr(runtime, "secrets", ()))
            runtime.log.extend(
                diagnostic.encode()[: max(0, config.limits.log_bytes - len(runtime.log))]
            )
