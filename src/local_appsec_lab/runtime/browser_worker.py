"""Trusted Playwright worker. HTTP is brokered to the parent; no direct page egress."""

import base64
import hashlib
import json
import sys


def main():
    from playwright.sync_api import sync_playwright

    init = json.loads(sys.argv[1])
    events = {"requests": 0, "console_errors": [], "blocked_websockets": 0}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            chromium_sandbox=True,
            args=[
                "--disable-dev-shm-usage",
                "--disable-background-networking",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--renderer-process-limit=1",
            ],
        )
        try:
            context = browser.new_context(
                service_workers="block",
                accept_downloads=False,
                ignore_https_errors=False,
                extra_http_headers=init.get("headers", {}),
                viewport={"width": 1024, "height": 768},
            )

            def route(route, request):
                raw = request.post_data_buffer
                if raw is not None and len(raw) > 16384:
                    route.abort()
                    return
                events["requests"] += 1
                print(
                    json.dumps(
                        {
                            "type": "request",
                            "url": request.url,
                            "method": request.method,
                            "headers": dict(request.headers),
                            "body": base64.b64encode(raw).decode() if raw else None,
                        }
                    ),
                    flush=True,
                )
                message = json.loads(sys.stdin.readline())
                if message.get("abort"):
                    route.abort()
                    return
                route.fulfill(
                    status=message["status"],
                    headers=message["headers"],
                    body=base64.b64decode(message["body"]),
                )

            context.route("**/*", route)

            def websocket(socket):
                events["blocked_websockets"] += 1
                socket.close(code=1008, reason="WebSocket not in the approved HTTP workflow")

            context.route_web_socket("**/*", websocket)
            page = context.new_page()
            page.set_default_timeout(5000)
            page.set_default_navigation_timeout(10000)

            def error(message):
                if len(events["console_errors"]) < 10:
                    events["console_errors"].append(
                        hashlib.sha256(str(message).encode()).hexdigest()
                    )

            page.on("pageerror", error)
            page.on(
                "console", lambda message: error(message.text) if message.type == "error" else None
            )
            response = page.goto(init["url"], wait_until="domcontentloaded")
            observations = []
            for step in init.get("steps", []):
                action = step["action"]
                if action == "fill":
                    page.locator(step["selector"]).fill(step["value"])
                elif action == "click":
                    page.locator(step["selector"]).click()
                elif action == "goto":
                    page.goto(init["origin"] + step["value"], wait_until="domcontentloaded")
                elif action == "expect_text":
                    actual = page.locator(step["selector"]).inner_text()
                    if step["value"] not in actual:
                        raise ValueError("Synthetic text assertion failed")
                elif action == "expect_path":
                    if page.url != init["origin"] + step["value"]:
                        raise ValueError("Path assertion failed")
                observations.append({"action": action, "passed": True})
            # Capture actual rendered output but retain only its digest by default.
            # No page pixels, console strings, cookies or arbitrary response bodies leave this worker.
            screenshot = page.screenshot(animations="disabled", timeout=5000)
            if len(screenshot) > 2_000_000:
                raise ValueError("Screenshot budget exceeded")
            headers = response.all_headers() if response else {}
            anchors = page.locator("a[href]").evaluate_all(
                '(links) => links.slice(0, 50).map(a => a.getAttribute("href"))'
            )
            result = {
                "type": "result",
                "passed": True,
                "steps": observations,
                "screenshot_sha256": hashlib.sha256(screenshot).hexdigest(),
                "screenshot_bytes": len(screenshot),
                "artifact_policy": "hash-only; raw screenshot discarded",
                "console_error_sha256": events["console_errors"],
                "http_requests": events["requests"],
                "blocked_websockets": events["blocked_websockets"],
                "csp_present": bool(headers.get("content-security-policy")),
                "routes": [
                    value
                    for value in anchors
                    if isinstance(value, str)
                    and value.startswith("/")
                    and not value.startswith("//")
                ][:30],
            }
            print(json.dumps(result), flush=True)
        finally:
            browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc)[:12000], file=sys.stderr, flush=True)
        print(
            json.dumps({"type": "result", "passed": False, "error": type(exc).__name__}), flush=True
        )
        raise SystemExit(1) from None
