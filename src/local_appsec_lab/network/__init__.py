from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from local_appsec_lab.configuration import Limits
from local_appsec_lab.errors import BudgetExceeded, ScopeError


def local_url(url: str, allowed_ports: set[int]) -> tuple[str, int, str]:
    if any(ord(c) < 33 for c in url) or "\\" in url:
        raise ScopeError("Invalid URL characters")
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment:
            raise ScopeError("Only credential-free local HTTP URLs are supported")
        if "%" in parsed.netloc or parsed.hostname is None:
            raise ScopeError("Encoded or missing host")
        host = parsed.hostname
        # DNS is not used to connect. Localhost must resolve only to loopback.
        if host == "localhost":
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
            if not addresses or any(not ipaddress.ip_address(a).is_loopback for a in addresses):
                raise ScopeError("Localhost resolution includes a non-loopback address")
            host = "127.0.0.1"
        address = ipaddress.ip_address(host)
        if address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else False:
            raise ScopeError("IPv4-mapped address forms are prohibited")
        if str(address) not in {"127.0.0.1", "::1"}:
            raise ScopeError("Only explicit loopback literals are permitted")
        port = parsed.port or 80
        if port not in allowed_ports:
            raise ScopeError("Destination port is not authorized")
        return (
            str(address),
            port,
            (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
        )
    except (ValueError, OSError) as exc:
        raise ScopeError("Invalid or unapproved destination") from exc


def safe_path(path: str) -> str:
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "://" in decoded
        or "\\" in decoded
        or any(ord(c) < 32 for c in decoded)
        or ".." in decoded.split("/")
        or "#" in path
    ):
        raise ScopeError("Unsafe request path")
    return path


class Budget:
    def __init__(self, limits: Limits, expires_at: float | None = None):
        self.limits = limits
        self.started = time.monotonic()
        self.expires_at = expires_at
        self.requests = 0
        self.last_request = 0.0
        self.lock = threading.Lock()
        self.reserved = 0
        self.local = threading.local()

    def remaining(self) -> float:
        remaining = self.limits.duration_seconds - (time.monotonic() - self.started)
        if self.expires_at is not None:
            remaining = min(remaining, self.expires_at - time.time())
        if remaining <= 0:
            raise BudgetExceeded("Run duration exceeded")
        return remaining

    @contextmanager
    def reserve(self, count: int):
        """Reserve all requests, including rollback, before starting a scenario."""
        with self.lock:
            if getattr(self.local, "credits", 0):
                raise BudgetExceeded("Nested reservations are unsupported")
            if self.requests + self.reserved + count > self.limits.max_requests:
                raise BudgetExceeded(
                    "Insufficient request budget for the complete scenario and rollback"
                )
            if self.remaining() < count * (3 + 1 / self.limits.requests_per_second):
                raise BudgetExceeded("Insufficient duration budget for the complete scenario")
            self.reserved += count
            self.local.credits = count
        try:
            yield
        finally:
            with self.lock:
                self.reserved -= self.local.credits
                self.local.credits = 0

    def claim(self) -> None:
        with self.lock:
            remaining = self.remaining()
            credits = getattr(self.local, "credits", 0)
            if not credits and self.requests + self.reserved >= self.limits.max_requests:
                raise BudgetExceeded("HTTP request budget exhausted")
            delay = 1 / self.limits.requests_per_second - (time.monotonic() - self.last_request)
            if delay > 0:
                if delay >= remaining:
                    raise BudgetExceeded("Rate-limit delay exceeds the remaining run duration")
                time.sleep(delay)
            self.remaining()
            if credits:
                self.local.credits -= 1
                self.reserved -= 1
            self.requests += 1
            self.last_request = time.monotonic()


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool

    def evidence(self, marker: str | None = None) -> dict:
        # Never retain arbitrary response bodies or authentication headers.
        return {
            "status": self.status,
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "body_bytes": len(self.body),
            "truncated": self.truncated,
            "marker_present": bool(marker and marker.encode() in self.body),
            "security_headers": {
                k: v
                for k, v in self.headers.items()
                if k
                in {
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "content-type",
                }
            },
        }


class Client:
    def __init__(
        self,
        url: str,
        port: int,
        budget: Budget,
        allowed_mutations: set[tuple[str, str]] | None = None,
    ):
        self.host, self.port, _ = local_url(url, {port})
        if _ != "/":
            raise ScopeError(
                "Service base URL must have no path or query; configure individual endpoint paths"
            )
        self.url = (
            f"http://[{self.host}]:{self.port}"
            if ":" in self.host
            else f"http://{self.host}:{self.port}"
        )
        self.budget = budget
        self.allowed_mutations = allowed_mutations or set()

    def request(
        self,
        path: str,
        headers: dict[str, str] | None = None,
        method: str = "GET",
        body: dict | None = None,
    ) -> Response:
        safe_path(path)
        if method not in {"GET", "HEAD"} and (method, path) not in self.allowed_mutations:
            raise ScopeError("State-changing operation is outside the authorized scenario")
        if headers and any(
            k.lower()
            in {"host", "connection", "transfer-encoding", "content-length", "proxy-authorization"}
            or "\n" in k + v
            or "\r" in k + v
            for k, v in headers.items()
        ):
            raise ScopeError("Unsafe request headers")
        data = json.dumps(body).encode() if body is not None else None
        if data and len(data) > 4096:
            raise ScopeError("Request body exceeds safe input budget")
        self.budget.claim()
        timeout = min(3, self.budget.remaining())
        connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        expired = threading.Event()

        def abort():
            expired.set()
            if connection.sock:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()

        timer = threading.Timer(timeout, abort)
        timer.daemon = True
        timer.start()
        try:
            connection.request(
                method,
                path,
                body=data,
                headers={
                    "User-Agent": "Local-AppSec-Lab/0.1",
                    **({"Content-Type": "application/json"} if data else {}),
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            content = response.read(self.budget.limits.response_bytes + 1)
            if expired.is_set():
                raise BudgetExceeded("Response deadline exceeded")
            if 300 <= response.status < 400:
                # No redirect is followed, including redirects within scope.
                raise ScopeError("Redirect refused; configure the final local endpoint explicitly")
            return Response(
                response.status,
                {k.lower(): v[:4096] for k, v in response.getheaders()},
                content[: self.budget.limits.response_bytes],
                len(content) > self.budget.limits.response_bytes,
            )
        finally:
            timer.cancel()
            connection.close()
