"""Synthetic HTTP API backed by the actually provisioned disposable PostgreSQL."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        actor = self.headers.get("X-Test-User")
        with psycopg.connect(os.environ["DATABASE_URL"]) as connection:
            if self.path == "/health":
                connection.execute("SELECT 1").fetchone()
                return self.send(200, {"ready": True})
            if self.path in {"/records/vulnerable/42", "/records/secure/42"}:
                row = connection.execute(
                    "SELECT owner, body FROM records WHERE id=%s", (42,)
                ).fetchone()
                if not actor:
                    return self.send(401, {"error": "authenticate"})
                if self.path.startswith("/records/secure") and actor != row[0]:
                    return self.send(403, {"error": "forbidden"})
                return self.send(200, {"owner": row[0], "data": row[1]})
        return self.send(404, {"error": "not found"})

    def send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8765"))), Handler).serve_forever()
