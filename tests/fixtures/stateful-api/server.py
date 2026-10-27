"""Disposable in-memory workflow and query-validation controls; synthetic data only."""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

records = {}
next_id = 0


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/health":
            return self.respond(200, {"healthy": True})
        if target.path in {"/validate", "/validate-vulnerable"}:
            value = parse_qs(target.query).get("count", [""])[0]
            valid = value.isdigit() and 1 <= int(value) <= 10
            return self.respond(
                200 if valid or target.path.endswith("vulnerable") else 422, {"synthetic": True}
            )
        key = target.path.rsplit("/", 1)[-1]
        if key in records and self.headers.get("X-Test-User") == "alice":
            return self.respond(200, {"record": "SYNTHETIC_RECORD", "state": records[key]})
        self.respond(404, {})

    def do_POST(self):
        global next_id
        if self.path == "/records" and self.headers.get("X-Test-User") == "alice":
            next_id += 1
            records[str(next_id)] = "pending"
            return self.respond(201, {"id": next_id, "record": "SYNTHETIC_RECORD"})
        pieces = self.path.split("/")
        if len(pieces) == 4 and pieces[2] in records:
            if pieces[3] == "secure-release" and self.headers.get("X-Test-User") != "alice":
                return self.respond(403, {})
            records[pieces[2]] = "released"
            return self.respond(200, {"result": "SYNTHETIC_RELEASED"})
        self.respond(404, {})

    def do_DELETE(self):
        key = self.path.rsplit("/", 1)[-1]
        if self.headers.get("X-Test-User") != "alice":
            return self.respond(403, {})
        records.pop(key, None)
        self.respond(200, {"removed": True})


HTTPServer(("127.0.0.1", int(os.environ["PORT"])), Handler).serve_forever()
