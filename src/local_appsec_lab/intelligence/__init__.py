"""Explicitly authorized vulnerability intelligence with bounded offline snapshots."""

from __future__ import annotations

import json
import re
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from local_appsec_lab.errors import AuthorizationError, BudgetExceeded, ConfigError
from local_appsec_lab.utilities.files import atomic_json, inside, read_text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AuthorizationError("Advisory redirects are prohibited")


def fetch_osv(payload: dict, timeout: float = 15) -> dict:
    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "local-appsec-lab/0.1"},
        method="POST",
    )
    from local_appsec_lab.utilities.tls import context

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context()),
        NoRedirect(),
    )
    with opener.open(request, timeout=timeout) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise BudgetExceeded("Advisory response exceeds 2 MB")
    return json.loads(data)


def refresh(
    root: Path,
    state: Path,
    inventory: dict,
    authorized: bool,
    *,
    fetch=fetch_osv,
    max_requests: int = 50,
) -> dict:
    if not authorized:
        raise AuthorizationError(
            "Advisory refresh needs --allow-network; exact dependency names/versions will be sent to api.osv.dev"
        )
    dependencies = sorted(
        {
            (d["ecosystem"], d["name"], d["version"])
            for d in inventory["dependencies"]
            if d["locked"]
        }
    )
    if len(dependencies) > max_requests:
        raise BudgetExceeded("Dependency inventory exceeds the advisory request budget")
    start = time.monotonic()
    requests, advisories, queried = 0, [], []
    for ecosystem, name, version in dependencies:
        if len(name) > 256 or len(version) > 128 or not re.fullmatch(r"[A-Za-z0-9@._/+:-]+", name):
            raise ConfigError("Unsupported dependency identifier")
        token, seen = None, set()
        while True:
            if requests >= max_requests or time.monotonic() - start > 120:
                raise BudgetExceeded(
                    "Advisory refresh budget exceeded; previous snapshot preserved"
                )
            payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            if token:
                payload["page_token"] = token
            data = fetch(payload)
            requests += 1
            for advisory in data.get("vulns", []):
                identifier = advisory.get("id")
                if not isinstance(identifier, str) or len(identifier) > 200:
                    raise ConfigError("Malformed advisory identity")
                if advisory.get("withdrawn"):
                    continue
                advisories.append(
                    {
                        "id": identifier,
                        "name": name,
                        "ecosystem": ecosystem,
                        "versions": [version],
                        "modified": advisory.get("modified"),
                        "summary": str(advisory.get("summary", ""))[:2000],
                        "severity": advisory.get("severity", []),
                        "references": advisory.get("references", [])[:10],
                    }
                )
            token = data.get("next_page_token")
            if not token:
                break
            if not isinstance(token, str) or len(token) > 4096 or token in seen:
                raise ConfigError("Invalid advisory pagination token")
            seen.add(token)
        queried.append({"ecosystem": ecosystem, "name": name, "version": version})
    snapshot = {
        "schema_version": 1,
        "updated": datetime.now(UTC).isoformat(),
        "source": "https://api.osv.dev/v1/query",
        "requests": requests,
        "dependencies": queried,
        "advisories": advisories,
    }
    if len(json.dumps(snapshot).encode()) > 8_000_000:
        raise BudgetExceeded("Advisory snapshot too large")
    destination = inside(root, state.relative_to(root) / "advisories" / "osv.json")
    atomic_json(destination, snapshot)
    return {
        "snapshot": destination.relative_to(root).as_posix(),
        "dependencies_queried": len(queried),
        "advisories": len(advisories),
        "requests": requests,
        "updated": snapshot["updated"],
    }


def snapshot_age(data: dict) -> float:
    try:
        stamp = datetime.fromisoformat(data["updated"].replace("Z", "+00:00"))
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["updated"]):
            stamp = stamp.replace(tzinfo=UTC)
        if stamp.tzinfo is None:
            raise ValueError("Timezone required")
        age = (datetime.now(UTC) - stamp).total_seconds()
        if age < -300:
            raise ValueError("Future timestamp")
        return max(0, age / 86400)
    except (ValueError, KeyError, TypeError) as exc:
        raise ConfigError("Advisory timestamp must be a valid timezone-aware date") from exc


def status(root: Path, snapshot: str) -> dict:
    data = json.loads(read_text(root, snapshot, 8_000_000))
    return {
        "snapshot": snapshot,
        "updated": data["updated"],
        "age_days": snapshot_age(data),
        "advisories": len(data["advisories"]),
    }
