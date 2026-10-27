"""Parent-owned, versioned shared knowledge with immutable event history."""

import json
import threading
from typing import Literal

from pydantic import Field

from local_appsec_lab.models import Model, digest
from local_appsec_lab.utilities.files import atomic_json
from local_appsec_lab.utilities.redaction import redact


class Knowledge(Model):
    schema_version: Literal[1] = 1
    revision: int = 0
    architecture: dict
    service_graph: dict
    endpoints: list[dict]
    source_references: list[str]
    authentication: list[dict]
    environment: dict = Field(default_factory=lambda: {"state": "source-only"})
    completed_checks: list[dict] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
    verification: list[dict] = Field(default_factory=list)


class SharedKnowledge:
    def __init__(self, store, run_id, inventory):
        self.store, self.run_id = store, run_id
        self.lock = threading.Lock()
        self.value = Knowledge(
            architecture={
                key: inventory[key] for key in ("languages", "frameworks", "package_managers")
            },
            service_graph=inventory["service_graph"],
            endpoints=inventory["routes"][:500],
            source_references=inventory["security_sensitive_files"][:200],
            authentication=[
                {"path": r["path"], "declared": r.get("authentication", "unknown")}
                for r in inventory["routes"][:500]
            ],
        )
        self.publish("inventory", [], [])

    def publish(self, stage, findings, checks, environment=None):
        with self.lock:
            self.value.revision += 1
            self.value.findings = [f.model_dump() for f in findings[:200]]
            self.value.verification = [
                {"finding": f.id, "verdicts": f.verification}
                for f in findings[:200]
                if f.verification
            ]
            self.value.completed_checks = [
                {"id": c.id, "category": c.category, "status": c.status, "target": c.target}
                for c in checks[:1000]
            ]
            if environment:
                self.value.environment = environment
            data = redact(self.value.model_dump())
            # SQLite history is append-only; a worker cannot overwrite another verdict.
            self.store.event(
                self.run_id,
                "knowledge",
                {
                    "stage": stage,
                    "revision": self.value.revision,
                    "snapshot_sha256": digest(data),
                    "findings": data["findings"],
                    "checks": data["completed_checks"],
                },
            )
            atomic_json(self.store.state / "runs" / self.run_id / "knowledge.json", data)

    def context(self, role_categories):
        with self.lock:
            data = self.value.model_dump()
            selected = [
                {
                    "rule": f["rule"],
                    "category": f["category"],
                    "state": f["state"],
                    "source": {key: f["source"][key] for key in ("path", "line", "end_line")}
                    if f["source"]
                    else None,
                    "endpoint": f["endpoint"],
                }
                for f in data["findings"]
                if f["category"] in role_categories
            ][:20]
            return json.loads(
                json.dumps(
                    redact(
                        {
                            "architecture": {
                                key: list(value) for key, value in data["architecture"].items()
                            },
                            "service_graph": data["service_graph"],
                            "endpoints": data["endpoints"][:30],
                            "environment": data["environment"],
                            "existing_related_findings": selected,
                            "revision": data["revision"],
                        }
                    )
                )
            )
