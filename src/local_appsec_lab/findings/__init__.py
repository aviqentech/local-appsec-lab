from __future__ import annotations

import json
import os
import stat
import sqlite3
import threading
from pathlib import Path

from local_appsec_lab.models import Report, now
from local_appsec_lab.errors import ScopeError
from local_appsec_lab.utilities.files import atomic_json, inside, private_dir, read_text
from local_appsec_lab.utilities.redaction import redact


class RunStore:
    """Parent-owned snapshots with an append-only event history per run."""

    def __init__(self, state: Path):
        self.state = private_dir(state)
        self.lock = threading.Lock()
        for name in ("runs", "reports", "cache", "evidence"):
            private_dir(inside(self.state, Path(name)))
        database = inside(state, Path("events.sqlite3"))
        for path in [
            database,
            Path(str(database) + "-wal"),
            Path(str(database) + "-shm"),
            Path(str(database) + "-journal"),
        ]:
            if path.exists() or path.is_symlink():
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.is_symlink():
                    raise ScopeError(
                        "State databases and journals must be ordinary non-linked files"
                    )
                path.chmod(0o600)
        self.db = sqlite3.connect(database, check_same_thread=False)
        database.chmod(0o600)
        if os.name == "nt":
            from local_appsec_lab.utilities.windows_files import secure_path

            secure_path(database, directory=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, run_id TEXT NOT NULL, timestamp TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self.db.commit()

    def event(self, run_id: str, kind: str, payload: dict) -> None:
        with self.lock:
            self.db.execute(
                "INSERT INTO events(run_id,timestamp,kind,payload) VALUES(?,?,?,?)",
                (run_id, now(), kind, json.dumps(redact(payload))),
            )
            self.db.commit()

    def status(self, run_id: str, value: dict) -> None:
        directory = inside(self.state, Path("runs") / run_id)
        private_dir(directory)
        atomic_json(
            directory / "status.json", redact({"run_id": run_id, "updated": now(), **value})
        )
        self.event(run_id, "progress", value)

    def save(self, report: Report) -> None:
        data = redact(report.model_dump())
        atomic_json(inside(self.state, Path("runs") / report.run_id / "report.json"), data)
        self.event(
            report.run_id, "report", {"status": report.status, "findings": len(report.findings)}
        )

    def read(self, run_id: str = "latest") -> Report:
        if run_id == "latest":
            runs = self.runs()
            if not runs:
                raise ValueError("No assessment runs found")
            run_id = runs[0]["run_id"]
        return Report.model_validate_json(
            read_text(self.state, f"runs/{run_id}/report.json", 8_000_000)
        )

    def runs(self) -> list[dict]:
        result = []
        for path in (self.state / "runs").iterdir():
            if path.is_symlink() or not path.is_dir():
                continue
            report = path / "report.json"
            status = path / "status.json"
            if status.is_file():
                value = json.loads(read_text(self.state, status.relative_to(self.state).as_posix()))
                value["has_report"] = report.is_file()
                result.append(value)
        return sorted(result, key=lambda r: r.get("updated", ""), reverse=True)

    def close(self):
        self.db.close()
