"""Bounded persistent cache for deterministic source results, never AI verdicts."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import stat
from itertools import islice
from pathlib import Path
from collections.abc import Callable

from local_appsec_lab.models import Check, Finding, digest
from local_appsec_lab.errors import LabError
from local_appsec_lab.utilities.files import atomic_json, private_dir, read_bytes, read_text


class AnalysisCache:
    def __init__(self, state: Path, root: Path, inventory: dict):
        from local_appsec_lab.intelligence.cache_key import key

        self.seal_key = key(root)
        self.directory = state / "analysis-cache"
        try:
            private_dir(self.directory)
        except (OSError, LabError):
            self.seal_key = None
        self.root = root
        self.lock = threading.Lock()
        self.hits = self.misses = 0
        self.source_digest = digest(
            [(p, hashlib.sha256(read_bytes(root, p)).hexdigest()) for p in inventory["files"]]
        )
        modules = [
            Path(__file__).parent.parent / "scanners" / "__init__.py",
            Path(__file__).parent / "dataflow.py",
        ]
        self.analyzer_digest = digest(
            [(p.name, hashlib.sha256(p.read_bytes()).hexdigest()) for p in modules if p.exists()]
        )

    def source(
        self, categories: list[str], operation: Callable
    ) -> tuple[list[Finding], list[Check]]:
        key = digest([2, self.source_digest, self.analyzer_digest, sorted(categories)])
        path = self.directory / (key + ".json")
        with self.lock:
            if self.seal_key and path.exists():
                try:
                    value = json.loads(read_text(self.directory, path.name, 8_000_000))
                    if value["key"] != key:
                        raise ValueError("Cache identity mismatch")
                    signature = value.pop("signature", "")
                    expected = hmac.new(
                        self.seal_key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256
                    ).hexdigest()
                    if not hmac.compare_digest(signature, expected):
                        raise ValueError("Cache seal does not match this trusted installation")
                    findings = [Finding.model_validate(v) for v in value["findings"]]
                    checks = [Check.model_validate(v) for v in value["checks"]]
                    if any(f.state not in {"candidate", "informational"} for f in findings):
                        raise ValueError("Cached verification is prohibited")
                    for check in checks:
                        check.observations.append(
                            {"analysis_cache": "hit", "source_digest": self.source_digest}
                        )
                    self.hits += 1
                    return findings, checks
                except (ValueError, KeyError, OSError, TypeError, LabError):
                    pass
            self.misses += 1
        findings, checks = operation()
        value = {
            "key": key,
            "findings": [f.model_dump() for f in findings],
            "checks": [c.model_dump() for c in checks],
        }
        if self.seal_key:
            value["signature"] = hmac.new(
                self.seal_key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256
            ).hexdigest()
        if self.seal_key and len(json.dumps(value).encode()) <= 8_000_000:
            with self.lock:
                if path.is_symlink():
                    return findings, checks
                try:
                    candidates = list(islice(self.directory.iterdir(), 513))
                    if len(candidates) > 512:
                        return findings, checks
                    atomic_json(path, value)
                    entries = sorted(
                        [
                            p
                            for p in {*candidates, path}
                            if len(p.stem) == 64
                            and all(c in "0123456789abcdef" for c in p.stem)
                            and p.suffix == ".json"
                            and stat.S_ISREG(p.lstat().st_mode)
                            and p.lstat().st_nlink == 1
                        ],
                        key=lambda p: p.lstat().st_mtime,
                        reverse=True,
                    )
                    total = 0
                    for index, entry in enumerate(entries):
                        total += entry.lstat().st_size
                        if index >= 128 or total > 32_000_000:
                            entry.unlink()
                except (OSError, LabError):
                    # Optional cache failure must never discard freshly computed analysis.
                    pass
        return findings, checks
