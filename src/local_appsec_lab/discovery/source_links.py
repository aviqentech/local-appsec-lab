"""Conservative route declaration/dispatch references, without claiming a taint trace."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from local_appsec_lab.models import Finding, Source
from local_appsec_lab.utilities.files import read_text
from local_appsec_lab.utilities.redaction import redact


def attach_sources(root: Path, inventory: dict, findings: list[Finding]) -> None:
    for finding in findings:
        if finding.source or not finding.endpoint:
            continue
        endpoint = finding.endpoint.split("?", 1)[0]
        candidates = [
            (r["source"], r["line"])
            for r in inventory["routes"]
            if r["path"] == endpoint and Path(r["source"]).suffix in {".py", ".js", ".ts"}
        ]
        if not candidates:
            dispatch = re.compile(r"\.pathname\s*===?\s*['\"]" + re.escape(endpoint) + r"['\"]")
            for path in inventory["files"]:
                if Path(path).suffix not in {".js", ".ts"}:
                    continue
                text = read_text(root, path)
                match = dispatch.search(text)
                if match:
                    candidates.append((path, text[: match.start()].count("\n") + 1))
        if len(candidates) == 1:
            path, line = candidates[0]
            text = read_text(root, path)
            end = min(len(text.splitlines()), line + (3 if path.endswith(".py") else 0))
            finding.source = Source(
                path=path,
                line=line,
                end_line=end,
                excerpt=redact("\n".join(text.splitlines()[line - 1 : end])),
                sha256=hashlib.sha256(text.encode()).hexdigest(),
            )
            finding.limitations.append(
                "Source reference identifies the route declaration/dispatch; it is not a complete execution-path trace."
            )
