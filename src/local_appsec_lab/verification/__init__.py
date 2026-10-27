from __future__ import annotations

import hashlib
from pathlib import Path

from local_appsec_lab.configuration import Config
from local_appsec_lab.dynamic_tests import scenario_observation
from local_appsec_lab.errors import LabError, RollbackFailure
from local_appsec_lab.models import Finding, now
from local_appsec_lab.network import Client
from local_appsec_lab.utilities.files import read_text


def verify(
    finding: Finding,
    root: Path,
    config: Config,
    client: Client | None,
    mode: str = "review",
    allowed_categories: tuple[str, ...] = (),
) -> Finding:
    verdict = {
        "reviewer": "independent-deterministic-verifier",
        "timestamp": now(),
        "previous_state": finding.state,
    }
    if finding.rule.startswith("boundary:"):
        scenario_id = finding.rule.split(":", 1)[1]
        scenario = next((s for s in config.scenarios if s.id == scenario_id), None)
        if (
            not client
            or not scenario
            or finding.provenance != "builtin"
            or mode != "local-active"
            or scenario.category not in allowed_categories
        ):
            finding.state = "blocked"
            verdict["conclusion"] = (
                "Safe reproduction requires an authorized running service and the original scenario"
            )
        else:
            try:
                # New owner/actor HTTP observations; never infer success from old evidence.
                result = scenario_observation(client, scenario)
                finding.state = (
                    "confirmed"
                    if result["violation"]
                    else "not_reproduced"
                    if result["owner_precondition"]
                    else "blocked"
                )
                if scenario.category == "validation" and result["violation"]:
                    finding.state = "candidate"
                    result["limitations"] = (
                        "Unexpected input response reproduced; security impact is not established"
                    )
                verdict.update({"conclusion": finding.state, "new_observation": result})
            except RollbackFailure:
                raise
            except (OSError, LabError) as exc:
                finding.state = "blocked"
                verdict["conclusion"] = type(exc).__name__
    elif finding.source:
        source = read_text(root, finding.source.path)
        current_hash = hashlib.sha256(source.encode()).hexdigest()
        if finding.source.sha256 and finding.source.sha256 != current_hash:
            finding.state = "not_reproduced"
            verdict["conclusion"] = (
                "Source changed; a fresh source scan is required; not automatically resolved"
            )
        elif finding.source.line > len(source.splitlines()):
            finding.state = "false_positive"
            verdict["conclusion"] = "Source location does not exist"
        else:
            # Re-read evidence independently but refuse to promote syntactic matches.
            verdict["conclusion"] = (
                "Source location exists; applicability/reachability requires contextual review"
            )
            verdict["source_sha256"] = current_hash
    else:
        verdict["conclusion"] = "Response observation retained; exploitability is not established"
    finding.verification.append(verdict)
    return finding


def deduplicate(findings: list[Finding], repository: str) -> list[Finding]:
    unique = {}
    for finding in findings:
        finding.identify(repository)
        if finding.fingerprint in unique:
            existing = unique[finding.fingerprint]
            existing.evidence.extend(e for e in finding.evidence if e not in existing.evidence)
            existing.verification.extend(finding.verification)
        else:
            unique[finding.fingerprint] = finding
    return sorted(unique.values(), key=lambda f: f.fingerprint)
