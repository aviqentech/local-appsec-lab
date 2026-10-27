"""Untrusted model proposals pass a final parent-owned, read-only policy gate."""

from local_appsec_lab.errors import LabError, ScopeError
from local_appsec_lab.models import Check
from local_appsec_lab.network import safe_path


def run(client, proposals, routes, checks, mode, categories, owned):
    known = {
        r["path"]
        for r in routes
        if r["method"] == "GET" and not any(c in r["path"] for c in "{}:*<>")
    }
    completed = {(c.target, c.category) for c in checks if c.status == "completed"}
    output, growth = [], 0
    for index, proposal in enumerate(proposals[:40]):
        category, path = proposal.get("category"), proposal.get("path", "")
        check = Check(
            id="adaptive:" + str(index),
            category="adaptive_exploration",
            status="blocked",
            target=path[:256],
        )
        try:
            safe_path(path)
            if (
                mode != "local-active"
                or not owned
                or category not in categories
                or category not in {"headers", "cors", "error_handling"}
            ):
                raise ScopeError(
                    "Proposal cannot grant itself an execution category or owned runtime"
                )
            if path not in known:
                raise ScopeError(
                    "Proposal destination is absent from the parent-owned GET endpoint inventory"
                )
            if (path, category) in completed:
                check.status, check.reason = "not_applicable", "No new endpoint/category coverage"
            elif growth >= 4:
                check.reason = "Adaptive coverage-growth budget exhausted"
            else:
                headers = {"Origin": "https://appsec-lab.invalid"} if category == "cors" else {}
                response = client.request(path, headers)
                check.status, check.reason = (
                    "completed",
                    "Parent-authorized GET observation; no model-supplied method, headers, body, or permissions",
                )
                check.observations = [
                    {
                        "category": category,
                        "response": response.evidence(),
                        "new_coverage": True,
                        "proposer": proposal.get("proposer"),
                    }
                ]
                completed.add((path, category))
                growth += 1
        except (LabError, OSError) as exc:
            check.reason = str(exc)
        output.append(check)
    return output
