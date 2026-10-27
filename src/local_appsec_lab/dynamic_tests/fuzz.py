"""Small schema properties, with a valid control before malformed read-only inputs."""

from urllib.parse import quote

import jsonschema

from local_appsec_lab.errors import LabError
from local_appsec_lab.models import Check, Finding


def cases(schema, maximum):
    kind = schema["type"]
    if "enum" in schema and schema["enum"]:
        valid = schema["enum"][0]
    else:
        valid = (
            max(schema.get("minimum", 0), min(1, schema.get("maximum", 1)))
            if kind == "integer"
            else "x" * max(schema.get("minLength", 0), min(1, schema.get("maxLength", 1)))
            if kind == "string"
            else True
        )
    jsonschema.validate(valid, schema)
    proposed = ["appsec_invalid", "", 129, -1, False]
    if kind == "integer":
        proposed = [
            "appsec_invalid",
            schema.get("minimum", 0) - 1,
            schema.get("maximum", 127) + 1,
            *proposed,
        ]
    elif kind == "string":
        proposed = ["", "x" * min(129, schema.get("maxLength", 127) + 1), 0, *proposed]
    result = []
    for value in proposed:
        if (
            not jsonschema.Draft202012Validator(schema).is_valid(value)
            and len(str(value).encode()) <= 129
            and value not in result
        ):
            result.append(value)
    return valid, result[:maximum]


def run(client, config, mode, categories):
    findings, checks = [], []
    for target in config.fuzz_targets:
        check = Check(
            id="fuzz:" + target.id, category="validation", target=target.path, status="not_tested"
        )
        if mode != "local-active" or "validation" not in categories:
            check.reason = "Fuzz properties require explicit active validation authorization"
            checks.append(check)
            continue
        try:
            valid, invalid = cases(target.input_schema, target.max_cases)
            observations = []
            with client.budget.reserve(1 + len(invalid)):
                for index, value in enumerate([valid, *invalid]):
                    encoded = str(value).lower() if isinstance(value, bool) else str(value)
                    path = (
                        target.path
                        + ("&" if "?" in target.path else "?")
                        + target.parameter
                        + "="
                        + quote(encoded, safe="")
                    )
                    response = client.request(path)
                    expected = (
                        target.expected_valid_status
                        if index == 0
                        else target.expected_invalid_status
                    )
                    observations.append(
                        {
                            "case": "valid-control" if index == 0 else "schema-invalid",
                            "input_bytes": len(encoded.encode()),
                            "expected_status": expected,
                            "matched": response.status in expected,
                            "response": response.evidence(),
                        }
                    )
                    if index == 0 and response.status not in expected:
                        check.status, check.reason = (
                            "blocked",
                            "Valid input control failed; malformed inputs not sent",
                        )
                        break
                else:
                    check.status, check.reason = (
                        "completed",
                        "Bounded schema properties; HTTP status alone is not exploit confirmation",
                    )
            check.observations = observations
            if check.status == "completed" and any(not row["matched"] for row in observations[1:]):
                findings.append(
                    Finding(
                        rule="fuzz:" + target.id,
                        title="Input validation property was not enforced",
                        category="validation",
                        severity="medium",
                        severity_reason="The configured invalid scalar received a status outside the expected rejection policy; downstream impact is unverified.",
                        endpoint=target.path,
                        description="A valid control succeeded and at least one schema-invalid case did not match the expected status policy.",
                        expected="Reject the configured malformed or boundary input safely.",
                        observed="Configured rejection property failed.",
                        evidence=observations,
                        remediation="Validate the request field against its documented schema before using it.",
                        limitations=[
                            "Query coercion and the supplied schema/status policy need application-specific review."
                        ],
                    )
                )
        except (LabError, OSError, ValueError, jsonschema.ValidationError) as exc:
            check.status, check.reason = "blocked", type(exc).__name__
        checks.append(check)
    return findings, checks
