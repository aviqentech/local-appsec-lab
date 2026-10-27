#!/bin/sh
# Run from the repository root after installing the CLI.
appsec-lab inspect --project tests/fixtures/javascript-api
appsec-lab plan --project tests/fixtures/javascript-api
# Review the plan above; --authorize applies only to the configuration it describes.
PLAN_DIGEST=$(appsec-lab plan --project tests/fixtures/javascript-api | python3 -c 'import json, sys; print(json.load(sys.stdin)["plan_digest"])')
appsec-lab scan --project tests/fixtures/javascript-api --mode local-active --authorize --plan-digest "$PLAN_DIGEST"
# Expected exit code 1 for the deliberately vulnerable fixture.
