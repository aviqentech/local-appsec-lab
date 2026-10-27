#!/bin/sh
# Run from the repository root after installing the CLI.
appsec-lab inspect --project tests/fixtures/javascript-api
appsec-lab plan --project tests/fixtures/javascript-api
appsec-lab scan --project tests/fixtures/javascript-api --mode local-active --authorize
# Expected exit code 1 for the deliberately vulnerable fixture.
