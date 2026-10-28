# Troubleshooting

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| `0` | Command succeeded; an assessment has no confirmed finding meeting `fail_on` and is not partial | Read coverage and candidates; this is not a security clearance |
| `1` | A confirmed finding meets the configured severity threshold | Review evidence and remediate; the same report may still contain coverage gaps |
| `2` | Assessment is partial, a budget/rollback limit was hit, or argument parsing failed | For a report, inspect blocked/not-tested checks; for usage errors, read stderr and command help |
| `3` | Invalid configuration, project path or supported argument combination | Correct the YAML/path/options, validate configuration and regenerate the plan |
| `4` | Execution authorization or scope was rejected | Review the exact project, mode, plan digest and existing-instance approval; do not bypass scope controls |
| `5` | Application startup/readiness failed | Check the Docker daemon, prepared image, dependencies, startup command, port, health endpoint and runtime diagnostics |
| `6` | A dependency failure was returned directly by the command | Check explicitly provisioned packages, scanner binaries/data and the reported prerequisite |
| `70` | Unexpected internal error | Keep sanitized version/error details and report the defect; do not publish secrets or private reports |
| `130` | Run interrupted/cancelled | Inspect final status and run `clean` with the same project/config after interruption |

For scan/verify reports, exit selection is: cancellation → threshold-triggering
confirmed finding → startup failure → partial coverage → success. An exit `1`
can therefore accompany a partial report. Caught worker/dependency failures can
appear as blocked checks and exit `2`; not every missing dependency produces `6`.
Argument-parser errors also use `2` and may print usage rather than report JSON.
Always read the report status and coverage alongside the exit code.

Partial coverage is expected when advisory data or requested checks are unavailable.

## Runtime and setup

Nested Codex/macOS sandboxes may block sandbox-exec; use source review or an
explicitly permitted sandbox invocation. Never remove isolation to get a test green.
If Docker is stopped, start it yourself and preload reviewed images. Missing Python
or Node dependencies need trusted provisioning; the engine will not implicitly fetch them.
Run clean after interruption. Preserve modified installations; installer refuses
updates/uninstall when ownership hashes do not match. A broken foreign symlink
requires manual review and is deliberately not followed or removed.

Explicit `setup --authorize --allow-network` can provision supported locked public
Python-wheel/npm artifacts. It cannot run arbitrary build or lifecycle scripts.
