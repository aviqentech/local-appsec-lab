# Usage

## Command conventions

Use the Python environment where you installed the engine. `python -m local_appsec_lab` is equivalent to `appsec-lab`. On Windows without activation, use the environment's full executable path. All commands except help/version emit JSON. Scan commands report paths rather than opening a browser.

`--project`, `--workspace` and `--config` may appear before or after a subcommand. `--project` defaults to the current directory; `--workspace` defaults to the selected project and must contain it. `--config` is a path **inside the project**, not an arbitrary external file. Quote paths containing spaces.

## Inspect and review an application

```sh
appsec-lab inspect --project /path/to/application
appsec-lab plan --project /path/to/application
appsec-lab scan --project /path/to/application --mode review
```

`inspect` inventories source/frameworks/services. `plan` describes the selected work and startup without executing application code. `review` runs source and configured offline dependency checks. No execution approval is needed for source review. A recognized framework is not a promise that its entire application can be launched or semantically audited.

To create a starting configuration:

```sh
appsec-lab init --project /path/to/application
appsec-lab config validate --project /path/to/application
```

`init` refuses to overwrite an existing configuration. Keep `.appsec-lab/` ignored by version control; it can contain sensitive local evidence and run history.

## Choose a mode

| Mode | Behavior | Consent |
|---|---|---|
| `review` | Reads source; no application execution | No execution consent |
| `local-passive` | Starts one reviewed service; reads approved local responses | Fresh `--authorize` with the `plan_digest` from `plan` |
| `local-active` | Adds configured synthetic owner/actor and validation scenarios | Fresh `--authorize` with the `plan_digest` from `plan` |

```sh
appsec-lab scan --project /path/to/application --mode local-passive --authorize --plan-digest PLAN_DIGEST
appsec-lab scan --project /path/to/application --mode local-active --authorize --plan-digest PLAN_DIGEST
```

Review the startup command, service directory, runtime image, synthetic data, port and budgets first. Configuration cannot grant consent. Approval binds source/config/root/mode/run/service/categories/limits and expiry. Changes require a fresh run. No public targets, redirects, unapproved ports, brute force or arbitrary exploit workflows are supported.

## Run the synthetic Node demo

Run these commands from the Local AppSec Lab checkout, using its installed Python environment. The fixture contains synthetic identities/data only.

### macOS Seatbelt

Have Node available and a working Seatbelt backend:

```sh
appsec-lab config validate --project tests/fixtures/javascript-api
appsec-lab plan --project tests/fixtures/javascript-api
appsec-lab scan --project tests/fixtures/javascript-api --mode local-active --authorize --plan-digest PLAN_DIGEST
```

### Docker on Linux / Windows / macOS

Start a local Docker Linux-container engine, then explicitly build the trusted test image:

```sh
docker build -t local-appsec-lab-test:0.1.0 -f tests/compatibility/runtime.Dockerfile tests/compatibility
```

On macOS/Linux, copy the demo configuration:

```sh
cp examples/configuration/docker-synthetic.yaml tests/fixtures/javascript-api/docker-demo.yaml
```

On Windows PowerShell:

```powershell
Copy-Item examples/configuration/docker-synthetic.yaml tests/fixtures/javascript-api/docker-demo.yaml
```

Then validate, inspect and authorize it:

```sh
appsec-lab config validate --project tests/fixtures/javascript-api --config docker-demo.yaml
appsec-lab plan --project tests/fixtures/javascript-api --config docker-demo.yaml
appsec-lab scan --project tests/fixtures/javascript-api --config docker-demo.yaml --mode local-active --authorize --plan-digest PLAN_DIGEST
```

Use `.\.venv\Scripts\appsec-lab.exe` on Windows when unactivated. This is the intended Windows setup; execution through Docker Desktop on native Windows remains unverified. Linux and macOS Docker assessments passed.

### Expected results

The vulnerable cross-user route should produce one independently reproduced high-severity boundary finding. The secure cross-user control should not be reported as vulnerable. An informational header observation can also appear. Exit `1` is expected when the confirmed finding meets the default high threshold. Missing advisory data and unimplemented categories are disclosed as partial coverage; no claim of complete security follows from a run.

Services should stop, their owned scratch should be removed, and report/history files should remain. Run `appsec-lab clean --project tests/fixtures/javascript-api --config docker-demo.yaml` after an interrupted Docker demo.

The Flask fixture uses the same policy pattern. On macOS install the trusted development extra with `python -m pip install '.[dev]'` before running it; in Docker use an image containing Flask and set its backend/image explicitly. The included test image supplies Flask.

## Reports, verification and comparison

```sh
appsec-lab runs --project /path/to/application
appsec-lab status --project /path/to/application
appsec-lab report --project /path/to/application --run latest --format html
appsec-lab report --project /path/to/application --run latest --format sarif
appsec-lab report --project /path/to/application --run latest --format all --shareable
```

Use the `run_id` from a scan and a finding ID from its JSON report:

```sh
appsec-lab verify --project /path/to/application --run RUN_ID --finding LAB_ID --authorize --plan-digest PLAN_DIGEST
appsec-lab compare --project /path/to/application OLD_RUN_ID NEW_RUN_ID
```

Verification makes a new run with fresh evidence and preserves the original finding fingerprint. `not_reproduced` is not automatic closure; compare scope and coverage before deciding a defect is resolved. `--shareable` generalizes repository/operator metadata, but source-derived content still needs human review before publication. See [report semantics](report-format.md).

Use the same `--config` for later commands when the assessment used a custom configuration/output location. State defaults to `.appsec-lab` inside the assessed repository. Reports are written beneath its `reports` directory; the CLI's JSON gives exact paths.

## Optional model and scanner integrations

The deterministic path needs neither a model nor scanner binaries. Optional HTTPS model use requires an explicitly reviewed endpoint, positive token/cost budgets, conservative pricing and separate `--allow-model-requests` consent. A trusted `--model-key-env NAME` flag selects a credential; repository config cannot select an ambient credential. Model calls may transmit selected redacted context. See [configuration](configuration.md) and [integrations](integrations.md).

Optional Semgrep/OSV-Scanner/Trivy binaries and offline data must be provisioned explicitly. Their intended contracts are implemented, but successful real-tool integration has not been validated. ZAP/browser references do not imply implemented execution.

## Cleanup and cancellation

Press Ctrl+C to cancel. After interruption, use:

```sh
appsec-lab clean --project /path/to/application
```

Cleanup only handles resources whose ownership can be established and preserves assessment history. Do not delete unfamiliar containers/processes or remove isolation to bypass a failure. Detached daemons and hostile concurrent state tampering are outside the supported model.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Selected work completed without a threshold-triggering confirmed finding |
| `1` | Confirmed finding meets the configured severity threshold |
| `2` | Partial coverage or exhausted budget |
| `3` | Invalid configuration or path |
| `4` | Authorization/scope rejection |
| `5` | Startup failure |
| `6` | Dependency failure; reserved for direct adapter failures |
| `70` | Unexpected internal error |
| `130` | Cancellation |

Read both the exit code and report coverage. A zero exit status is not a guarantee that the application is secure. In CI, decide explicitly whether partial coverage is acceptable; do not hide every nonzero exit code.
