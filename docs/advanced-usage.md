# Advanced workflows

Start with `inspect`, `plan` and a source-only review. Configuration examples here are schema-backed; adapt all identities, expected policies and paths to synthetic data in an authorized project. `appsec-lab init` creates defaults without overwriting existing configuration.

## AI workers

Install and authenticate a supported Codex, Claude Code, Cursor agent or Gemini CLI separately using its official instructions. Keep login directories outside the assessed repository. The engine starts each worker in a new trusted temporary workspace outside the target, gives it bounded redacted source context and disables executable tools. A fresh worker reviews significant candidates; a separate worker recommends remediation. Deterministic results and all disagreements stay in the run.

```yaml
ai:
  strategy: native
  context_bytes: 6000
limits:
  model_tokens: 200000
  model_calls: 6
  duration_seconds: 300
categories: [input_data_flow, authorization]
```

```sh
appsec-lab scan --project /path/to/application --mode review \
  --native-host codex --allow-model-requests
```

Use `claude`, `cursor` or `gemini` for the other native hosts. `--native-model` selects a trusted host model. Cursor/Gemini default to a dedicated per-user Local AppSec Lab auth directory; `--native-auth-dir /trusted/outside/path` selects a directory you authenticated explicitly. The setting comes from the CLI, not repository configuration. API-key authentication uses `--model-key-env MY_CHOSEN_VARIABLE`; the engine forwards only that selected key under the provider's expected variable name. Never put credentials in YAML or command arguments.

Native CLI calls have wall/output/call bounds and conservative token reservations. Reported vendor usage is reconciled when available. A native subscription can omit usage and cannot uniformly enforce the configured dollar/token cap at the vendor. Reports expose that limitation. If strict metered request caps are required, use the HTTPS backend with explicit pricing and output bounds; provider billing can still differ from local estimates.

`ai.strategy: http` accepts a reviewed HTTPS OpenAI-compatible Chat Completions endpoint/model. Use `--allow-model-requests`, `--model-key-env NAME` and `--model-price-per-million PRICE` with positive token/cost budgets. There is no real HTTP-provider certification without a credentialed test. `ai.strategy: host` exports assignments and can import fingerprint-bound `--host-results`; it does not automatically start another application. Native strategy is the automatic CLI path.

Gemini CLI 0.65.0's individual-account OAuth exchange was rejected by Google during validation. Do not retry a consumed authorization code. Use authentication currently supported for your account and installed CLI.

## Locked dependency setup

Explicitly preload a trusted runtime image containing Python plus the target runtime. Python setup accepts exact versions with SHA-256 hashes for every requirement and downloads matching binary wheels only. npm setup accepts public-registry integrity-pinned package-lock v2/v3 without workspace/local links. Arbitrary registry URLs, source builds and install lifecycle scripts are refused.

```yaml
execution:
  backend: docker
  image: your-reviewed-runtime:version
  command: [python, app.py]
  dependency_lock: requirements.lock
limits:
  storage_mb: 256
  duration_seconds: 300
```

```sh
appsec-lab setup --project /path/to/application --authorize --allow-network
appsec-lab scan --project /path/to/application --mode local-active --authorize
# Combined, with the same explicit download authorization:
appsec-lab scan --project /path/to/application --mode local-active --authorize \
  --setup-dependencies --allow-network
```

Downloads run through the trusted fixed-registry client; package installation runs non-root in a no-network container. The source remains unchanged. Prepared dependencies are bound to lockfile/image/content hashes and mounted read-only in the application. Configure a larger budget or prepare a reviewed image if dependencies exceed limits. Setup does not build target images or run repository installation hooks.

## Disposable Compose and databases

Set `execution.compose_file` and `execution.service`. Every service needs a preloaded image. The engine reads supported declarations and generates its own constrained Compose file; host binds, privileged settings, external networking, env files and entrypoint overrides are refused. Ports are not published. Docker Engine 28+ isolated internal bridge networking is required. PostgreSQL/Redis data and credentials are disposable.

```yaml
execution:
  compose_file: compose.yaml
  service: api
  command: [python, server.py]
  startup_timeout: 40
  seeds:
    database: seed.sql
  migrations:
    api: [python, migrate.py]
```

A minimal Compose input has an `api` image/argument-array command and a `database` image such as `postgres:17-alpine`. Application database URLs must name an owned service; external destinations are refused. See the real [database fixture](../tests/fixtures/database-api). Migrations execute target code only inside the approved disposable environment; their named containers are recorded before launch and removed on failure or timeout. `clean` recovers exact owned resources and ephemeral leases after interruption.

## Browser workflows

Explicitly prepare an image with compatible Python Playwright and Chromium, Python for the bridge, and the target's runtime/dependencies. The tested [browser Dockerfile](../tests/compatibility/browser.Dockerfile) uses Playwright 1.64.1. Building/pulling it is a separate trusted provisioning action.

```sh
docker build -t local-appsec-lab-browser:0.2.0 \
  -f tests/compatibility/browser.Dockerfile tests/compatibility
```

```yaml
browser: true
execution:
  backend: docker
  image: local-appsec-lab-browser:0.2.0
  command: [node, server.js]
limits:
  memory_mb: 1024
  processes: 128
  storage_mb: 256
browser_workflows:
  - id: page-policy
    path: /html-secure
    steps:
      - action: expect_text
        selector: h1
        value: Local security fixture
```

Run with `--mode local-active --authorize` and include `browser` if restricting categories. Supported actions are fill/click/goto/expect_text/expect_path. Browser mutation paths require an explicit allowlist, `synthetic: true`, `disposable: true` and DELETE `rollback_path`. Every HTTP request goes through the parent's scope/rate/body budget. WebSockets, service workers and external requests are blocked. Chromium's sandbox stays enabled; the browser uses a UID distinct from the application. Evidence records HTTP status/body hashes, assertions and screenshot size/hash; raw screenshots, response bodies, cookies and captured identifiers are not saved.

## Stateful workflows and fuzzing

`workflows` defines explicit identities, steps, expected statuses, named scalar JSON captures and a DELETE rollback. `synthetic: true` and `disposable: true` are mandatory. Captures such as `/id` can be substituted into later paths as `{{record}}`; they stay in memory and are URL-quoted. A security assertion needs an inert synthetic marker. The entire sequence and rollback must fit the budget before mutation begins. A fresh full sequence independently verifies a violation; failed rollback aborts subsequent work.

`fuzz_targets` accepts small integer/string/boolean JSON schemas for explicitly selected GET query fields. It sends a valid control before a bounded set of malformed/boundary values. A failed valid control blocks malformed cases. Unexpected rejection status creates a candidate, never an exploitation confirmation. See [stateful/fuzz tests](../tests/integration/test_workflows.py) for complete positive and protected controls.

## Advisory updates and scanner data

```sh
appsec-lab advisories update --project /path/to/application --allow-network
appsec-lab advisories status --project /path/to/application
appsec-lab tools update osv-scanner --project /path/to/application --allow-network --ecosystem PyPI
appsec-lab tools update trivy --project /path/to/application --allow-network
```

Live OSV lookup transmits exact locked package names/versions after consent, then writes an offline snapshot. Updates are bounded and preserve prior data on failure. The default maximum advisory age is seven days. OSV ecosystem archives and Trivy's checksum-verified fixed-origin OCI database are explicit data downloads; target/scanner processes remain offline. Trivy data can require roughly 2 GB plus staging, separate from the application's scratch budget. Scanner executables/images must be installed or preloaded separately.

```yaml
tools:
  semgrep: true
  osv_scanner: true
  trivy: true
  backend: docker
  images:
    semgrep: semgrep/semgrep:1.182.1
    osv-scanner: ghcr.io/google/osv-scanner:v2.7.0
    trivy: aquasec/trivy:0.72.0
```

These are the tested scanner versions, not minimum-version promises. `tools.backend: macos` uses separately installed executable paths. The package redistributes no scanner binaries. Native Windows scanner execution is not supported; use the Docker path and record actual results.

## Cache, CVSS and fixes

```sh
appsec-lab cache status --project /path/to/application
appsec-lab cache clear --project /path/to/application
appsec-lab cvss --vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
appsec-lab fix --project /path/to/application --run latest --finding FINDING_ID
appsec-lab fix --project /path/to/application --apply FIX_ID --authorize-fix
appsec-lab fix --project /path/to/application --rollback FIX_ID --authorize-fix
```

The deterministic cache is sealed with a per-user key outside the target and invalidates on source/analyzer changes. No AI verdict or runtime confirmation is reused. An unavailable trusted key causes recomputation.

CVSS v4 requires an explicit supplied vector; the engine does not infer missing metrics. Fix preparation writes a private hash-bound diff and syntax/source-check results without changing application source. Automatic generation currently covers Python `debug=True`; otherwise supply a reviewed project-relative Python/JSON `--replacement`. Apply/rollback each need explicit authorization and refuse changed source or bundle hashes. Syntax/source checks are not runtime compatibility proof. Rescan and run the application's relevant regressions after applying a fix.
