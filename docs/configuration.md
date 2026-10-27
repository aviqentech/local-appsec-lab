# Configuration and budgets

The authoritative machine-readable definition is [config.schema.json](../schemas/config.schema.json). Unknown keys, unsupported values, YAML aliases and invalid ranges fail validation. `appsec-lab config validate` checks configuration without starting an application.

## Files and precedence

From highest to lowest priority:

1. Supported explicit CLI flags, such as `scan --fail-on`.
2. Project `appsec-lab.yaml`, or the project-relative file selected with `--config`.
3. `~/.config/local-appsec-lab/config.yaml` (the same home-relative path on Windows).
4. Built-in defaults.

Mappings merge recursively; lists are replaced. An explicit `--config` file must exist inside the selected project. No configuration layer can grant execution or model consent. Output/state must stay inside the authorized project. `init` writes the full default configuration and refuses an existing file.

## Minimal source-only configuration

Configuration is optional for review; this is a valid minimal file:

```yaml
version: 1
```

```sh
appsec-lab scan --project /path/to/application --mode review
```

## Synthetic active example

This example matches the included Node fixture; adapt routes/identities only to synthetic data you control:

```yaml
version: 1
execution:
  command: [node, server.js]
  port: 8765
  health_path: /health
limits:
  duration_seconds: 300
  max_requests: 100
  requests_per_second: 2
fail_on: high
scenarios:
  - id: vulnerable-cross-user
    category: authorization
    path: /records/vulnerable/42
    owner_headers:
      X-Test-User: alice
    actor_headers:
      X-Test-User: bob
    marker: SYNTHETIC_ALICE_RECORD_42
    expected_status: [401, 403, 404]
```

On Linux/Windows select `execution.backend: docker` and a preloaded image with Python plus the application's runtime/dependencies. The complete [Docker demo configuration](../examples/configuration/docker-synthetic.yaml) includes vulnerable and secure controls. See [runtime setup](installation.md#set-up-docker-explicitly).

## Execution settings

| Key | Default / meaning |
|---|---|
| `execution.backend` | `auto`; explicit `macos`, `docker`, or experimental `bubblewrap` |
| `execution.command` | Argument array; never a shell string. Empty means use supported discovery |
| `execution.service` | Optional repository-relative service directory; selects one service |
| `execution.port` | `8765`, range 1024–65535 |
| `execution.health_path` | `/health`; readiness expects HTTP 200 |
| `execution.startup_timeout` | 20 seconds |
| `execution.image` | `python:3.13-slim`; must already exist locally and contain all required runtimes |
| `execution.environment` | Explicit allowlist; interpreter, loader, PATH/HOME and Docker-control overrides are rejected |
| `output` | `.appsec-lab`, inside the project |
| `fail_on` | `high`; threshold for independently confirmed findings |
| `categories` | Empty selects the default catalog; explicit values restrict selected work |
| `product_name` | `Local AppSec Lab`; display name only |

Automatic selection prefers Docker, then bubblewrap on Linux. Native macOS requires explicit `execution.backend: macos` and reviewed source. An installed but stopped Docker client can therefore cause an honest runtime failure. Use an explicit backend when needed. Existing-instance mode uses `existing_url`, `existing_identity`, and the manifest digest printed by `plan`; consent must include `--existing-manifest-digest`. The engine cannot sandbox an existing service's egress. See the [security model](security-model.md).

The runtime receives a disposable source copy with `.env`, credential directories, private keys, databases and dependency directories excluded. Provision dependencies in the trusted runtime/image; do not expect an existing `node_modules` or project virtual environment to be copied.

## Limits

| Limit | Default |
|---|---:|
| `duration_seconds` | 300 |
| `max_requests` | 100 |
| `requests_per_second` | 2 |
| `response_bytes` | 65,536 |
| `log_bytes` | 262,144 |
| `storage_mb` | 64 |
| `memory_mb` | 512 |
| `processes` | 32 |
| `cpus` | 1 |
| `max_concurrent` | 2 |
| `retries` | 0 |
| `model_tokens` | 0 |
| `model_cost_usd` | 0 |
| `model_calls` | 16 |
| `max_findings` | 500 |

The schema defines supported bounds. Requests, response sizes, expiry and selected work are budgeted. Docker enforces CPU/memory/PID limits; macOS aggregate process/RSS/storage limits are monitored and are weaker than hard cgroups. Bubblewrap remains experimental.

## Scenario contracts

Scenarios select a category, project-local path, method and expected behavior. Authentication/authorization/tenant scenarios require a protected synthetic response marker and distinct owner/actor identities. A plain 200 response does not establish a cross-user data leak; the owner's baseline must succeed and return the expected marker before an actor result can establish a violation.

State-changing methods require `synthetic: true`, `disposable: true`, and `rollback_path`. Rollback uses DELETE inside the same approved scope; use explicitly provisioned disposable backing data. Budgets reserve rollback capacity first, and a rollback failure stops subsequent scenarios. Prefer read-only synthetic checks while establishing a project configuration. No production credentials or real customer records belong in these files.

## Optional model and scanner settings

`ai.strategy` is `deterministic`, `host`, `native` or `http`. HTTP use requires a reviewed HTTPS `ai.endpoint`, `ai.model`, positive model budgets, explicit `--allow-model-requests`, a conservative `--model-price-per-million` bound and a trusted `--model-key-env NAME` selection. Repository config cannot select an unrelated ambient credential. Redirects and endpoint query credentials are rejected. Selected redacted context may leave the machine after consent; native Codex/Claude/Cursor worker contracts were exercised; the generic HTTPS backend still needs a real credentialed endpoint test.

`tools` controls optional scanner adapters and `advisory_snapshot`. Tools and offline data must be explicitly provisioned. Consult the [model example](../examples/configuration/model.yaml), [integration notes](integrations.md), and schema. `browser: true` enables explicitly configured `browser_workflows` in a prepared Docker image. Stateful `workflows`, `fuzz_targets`, `execution.compose_file`, dependency setup, `cvss_vectors`, `limits.model_calls` and `limits.max_findings` are defined by the schema. See [advanced usage](advanced-usage.md) for complete prerequisites and examples.

Native macOS Seatbelt is an explicit reviewed-source option. It cannot block every
numeric same-user process-argument query; host process environment/arguments may
be exposed. Use Docker for untrusted application or scanner code.
