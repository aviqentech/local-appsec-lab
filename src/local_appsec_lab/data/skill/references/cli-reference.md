# Command reference and assessment workflows

This guide describes the checked-out source. Installed releases may have fewer
options: check `appsec-lab --version` and `appsec-lab COMMAND --help`. Experimental
features and tested environments are recorded in the repository's validation guide.

## Decide what you want to assess

There are three scan modes, four AI strategies, and separate execution backends.
These choices are independent; enabling AI does not enable application execution.

| Request | Mode | Application execution | Additional requirements |
|---|---|---|---|
| Inspect project structure | `inspect` command | None | Readable project directory |
| Preview component actions/startup | `plan` command | None | Selected project configuration |
| Review code/configuration/dependencies | `scan --mode review` | None | Advisory/scanner data for dependency claims |
| Examine a local running application's responses | `scan --mode local-passive` | Starts approved profile or uses an explicitly approved existing instance | Prepared runtime and reviewed execution plan |
| Exercise access policies, workflows and input handling | `scan --mode local-active` | Same as passive, plus configured synthetic tests | Synthetic users, expected policy, markers and mutation rollback where applicable |
| Exercise browser interactions | Live mode with browser configuration | Owned Docker runtime and Chromium | Playwright/Chromium image and explicit browser workflows; use active mode for configured security workflows |

| `ai.strategy` | What runs | What it does not mean |
|---|---|---|
| `deterministic` | Built-in source rules and configured integrations | No AI model calls |
| `native` | Authenticated Codex/Claude/Cursor/Gemini CLI specialists and fresh verifier workers | No unrestricted agent shell, browser or whole-repository access |
| `http` | Reviewed HTTPS model endpoint with explicit credential selection and budgets | No automatic provider selection, authentication or enforceable billing guarantee |
| `host` | Exports assignments and optionally imports fingerprint-bound host results | Does not automatically launch model workers |

AI workers receive selected redacted context. The parent engine controls runtime
startup, permitted requests, budgets and evidence. A model cannot grant consent,
choose arbitrary commands or bypass the parent policy. More tokens do not imply
that every source file was shown to a model.

## Common arguments and configuration

All application commands accept:

| Argument | Meaning |
|---|---|
| `--project PATH` | Assessed directory; defaults to current directory |
| `--workspace PATH` | Explicit enclosing workspace; project must be inside it; does not expand network scope |
| `--config FILE` | YAML file relative to the project; must exist inside that project |
| `--help` | Actual command syntax and available options |
| Root `--version` | Installed engine version |

Configuration precedence is supported CLI overrides, project YAML, user-global
configuration, then built-in defaults. A custom `--config` selects that project's
file instead of its default `appsec-lab.yaml`; it is not an additional project
file merged on top. Child `--project` directories do not inherit parent YAML.
Use the actual project/component location; there is no required folder named api
or ui. Quote paths containing spaces. Use `--project .` only when already working
in the intended project directory.
Keep the same project/config when reading reports or cleaning that run's state.

Only `init` creates configuration. Edit the generated file, then validate and
review a fresh plan. Init preserves existing files. Native initialization detects
eligible text size and selects starter budgets: small 200000 tokens/12 calls/300s,
medium 500000/24/600s, large 1000000/32/900s. Small is at most 100 files and
1000000 bytes; medium is above small and at most 500 files and 10000000 bytes;
large exceeds either medium boundary. Incomplete discovery uses conservative
small budgets and is disclosed. Per-assignment context starts at 6000 bytes.
Init prints the exact YAML path and chosen settings. Generated comments explain
AI/limit units and supported bounds. These budgets do not guarantee coverage or
uniform hard enforcement of native vendor spending/token usage.

All commands except help/version emit JSON. Assessment reports are separate
JSON, Markdown, HTML and SARIF files. HTML is written locally, not automatically
opened. Paths in examples such as `/path/to/application`, `PLAN_DIGEST`, `RUN_ID`,
`LAB_ID`, `FIX_ID` and `PATH` must be replaced; they are not working defaults.

## Every application command

| Command | Use | Requirements, side effects and limits |
|---|---|---|
| `doctor` | Check local environment, isolation and tool availability | Capability probes; does not prove your application will start |
| `init` | Generate commented YAML, component hints, budgets and next steps | Writes YAML and `.gitignore` exclusion; no target execution, login, downloads or model requests |
| `inspect` | Inventory files, frameworks, routes, components, dependencies and references | Source recognition only; discovered routes are not tested routes |
| `plan` | Show startup, component actions, budgets, prerequisites and digest | No application startup; `--mode` defaults to `local-active` for planning only |
| `scan` | Perform selected assessment | Defaults to `review`; live/AI/scanner features require their configuration and consent |
| `config validate` | Validate YAML/schema | Does not check credentials, install dependencies or prove runtime readiness |
| `status` | Show latest run status | Uses the selected project's state; not a machine-wide Docker/process monitor |
| `runs` | List assessment runs | Local history only |
| `report` | Render an existing run | `--run latest` default; `--format json|markdown|html|sarif|all`; `--shareable` generalizes local metadata but still needs content review |
| `verify` | Create a fresh run for one finding | `--finding LAB_ID`; defaults to latest run and preserves its mode; live findings need fresh execution approval/digest |
| `compare OLD_RUN NEW_RUN` | Compare findings between runs | Changed coverage and missing findings do not prove remediation |
| `clean` | Recover/stop exact resources owned by assessments | Preserves reports/history; not a generic container cleanup command |
| `setup` | Prepare supported locked Python/npm dependencies | Needs `--authorize --allow-network`, reviewed lockfile and prepared Docker image; not app startup or arbitrary build execution |
| `advisories status` | Inspect configured/default advisory snapshot status | No download or live vulnerability lookup |
| `advisories update` | Refresh OSV results for exact recognized package versions | `--allow-network`; package coordinates leave the machine; not every manifest/dependency is necessarily resolved |
| `tools update osv-scanner` | Refresh supported offline OSV ecosystem data | `--allow-network --ecosystem PyPI` (repeat ecosystem as needed); does not install scanner binary |
| `tools update trivy` | Refresh supported Trivy database data | `--allow-network`; does not install Trivy or scan arbitrary images |
| `cache status` / `cache clear` | Inspect/remove deterministic analysis cache entries | Clears deterministic analysis entries, not reports, advisory databases or host-provider caches; no cached AI verdict/runtime confirmation |
| `skills doctor` | Show skill target locations | Does not install/update the portable skill or authenticate hosts |
| `cvss --vector VECTOR` | Calculate severity from explicit supported CVSS v4 vector | Does not infer missing impact metrics or prove exploitability |
| `fix` | Prepare a private remediation bundle for a finding | No application-source edit during preparation; supported automatic rewrite is narrow; reviewed replacements use `--replacement FILE` |
| `fix --apply FIX_ID` / `fix --rollback FIX_ID` | Apply/undo a reviewed bundle | Requires `--authorize-fix`; may change application source; content/scope checks still apply |

There is no standalone `start`, `docker up`, `attack`, `login`, `test-all` or
`skills install` application subcommand. Scan owns startup and cleanup. Skill
installation has a separate module entry point, described below.

## Source and AI review

Initialize once in the exact selected scope:

```sh
appsec-lab init --project /path/to/application --native-host codex
appsec-lab inspect --project /path/to/application
appsec-lab config validate --project /path/to/application
appsec-lab plan --project /path/to/application --mode review
appsec-lab scan --project /path/to/application --mode review \
  --native-host codex --allow-model-requests
```

Select one of `codex`, `claude`, `cursor`, `gemini` on init and scan. Each host
must be installed/authenticated separately. Existing YAML must be edited instead
of rerunning init. Without AI, initialize without a host, keep deterministic
strategy and omit model flags. A model host with deterministic configuration is
an error in this source version, not an instruction to silently skip AI.

Additional scan/verify model options:

| Option | Purpose |
|---|---|
| `--native-host HOST` | Trusted choice of authenticated native CLI |
| `--allow-model-requests` | Consent to transmit selected redacted context; does not authorize containers, API requests or downloads |
| `--native-model MODEL` | Optional native host model selection |
| `--native-auth-dir PATH` | Explicit trusted login directory, outside the target; does not log in |
| `--model-key-env NAME` | Select one credential environment variable; do not put credentials in YAML or command values |
| `--model-price-per-million PRICE` | Conservative HTTP provider token-price estimate, with positive configured token/cost budgets |
| `--host-results FILE` | Project-relative imported results for configured `host` strategy; assignments/fingerprint must match |

HTTP strategy additionally requires reviewed `ai.endpoint`, `ai.model` and
positive budgets. Generic real HTTP provider execution and Gemini supported
authentication remain separate verification prerequisites; native source-host
support is not a promise that every account/version works.

## Live API testing and containers

Before running, configure `execution.backend`, `image`, `command`, `service`,
`port` and `health_path` as appropriate. An image must contain Python for the
trusted bridge plus the target runtime/dependencies. Runtime commands are
supported Python/Node entry points; arbitrary JVM/Go/mobile startup is not
implemented merely because those languages are recognized.

Images are not built/pulled automatically. Prepare them explicitly from reviewed
sources. No repository lifecycle hooks or `.env` files are loaded implicitly.
For custom images and external-service-heavy applications, this is a real setup
task, not a flag that can be inferred safely from the repository name.

Once the actual configuration is ready:

```sh
appsec-lab config validate --project /path/to/application
appsec-lab plan --project /path/to/application --mode local-active
# Review startup, services, scope, users, test scenarios and limits; use its digest:
appsec-lab scan --project /path/to/application --mode local-active \
  --authorize --plan-digest PLAN_DIGEST
```

To combine native AI with the live run, configure native strategy and append
`--native-host codex --allow-model-requests` to scan. For response-only testing,
plan/scan with `local-passive`. Test completion must be established from report
metrics, not the fact that the command used a live mode.

| Runtime | What the engine supports | Boundary |
|---|---|---|
| Docker single service | Owned non-root container, read-only source/root, resource limits, local HTTP through trusted bridge | Docker daemon must run; prepared image required; no published host port or arbitrary external egress |
| Constrained Compose | One reviewed application group with disposable supporting services | Docker Engine 28+, preloaded images, supported configuration, explicit seeds/migrations; does not execute arbitrary project Compose semantics |
| Linux bubblewrap | Isolated supported startup on a compatible host | Experimental; unprivileged user namespaces may be unavailable |
| macOS Seatbelt | Explicit reviewed-source Python/Node startup | Weaker host isolation; same-user process metadata/environment exposure remains possible; Docker recommended for untrusted code |
| Existing local instance | Explicit approved instance at the configured loopback port | Needs `execution.existing_url`, `existing_identity`, health header `X-AppSec-Lab-Identity`, and separate manifest approval; does not start the instance |

For an existing instance, review plan's `existing_manifest_digest`, then also pass
`--existing-manifest-digest EXISTING_DIGEST` on scan/verify. An open localhost port
or an inferred hostname never establishes ownership or authorization.

Automatic backend selection prefers Docker, then available Linux bubblewrap;
macOS execution requires explicit selection. Windows live testing requires a
Linux-container engine; native Windows Docker execution is not certified by the
source-test matrix.

For Compose, select `execution.compose_file` and `execution.service` in YAML.
Keep every referenced source/configuration inside the project scope. Databases
are supporting services, not HTTP apps to scan independently. Host mounts,
privileged execution, external destinations and env-file semantics can be
rejected. A working development Compose file is not necessarily accepted.

## Browser, access-policy and workflow tests

Browser tests require `browser: true`, configured `browser_workflows` and an image
with compatible Playwright/Chromium, Python and application dependencies. Merely
running a frontend or enabling AI does not create browser workflows.

API authorization scenarios need known synthetic owner/actor identities, a valid
owner response, expected denied statuses and an inert data marker. The engine
cannot infer whether one tenant should access another tenant's record. Stateful
mutations need explicit disposable synthetic data and supported rollback.
Schema fuzzing is bounded; an unexpected status is a candidate, not proof of a
security impact. AI-proposed adaptive checks remain constrained by the parent's
allowed local paths, methods and budgets.

In a monorepo, inspect the root, divide components, preserve infrastructure and
manifest review, and plan each runtime profile. A CLI scan executes one selected
service or one constrained Compose group. The portable skill coordinates separate
scopes; there is no automatic all-services CLI batch. Reports must distinguish
source-only, selected, not-selected, blocked and actually-started components.

## Working synthetic Docker example

From the source repository checkout, with Docker running, explicitly build the
trusted fixture image (downloads packages during the build):

```sh
docker build -t local-appsec-lab-test:0.1.0 \
  -f tests/compatibility/runtime.Dockerfile tests/compatibility
```

On macOS/Linux, copy the supplied test configuration. On Windows use PowerShell
`Copy-Item` in place of `cp` and the installed Windows executable as needed.

```sh
cp examples/configuration/docker-synthetic.yaml tests/fixtures/javascript-api/docker-demo.yaml
appsec-lab config validate --project tests/fixtures/javascript-api --config docker-demo.yaml
appsec-lab plan --project tests/fixtures/javascript-api --config docker-demo.yaml --mode local-active
appsec-lab scan --project tests/fixtures/javascript-api --config docker-demo.yaml \
  --mode local-active --authorize --plan-digest PLAN_DIGEST
appsec-lab report --project tests/fixtures/javascript-api --config docker-demo.yaml --format html
```

Replace the digest after reviewing the plan. This demo has synthetic users and
known vulnerable/protected controls already configured. It is not a universal
configuration for your application. A confirmed threshold finding can exit 1;
missing unrelated coverage can still be reported as partial. Cleanup preserves
reports; use `clean` with the same project/config after interruption.

## Dependency intelligence and prepared packages

```sh
appsec-lab advisories status --project /path/to/application
appsec-lab advisories update --project /path/to/application --allow-network
appsec-lab tools update osv-scanner --project /path/to/application --ecosystem PyPI --allow-network
appsec-lab tools update trivy --project /path/to/application --allow-network
```

Optional Semgrep, OSV-Scanner and Trivy require explicitly provisioned binaries,
offline data, configured adapters and a supported sandbox. Data refresh is not
binary installation. Supported tool versions were exercised; that does not
certify all versions/platforms. ZAP is not an implemented scanner adapter.

With a supported reviewed `execution.dependency_lock` and prepared image:

```sh
appsec-lab setup --project /path/to/application --authorize --allow-network
```

Or add `--setup-dependencies --allow-network` to an already approved live scan.
Setup supports exact hash-pinned public Python wheels or integrity-pinned npm
locks under its documented restrictions. It does not run arbitrary install hooks,
compile source packages, build images or support every private registry.

## Findings, reports and follow-up

Use `runs`, `status` and `report` to inspect execution. Important metrics are
`model_calls`, `services_started`, `routes_tested`, `http_requests`,
`browser_workflows` and blocked/not-tested counts. Discovered routes are not
measured test coverage. Model-reported usage is separate from local reservation
budgets; reported zero cost does not establish that provider usage was free.

| Finding state/verdict | Meaning |
|---|---|
| `candidate` | Potential issue; reachability/impact may be unresolved |
| AI `supported` | Supplied source supports the issue; does not automatically change the finding state to runtime-confirmed |
| AI `rejected` / `needs_context` | Reviewer disagrees or lacks context; verdict is preserved; candidate counts currently retain these records |
| `confirmed` | Engine's applicable confirmation criteria were met; inspect repeated evidence and scope |
| `not_reproduced` | Fresh test did not reproduce the issue under its conditions; not automatic closure |
| `false_positive` | Finding was rejected by the applicable engine checks; independent AI rejection alone currently does not set this state |
| `blocked` / `not_tested` | Work could not run or was not performed |
| `informational` | Observation without a confirmed vulnerability claim |

Source-only findings normally stay candidates in the current implementation.
Zero confirmed findings therefore does not mean zero source-supported issues,
and a successful process exit does not establish security.

```sh
appsec-lab runs --project /path/to/application
appsec-lab status --project /path/to/application
appsec-lab report --project /path/to/application --run RUN_ID --format all
appsec-lab verify --project /path/to/application --run RUN_ID --finding LAB_ID \
  --authorize --plan-digest PLAN_DIGEST
appsec-lab compare --project /path/to/application OLD_RUN_ID NEW_RUN_ID
appsec-lab clean --project /path/to/application
```

Verify inherits the original run's mode. Review-only findings do not require
execution authorization; live verification does. Native/HTTP configuration still
requires its model flags. Regenerate the plan after configuration changes.
Source changes and differing scope can explain comparison differences.

Fix preparation is separate from scanning:

```sh
appsec-lab fix --project /path/to/application --run RUN_ID --finding LAB_ID
# Review the generated private bundle before either operation:
appsec-lab fix --project /path/to/application --apply FIX_ID --authorize-fix
appsec-lab fix --project /path/to/application --rollback FIX_ID --authorize-fix
```

For supported reviewed replacements, add `--replacement relative/replacement.py`
to preparation. No universal auto-fix is implemented. CVSS needs an explicit
supported v4 vector: `appsec-lab cvss --vector VECTOR`. Do not invent metrics.

## Skill installation and host use

Install the portable skill separately from initializing a target project:

```sh
python -m local_appsec_lab.install --global --target codex
python -m local_appsec_lab.install --global --target codex --operation doctor
python -m local_appsec_lab.install --global --target codex --operation update
python -m local_appsec_lab.install --global --target codex --operation uninstall
```

Choose `claude`, `cursor`, `gemini`, `generic` or `all` as appropriate. For an
existing project instead of global installation, replace `--global` with
`--project /path/to/application`. Shared destinations are deduplicated. Updating
the package does not automatically refresh previously copied skill engines;
update the managed skill too. Its recorded Python interpreter must remain usable.

Ask the host for the outcome: “Review source only,” or “Prepare a disposable API
assessment, show the plan, run the authorized checks, and explain blocked work.”
The skill reads component boundaries and coordinates applicable scans. Host skill
discovery/invocation, native model workers and the CLI are distinct capabilities.
Installing a skill does not authenticate hosts, authorize execution or guarantee
that a particular desktop GUI discovers it.

## Consent and scope

| Choice | Authorizes | Does not authorize |
|---|---|---|
| `--allow-model-requests` | Selected redacted context sent through configured model integration | Target execution, downloads or source edits |
| `--authorize --plan-digest DIGEST` | Reviewed bounded live scan/verification | Arbitrary shell access, remote targets or unreviewed configuration |
| `--allow-network` | The selected explicit advisory/data/dependency download operation | Arbitrary application internet access |
| `--existing-manifest-digest DIGEST` | Exact reviewed existing-instance manifest | Ownership of any other localhost process |
| `--authorize-fix` | Apply/rollback the selected reviewed fix bundle | Unrelated application edits |

Only use authorized local projects and synthetic fixtures. Secrets and `.env`
files are excluded, not automatically imported. State-changing tests require
explicit policies. Reports/cache/state can contain sensitive source-derived
information; keep `.appsec-lab/` private. `--shareable` is not a guarantee that
all sensitive content has been removed.

## Limits and unsupported behavior

- No automatic execution of an arbitrary full application stack, production
  infrastructure, package lifecycle script or project Compose file.
- No automatic account creation, provider login, secret import, tenant-policy
  inference, database seeding semantics or generation of comprehensive browser tests.
- No remote/public-target testing, unrestricted outbound application access,
  destructive testing, brute force or universal exploit chaining.
- No universal whole-program data-flow proof, full semantic review of every file,
  automatic visual vulnerability inference or mobile emulation.
- Inventory is bounded to 10000 eligible files, 50000000 bytes total and 1000000
  bytes per eligible file. Oversized files are skipped; total/file-count overflow
  rejects the inventory. This cap is separate from `limits.storage_mb`.
- Binary/non-UTF-8 content skips discovery text parsing. Dependency directories,
  generated `.next`/build output, secret files, symlinks/reparse points and other
  excluded paths are not silently interpreted as application source.
- Native Windows Docker, real Gemini supported authentication and generic HTTPS
  provider operation retain the verification limits listed in validation docs.
  Linux bubblewrap depends on host namespace policy; macOS isolation is weaker.
- Syntactic matches, model agreement, scanner exit codes and zero findings are
  not security certification. Preserve disagreements and blocked coverage.

## Common outcomes and exit codes

| Result | Explanation/action |
|---|---|
| Zero model calls | Check `ai.strategy`, budgets, model consent, host authentication and blocked-worker checks |
| Zero HTTP/browser tests | Review mode never executes; otherwise check startup, configured scenarios/browser workflows and blockers |
| Cannot connect to Docker daemon | Start the intended Docker engine and verify its context; changing AI budgets cannot fix this |
| Startup ambiguous | Select/prepare the correct profile or component scope, then validate and plan |
| Dependency advisories blocked | Configure a valid supported offline snapshot or explicitly refresh advisory data |
| Inventory over budget | Exclude supported generated output or choose smaller scopes while preserving parent manifest/infrastructure review |
| Plan rejected | Regenerate/review after configuration changes and use the new digest |
| Partial coverage | Read blocked/not-tested checks; do not report a complete security clearance |

| Exit | Meaning |
|---|---|
| 0 | Selected work completed without a threshold-triggering confirmed finding |
| 1 | Confirmed finding meets configured severity threshold |
| 2 | Partial coverage or exhausted budget; argument-parser usage errors can also exit 2 |
| 3 | Invalid configuration/path |
| 4 | Authorization/scope rejection |
| 5 | Startup failure |
| 6 | Dependency failure for applicable direct failures |
| 70 | Unexpected internal error |
| 130 | Cancellation |

`scan --fail-on informational|low|medium|high|critical` selects the confirmed-finding
threshold; it does not suppress blocked coverage. Always read status, metrics and
findings alongside the process exit code. Use command help for installed-version
syntax rather than guessing missing subcommands.
