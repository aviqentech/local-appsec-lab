<p align="center">
  <a href="https://appsec.aviqen.com/">
    <img src="https://raw.githubusercontent.com/aviqentech/local-appsec-lab/26b645905434a147bf01c853b253998924e03941/docs/assets/banner.png" alt="Local AppSec Lab — the AI security scanner that runs on your machine. Official website: appsec.aviqen.com" width="100%">
  </a>
</p>

<p align="center">
  <a href="https://appsec.aviqen.com/"><img alt="Website" src="https://img.shields.io/badge/website-appsec.aviqen.com-38bdf8?style=for-the-badge&logo=googlechrome&logoColor=white"></a>
  <a href="https://pypi.org/project/local-appsec-lab/"><img alt="PyPI" src="https://img.shields.io/pypi/v/local-appsec-lab?style=for-the-badge&logo=pypi&logoColor=white&color=6366f1"></a>
  <a href="https://github.com/aviqentech/local-appsec-lab/actions/workflows/test.yml"><img alt="Tests" src="https://img.shields.io/github/actions/workflow/status/aviqentech/local-appsec-lab/test.yml?branch=main&style=for-the-badge&label=tests"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-5eead4?style=for-the-badge&logo=python&logoColor=white">
  <a href="https://github.com/aviqentech/local-appsec-lab/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-a78bfa?style=for-the-badge"></a>
</p>

<p align="center">
  <b><a href="https://appsec.aviqen.com/">Website</a></b> ·
  <a href="#-install">Install</a> ·
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-ai-workers-and-agent-skill">AI &amp; skill</a> ·
  <a href="#-documentation">Docs</a> ·
  <a href="https://github.com/aviqentech/local-appsec-lab/blob/main/SECURITY.md">Security</a>
</p>

---

**Local AppSec Lab** is an open-source application security engine and portable Agent Skill from [AVIQEN](https://github.com/aviqentech). It supports source review and explicitly configured local API/browser testing. The default scan reads source; it does not start your application. Live modes start a reviewed runtime when prerequisites are ready and run applicable configured checks. Deterministic review needs no model subscription or API key. Optional model calls transmit selected redacted context; advisory lookups transmit package coordinates after separate consent.

> [!IMPORTANT]
> **Version 0.2.3 is experimental.** Assess repositories you own or are authorized to test. Findings carry evidence and coverage limits; a scan cannot certify an application as secure.

## ✨ Why Local AppSec Lab

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🏠 Local first</h3>
      Source analysis, sandboxed runtime and reports all happen on your machine. Model context and advisory package coordinates leave the machine only through explicitly permitted integrations. Application runtime egress is restricted.
    </td>
    <td width="50%" valign="top">
      <h3>🔬 Evidence, not guesses</h3>
      Every finding records how it was observed. An independent verifier repeats boundary checks, candidates stay labelled as candidates, and untested coverage stays visible.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧪 Tests the real app</h3>
      Configured live modes can start supported Python/Node services in a prepared sandbox. API policies, database fixtures and Chromium workflows require project-specific setup.
    </td>
    <td width="50%" valign="top">
      <h3>🔐 You stay in control</h3>
      Review mode never executes code. Execution needs a fresh <code>--authorize</code> bound to the exact plan you reviewed. No implicit installs, downloads, redirects or non-loopback targets.
    </td>
  </tr>
</table>

## 🧭 How it works

| Step | Command | What happens |
|:---:|---|---|
| 0 | `init` | Creates a commented project configuration, detects supported startup hints and explains remaining AI/live-test setup |
| 1 | `inspect` | Inventories files, languages, frameworks, routes, dependencies and security-sensitive code |
| 2 | `plan` | Shows the startup command, sandbox, port, synthetic users, test categories and budgets, plus a `plan_digest` |
| 3 | `scan` | Runs source checks; configured integrations/AI are optional; live modes start the approved profile and applicable tests |
| 4 | `verify` | Repeats a synthetic boundary check after a fix; absence alone never closes an issue |
| 5 | `report` | Writes JSON, SARIF, Markdown and offline HTML with evidence, coverage and limits |
| 6 | `fix` | Prepares a private patch; applying or rolling it back needs separate authorization |

Three modes control how far a run goes:

| Mode | Behavior | Consent |
|---|---|---|
| `review` | Reads source; never executes application code | No execution consent; AI/network integrations need separate consent |
| `local-passive` | Starts one reviewed service and reads approved local responses | `--authorize --plan-digest` |
| `local-active` | Adds synthetic owner/actor, validation, workflow and fuzz scenarios | `--authorize --plan-digest` |


## Choose an assessment

| Goal | What to use | What actually executes |
|---|---|---|
| Understand project structure | `inspect` | Source inventory and component classification |
| Review source without AI | `scan --mode review`, deterministic YAML | Built-in checks and configured offline integrations |
| Review source with AI | Native/HTTP strategy and explicit model flags | Bounded source-context model workers; no target application |
| Read live API responses | `scan --mode local-passive` | Prepared reviewed runtime or explicitly approved existing instance, plus scoped HTTP checks |
| Test access policies/workflows | `scan --mode local-active` | Same runtime, with configured synthetic identities, assertions and bounded inputs |
| Test frontend/browser behavior | Live configuration plus `browser_workflows` | Prepared Playwright/Chromium Docker runtime and explicit workflow steps |
| Review a monorepo | Component map and separate profiles/shared Compose group | Skill coordinates scopes; one CLI scan executes one selected profile/group |

AI strategy, scan mode and backend are separate settings. AI permission does not
start containers; selecting Docker does not generate API/browser test scenarios.
There is no standalone `start`, `attack`, `test-all` or `docker up` command.

Read the [complete command and workflow reference](docs/command-reference.md) for
every command, option, prerequisites, model/provider choices, consent boundaries,
report states and troubleshooting. It is also bundled with the portable skill.

## 📦 Install

**From PyPI**

```sh
python -m pip install local-appsec-lab
appsec-lab doctor
```

**From source** (macOS / Linux)

```sh
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-lab doctor
```

<details>
<summary><b>Windows PowerShell</b> (no script activation or execution-policy change)</summary>

```powershell
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\appsec-lab.exe doctor
```

Use the explicit Windows executable in later examples when the environment is not active.
</details>

**Prerequisites:** Python 3.11+, `venv` and `pip`; Git for cloning. Running applications also needs a supported isolation backend and a prepared runtime. Browser and database workflows need Docker with **Linux containers**. See the [installation guide](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/installation.md) for updates and uninstalling.

## 🚀 Quick start

Start with project understanding: `inspect` divides the inventory into application
startup candidates, frontends, supporting services, libraries/unknown code,
infrastructure, docs and assets. `init` includes that map in its setup guidance.
`plan --mode review|local-passive|local-active` explains the action for each part:
source-only, selected for execution, not selected, or blocked with a reason.
Discovery does not prove a service can start.

When using the skill, ask for the outcome, for example: “Assess this project:
review all relevant source, run the supported API services in disposable
containers, and test configured browser workflows; explain anything blocked.”
The skill coordinates separate service scopes and shared Compose groups. Each
CLI scan still executes one selected profile/group; it does not automatically
launch every discovered script. Reports include component coverage and measured
starts/HTTP requests, keeping source-only work distinct from actual live tests.

Point it at a repository you are authorized to test:

```sh
appsec-lab init    --project /path/to/application
appsec-lab inspect --project /path/to/application
appsec-lab plan    --project /path/to/application --mode review
appsec-lab scan    --project /path/to/application --mode review
appsec-lab report  --project /path/to/application --run latest --format html
```

`init` creates **`/path/to/application/appsec-lab.yaml`** and prints its location,
detected startup hints, remaining prerequisites and next commands. Edit that file
to change the startup command, budgets, AI strategy, API scenarios or browser
workflows. It preserves existing configuration; after editing, run:

```sh
appsec-lab config validate --project /path/to/application
appsec-lab plan --project /path/to/application
```

**Want AI review?** Initialize with your authenticated host selection instead of
the default `init` above:

```sh
appsec-lab init --project /path/to/application --native-host codex
appsec-lab scan --project /path/to/application --mode review \
  --native-host codex --allow-model-requests
```

This sets `ai.strategy: native` and explicit starter model budgets. Substitute
`claude`, `cursor` or `gemini` as appropriate. Initialization never logs in, sends
source or starts the application. Without a host selection, it configures
deterministic review. An existing file must be edited; rerunning `init` does not
overwrite it. See [AI configuration](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/advanced-usage.md#ai-workers).

Choose the host you use; the initialization flow supports all four:

| Host | Initialize this project |
|---|---|
| Codex | `appsec-lab init --project api --native-host codex` |
| Claude Code | `appsec-lab init --project api --native-host claude` |
| Cursor | `appsec-lab init --project api --native-host cursor` |
| Gemini CLI | `appsec-lab init --project api --native-host gemini` |

Use the same host on `scan`, with `--allow-model-requests`. Each CLI requires its
own supported authentication; generating configuration does not verify login.
Other agent hosts can use the portable skill/host-result exchange, but are not
additional automatic `--native-host` providers.

Native initialization sizes starter budgets from eligible text files and bytes:

| Project size | Text inventory | Model tokens | Model calls | Duration (seconds) |
|---|---|---:|---:|---:|
| Small | At most 100 files and 1 MB | 200,000 | 12 | 300 |
| Medium | Above small; at most 500 files and 10 MB | 500,000 | 24 | 600 |
| Large | More than 500 files or 10 MB | 1,000,000 | 32 | 900 |
| Unknown | Discovery could not complete | 200,000 | 12 | 300 |

MB here means 1,000,000 bytes. Binary assets and excluded build output do not count.
`ai.context_bytes` starts at 6000 per specialist assignment for every size.
Init prints `configured_settings` with the exact file path, all AI/limit values,
sizing inputs and edit instructions. Edit that file to fit your needs, then
validate and review the plan again. Every AI and limits field has a YAML comment.
These are scheduling budgets, not a coverage guarantee or an enforceable native
provider spending cap. Deterministic initialization keeps model work disabled.

**Scan a monorepo service?** Initialize that exact directory, for example
`appsec-lab init --project api --native-host codex`. Scans of `api` or `ui/src`
do not inherit a configuration created at the repository root. Narrow source
scopes also omit parent deployment files and dependency manifests.

To test the running app, add a startup command and synthetic scenarios to `appsec-lab.yaml`, review the plan, then authorize with the `plan_digest` it printed. The scan is refused if the effective configuration changed since you reviewed it:

Init can fill an unambiguous supported startup command, but port/health settings,
runtime dependencies, disposable databases and intended user permissions need
review. Browser testing additionally requires `browser: true`, configured
`browser_workflows` and a prepared Playwright/Chromium runtime. Init reports this
remaining setup; it does not claim that live testing is ready.

```sh
appsec-lab plan --project /path/to/application --mode local-active
appsec-lab scan --project /path/to/application --mode local-active --authorize --plan-digest PLAN_DIGEST
appsec-lab clean --project /path/to/application
```

<details>
<summary><b>Example <code>appsec-lab.yaml</code></b></summary>

```yaml
version: 1
execution:
  command: [node, server.js]
  port: 8765
  health_path: /health
limits:
  requests_per_second: 10
  max_requests: 100
scenarios:
  - id: cross-user-record
    path: /records/42
    category: authorization
    owner_headers: { X-Test-User: alice }
    actor_headers: { X-Test-User: bob }
    marker: SYNTHETIC_ALICE_RECORD_42
```

Generate a full template with `appsec-lab init`. All fields are in the [configuration guide](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/configuration.md).
</details>

### Exit codes

| Code | Meaning |
|:---:|---|
| `0` | Completed without a confirmed finding at or above the `fail_on` threshold |
| `1` | A confirmed finding meets the threshold |
| `2` | Partial coverage or exhausted budget; check blocked and untested checks |
| `3` / `4` | Invalid configuration or path / authorization or scope rejection |
| `5` | Application startup failure |
| `130` | Cancelled |

A zero exit status never means the application is secure. Read the report's coverage too. More in [usage](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/usage.md).

## Complete command catalog

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
| `cache status` / `cache clear` | Inspect/remove deterministic analysis cache entries | Does not delete reports or guarantee complete rescanning of every external integration; no cached AI verdict/runtime confirmation |
| `skills doctor` | Show skill target locations | Does not install/update the portable skill or authenticate hosts |
| `cvss --vector VECTOR` | Calculate severity from explicit supported CVSS v4 vector | Does not infer missing impact metrics or prove exploitability |
| `fix` | Prepare a private remediation bundle for a finding | No application-source edit during preparation; supported automatic rewrite is narrow; reviewed replacements use `--replacement FILE` |
| `fix --apply FIX_ID` / `fix --rollback FIX_ID` | Apply/undo a reviewed bundle | Requires `--authorize-fix`; may change application source; content/scope checks still apply |

Use `appsec-lab COMMAND --help` for the installed version. Common options are
`--project`, `--workspace` and project-relative `--config`. Defaults and complete
examples are in the [command reference](docs/command-reference.md).

## 🤖 AI workers and agent skill

Install the skill for your coding agent, per user or per project:

```sh
python -m local_appsec_lab.install --global --target all
# Or: python -m local_appsec_lab.install --project /path/to/application --target codex
```

Targets: **Claude Code**, **Codex**, **Cursor**, **Gemini CLI** and generic Agent Skills hosts. Installing files, invoking a skill and running model workers are separate capabilities; see [integrations](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/integrations.md).

For automatic specialist workers, set `ai.strategy: native` with a positive `limits.model_tokens` budget and bounded `limits.model_calls`, then explicitly allow sending selected, redacted context:

```sh
appsec-lab scan --project /path/to/application --mode review \
  --native-host codex --allow-model-requests
```

`claude`, `cursor` and `gemini` are also valid `--native-host` values; their CLIs must be installed and signed in separately. Vendor token and cost caps aren't uniformly enforceable, so reports separate reserved from reported usage. Gemini's individual-account OAuth client was rejected by Google in testing; use supported API or enterprise authentication. Details in [AI setup](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/advanced-usage.md#ai-workers).

## 🧰 Capabilities

| Capability | Implemented behavior |
|---|---|
| Source review | File/route/dependency inventory, deterministic candidates, bounded interprocedural Python provenance; Semgrep adds supported JS/TS taint rules |
| Specialist orchestration | Distinct scheduled roles, parent-owned shared knowledge, fresh AI verifier and remediation processes, bounded adaptive check proposals |
| Local execution | macOS Seatbelt, Docker Linux containers; experimental Linux bubblewrap |
| Environment setup | Integrity-pinned public Python wheels/npm packages with lifecycle scripts disabled; constrained generated Compose, disposable PostgreSQL/Redis, explicit seeds/migrations |
| Active tests | Synthetic access policies, multi-step state workflows with rollback, bounded scalar-schema fuzzing and isolated Playwright/Chromium workflows |
| Security intelligence | Explicit OSV refresh and offline OSV/Trivy database updates, staleness reporting, sealed persistent deterministic cache |
| Scanners | Offline Semgrep, OSV-Scanner and Trivy adapters on macOS and Docker; no implicit installs or downloads |
| Remediation | Contextual guidance, explicit CVSS v4 vectors, private patch preparation, separately authorized apply/rollback |
| Reports | JSON with schema, SARIF, Markdown and offline HTML; candidates and untested coverage remain visible |

**Not in scope yet:** whole-program proof, arbitrary Compose files, inferred business policies, mobile emulators and ZAP execution. Recognizing a runtime doesn't mean every framework can be launched. Fix generation covers a narrow Python debug rewrite or a reviewed Python/JSON replacement. See the [requirement-by-requirement status](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/requirements-status.md).

## 🖥️ Platform support

| Platform / host | Verification boundary |
|---|---|
| 🍎 macOS | Seatbelt and Docker applications, browser/database workflows, scanners and Codex/Claude/Cursor model workers tested locally |
| 🐧 Linux | Native source/installer and Linux Docker tested; bubblewrap passed with a trusted root controller, unprivileged restrictions documented |
| 🪟 Windows | Native source/installer tests; Linux-container execution needs Docker Desktop and a native Windows test machine |
| 🧩 Agent hosts | Skill installation supports all four; worker verification and skill discovery are tracked separately |

Exact measured results and open prerequisites are in [validation](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/validation.md).

## What is and is not automatic

**Implemented for supported configurations:** component discovery; bounded source
and Python data-flow checks; optional native/HTTP AI specialists and verification;
configured offline scanners/advisory refresh; owned Python/Node runtime startup;
constrained Compose/database execution; explicit synthetic API/browser workflows;
evidence reports, comparison, cleanup and limited reviewed remediation.

**Requires project-specific preparation:** trusted runtime images, dependencies,
ports and health endpoints, disposable databases/seeds, synthetic identities and
expected access policies, browser selectors/workflows, host login and optional
scanner/data provisioning. Init explains known startup candidates and remaining
requirements; it does not complete every application's environment setup.

**Not provided:** automatic execution of arbitrary application stacks or project
Compose semantics; unrestricted AI tools; automatic production credentials or
business-policy inference; public/remote target scanning; destructive testing;
comprehensive automatic browser journeys; universal whole-program proof or
universal auto-fixing. ZAP and mobile execution are not implemented adapters.

**Reporting caveat:** source findings normally remain candidates. AI verdicts
`supported`, `rejected` and `needs_context` are recorded independently and currently
do not automatically alter candidate state/counts. Zero engine-confirmed findings
can include source-supported issues. Discovered routes and model calls are not
live API/browser coverage: inspect `services_started`, `http_requests`,
`routes_tested`, `browser_workflows` and blocked/not-tested checks.

For a [complete synthetic Docker walkthrough](docs/command-reference.md#working-synthetic-docker-example),
use the source checkout's fixture and prepared test image. This demonstrates actual
container/API execution without pretending that its configuration fits your app.
See [advanced workflows](docs/advanced-usage.md) for constrained Compose, browser,
stateful and dependency setup. See [validation](docs/validation.md) for tested
platforms/host versions and unresolved prerequisites.

## 🛡️ Safety model

- **Authorization is per run.** `--authorize` binds the repository fingerprint, plan digest, mode, port, categories, budgets and expiry. Configuration must match the reviewed plan; source changes after run authorization are rejected.
- **Loopback only.** Requests go to explicit `127.0.0.1` / `::1` on the approved port; redirects, proxies, encoded or mapped addresses and other hosts are refused.
- **Synthetic data only.** State-changing tests need disposable synthetic data and an explicit rollback.
- **Untrusted output.** Model and scanner output can't run commands; the parent checks categories, source spans and evidence, and model findings stay candidates until verified.
- **Private state.** `.appsec-lab/` holds local security evidence and must stay out of version control.

> [!WARNING]
> Native macOS Seatbelt is for reviewed source. It can't block every same-user process-argument query, so host process environment or arguments may be exposed. Use Docker for untrusted application or scanner code.

Read the full [security model](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/security-model.md).

## 📚 Documentation

Start with the [complete command/workflow reference](docs/command-reference.md)
and [configuration guide](docs/configuration.md). This README describes the current
source branch; compare installed `--version`/`--help` before using newly added options.

| Get started | Go deeper | Project |
|---|---|---|
| [Installation](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/installation.md) | [Architecture](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/architecture.md) | [Validation](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/validation.md) |
| [Usage](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/usage.md) | [Security model](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/security-model.md) | [Requirements status](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/requirements-status.md) |
| [Configuration](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/configuration.md) | [Framework support](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/supported-frameworks.md) | [Release procedure](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/releasing.md) |
| [Advanced workflows](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/advanced-usage.md) | [Report format](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/report-format.md) | [Changelog](https://github.com/aviqentech/local-appsec-lab/blob/main/CHANGELOG.md) |
| [Troubleshooting](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/troubleshooting.md) · [FAQ](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/faq.md) | [Integrations](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/integrations.md) | [Third-party notices](https://github.com/aviqentech/local-appsec-lab/blob/main/THIRD_PARTY_NOTICES.md) |

## 🔄 Releases

Every pull request merged into `main` publishes a new PyPI release once CI passes. The workflow picks the next unused patch version, syncs package, CLI and changelog versions, validates the distributions, publishes through the Trusted Publisher and verifies a fresh public install. Direct pushes and unmerged PRs don't publish. See the [release process](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/releasing.md).

## 🛠️ Development

```sh
python -m pip install '.[dev]'
make lint
python -m pytest -q
python -m build
```

Runtime tests need their documented platform and preloaded images. A skipped integration test is not a successful one.

## 🤝 Contributing and security

Contributions are welcome. Start with [CONTRIBUTING](https://github.com/aviqentech/local-appsec-lab/blob/main/CONTRIBUTING.md) and the [code of conduct](https://github.com/aviqentech/local-appsec-lab/blob/main/CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY](https://github.com/aviqentech/local-appsec-lab/blob/main/SECURITY.md), not in public issues.

## 📄 License

Apache-2.0. See [LICENSE](https://github.com/aviqentech/local-appsec-lab/blob/main/LICENSE) and [NOTICE](https://github.com/aviqentech/local-appsec-lab/blob/main/NOTICE).

---

<p align="center">
  <a href="https://appsec.aviqen.com/"><b>appsec.aviqen.com</b></a><br>
  <sub>Built by <a href="https://github.com/aviqentech">AVIQEN</a> · Assess only what you own or are authorized to test.</sub>
</p>
