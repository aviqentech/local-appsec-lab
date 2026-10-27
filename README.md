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

**Local AppSec Lab** is an open-source application security engine and portable Agent Skill from [AVIQEN](https://github.com/aviqentech). It reviews your source, starts your app in a sandbox, tests it with synthetic users, and reports only what it can back with evidence. Your code stays on your machine. Deterministic assessments need no model subscription or API key.

> [!IMPORTANT]
> **Version 0.2.2 is experimental.** Assess repositories you own or are authorized to test. Findings carry evidence and coverage limits; a scan cannot certify an application as secure.

## ✨ Why Local AppSec Lab

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🏠 Local first</h3>
      Source analysis, sandboxed runtime and reports all happen on your machine. Nothing is uploaded unless you separately allow redacted context to reach a model you chose.
    </td>
    <td width="50%" valign="top">
      <h3>🔬 Evidence, not guesses</h3>
      Every finding records how it was observed. An independent verifier repeats boundary checks, candidates stay labelled as candidates, and untested coverage stays visible.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧪 Tests the real app</h3>
      Starts your service in Docker, macOS Seatbelt or bubblewrap and runs synthetic owner/actor access checks, stateful workflows, bounded fuzzing and isolated Chromium flows.
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
| 1 | `inspect` | Inventories files, languages, frameworks, routes, dependencies and security-sensitive code |
| 2 | `plan` | Shows the startup command, sandbox, port, synthetic users, test categories and budgets, plus a `plan_digest` |
| 3 | `scan` | Runs source review, scanners and AI specialists; in local modes, starts the app and runs scoped tests |
| 4 | `verify` | Repeats a synthetic boundary check after a fix; absence alone never closes an issue |
| 5 | `report` | Writes JSON, SARIF, Markdown and offline HTML with evidence, coverage and limits |
| 6 | `fix` | Prepares a private patch; applying or rolling it back needs separate authorization |

Three modes control how far a run goes:

| Mode | Behavior | Consent |
|---|---|---|
| `review` | Reads source; never executes application code | None |
| `local-passive` | Starts one reviewed service and reads approved local responses | `--authorize --plan-digest` |
| `local-active` | Adds synthetic owner/actor, validation, workflow and fuzz scenarios | `--authorize --plan-digest` |

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

Point it at a repository you are authorized to test:

```sh
appsec-lab inspect --project /path/to/application
appsec-lab plan    --project /path/to/application
appsec-lab scan    --project /path/to/application --mode review
appsec-lab report  --project /path/to/application --run latest --format html
```

To test the running app, add a startup command and synthetic scenarios to `appsec-lab.yaml`, review the plan, then authorize with the `plan_digest` it printed. The scan is refused if the effective configuration changed since you reviewed it:

```sh
appsec-lab scan  --project /path/to/application --mode local-active --authorize --plan-digest PLAN_DIGEST
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

## 🛡️ Safety model

- **Authorization is per run.** `--authorize` binds the repository fingerprint, plan digest, mode, port, categories, budgets and expiry. Changed source or configuration is rejected.
- **Loopback only.** Requests go to explicit `127.0.0.1` / `::1` on the approved port; redirects, proxies, encoded or mapped addresses and other hosts are refused.
- **Synthetic data only.** State-changing tests need disposable synthetic data and an explicit rollback.
- **Untrusted output.** Model and scanner output can't run commands; the parent checks categories, source spans and evidence, and model findings stay candidates until verified.
- **Private state.** `.appsec-lab/` holds local security evidence and must stay out of version control.

> [!WARNING]
> Native macOS Seatbelt is for reviewed source. It can't block every same-user process-argument query, so host process environment or arguments may be exposed. Use Docker for untrusted application or scanner code.

Read the full [security model](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/security-model.md).

## 📚 Documentation

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
