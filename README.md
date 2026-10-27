# Local AppSec Lab

A local application security engine and portable Agent Skill from [AVIQEN](https://github.com/aviqentech), licensed under Apache-2.0.

**Version 0.2.0 is experimental.** Assess repositories you own or are authorized to test. Findings carry evidence and coverage limits; a scan cannot certify an application as secure.

The engine inventories source, runs bounded source and Python data-flow analysis, coordinates specialist AI workers with fresh verification and remediation workers, provisions supported locked dependencies and disposable Compose services, and tests actual local applications through scoped HTTP and Chromium. It produces JSON, Markdown, offline HTML and SARIF reports. Deterministic assessments require no model subscription or API key.

## Install

Install the published package in your chosen Python environment:

```sh
python -m pip install local-appsec-lab
appsec-lab doctor
```

Or install from source using the commands below.

Prerequisites: **Python 3.11+**, `venv` and `pip`; Git for cloning. Active execution also needs a supported OS isolation backend and a prepared runtime. Browser/database workflows require Docker with **Linux containers**. See the [full prerequisites and installation guide](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/installation.md).

```sh
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-lab doctor
```

Windows PowerShell, without activating scripts or changing execution policy:

```powershell
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\appsec-lab.exe doctor
```

Use the explicit Windows executable in subsequent examples when the environment is not active. The PyPI package and source checkout provide the same CLI and portable skill.

## Use it

Replace `/path/to/application` with an authorized local repository:

```sh
appsec-lab inspect --project /path/to/application
appsec-lab plan --project /path/to/application
appsec-lab scan --project /path/to/application --mode review
appsec-lab report --project /path/to/application --run latest --format html
```

Review does not execute application code. Configure a supported startup command and synthetic test policies, inspect the plan, then authorize execution with the `plan_digest` that `plan` printed. The scan is refused if the effective configuration has changed since:

```sh
appsec-lab scan --project /path/to/application --mode local-active --authorize --plan-digest PLAN_DIGEST
appsec-lab clean --project /path/to/application
```

A deliberately vulnerable fixture can exit `1` for a confirmed finding. Exit `2` means partial coverage; inspect blocked and untested checks. Read [usage and exit codes](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/usage.md) and the [configuration guide](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/configuration.md).

## Optional AI and skill

Install the skill in a user or project directory:

```sh
python -m local_appsec_lab.install --global --target all
# Or: python -m local_appsec_lab.install --project /path/to/application --target codex
```

Targets are Claude Code, Codex, Cursor, Gemini CLI and generic Agent Skills hosts. Installing files, invoking a skill, and running specialist model workers are distinct capabilities. Use [host instructions and measured compatibility](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/integrations.md).

For automatic model workers, set `ai.strategy: native`, a positive `limits.model_tokens` budget and a bounded `limits.model_calls`, then explicitly authorize transmitting selected redacted context:

```sh
appsec-lab scan --project /path/to/application --mode review \
  --native-host codex --allow-model-requests
```

Claude, Cursor and Gemini have corresponding `--native-host` values. Authenticated CLIs must be installed separately. Native vendor token/cost caps are not uniformly enforceable; reports distinguish reserved and reported usage. Gemini's individual-account OAuth client was rejected by Google during testing; supported API/enterprise authentication is needed. See [AI setup](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/advanced-usage.md#ai-workers).

## Capabilities and limits

| Capability | Implemented behavior |
|---|---|
| Source review | File/route/dependency inventory, deterministic candidates, bounded interprocedural Python provenance; Semgrep adds supported JS/TS taint rules |
| Specialist orchestration | Distinct scheduled roles, parent-owned shared knowledge, fresh AI verifier and remediation processes, bounded adaptive check proposals |
| Local execution | macOS Seatbelt, Docker Linux containers; experimental Linux bubblewrap |
| Environment setup | Integrity-pinned public Python wheels/npm packages, lifecycle scripts disabled; constrained generated Compose, disposable PostgreSQL/Redis, explicit seeds/migrations |
| Active tests | Synthetic access policies, multi-step state workflows with rollback, bounded scalar-schema fuzzing and isolated Playwright/Chromium workflows |
| Security intelligence | Explicit OSV refresh and offline OSV/Trivy database updates, staleness reporting, sealed persistent deterministic cache |
| Scanners | Real offline Semgrep, OSV-Scanner and Trivy adapters on macOS and Docker; no implicit installs/downloads |
| Remediation | Contextual guidance, explicit CVSS v4 vectors, private patch preparation, separately authorized apply/rollback |
| Reports | JSON/schema, SARIF, Markdown and offline HTML; candidates and untested coverage remain visible |

Runtime recognition does not imply universal framework launch. Whole-program proof, arbitrary Compose files, inferred business policies, mobile emulators and ZAP execution are outside the implemented scope. Fix generation currently supports a narrow Python debug rewrite or a reviewed Python/JSON replacement. See the [requirement-by-requirement status](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/requirements-status.md).

| Platform/host | Verification boundary |
|---|---|
| macOS | Real Seatbelt/Docker applications, browser/database workflows, scanners and Codex/Claude/Cursor model workers tested locally |
| Linux | Native source/installer and Linux Docker tested; bubblewrap passed with a trusted root controller, with unprivileged restrictions documented |
| Windows | Native source/installer tests; Linux-container execution requires Docker Desktop and a native Windows test machine |
| Agent hosts | Skill installation supports all four; worker verification and skill discovery are tracked separately |

Consult [validation](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/validation.md) for exact measured results and outstanding prerequisites.

## Documentation and development

- [Installation, update and uninstall](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/installation.md)
- [Usage](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/usage.md), [advanced workflows](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/advanced-usage.md), [configuration/schema](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/configuration.md)
- [Architecture](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/architecture.md), [security model](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/security-model.md), [framework support](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/supported-frameworks.md)
- [Troubleshooting](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/troubleshooting.md), [FAQ](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/faq.md), [report format](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/report-format.md)
- [Validation](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/validation.md), [requirements status](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/requirements-status.md), [release procedure](https://github.com/aviqentech/local-appsec-lab/blob/main/docs/releasing.md)
- [Contributing](https://github.com/aviqentech/local-appsec-lab/blob/main/CONTRIBUTING.md), [security disclosure](https://github.com/aviqentech/local-appsec-lab/blob/main/SECURITY.md), [third-party notices](https://github.com/aviqentech/local-appsec-lab/blob/main/THIRD_PARTY_NOTICES.md)

```sh
python -m pip install '.[dev]'
make lint
python -m pytest -q
python -m build
```

Runtime tests need their documented platform and preloaded images. Never treat skipped integration tests as successful execution. Private `.appsec-lab` state contains local security evidence and must stay out of version control.

Native macOS Seatbelt is an explicit reviewed-source option. It cannot block every
numeric same-user process-argument query; host process environment/arguments may
be exposed. Use Docker for untrusted application or scanner code.
