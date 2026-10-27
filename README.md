# Local AppSec Lab

A local application security CLI and portable Agent Skill from [AVIQEN](https://github.com/aviqentech), licensed under Apache-2.0.

**Version 0.1.0 is experimental.** It performs source review and bounded tests of supported local applications. It does not provide complete penetration testing, universal framework support, or a security guarantee.

The engine inventories real source, schedules deterministic review workers, starts supported Python/Node services in an OS sandbox, checks configured synthetic access policies through HTTP, independently repeats boundary findings, and produces JSON, Markdown, offline HTML and SARIF reports. No AI subscription, API key or cloud account is required for deterministic assessments.

## Prerequisites

| Requirement | When needed |
|---|---|
| Python 3.11 or newer, with `venv` and `pip` | All installations; Python 3.11 and 3.13 were tested |
| Git | Cloning and updating this repository |
| Internet access | Initial package installation and explicit image/tool provisioning; optional model requests |
| Node.js | JavaScript application execution; Node 22 is used in native CI |
| Flask or other application dependencies | Running applications that use them; provision them in the selected trusted runtime |
| OS isolation backend | Application execution: macOS Seatbelt, or Docker with a Linux engine on Linux/Windows/macOS |
| A compatible agent application | Using the optional skill in Claude Code, Codex, Cursor or Gemini CLI |

Source review needs Python and the package dependencies, but does not require Docker, Node or an agent application. The engine never installs application dependencies, builds images or pulls images implicitly. See [installation and runtime setup](docs/installation.md).

## Install

Clone the project from the publication account:

```sh
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
```

### macOS / Linux

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-lab --version
appsec-lab doctor
```

### Windows PowerShell

These commands work without changing PowerShell's script execution policy:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\appsec-lab.exe --version
.\.venv\Scripts\appsec-lab.exe doctor
```

If the `py` launcher is unavailable, use `python` after checking `python --version` is 3.11+. In the examples below, Windows users can replace `appsec-lab` with the full path to `.venv\Scripts\appsec-lab.exe`. Source installation is supported; no PyPI publication is assumed.

## First source review

Use a repository you own or are authorized to assess. Replace the example path with a real directory:

```sh
appsec-lab inspect --project /path/to/application
appsec-lab plan --project /path/to/application
appsec-lab scan --project /path/to/application --mode review
appsec-lab status --project /path/to/application
appsec-lab report --project /path/to/application --run latest --format html
```

Review mode does not execute application code. Configuration is optional for review. Run `appsec-lab init --project /path/to/application` if you want a starting `appsec-lab.yaml`; it refuses to overwrite an existing file and adds `.appsec-lab/` to that project's `.gitignore`.

Commands return JSON with report paths. A scan can exit with `2` when coverage is partial, for example when advisory data is missing. This is disclosed incomplete coverage. Exit `1` means a confirmed finding meets the configured severity threshold. See the [exit-code table](docs/usage.md#exit-codes).

## Install the optional agent skill

From the Python environment where the engine was installed:

```sh
python -m local_appsec_lab.install --global --target all
# Or install only in an existing application repository:
python -m local_appsec_lab.install --project /path/to/application --target codex
```

On Windows, use `.\.venv\Scripts\python.exe` in place of `python` if the environment is not activated. Targets are `claude`, `codex`, `cursor`, `gemini`, `generic` or `all`. The installer copies the skill and its engine, validates the copied helper, and records the installing Python interpreter. Keep that Python environment available.

Host discovery and interactive invocation remain unverified. The installed files do not automatically start native subagents. See [host paths and integration limits](docs/installation.md#agent-skill-installation).

## Run an application assessment

Review the startup command, service, isolation backend, synthetic data, scope and budgets before authorizing execution:

```sh
appsec-lab config validate --project /path/to/application
appsec-lab plan --project /path/to/application
appsec-lab scan --project /path/to/application --mode local-active --authorize
appsec-lab clean --project /path/to/application
```

`local-passive` starts the selected service and inspects approved responses. `local-active` also executes configured synthetic policy scenarios. Both require fresh `--authorize` consent. The tool never tests public targets or infers arbitrary attack workflows.

For a working example, follow the [Node demo](docs/usage.md#run-the-synthetic-node-demo). It intentionally contains a cross-user access defect and a secure control. Linux/Windows Docker setup needs an explicitly built image with Python plus Node; the default Python-only image cannot run Node. A [Docker demo configuration](examples/configuration/docker-synthetic.yaml) and trusted [test image recipe](tests/compatibility/runtime.Dockerfile) are included.

## Platform evidence

| Surface | Validation | Remaining limits |
|---|---|---|
| Windows | Native source review, CLI and installer tests on Python 3.11/3.13; PowerShell wrapper help | Docker Desktop Linux-container execution unverified |
| Linux | Native source/installer tests; real Node/Flask Docker assessments and cleanup | Bubblewrap probe blocked by runner namespace permissions; experimental |
| macOS | Native source/installer CI; real Seatbelt Node/Flask execution; local arm64 Docker tests | Aggregate process/memory/storage limits are monitored rather than hard cgroup limits |
| Agent applications | Installer, copied helper and definition files for all four hosts | Interactive skill discovery/invocation and native host dispatch unverified |

Native platform CI and Linux container assessments passed in the [public repository validation](docs/validation.md#public-repository-validation). The [publication summary](examples/publication-validation.json) links the actual runs and records skipped work. Historical pre-publication measurements remain separately labeled in [compatibility-results.json](examples/compatibility-results.json).

## Capabilities and limitations

| Area | Implemented | Limits |
|---|---|---|
| Discovery | Languages, manifests, frameworks, routes/OpenAPI, service graph | Recognition is broader than analysis |
| Source analysis | Python AST and bounded multi-language patterns | Candidates need review; no whole-program taint analysis |
| Dependencies | Exact locked versions, supplied offline snapshots, optional adapters | No built-in current advisory lookup |
| Dynamic checks | Headers, CORS, cookies, synthetic owner/actor access policies | No arbitrary crawling, brute force or remote targets |
| Verification | Fresh source reads and independent repeated HTTP evidence | Deterministic verification, not an independent AI audit |
| Reports | JSON schemas, Markdown, HTML, SARIF and run comparisons | Redaction is best effort; review before sharing |
| AI | Optional host task exchange and HTTPS Chat Completions backend | Separate consent/budgets; real provider integration unverified |
| Runtime | Python/Node single service in macOS/Docker isolation | No automatic Compose/database provisioning or application setup |

Browser workflows, ZAP execution, mobile emulators, CVSS scoring, universal framework launch and automatic host-agent dispatch are not implemented. See [requirements status](docs/requirements-status.md). Review the [security model](docs/security-model.md) before running application code, especially code you do not trust.

## Documentation

- [Installation, prerequisites, updates and uninstall](docs/installation.md)
- [Usage, synthetic demo, reports and exit codes](docs/usage.md)
- [Configuration and budgets](docs/configuration.md)
- [Agent and optional scanner integrations](docs/integrations.md)
- [Supported framework recognition](docs/supported-frameworks.md)
- [Report format and evidence states](docs/report-format.md)
- [Architecture](docs/architecture.md), [security model](docs/security-model.md), and [validation evidence](docs/validation.md)
- [Troubleshooting](docs/troubleshooting.md) and [FAQ](docs/faq.md)
- [Contributing](CONTRIBUTING.md), [release process](docs/releasing.md), [security policy](SECURITY.md), and [code of conduct](CODE_OF_CONDUCT.md)

## License and support

Apache-2.0; see [LICENSE](LICENSE), [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md). Report non-sensitive defects through [GitHub Issues](https://github.com/aviqentech/local-appsec-lab/issues). Follow [SECURITY.md](SECURITY.md) for confidential vulnerability reports. Version 0.1.x receives best-effort maintenance without a response SLA.
