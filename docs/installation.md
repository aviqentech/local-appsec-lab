# Installation and prerequisites

## Choose what you need

The CLI works independently of an AI agent. Installing the skill is optional and does not install Claude Code, Codex, Cursor, Gemini CLI, Docker, Node or application dependencies.

| Use case | Requirements |
|---|---|
| Source review and report generation | Python 3.11+, `pip`, `venv`, and the package dependencies |
| macOS application execution | Above, working `sandbox-exec`, and the selected runtime/dependencies |
| Linux application execution | Above, Docker Engine with Linux containers and a reviewed preloaded image |
| Windows application execution | Above, Docker Desktop configured for Linux containers and a reviewed preloaded image; native Windows execution remains unverified |
| Experimental Linux bubblewrap | Working user/network namespaces and `bwrap`; CI's namespace probe was blocked |
| Agent skill | Above, a compatible installed host, and permission to write the selected skill directory |
| Development | `.[dev]`; Node for JavaScript runtime fixtures; Docker for container tests |

Installation may access the network to resolve Python dependencies. Deterministic source review works offline after installation. Optional model calls and explicit dependency/image provisioning need their own connectivity. No API key is required for deterministic execution. The browser extra is a dependency option only; browser workflow execution is not implemented.

## Install from source

```sh
git clone https://github.com/aviqentech/local-appsec-lab.git
cd local-appsec-lab
```

On macOS/Linux:

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
appsec-lab --help
appsec-lab doctor
```

On Windows PowerShell:

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\appsec-lab.exe --help
.\.venv\Scripts\appsec-lab.exe doctor
```

Use `python` instead of `py -3` if that is your installed Python 3.11+ command. These Windows commands do not require virtual-environment activation or a PowerShell execution-policy change. In subsequent examples, use the explicit environment interpreter/executable when the environment is not active.

`doctor` reports dependency/isolation availability; a missing runtime backend does not prevent source-only review. No registry release is assumed. If you have a locally built wheel, install its exact path with `python -m pip install /path/to/local_appsec_lab-0.1.0-py3-none-any.whl`.

## Agent skill installation

Run the module using the same Python environment that contains the engine:

```sh
python -m local_appsec_lab.install --global --target all
python -m local_appsec_lab.install --global --target codex --operation doctor
```

To install into one existing repository:

```sh
python -m local_appsec_lab.install --project /path/to/application --target codex
```

| Target | Directory relative to user home or selected project |
|---|---|
| `claude` | `.claude/skills/local-appsec-lab` |
| `codex` | `.agents/skills/local-appsec-lab` |
| `cursor` | `.cursor/skills/local-appsec-lab` |
| `gemini` | `.gemini/skills/local-appsec-lab` |
| `generic` | `.agents/skills/local-appsec-lab` |

`all` deduplicates shared destinations. Project base directories must already exist. Paths containing spaces are supported. A missing host binary does not prevent an explicitly selected installation.

The installed copy contains `SKILL.md`, supporting references, a copied engine, `scripts/appsec_lab.py`, and `scripts/python.json` recording the interpreter path. Keep that interpreter and its dependencies available. Moving/deleting the virtual environment requires installing again with a working interpreter. The installer does not modify the host's settings to enable features or promise interactive skill discovery.

Use the host's skill picker or documented skill invocation. Intended definitions include `/local-appsec-lab` for Claude Code/Cursor, `$local-appsec-lab` for Codex, and skill selection in Gemini CLI. These invocation paths have not been validated interactively; consult the [official host references](integrations.md). Missing native delegation does not prevent using the CLI directly.

The checkout also supplies `install.py` and `installers/install.sh` / `installers/install.ps1` wrappers. Their flags are the same as the module's; use the intended Python environment. The shell wrapper invokes `python3`, and the PowerShell wrapper invokes `python` from `PATH`.

## Set up Docker explicitly

Application execution uses a local Unix-socket or Windows named-pipe daemon. Remote TCP daemons are rejected. Docker's application environment cannot redirect the host control client. The runtime publishes no ports and gives the application no network egress.

For a standard-library-only Python application, explicitly preload the default image:

```sh
docker info
docker pull python:3.13-slim
```

For the repository's Node and Flask demos, explicitly build the trusted test image:

```sh
docker build -t local-appsec-lab-test:0.1.0 -f tests/compatibility/runtime.Dockerfile tests/compatibility
```

Select `execution.backend: docker` and `execution.image: local-appsec-lab-test:0.1.0` in the project configuration. The [Docker demo](../examples/configuration/docker-synthetic.yaml) is ready to copy for the Node fixture. The image must contain Python for the trusted HTTP bridge **and** the application's runtime/dependencies. A Node-only image or the default Python-only image is insufficient for the Node demo.

The engine uses `--pull=never`, a read-only root/source, a non-root UID, dropped capabilities, no published ports, a private network namespace, resource limits and bounded writable `/tmp`. It does not install packages, execute setup hooks, build images, seed databases or provision Compose services. Use a reviewed image you prepared explicitly. Windows containers are unsupported.

## Update

From the trusted source checkout and the intended environment:

```sh
git pull --ff-only
python -m pip install .
python -m local_appsec_lab.install --global --target all --operation update
python -m local_appsec_lab.install --global --target all --operation doctor
```

Replace `--global` with `--project /path/to/application` for project installations. The installer refuses to overwrite modified or foreign files. Preserve your edits separately and review the existing installation; do not delete the ownership manifest to bypass protection.

## Uninstall

Remove the managed skill copies before removing the Python environment:

```sh
python -m local_appsec_lab.install --global --target all --operation uninstall
python -m pip uninstall local-appsec-lab
```

For project copies, select that project instead of `--global`. The installer removes only verified managed trees and refuses altered copies. Private `.appsec-lab` histories are separate project data and are not deleted by uninstall. `appsec-lab clean` stops exact owned runtime resources; it does not erase assessment history.

## Installation verification

```sh
appsec-lab --version
appsec-lab doctor
appsec-lab skills doctor
python -m local_appsec_lab.install --global --target codex --operation doctor
```

The final command checks a target that you actually installed. `skills doctor` lists locations/detection; the installer's `--operation doctor` validates managed file hashes. Review [platform evidence](validation.md) and [troubleshooting](troubleshooting.md) for environment-specific limits.
