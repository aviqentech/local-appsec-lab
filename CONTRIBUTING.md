# Contributing

Contributions use Apache-2.0; no separate contributor agreement is required. Use synthetic fixtures and discuss concrete behavior, evidence and coverage limits. Follow the [code of conduct](CODE_OF_CONDUCT.md). Use [private reporting](SECURITY.md) for vulnerabilities in the tool and public issues only for non-sensitive defects.

## Development setup

Use Python 3.11+ and Node for JavaScript runtime fixtures. From a trusted checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

On Windows, create the venv with `py -3 -m venv .venv` and use `.\.venv\Scripts\python.exe` in place of `python`. GNU Make is optional; the commands below work directly through Python.

## Checks

```sh
python scripts/sync_resources.py --check
python -m ruff check src tests installers benchmarks scripts install.py
python -m ruff format --check src tests installers benchmarks scripts install.py
python -m pytest -q
python -m build
```

On macOS/Linux, `make check` runs resource checks, lint/format and pytest. `requirements-dev.lock` records the validated Python 3.13 environment; it is a snapshot rather than a universal OS/Python lock. Use `.[dev]` for supported dependency ranges.

The suite skips platform-specific/runtime cases when prerequisites are absent. A green suite with skips is not runtime evidence. To exercise the real container fixtures, explicitly provision the test image:

```sh
docker build -t local-appsec-lab-test:0.1.0 -f tests/compatibility/runtime.Dockerfile tests/compatibility
APPSEC_TEST_IMAGE=local-appsec-lab-test:0.1.0 python -m pytest tests/compatibility -q
```

On PowerShell set `$env:APPSEC_TEST_IMAGE = 'local-appsec-lab-test:0.1.0'` before the pytest command. Native Windows Docker execution is still unverified. `APPSEC_TEST_BWRAP=1` explicitly selects the experimental native Linux probe; restricted runners may skip it with a documented denial. Never weaken host isolation just to make a test pass.

## Changes and pull requests

Add a synthetic vulnerable fixture and a secure negative control for a new security rule. Use meaningful regressions for changed authorization, cleanup, scope, budgets or trust boundaries. Keep source results as candidates until their evidence proves the claimed behavior. Never target a public service or use real credentials/customer data.

Update relevant docs and the changelog. Changes to schemas, adapters or skill sources must be synchronized with `python scripts/sync_resources.py`, followed by `--check`. Describe the trigger, resulting behavior, validation and any changed scope/isolation/coverage in the PR. Security-sensitive changes need independent review before release.

## Publication

Follow [the release process](docs/releasing.md). Builds, private assessment histories, virtual environments, credentials and local machine metadata do not belong in a public release. Do not claim a platform, agent host, scanner or model provider was tested unless its actual integration ran and the evidence records skipped work.
