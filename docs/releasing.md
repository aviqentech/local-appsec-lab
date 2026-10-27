# Release process

The publication repository is `aviqentech/local-appsec-lab`. Publishing the GitHub source repository does not publish a Python package or prove production readiness. Version 0.2.0 must remain labeled experimental.

## Prepare a source publication

1. Complete README, prerequisites, Windows/macOS/Linux installation, usage/demo, configuration, updates/uninstall, troubleshooting, security policy, license/notices and coverage disclosures.
2. Verify the GitHub CLI identity with `gh api user --jq .login`; it must be `aviqentech`. Check the exact destination with `git remote -v`. Never push from a different active account or to an old test repository.
3. Keep author/committer metadata appropriate for the publication account. An ownership migration should publish only its intended clean branch, without legacy private history, private account URLs, local usernames/paths or machine identifiers. Preserve original local evidence separately.
4. Check the staged tree for secrets, private `.appsec-lab` data, environments and generated build directories. Sanitized sample reports still require human review. Account-neutral historical validation summaries must remain clearly historical rather than relabeled as new public CI.
5. Enable GitHub private vulnerability reporting and verify its availability before directing confidential reports there. Do not publish a fabricated security email address.
6. Run resource synchronization checks, lint/format, appropriate tests and package builds. Inspect actual skips and archive contents.
7. Push only the reviewed publication branch. Check native Windows/Linux/macOS tests, container assessments, lint and source-assessment workflows on the new repository. Record the actual run URLs and conclusions.

## Build and inspect distributions

From the development environment:

```sh
python scripts/sync_resources.py --check
python -m ruff check src tests installers benchmarks scripts install.py
python -m ruff format --check src tests installers benchmarks scripts install.py
python -m pytest -q
python -m build
```

Inspect both `dist/local_appsec_lab-0.2.0.tar.gz` and the wheel. They must contain their license/notice and bundled resources, and exclude `.appsec-lab`, `.venv`, credentials, bytecode and private evidence. Install a wheel into a clean temporary environment and verify CLI help plus managed skill installation/doctor/uninstall before distributing a binary release.

## Tagged or registry releases

A source push is separate from creating a GitHub Release, uploading artifacts, tagging a release or publishing to PyPI. Make those choices explicitly. Update version/changelog consistently, retain experimental status and platform gaps, verify artifact checksums, and document the exact source commit and tests used. Do not reuse a version for different uploaded package contents.

The manually dispatched `publish-pypi.yml` workflow builds and checks the exact distributions, validates source/installer tests and smoke-tests the wheel outside the checkout. Its `publish` input defaults to false. Only a main-branch run in `aviqentech/local-appsec-lab` can build for this workflow; the separate production job uses the `pypi` GitHub environment and a pinned official PyPA action with job-local `id-token: write` permission. It stores no long-lived PyPI token.

For first publication, sign in to PyPI as the intended owner and register a pending GitHub trusted publisher with project `local-appsec-lab`, owner `aviqentech`, repository `local-appsec-lab`, workflow `publish-pypi.yml`, environment `pypi`. This grants that workflow publishing authority for this project; it is a separate account-security action. Official guidance: https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/ .

Run once with `publish: false` to review validation, then explicitly dispatch with `publish: true` for a production release. Verify the PyPI version, distribution SHA-256 values and a fresh `pip install local-appsec-lab==VERSION`. PyPI versions/files cannot be overwritten. Keep experimental status and platform limits visible. Independent security review is required before presenting this tool as suitable for hostile-code production assessments.
