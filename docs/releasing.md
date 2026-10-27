# Release process

The publication repository is `aviqentech/local-appsec-lab`. Publishing the GitHub source repository does not publish a Python package or prove production readiness. Keep current releases labeled experimental until their documented readiness changes.

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

Merged-main PRs now authorize the automatic PyPI flow described below; other source pushes remain separate from package publication. GitHub Releases and tags are separate choices. Update version/changelog consistently, retain experimental status and platform gaps, verify artifact checksums, and document the exact source commit and tests used. Do not reuse a version for different uploaded package contents.

The `publish-pypi.yml` workflow automatically releases after a PR merges into `main`.
A main push is eligible only when GitHub identifies it as the merge commit of an
actually merged PR targeting this repository's main branch. Opening/closing an
unmerged PR, pushing a feature branch, or directly pushing main does not publish.
No unmerged PR code runs with publishing privileges.

Before an automatic release, all five normal push-CI workflows for that exact merge
revision must succeed: native tests, container/browser/database tests, lint, source
assessment and platform capabilities. The release then:

1. Reads existing PyPI versions and chooses the next unused patch version; a higher
   stable major/minor version explicitly prepared in the PR is preserved.
2. Synchronizes package/CLI versions and the README version label, and moves
   `Unreleased` changelog notes under the new dated release.
3. Runs lint, source/installer tests, strict distribution checks and an independent
   wheel installation before committing the version update to main.
4. Pushes only a normal fast-forward version commit with the repository's
   `GITHUB_TOKEN`; this does not retrigger push workflows, preventing release loops.
5. Publishes those exact validated artifacts through the existing `pypi` Trusted
   Publisher, then compares registry SHA-256 values and tests a fresh PyPI install
   plus every skill install/doctor/uninstall target.

Publishing is isolated in its own job with job-local `id-token: write`; it performs
no checkout or package build. No extra PyPI token or personal access token is needed.
Only the version-recording job has repository write permission. Branch rules must permit the repository workflow to write its version commit; a
blocked push stops publication. When renaming CI workflows, update
`REQUIRED_CI` in `scripts/release_automation.py`. Current main is
checked again before pushing; a concurrent merge aborts a stale release before upload.
GitHub serializes publishing and may coalesce rapid pending merges into one release
of the newest main, including the earlier merged changes.

Manual dispatch remains available: `publish: false` validates the next version
without changing main or uploading; `publish: true` explicitly releases reviewed main.
If CI fails, fix it and rerun the workflow or merge the correction. If upload fails
after a successful build, rerun the failed publishing job: existing files may be
skipped only when their digests match the original validated artifact. Different
contents never overwrite a PyPI version. Changes arriving on main during a run must
be released by the newest merge or a fresh manual run, never a force push.

For first publication, sign in to PyPI as the intended owner and register a pending GitHub trusted publisher with project `local-appsec-lab`, owner `aviqentech`, repository `local-appsec-lab`, workflow `publish-pypi.yml`, environment `pypi`. This grants that workflow publishing authority for this project; it is a separate account-security action. Official guidance: https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/ .

Run once with `publish: false` to review validation, then explicitly dispatch with `publish: true` for a production release. Verify the PyPI version, distribution SHA-256 values and a fresh `pip install local-appsec-lab==VERSION`. PyPI versions/files cannot be overwritten. Keep experimental status and platform limits visible. Independent security review is required before presenting this tool as suitable for hostile-code production assessments.


## Published 0.2.0

Version [0.2.0 on PyPI](https://pypi.org/project/local-appsec-lab/0.2.0/) was published
from executable/source revision `2a36621727a0a93ff9956178fa5ea1a89cf0182d` using
[the trusted publishing workflow](https://github.com/aviqentech/local-appsec-lab/actions/runs/40523120905).
The wheel and source archive SHA-256 values match the validated Actions artifacts.
A fresh install directly from PyPI passed CLI version/inspection and all-target skill
install/doctor/uninstall checks. Exact artifact URLs and digests are recorded in
[pypi-release-0.2.0.json](../examples/pypi-release-0.2.0.json).

```sh
python -m pip install local-appsec-lab==0.2.0
```
