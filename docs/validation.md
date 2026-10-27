# Validation — 27 October 2026

Validated locally on macOS 26.6.2 arm64, Python 3.13.0 and Node 24.6.0.
The automated suite's exact counts and timing are recorded in
[the JUnit artifact](../examples/test-results.xml). Latest validated suite:
**123 passed, 0 failed, 1 skipped**. Docker Desktop 29.4.0 was explicitly started,
the official Python 3.13 slim image was preloaded, and a trusted test image was
explicitly built with Node and Flask. The skipped case is the native Linux
bubblewrap test. The engine did not download images or install application dependencies.

## Actual application assessments

| Fixture | Services started | Routes tested | HTTP requests | Confirmed | Other findings | Cleanup |
|---|---:|---:|---:|---:|---|---|
| Node API | 1 | 8 | 25 | 1 high cross-user access violation | 1 low informational HTML-header observation | Passed |
| Flask API | 1 | 5 | 19 | 1 high cross-user access violation | None | Passed |

Both assessments used the actual fixture source in macOS Seatbelt scratch copies.
Each vulnerable access-policy result was independently repeated. The secure
cross-user route was not reported as vulnerable. The synthetic negative-control
source fixture generated no findings in the benchmark. App ports closed and owned
scratch directories were removed after scans. CLI verification reproduced the
original Node finding using fresh authorization; details are in
[verification-results.json](../examples/verification-results.json).

Reports remain **partial**, with one advisory-data blocker and five unexecuted
categories in each active sample. This is disclosed coverage, not a clean bill of
health. No model calls, browser workflows or current advisory lookups ran.

Sample reports were generated from those real runs, then exported through the
engine's shareable renderer to generalize local repository/operator metadata.
Finding IDs, states, evidence and measured counts were retained. Original private
reports, diagnostics and generated executable regressions remain in the fixture's
`.appsec-lab/runs` and `.appsec-lab/reports` directories.

## Validation performed

- Editable package installation, CLI help/doctor/config validation and source-only scan.
- Real Node/Flask startup, readiness, HTTP, independent reproduction and shutdown.
- Invalid/expired approvals, changed source/config/mode/run and workspace rejection.
- Public/private/metadata/encoded/mapped-address rejection; DNS pinning; redirects;
  proxy-environment rejection; request/body/response budgets and per-request expiry.
- OS-enforced denial of a synthetic canary outside scratch and an unapproved local
  egress port. The exact root-directory literal was proven non-recursive.
- Passive verification gates, model rule namespacing, rollback reservation/failure,
  host Docker environment separation and surviving-child cleanup regressions.
- CLI SIGINT cancellation, cleanup, occupied-port and unowned-resource protection.
- Distinct worker scheduling, concurrency, retries, async timeout/cancellation,
  bounded queues and mocked model contract/budget accounting.
- JSON report and SARIF validation against the published schemas; HTML escaping and
  offline generation. Browser file-URL policy blocked visual preview, so visual
  browser rendering and interactive filter behavior remain unverified.
- Global installation in temporary homes, per-project installation, all four hosts,
  paths with spaces, repeated installation/update/doctor/uninstall, modified/foreign
  install preservation and broken-symlink refusal.
- Wheel and source archive builds. Their contents exclude private `.appsec-lab`
  state. A wheel was installed into an unrelated temporary directory; import,
  four-host skill installation, doctor and uninstall passed without source paths.
- Ruff lint/format and Agent Skill frontmatter validation.

## Compatibility evidence

| Surface | Actually exercised | Unverified |
|---|---|---|
| macOS | CLI, installer, Node/Flask Seatbelt runtime, safety suite; native CI on Python 3.11/3.13; local arm64 Docker assessments | Hostile-code isolation beyond documented limits |
| Linux | Native source/installer CI on Python 3.11/3.13, stdlib Docker bridge, real Node/Flask Docker assessments | Bubblewrap runtime: runner denied namespace loopback setup |
| Windows | Native source/installer CI on Python 3.11/3.13, PowerShell wrapper help entry point | Docker Desktop Linux-container execution; interactive host invocation |
| Claude Code | Installation and definition files | Interactive skill discovery/invocation and native dispatch |
| Codex | Installation and definition files; independent read-only skill forward test | Installed skill discovery and native custom-agent dispatch |
| Cursor | Installation paths and portable skill files | Interactive skill discovery/invocation |
| Gemini CLI | Installation paths and portable skill files | Interactive skill discovery/invocation |
| HTTP model backend | Mocked protocol, scopes and budget accounting | Real model API, provider billing/usage reconciliation |
| Optional scanners | Normalization and absence/failure handling | Real Semgrep/OSV/Trivy successful scans/databases |

### Remote compatibility runs

These completed pre-publication runs used a private test repository. Their
downloaded JUnit artifacts were inspected and summarized below. Historical source
identity is retained in the JSON summary; these are not runs in the publication
repository.

| Job | Passed | Failed/errors | Skipped |
|---|---:|---:|---:|
| Windows, Python 3.11 | 110 | 0 | 14 |
| Windows, Python 3.13 | 110 | 0 | 14 |
| Linux, Python 3.11 | 111 | 0 | 13 |
| Linux, Python 3.13 | 111 | 0 | 13 |
| macOS, Python 3.11 | 119 | 0 | 5 |
| macOS, Python 3.13 | 119 | 0 | 5 |
| Separate Linux container job | 3 | 0 | 1 |

Account-specific private CI links were removed during the ownership migration.
The measured counts and skip reasons are retained in
[compatibility-results.json](../examples/compatibility-results.json). Public CI
results should be checked in this repository's Actions tab after publication;
historical private CI is not represented as public CI.
Windows and Linux skip the nine macOS-specific runtime tests. The three additional
container assessments run in their own Linux job with the explicitly built image;
they are skipped in the native matrix. Windows and macOS runners lack a usable
cached Linux Docker image. The bubblewrap test is selected only in the Linux runtime
job and was skipped with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
No namespace/security setting was weakened to make it pass.

The Linux container job actually starts the Node and Flask fixtures, independently
reproduces the vulnerable owner/actor result, verifies the secure route is not
reported, checks host-loopback denial, and confirms container and scratch removal.
The same three assessments plus the stdlib bridge passed locally through Docker
Desktop's arm64 Linux engine. This establishes the Linux container behavior;
it does not establish Docker Desktop behavior on a native Windows host.

Cross-platform testing found and fixed Docker cleanup signaling after container
removal and case differences in Docker's missing-object diagnostics. Native tests
exercise source discovery/scanning, authorization, reports, CLI behavior and
installation/update/doctor/uninstall for all skill targets in temporary directories.
The PowerShell wrapper's help entry point passed on both Windows Python versions;
actual skill discovery/invocation inside the four agent applications remains untested.

To repeat the Linux container assessments from a trusted checkout:

```sh
docker build -t local-appsec-lab-test:0.1.0 -f tests/compatibility/runtime.Dockerfile tests/compatibility
APPSEC_TEST_IMAGE=local-appsec-lab-test:0.1.0 python -m pytest tests/compatibility -q
```

Codex's ordinary nested sandbox cannot apply another Seatbelt profile. Runtime
validation used explicitly permitted executions of the same restrictive profile;
isolation was not disabled. macOS aggregate memory/process/storage limits remain
monitored rather than hard cgroup limits. Detached daemons are unsupported; crash
recovery refuses resources whose ownership can no longer be established.

This is an experimental tested core. The full master specification is incomplete;
see [requirements-status.md](requirements-status.md). A responsible public release
still needs an independent security review, Windows Docker/bubblewrap/interactive
host validation, a private disclosure contact, and name/package checks.
