# Validation — 0.2.0, 27 October 2026

## Current local evidence

The expanded suite passed **152 tests, 0 failed, 3 skipped** on macOS arm64,
Python 3.13, Node 24.6.0 and Docker Desktop Engine 29.4.0 (Linux containers).
The three skips select native Linux bubblewrap and native Windows junction/ACL
contracts. They are not successful platform executions. Tests use actual
synthetic fixture source and real local HTTP, rather than mocked application results.

[extended-validation.json](../examples/extended-validation.json) records measured
host/scanner/setup outcomes and the exact skip reasons. Private raw evidence stays
in ignored local state; no OAuth codes, login tokens or model transcripts are published.

| Surface | Actual evidence | Limit |
|---|---|---|
| Codex, Claude, Cursor native workers | Each ran a real specialist, fresh independent verifier and separate remediation process; unsafe SQL identified and parameterized control distinguished | Selected installed versions/accounts; no universal vendor hard token/cost cap; Cursor omitted usage |
| Codex, Claude, Cursor installed skills | Installed copied engine/helper, invoked skill, ran inspect and plan on benign source containing an instruction canary; canary and scan state absent | CLI host invocation; desktop GUI and unrelated host versions not certified |
| Gemini CLI 0.65.0 | OAuth code exchange attempted with user authorization; provider rejected unsupported individual-account client | No successful Gemini model/skill run claimed; API or supported enterprise auth needed |
| Semgrep 1.182.1, OSV-Scanner 2.7.0, Trivy 0.72.0 | Real offline positive/negative controls on macOS and non-root no-network Docker; version/provenance captured | Tested versions only; native Windows adapters not claimed |
| Advisory/data updates | Real live OSV lookup, official PyPI offline archive and checksum-verified fixed-origin Trivy OCI database refresh | Explicit consent; package coordinates leave host; database freshness is time-dependent |
| Locked setup | Actual SHA-pinned Python wheel and npm integrity-lock download/install followed by app import from prepared dependency tree; npm lifecycle canary absent | Wheels/public npm only; no source builds/private registry support |
| Compose/database | Real PostgreSQL seed/query and app routes, explicit isolated migration, secure/vulnerable controls and exact resource removal | Constrained generated Compose, preloaded images, Engine 28+ |
| Browser | Actual sandboxed Chromium, configured DOM assertion, brokered HTTP and hash-only screenshot evidence under a separate UID | Explicit workflow and image prerequisites; no arbitrary visual exploit inference |
| State/fuzz | Real create/capture/actor transition/read/DELETE rollback, fresh verification and secure negative control; valid-before-invalid schema cases | Configured synthetic semantics; fuzz status discrepancies remain candidates |
| Filesystem/cache | POSIX no-follow source reads, custom state exclusion, redaction, forged-cache rejection, source invalidation, detached worker knowledge | Native Windows handles/ACL require native CI; same-user compromised controller remains outside threat model |
| Fix workflow | Prepare without editing, default apply refusal, explicit apply/rescan, hash-drift refusal and rollback | Python debug rewrite/reviewed Python or JSON replacement; runtime regression not invented |

## Isolation finding and resulting default

A real macOS test established that numeric process-argument queries can expose
same-user host metadata/environment despite Seatbelt's named sysctl rules.
Automatic backend selection now chooses Docker, then Linux bubblewrap; macOS is
an explicit reviewed-source-only choice. Its limitation appears in plans/reports.
The test records capability without printing or retaining host process data.

Docker application code was separately tested against the observer's procfs
protocol descriptor and denied. Chromium retains its own sandbox and uses a
separate UID. Tests also exercise scope rejection, host-loopback denial, rollback
reservation/failure, cancellation, bounded subprocess input, cleanup, cache poisoning
and ignored malicious repository instructions. These checks do not replace an
independent external security assessment.

## Cross-platform CI

The repository's native matrix runs Python 3.11/3.13 on Windows, Linux and macOS,
including installer lifecycle and Windows protected-DACL/junction tests. The Linux
container job explicitly builds the runtime and browser images and preloads PostgreSQL.
The platform-capability workflow records unprivileged bubblewrap and a separate
trusted root controller in a disposable runner, without disabling AppArmor or kernel
protections. The Windows engine probe records prerequisites only.

A manually dispatched self-hosted Windows workflow requires the labels `Windows`
and `appsec-linux-containers` and a real local Linux-container engine. It is not run
or reported successful without that machine. Existing Windows hosted source tests
cannot establish native Windows Docker execution.

Current publication CI run links are recorded after the release source is pushed.
Earlier public 0.1.0 results are preserved separately in
[historical validation](validation-0.1.md); their counts do not describe this release.

## Reproduce from a trusted checkout

```sh
python -m pip install '.[dev]'
make lint
python -m pytest -q
docker build -t local-appsec-lab-test:0.1.0 -f tests/compatibility/runtime.Dockerfile tests/compatibility
docker build -t local-appsec-lab-browser:0.2.0 -f tests/compatibility/browser.Dockerfile tests/compatibility
docker pull postgres:17-alpine
APPSEC_TEST_IMAGE=local-appsec-lab-test:0.1.0 APPSEC_TEST_COMPOSE=1 APPSEC_TEST_BROWSER_IMAGE=local-appsec-lab-browser:0.2.0 python -m pytest -q
```

Runtime validation needs permission to invoke the actual OS isolation backend;
nested execution environments may block it. Images/data/model accounts are explicit
prerequisites. Do not bypass a denied boundary or reinterpret a skip as a pass.
