# Changelog

## Unreleased

- Refine discovery with validated, grouped and typed URL references, binary-safe
  text analysis, explained review priorities, static HTML route candidates,
  page/resource relationships and Apache/GitHub Actions context. Include
  `.htaccess` source in specialist review assignments.

## 0.2.1 — 2026-10-27

Released from PR #2, source `30a5160e0444cf8c10958d4b616e1c941c2d4c72`.

- Automatically publish a new patch release after merged-main PRs pass CI, with
  synchronized versions, immutable artifact checks and fresh PyPI installation tests.

- `scan`/`verify --authorize` now requires `--plan-digest` from `plan`; a
  repository config changed after review (backend, image, model endpoint) is refused.
- The repository fingerprint hashes raw bytes, so binary file changes invalidate approvals.
- Bubblewrap mounts the source copy read-only after the scratch bind, and the macOS
  profile denies writes to it.
- Request paths with raw spaces or DEL are scope errors; repeated response headers
  (each `Set-Cookie`) are kept, and cookie flags must hold for every cookie.
- Symlinks above an operator-chosen project or home directory (such as macOS `/tmp`)
  no longer break reads; symlinks inside the project are still refused.

## 0.2.0 — 2026-10-27

Published to PyPI using the AVIQEN GitHub Trusted Publisher; verified registry
artifact digests, clean package installation and all-target skill lifecycle.

Added real native specialist/verifier/remediation orchestration, shared knowledge,
bounded adaptive proposals, Python interprocedural provenance, sealed persistent
analysis caching, live OSV and offline scanner-data refresh, and tested offline
Semgrep/OSV/Trivy isolation on macOS and Docker. Added locked Python/npm setup,
constrained multi-service Compose with disposable databases/seeds/migrations,
sandboxed Chromium, stateful synthetic workflows, scalar-schema fuzzing, explicit
CVSS v4 vectors and separately authorized patch preparation/apply/rollback.

Hardened source traversal, Windows private artifact permissions, observer IPC,
macOS process metadata access, bounded subprocess input/output, startup config
inheritance, output-directory exclusions and crash recovery leases. Expanded real
integration and negative-control tests, schemas, skill guidance and installation docs.
Gemini authentication, native Windows Docker and provider/platform prerequisites
remain explicitly distinguished from successful tests.

## 0.1.0 — 2026-10-27

Initial experimental engine, portable skill, explicit approvals, bounded runtime,
source candidates, synthetic dynamic verification, local reports, installer and
fixture test suite. Incomplete requirements and platform limits are documented.

Publication preparation: AVIQEN repository metadata, account-neutral historical
validation artifacts, expanded cross-platform installation/usage/configuration and
maintenance documentation, explicit Docker demo setup, and a private reporting
policy. Historical private CI is distinguished from new publication-repository CI.
