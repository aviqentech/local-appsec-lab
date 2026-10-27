# Requirements status — 0.2.0

The requested architecture is implemented for the supported bounded workflows below. This remains an experimental security tool. Acceptance of a particular application requires its own reviewed configuration and observed coverage; universal platform or framework compatibility is not established.

| Requested area | Implementation | Boundary |
|---|---|---|
| Portable skill and installer | Managed install/update/doctor/uninstall for Claude, Codex, Cursor, Gemini and generic skills; bundled engine/helper/schema | Host versions and discovery policies vary; installation is distinct from invocation |
| CLI and repository understanding | Source/dependency/route/service inventory, config validation, inspect/plan/scan/verify/compare/report/clean | Static recognition is not proof of runtime authentication or universal launch |
| Automatic specialist agents | Native authenticated CLI or HTTPS workers, distinct role tasks, concurrency/cancellation, shared versioned knowledge, fresh verifier and remediation calls | Native host usage reporting varies; no universal hard vendor token/cost cap |
| Application setup | Hash-pinned Python wheels and integrity-pinned npm packages; no-network installation, no lifecycle scripts or source builds | Public registries only; custom builds/private registries need an explicitly prepared image |
| Multi-service runtime | Generated constrained Compose, internal isolated network, PostgreSQL/Redis, synthetic credentials, explicit seed/migration, owned resource cleanup | Does not execute arbitrary project Compose semantics; Docker Engine 28+ and preloaded images required |
| Browser workflows | Real sandboxed Chromium, parent-brokered HTTP, controlled selectors/navigation, independent browser UID, hash-only screenshot evidence | Explicit synthetic workflows; no visual vulnerability inference or arbitrary browser automation |
| Data-flow analysis | Bounded Python AST interprocedural summaries and source-to-sink provenance; offline Semgrep Python/JS/TS checks | Conservative candidates, not complete whole-program taint proof |
| Active security testing | Owner/actor controls, stateful capture/assertion/rollback workflows, bounded scalar-schema fuzz cases, parent-gated adaptive GET proposals | No inferred business policy, destructive payloads, remote testing or automated universal exploit chains |
| Current security intelligence | Explicit live OSV exact-coordinate lookup, OSV offline ecosystem and Trivy OCI database refresh, freshness policy | Network consent required; no guarantee that every vulnerability is known |
| Scanner integrations | Offline Semgrep, OSV-Scanner, Trivy; normalization, tool/version provenance, isolation and output budgets | Tested versions documented; ZAP is a methodology reference rather than an implemented adapter |
| Persistent analysis cache | Source/analyzer invalidation, HMAC seal with a trusted key outside target, bounded eviction | No cached AI verdict or runtime confirmation; unavailable key causes recomputation |
| Severity and remediation | Explicit CVSS v4 calculation, source/framework-aware guidance, AI recommendations, prepare/apply/rollback patch workflow | No invented CVSS metrics; automatic rewrite limited to Python debug mode, reviewed Python/JSON replacements otherwise |
| Evidence and reports | Independent runtime repetition or fresh source review; disagreement preserved; schema-valid JSON/SARIF, HTML/Markdown, histories and comparison | Source patterns and status-only fuzz results cannot become exploitation confirmations |
| Safety and filesystem handling | Approval/scope/budgets, no implicit network/install, POSIX descriptor traversal, Windows reparse-safe handles/private DACL, OS isolation, recovery leases | Trusted controller/toolchain; resource enforcement differs by OS; requires independent external security review |

## Verification still requiring external prerequisites

- Gemini real model integration: Google rejected the tested individual-account client. An API key or supported enterprise authentication is needed.
- Native Windows Docker: requires a Windows machine with a local Linux-container engine. Hosted native source tests do not establish this capability.
- Linux bubblewrap: unprivileged namespaces were blocked on the original hosted runner. A separate controlled capability test records its actual outcome without disabling host protections.
- Generic HTTPS model endpoint: strict contract tests exist; a real endpoint and explicitly selected credential are needed for provider validation.

Current evidence, including installed-skill tests, is maintained in [validation](validation.md). Unsupported cases produce blocked or untested coverage instead of fabricated success.
