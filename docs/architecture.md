# Architecture

The Python engine owns configuration, approval, scope, runtime, scanner scheduling,
verification, evidence and reporting. Version 1 JSON schemas are bundled under
schemas/. Workers return (findings, checks), never shell commands. The coordinator
writes append-only SQLite events and atomic run snapshots. Run jobs record role,
strategy, duration, attempts and errors. The independent deterministic verifier
reissues synthetic owner/actor requests and records its own observation.
The optional HTTP backend uses an OpenAI-compatible Chat Completions endpoint;
no shell or HTTP tools are exposed to model output. Model findings are scoped to
assigned files and forced to candidate. All provider responses remain untrusted.


Interfaces: discovery.inspect -> architecture dictionary; scanners -> Finding/Check;
Runtime.start -> scoped Client; Scheduler.run -> role-indexed results; verifier ->
Finding with append-only conclusions; RunStore -> immutable events + snapshots;
reporting.render -> output paths. Pydantic schemas and schema_version=1 provide
versioned contracts. No fake model or scanner result replaces production code.


The source phase populates parent-owned typed SharedKnowledge with immutable event
history. Relevant specialist contexts include architecture, routes and existing
finding references. Native providers invoke fresh no-tools host processes in trusted
empty workspaces outside the target. HTTP providers use the same structured review,
verification and remediation contract. Worker output is untrusted; the parent checks
categories, source spans, exact evidence, request proposals and final finding states.

The runtime layer supports single-service isolation or constrained generated Compose.
A non-dumpable Linux observer owns the HTTP protocol; target processes cannot open
its procfs descriptors. Chromium uses a separate UID and routes HTTP through the
parent's scoped Client. Stateful tests reserve rollback, and ephemeral containers
have recorded leases before launch. Dependencies and databases are explicit stages.
Deterministic caching uses source/analyzer fingerprints and a trusted external HMAC
key; AI verdicts and runtime confirmations are never cached.
