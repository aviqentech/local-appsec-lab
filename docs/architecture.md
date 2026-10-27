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
