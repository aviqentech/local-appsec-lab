# Agent Roles

- coordinator: architecture, scope, coverage, budgets.
- authentication: authentication, session, csrf.
- authorization: authorization, tenant_isolation.
- api: validation, error_handling, api.
- data_flow: input_data_flow, command_execution, template_rendering, file_upload, server_side_requests.
- business_logic: business_logic.
- frontend: frontend, headers, cors.
- supply_chain: dependencies.
- infrastructure: infrastructure, configuration.
- sensitive_data: sensitive_data, sensitive_logging, cryptography.
- ai_security: ai_security.
- verifier: independent evidence review.
- remediation: minimal fixes, regression.

`ai.strategy: native` automatically invokes installed authenticated host CLIs.
Use `--native-host` and explicit `--allow-model-requests`; set positive model token
and call budgets first. Each specialist, verifier and remediation worker has a
fresh context. Workers have no executable tools and run outside the assessed repo.
The parent owns a versioned knowledge snapshot and append-only verification history.
Native token/cost caps depend on the vendor; usage may be unavailable.

Codex and Claude use their existing trusted login. Cursor/Gemini use dedicated
per-user auth state; select an already authenticated outside-project directory with
`--native-auth-dir` if needed. `--model-key-env NAME` explicitly forwards one chosen
credential. Do not infer credentials from repository config or put keys in YAML.
Gemini individual OAuth was rejected by Google in the measured environment;
supported API/enterprise authentication is needed. Report unavailable hosts honestly.

`ai.strategy: host` exports assignments for a capable orchestrating host. Definitions
in assets/adapters/claude-code and assets/adapters/codex are optional examples;
installers do not alter existing host agent configuration. Imported JSON is an array
of {task_id, repository_fingerprint, findings}; the engine validates against fresh
assignments. Host results cannot grant execution or confirm exploitability.
`ai.strategy: http` uses an explicitly consented HTTPS Chat Completions endpoint,
selected credential, conservative pricing and positive token/cost budgets.
