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

Native host definitions are supplied in assets/adapters/claude-code and assets/adapters/codex.
They must be explicitly selected/delegated by a capable host. Installers do not
alter existing host agent configuration. Host JSON results are an array of
{task_id, repository_fingerprint, findings}; findings follow finding.schema.json.
Use the fingerprint from the exported task. --host-results imports and validates
against freshly generated context. No execution or confirmation permission passes
through host results. No host delegation was end-to-end tested in this release.
