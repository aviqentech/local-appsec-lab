# Troubleshooting

Exit codes: 0 selected work complete; 1 confirmed findings at threshold;
2 partial coverage/budget; 3 invalid configuration/path; 4 authorization/scope;
5 startup failure; 6 dependency failure (reserved for direct adapter failures);
70 unexpected internal error; 130 cancellation. Partial coverage is expected when
no advisory snapshot is supplied or categories cannot execute.
Nested Codex/macOS sandboxes may block sandbox-exec; use source review or an
explicitly permitted sandbox invocation. Never remove isolation to get a test green.
If Docker is stopped, start it yourself and preload reviewed images. Missing Python
or Node dependencies need trusted provisioning; the engine will not implicitly fetch them.
Run clean after interruption. Preserve modified installations; installer refuses
updates/uninstall when ownership hashes do not match. A broken foreign symlink
requires manual review and is deliberately not followed or removed.

Explicit `setup --authorize --allow-network` can provision supported locked public
Python-wheel/npm artifacts. It cannot run arbitrary build or lifecycle scripts.
