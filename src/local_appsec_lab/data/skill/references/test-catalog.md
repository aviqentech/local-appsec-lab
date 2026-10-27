# Test Catalog

Implemented source checks include expression-built SQL, shell=True/os.system,
unsafe deserialization/eval, token verification disabled, weak digests, debug mode,
direct HTML sinks, secret patterns, sensitive logging, wildcard CORS, CSRF disabled,
request-derived outbound URLs, dynamic templates, upload filenames, privileged/root
container config and model-output execution. Each is a candidate, with limitations.
Dynamic checks inspect HTML defense headers, cookie attributes and CORS reflection.
Explicit synthetic scenarios test authentication, authorization, tenant isolation,
validation and workflow expectations; mutations require disposable/synthetic flags
and a configured rollback. Bounded read-only malformed inputs are exposed through
the library helper. The engine does not infer state machines or upload payloads.
Optional Semgrep/OSV-Scanner/Trivy adapters are offline, opt-in, and unverified with
real tool installations. ZAP/browser integrations are not implemented.
