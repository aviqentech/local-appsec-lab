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
Optional Semgrep/OSV-Scanner/Trivy adapters run offline and have real macOS/Docker
integration tests. Executables/images and fresh data must be provisioned explicitly.
Python AST provenance follows bounded local/imported function summaries; Semgrep
adds supported Python/JS/TS rules. These remain source candidates.

Explicit browser workflows use real Chromium with parent-brokered HTTP, assertion
and hash-only evidence. Stateful workflows support scalar captures, identities and
reserved rollback; a fresh full sequence verifies a violation. Scalar-schema fuzzing
uses a valid control before malformed GET inputs and creates candidates only.
Model adaptive proposals may request at most four new known GET checks in approved
header/CORS/error categories. ZAP execution is not implemented.
