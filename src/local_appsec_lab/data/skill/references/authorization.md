# Authorization

Configuration never grants execution permission. --authorize is a fresh acknowledgment
for one run and must carry the `plan_digest` printed by `plan`, so repository
configuration cannot change the backend, image, endpoints or scenarios after review. The record binds canonical root, content fingerprint, config digest,
mode, service identity, literal loopback address, port, categories, budgets, user,
expiry and run ID. Changed source/config and expired approvals are rejected.
Only explicit HTTP loopback literals or validated localhost are accepted. Redirects,
encoded addresses, mapped IPv6, proxies, other ports and private/public destinations
are refused. Existing service identity is a user-approved manifest assertion plus
an HTTP header challenge, not cryptographic process provenance. Its egress cannot
be controlled by this engine; isolate the service yourself before approving it.
