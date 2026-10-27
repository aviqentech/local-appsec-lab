# Security Model

Configuration never grants execution permission. --authorize is a fresh acknowledgment
for one run. The record binds canonical root, content fingerprint, config digest,
mode, service identity, literal loopback address, port, categories, budgets, user,
expiry and run ID. Changed source/config and expired approvals are rejected.
Only explicit HTTP loopback literals or validated localhost are accepted. Redirects,
encoded addresses, mapped IPv6, proxies, other ports and private/public destinations
are refused. Existing service identity is a user-approved manifest assertion plus
an HTTP header challenge, not cryptographic process provenance. Its egress cannot
be controlled by this engine; isolate the service yourself before approving it.

The engine copies bounded non-symlink source files into owned scratch, excludes
.env/private-key files and dependency directories, sanitizes the environment,
starts reviewed code, verifies readiness and tracks its process group/container.
macOS Seatbelt denies other filesystem writes and network destinations, permits
only the approved 127.0.0.1 port, verifies listener process-group ownership and
monitors RSS, process count and scratch size. CPU/file/core limits use rlimits.
This is weaker than cgroup resource isolation. Daemonizing programs are unsupported.
Docker uses no network, read-only source/root, non-root UID, dropped capabilities,
no-new-privileges, CPU/memory/PID limits and a bounded tmpfs. A trusted JSON bridge
makes local HTTP requests inside the network namespace. No host ports are exposed.
Docker images must contain Python and the requested runtime/dependencies already.
Linux bubblewrap is experimental; the CI namespace probe was blocked by runner
permissions. Windows application execution requires Docker's Linux-container
engine and remains unverified on a native Windows host. Native source review and
installation passed on Windows and Linux; real Linux Docker assessments passed.
Cleanup handles owned live resources; crash recovery verifies process identity
before signalling. Report and event history remain private in .appsec-lab.

Threat model: repository instructions/config are data; configured executables are
untrusted. The CLI operator and installed engine/toolchain are trusted. Protect the
engine environment and .appsec-lab state against concurrent tampering. This release
does not provide race-proof openat2 traversal on every platform, cryptographic
approval storage, per-tenant hostile-code VM isolation or guaranteed secret detection.
macOS permits system toolchain reads; review the profile before hostile execution.
Security-critical decisions are enforced in Python/OS policy rather than prompts.
No production/network reconnaissance, host compromise, credential extraction,
malicious uploads, destructive exploit or lateral-movement features are included.

Application environment variables cannot change Docker's host/context/config. The
host Docker CLI uses a separately selected local socket/named pipe, pinned for
launch and cleanup. Remote daemons are rejected. Known credential directories,
private keys, package-registry credential files and existing database files are
excluded from runtime copies. Binary source assets retain their original bytes.
Independent source review found passive-verification escalation, rollback-budget,
Docker environment and orphan-child cleanup bugs during development; regression
tests now cover their fixes. This is not a substitute for an external security audit.
