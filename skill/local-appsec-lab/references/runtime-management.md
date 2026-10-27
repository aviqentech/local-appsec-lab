# Runtime Management

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
Linux bubblewrap is experimental and unverified; Windows requires Docker.
Cleanup handles owned live resources; crash recovery verifies process identity
before signalling. Report and event history remain private in .appsec-lab.
