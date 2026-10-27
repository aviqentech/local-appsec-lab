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


Explicit `setup --authorize --allow-network` provisions hash-pinned public Python
wheels or integrity-pinned npm lockfile packages in a no-network non-root container.
Lifecycle scripts and source builds are disabled. Prepared dependencies are bound
to image/lockfile/content hashes and mounted read-only; missing prerequisites block.
No image is pulled or built implicitly.

`execution.compose_file` selects constrained generated Compose with preloaded
images. Docker Engine 28+ is required for an isolated internal service network.
PostgreSQL/Redis use disposable data and synthetic credentials; explicit `seeds`
and `migrations` run only inside owned resources. Project host mounts, privileges,
external database destinations and env files are refused. Migration containers
and ephemeral scanner/setup leases are recorded before launch for owned recovery.

Browser workflows require Docker with an image containing compatible Playwright,
Chromium, Python and the application runtime. Chromium's sandbox remains enabled;
HTTP is brokered by the parent and bounded by the approved request policy. Only
explicit synthetic mutation paths with DELETE rollback are permitted. Screenshots
are hash-only evidence. Stateful workflows reserve the full sequence and rollback
before any mutation; rollback failure stops further checks.

Native macOS Seatbelt is an explicit reviewed-source option. It cannot block every
numeric same-user process-argument query; host process environment/arguments may
be exposed. Use Docker for untrusted application or scanner code.
