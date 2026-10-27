# Framework support

Recognition covers Python, JavaScript/TypeScript, PHP, JVM, Go, C#, Ruby, Rust,
Dart, HTML/CSS, shell and IaC. Recognition alone does not establish executable
startup, authentication, data flow or tested security coverage.

Supported application commands use Python or Node with explicit runtime prerequisites.
Locked Python-wheel/npm setup is an explicit authorized operation; no lifecycle
scripts, builds or downloads run implicitly. Arbitrary custom builds need a reviewed
preloaded image. Other language runtimes and mobile emulators need a supported
external setup and otherwise fall back to source review.

Constrained generated Compose supports owned application services with disposable
PostgreSQL/Redis, explicit seeds and migrations, preloaded images and Docker Engine
28+ isolated networking. Project Compose files are data, never executed unchanged.
Real Chromium workflows require a prepared Playwright/Python/application image,
explicit synthetic steps and parent-brokered HTTP. See runtime-management.md.
Native macOS is an explicit reviewed-source option; use Docker for untrusted code.
