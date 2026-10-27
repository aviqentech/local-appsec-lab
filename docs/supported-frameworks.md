# Supported Frameworks

Languages recognized: JavaScript, TypeScript, Python, PHP, Java, Kotlin, Go, C#,
Ruby, Rust, Dart, HTML/CSS, shell, Terraform and YAML. Framework evidence covers
Next.js, React, Vite, Vue, Nuxt, Angular, Express, NestJS, Fastify, SvelteKit, Django,
Flask, FastAPI, Starlette, Laravel, Symfony, WordPress, Spring Boot, ASP.NET Core,
Rails, Go HTTP and Flutter. Manifest recognition is heuristic, not full semantic support.
Package-manager lockfiles include npm/pnpm/Yarn/Bun, pip/Poetry/uv/pipenv,
Composer/Maven/Gradle/Cargo/Go/Bundler/NuGet/Flutter pub. Exact dependency extraction
currently covers npm package-lock, pinned requirements and uv lock entries; optional
OSV-Scanner/Trivy extend it. Mobile projects never launch as HTTP apps automatically.
Monorepos expose discovered services and dependency edges; select one reviewed
service. Compose, external databases/caches/queues and auto-builds are inventoried,
not automatically provisioned. Actual tested fixtures: see docs/validation.md.
