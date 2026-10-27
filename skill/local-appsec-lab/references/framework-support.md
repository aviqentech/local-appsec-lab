# Framework Support

Recognition covers Python, JavaScript/TypeScript, PHP, JVM, Go, C#, Ruby, Rust, Dart, HTML/CSS, shell and IaC; see source-repository docs/supported-frameworks.md for detailed recognition.
Execution currently supports a reviewed single-service Python or Node command,
with installed local dependencies or a preloaded container image. No package
scripts, builds, migrations or dependency installation run automatically.
Flask and Node fixtures are exercised on macOS. Compose is inventoried; automatic
multi-service provisioning, emulators, .NET/Java/PHP/Ruby/Go runtime launch and
browser execution are unsupported. Never translate recognition into coverage.
