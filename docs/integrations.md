# Integrations

Skill discovery, explicit invocation, external CLI execution, native host subagent
delegation and programmatic model calls are separate capabilities. Installing a
SKILL.md does not automatically run a host agent. Claude Markdown agent definitions
and current Codex standalone TOML agent examples are shipped under adapters/;
select them explicitly only on compatible installed versions. Older Codex versions
can use the skill with sequential contextual review. Cursor/Gemini use shared skill
instructions without invented delegation APIs. The deterministic runner works alone.

Official references checked during implementation:
- [Agent Skills specification](https://agentskills.io/specification)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Codex skills](https://developers.openai.com/codex/skills/)
- [Codex subagents](https://developers.openai.com/codex/subagents/)
- [Cursor skills](https://cursor.com/docs/skills)
- [Gemini CLI skills](https://geminicli.com/docs/cli/skills/)
- [Docker run](https://docs.docker.com/engine/containers/run/)
- [Semgrep CLI](https://docs.semgrep.dev/cli-reference)
- [OSV-Scanner source scanning](https://google.github.io/osv-scanner/usage/scan-source)
- [Trivy filesystem](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/)
- [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/)
- [Playwright networking](https://playwright.dev/python/docs/network)

Optional adapter contracts target Semgrep 1.x, OSV-Scanner 2.x and Trivy 0.60+.
These are intended version families, not a tested compatibility guarantee. Every
actual adapter run records tool version or failure. Tools must already exist; offline
databases must be provisioned. Playwright/Chromium workflows are implemented in a prepared Docker image. ZAP remains a methodology reference; no ZAP adapter is claimed.

Methodology references: [WSTG](https://wstg.owasp.org/),
[ASVS](https://asvs.owasp.org/), [CWE](https://cwe.mitre.org/),
[Cheat Sheets](https://cheatsheetseries.owasp.org/), [OSV](https://osv.dev/),
[OpenSSF](https://openssf.org/). These do not imply certification or full coverage.


## Measured native integration versions

Real specialist, fresh verifier and remediation calls were exercised using the
installed Codex CLI, Claude Code 2.1.311 and Cursor agent 2026.10.22. Gemini CLI
0.65.0 rejected the individual-account OAuth client at Google's token/service
exchange. Do not equate a packaged adapter with a successful Gemini model test.
Semgrep 1.182.1, OSV-Scanner 2.7.0 and Trivy 0.72.0 passed real offline positive
and negative controls on macOS and Docker. See [advanced setup](advanced-usage.md)
and [validation](validation.md) for auth, data, resource and platform boundaries.
