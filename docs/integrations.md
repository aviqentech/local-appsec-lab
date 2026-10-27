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
databases must be provisioned. ZAP and Playwright are methodology references only.

Methodology references: [WSTG](https://wstg.owasp.org/),
[ASVS](https://asvs.owasp.org/), [CWE](https://cwe.mitre.org/),
[Cheat Sheets](https://cheatsheetseries.owasp.org/), [OSV](https://osv.dev/),
[OpenSSF](https://openssf.org/). These do not imply certification or full coverage.
