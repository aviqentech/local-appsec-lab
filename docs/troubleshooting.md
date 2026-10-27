# Troubleshooting

Start with `appsec-lab --version`, `appsec-lab doctor`, and `appsec-lab config validate --project /path/to/application`. Keep the CLI's JSON error, exit code and sanitized platform/version details when reporting a defect. Never include tokens, private reports, production data or unredacted source in public issues.

| Symptom | What to check |
|---|---|
| `appsec-lab` command missing | Use the environment executable, or `python -m local_appsec_lab`; confirm you installed into that interpreter |
| Python version rejected | Python 3.11+ is required; verify the exact interpreter used for the venv |
| Windows activation is blocked | Activation is optional. Use `.\.venv\Scripts\python.exe` and `.\.venv\Scripts\appsec-lab.exe` directly |
| Linux cannot create a venv | Install your distribution's Python venv support through its normal package manager, then recreate the environment |
| No isolation backend | Source review still works. Configure a working OS backend before application execution |
| Docker stopped / image absent | Start the local Linux-container engine and explicitly preload/build the reviewed image |
| Docker Node/Flask startup fails | Image must contain Python for the bridge and the application's runtime/dependencies; use the documented trusted demo image |
| Docker path rejected | Bind paths containing commas are unsupported; use a different project location |
| Port occupied on macOS | Select an unused port in configuration; the engine will not assess or terminate an unrelated listener |
| Health check times out | Check the selected service directory, command, port and `/health` response; missing dependencies are not installed implicitly |
| Permission/namespace denial | Nested Seatbelt and restricted Linux user/network namespaces can block execution. Use source review or a supported backend; preserve isolation |
| Scan returns `1` | A confirmed finding meets the severity threshold; the intentionally vulnerable fixture should do this |
| Scan returns `2` / partial | Read blocked/untested checks; missing advisory data, unsupported categories and budget limits are disclosed coverage gaps |
| Execution consent rejected | Use fresh `--authorize` after reviewing current source/config/scope; a config file cannot grant consent |
| Skill appears installed but is unavailable | Check the intended host path and host's current skill discovery settings; interactive invocation has not been validated |
| Installed helper fails after moving venv | Reinstall from a working Python environment; the interpreter path is recorded at install time |
| Update/uninstall refuses files | Preserve your edits and inspect the installation; ownership hashes deliberately protect modified/foreign trees |
| Broken skill symlink | Review its target manually; the installer deliberately refuses it |
| Old runtime after interruption | Run `appsec-lab clean` with the same project/config; ownership must be established before deletion/signaling |

## Inspect private diagnostics

The scan's JSON gives its run ID and report paths. Default history is beneath the project's `.appsec-lab`; runtime diagnostics and ownership manifests are run-specific. They may contain private paths and bounded application logs. Review/redact before sharing, and keep the directory ignored by version control.

`clean` stops owned resources and removes their scratch; it preserves assessment history. It refuses resources whose ownership/identity no longer matches. Do not delete unrelated containers or processes to bypass that refusal. Detached daemons and hostile concurrent state changes are unsupported.

## Optional integrations

Model requests require separate consent and nonzero budgets. Scanner tools must be installed and supplied with the intended offline data. A missing integration is a coverage blocker, not evidence of safety. Codex/Claude/Cursor native workers and all three offline scanners have real integration evidence; see [validation](validation.md). Gemini individual OAuth was rejected by Google. Keep model login state outside the assessed project and use supported authentication.

For a reproducible bug, use the smallest synthetic fixture possible and include only non-sensitive commands plus the [exit code](usage.md#exit-codes). Use [private reporting](../SECURITY.md) for suspected vulnerabilities in this tool.
