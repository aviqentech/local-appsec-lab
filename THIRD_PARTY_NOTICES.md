# Third-party notices

Runtime dependencies retain their upstream licenses: Pydantic (MIT), PyYAML (MIT),
jsonschema (MIT), certifi (MPL-2.0; Mozilla CA bundle), and cvss (LGPL-3.0-or-later).
These are separately installed Python dependencies, not relicensed project source.
See each installed distribution's license files and source for applicable terms.

The Chromium seccomp profile at `src/local_appsec_lab/data/browser-seccomp.json`
is derived from the Apache-2.0 Moby default profile and the Playwright Chromium
sandbox instructions, with a narrow `chroot` syscall allowance for the sandbox.
Upstream: https://github.com/moby/profiles/blob/main/seccomp/default.json and
https://playwright.dev/python/docs/docker . No browser binary is redistributed.

The SARIF schema is from SchemaStore's `sarif-2.1.0.json` under Apache-2.0.
SARIF is an OASIS standard. No scanner/model executable, tool image or advisory
database is included in the source distribution. Semgrep, OSV-Scanner, Trivy,
Playwright, Chromium, Docker and their images/data retain their upstream licenses.
Review those licenses before redistributing prepared binaries, images or databases.
No endorsement by vendors, OWASP, OASIS or model providers is implied.
