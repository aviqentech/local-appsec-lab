# Security policy

## Supported versions and scope

Version 0.1.x receives best-effort security fixes; no response SLA is promised. This experimental tool executes application code and is not ready for hostile-code production use. Read the [security model](docs/security-model.md) and [coverage limits](docs/requirements-status.md). Do not bypass isolation or authorization to work around a failure.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/aviqentech/local-appsec-lab/security/advisories/new) for a suspected vulnerability in Local AppSec Lab. Include the affected version, OS/runtime, smallest synthetic reproduction, expected behavior and impact. Redact credentials, personal data, private application source and assessment histories.

Do not put sensitive vulnerability details in public issues. If GitHub says private reporting is unavailable, request a confidential contact from the maintainer without disclosing the vulnerability publicly. No security email address is assumed.

For an ordinary non-sensitive defect, use [GitHub Issues](https://github.com/aviqentech/local-appsec-lab/issues). Findings generated against your own application belong to that application's security process; they are not automatically vulnerabilities in this tool.

## Handling and disclosure

Maintainers assess reports using synthetic data, discuss remediation privately, and coordinate a disclosure date with the reporter when possible. Stop using an affected feature until a fix has been reviewed. Avoid publishing exploit details, secrets or a reporter's identity without agreement. An experimental release and passing tests do not replace an independent security review.
