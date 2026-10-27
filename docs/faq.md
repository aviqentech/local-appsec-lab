# Frequently asked questions

## Is this a complete autonomous penetration tester?

No. Version 0.1.0 is an experimental tested core. It combines source candidates, bounded HTTP observations and configured synthetic policy checks. Browser workflows, automatic Compose/database setup, whole-program taint, live advisory lookup and several other requested capabilities remain incomplete. See [requirements status](requirements-status.md).

## Does it work without an AI model or paid subscription?

Yes. The CLI's deterministic workers and verification do not require a model. Optional model requests need separate consent, endpoint configuration and budgets. Real provider integration has not been validated.

## Does installation prove it works in every agent?

No. The installer and copied helper were tested for all targets. Interactive discovery, invocation and native subagent dispatch inside the actual host applications remain unverified. The CLI works independently of an agent application.

## Do Windows and Linux need Docker for source review?

No. Native Python source review and installation passed on Windows and Linux. Application execution uses an OS isolation backend. Windows execution requires Docker with Linux containers and remains unverified on a native Windows host. Linux Docker execution passed; bubblewrap remains experimental after a runner namespace denial.

## Why did Docker fail even though my Node image works normally?

The engine uses a trusted Python HTTP bridge inside the isolated container. Its preloaded image must include Python as well as Node and application dependencies. It does not mount the host virtual environment or `node_modules`, publish ports or fetch missing packages. Use the explicit [demo setup](usage.md#run-the-synthetic-node-demo).

## Will it assess a public URL or my running production service?

Public targets are rejected. The normal workflow starts one reviewed local service in an owned scratch copy. Existing-instance mode has additional manifest/identity requirements and cannot enforce that service's egress; consult the [security model](security-model.md). Use synthetic data and disposable local environments.

## Why does a scan say partial or return 2?

A required advisory snapshot, category, environment or budget may be unavailable. The report discloses blocked and untested work. Partial coverage is not a clean bill of health. Review the report's exact reasons and the [exit-code table](usage.md#exit-codes).

## Does a source finding mean exploitation was proved?

No. Source findings are candidates unless supported by the engine's specific evidence/verification path. A confirmed synthetic boundary result means the configured violation was independently repeated. This is separate from severity and from complete vulnerability coverage.

## Where is my data stored, and can I share it?

Assessment history defaults to `.appsec-lab` inside the project. Keep it ignored by version control. Deterministic review sends no telemetry or findings to a service. Optional model requests can send selected redacted source after consent. Use `report --shareable` and review every artifact before sharing; redaction is best effort.

## Can I delete the environment after installing the skill?

Keep it. The installer records the Python interpreter and depends on its installed packages. If you move/delete it, reinstall the skill from a working environment. Update/uninstall refuses modified or foreign installations; preserve your changes before resolving an ownership refusal.

## Is a package published on PyPI?

These instructions assume source or locally built wheel installation. A registry publication is not claimed. Use this repository's releases and [release process](releasing.md) to verify any future distribution.
