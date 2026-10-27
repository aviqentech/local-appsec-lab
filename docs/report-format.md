# Report Format

Every run produces JSON, Markdown, offline HTML and SARIF 2.1.0. Reports disclose
mode, revision, environment, execution strategy, jobs, measured metrics, findings,
complete selected test inventory and limitations. No source or findings telemetry
is sent. Optional model calls transmit only the selected redacted context after
explicit consent. Review artifacts before sharing; redaction is best effort.
Findings use stable rule/component/source-expression fingerprints. Compare reports
show new/unchanged/changed/reopened findings, absent candidates and coverage changes.
A partial later run never establishes resolution merely by omitting a finding.

candidate: source or response hypothesis needing contextual evidence.
confirmed: a configured synthetic boundary violation reproduced independently.
not_reproduced: fresh behavior/source no longer matches; do not auto-close.
false_positive: evidence is invalid, for example a nonexistent source location.
informational: directly observed defense-in-depth/configuration detail.
blocked: a required environment, budget or approval is unavailable.
not_tested: the check did not execute.

Source evidence includes path, lines, redacted excerpt and content hash. Dynamic
evidence contains only status, body size/hash, synthetic marker presence and selected
security headers; response bodies and credentials are not retained. The verifier
preserves prior reviewer state and its own repeated observation. AI verification
must be labelled separately from deterministic verification. Candidate severity
is potential impact, separate from confidence; no CVSS vectors are invented.

`appsec-lab report --shareable` generalizes repository/operator metadata while retaining findings and evidence. Review artifacts before sharing; this is not a guarantee that arbitrary source-derived content contains no sensitive data.
