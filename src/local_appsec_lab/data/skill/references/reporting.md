# Reporting

Every run produces JSON, Markdown, offline HTML and SARIF 2.1.0. Reports disclose
mode, revision, environment, execution strategy, jobs, measured metrics, findings,
complete selected test inventory and limitations. No source or findings telemetry
is sent. Optional model calls transmit only the selected redacted context after
explicit consent. Review artifacts before sharing; redaction is best effort.
Findings use stable rule/component/source-expression fingerprints. Compare reports
show new/unchanged/changed/reopened findings, absent candidates and coverage changes.
A partial later run never establishes resolution merely by omitting a finding.
