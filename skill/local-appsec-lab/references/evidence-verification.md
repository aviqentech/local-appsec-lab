# Evidence Verification

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
