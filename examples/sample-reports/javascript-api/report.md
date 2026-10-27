# Local AppSec Lab assessment

Run: deb35e4c711542dca7b342d320c47045 · Mode: local-active · Status: **partial**

Repository: /assessed-project
Revision: unversioned
Started: 2026-10-27T07:30:49.279308+00:00 · Duration: 2.72s
Execution strategy: deterministic-workers

## Measured results

- source\_files\_inspected: 5
- dependencies\_identified: 0
- services\_identified: 1
- services\_started: 1
- routes\_discovered: 8
- routes\_tested: 8
- http\_requests: 25
- browser\_workflows: 0
- dynamic\_checks\_completed: 16
- worker\_assignments\_completed: 10
- candidate\_findings: 0
- confirmed\_findings: 1
- false\_positives: 0
- blocked\_checks: 1
- not\_tested\_checks: 5
- runtime\_startup\_failed: False
- cleanup\_completed: True
- model\_tokens\_reserved: 0
- model\_cost\_upper\_bound\_usd: 0

## Findings

### Browser defense headers absent

LAB-39965a8c6a50c56e · low potential severity · informational · confidence: high

Location: server.js:17
Rule: response-headers · no CWE mapping

An HTML response omitted common browser defense headers.

Root cause: Exact source-level cause is not established by the available evidence.
Expected: Set a suitable CSP and X-Content-Type-Options: nosniff.
Observed: Missing: content-security-policy
Severity rationale: Missing browser defense in depth; no script injection is established.

Evidence:
```json
[
  {
    "status": 200,
    "body_sha256": "91869435dd35d3008460ba74c9efaf2fee49a50c12da9de9d27cdb374f4926b6",
    "body_bytes": 79,
    "truncated": false,
    "marker_present": false,
    "security_headers": {
      "content-type": "text/html",
      "x-content-type-options": "nosniff"
    }
  }
]
```
Verification:
```json
[
  {
    "reviewer": "independent-deterministic-verifier",
    "timestamp": "2026-10-27T07:30:51.727544+00:00",
    "previous_state": "informational",
    "conclusion": "Source location exists; applicability/reachability requires contextual review",
    "source_sha256": "4bebe2d69e94c2cef027e1ee37706a86e53dc18a36ffdf9ef4a4a6a008ca8402"
  }
]
```
Remediation: Apply headers at the application or trusted proxy; test compatibility.
Regression: 
Limitations: Deployment reverse-proxy headers may differ.; Source reference identifies the route declaration/dispatch; it is not a complete execution-path trace.

### Synthetic access policy violated: vulnerable-cross-user

LAB-b700cb9bdca155b8 · high potential severity · confirmed · confidence: high

Location: server.js:14
Rule: boundary:vulnerable-cross-user · CWE-862

The owner baseline succeeded and the disallowed synthetic request received an unexpected response.

Root cause: Exact source-level cause is not established by the available evidence.
Expected: Actor response status in \[401, 403, 404\]; protected record inaccessible.
Observed: Actor received the configured synthetic resource or disallowed response.
Severity rationale: The configured lower-trust synthetic actor received the prohibited fixture response.

Evidence:
```json
[
  {
    "test_id": "vulnerable-cross-user",
    "category": "authorization",
    "method": "GET",
    "path": "/records/vulnerable/42",
    "timestamp": "2026-10-27T07:30:51.073197+00:00",
    "owner": {
      "status": 200,
      "body_sha256": "b4393615868dacc38e3eca28bce69ffedef145a2d1df6a0a702f8d592e24f3b1",
      "body_bytes": 52,
      "truncated": false,
      "marker_present": true,
      "security_headers": {
        "content-type": "application/json",
        "x-content-type-options": "nosniff"
      }
    },
    "actor": {
      "status": 200,
      "body_sha256": "b4393615868dacc38e3eca28bce69ffedef145a2d1df6a0a702f8d592e24f3b1",
      "body_bytes": 52,
      "truncated": false,
      "marker_present": true,
      "security_headers": {
        "content-type": "application/json",
        "x-content-type-options": "nosniff"
      }
    },
    "owner_precondition": true,
    "expected_status": [
      401,
      403,
      404
    ],
    "violation": true,
    "actor_identity": "configured-synthetic-actor",
    "duration_seconds": 0.2191947909996088,
    "limitations": "Expected policy and fixture ownership are supplied by the developer."
  }
]
```
Verification:
```json
[
  {
    "reviewer": "independent-deterministic-verifier",
    "timestamp": "2026-10-27T07:30:51.728049+00:00",
    "previous_state": "candidate",
    "conclusion": "confirmed",
    "new_observation": {
      "test_id": "vulnerable-cross-user",
      "category": "authorization",
      "method": "GET",
      "path": "/records/vulnerable/42",
      "timestamp": "2026-10-27T07:30:51.939459+00:00",
      "owner": {
        "status": 200,
        "body_sha256": "b4393615868dacc38e3eca28bce69ffedef145a2d1df6a0a702f8d592e24f3b1",
        "body_bytes": 52,
        "truncated": false,
        "marker_present": true,
        "security_headers": {
          "content-type": "application/json",
          "x-content-type-options": "nosniff"
        }
      },
      "actor": {
        "status": 200,
        "body_sha256": "b4393615868dacc38e3eca28bce69ffedef145a2d1df6a0a702f8d592e24f3b1",
        "body_bytes": 52,
        "truncated": false,
        "marker_present": true,
        "security_headers": {
          "content-type": "application/json",
          "x-content-type-options": "nosniff"
        }
      },
      "owner_precondition": true,
      "expected_status": [
        401,
        403,
        404
      ],
      "violation": true,
      "actor_identity": "configured-synthetic-actor",
      "duration_seconds": 0.211418250000861,
      "limitations": "Expected policy and fixture ownership are supplied by the developer."
    }
  }
]
```
Remediation: Enforce the configured ownership/role/input policy at the server-side resource boundary.
Regression: Run \`appsec-lab verify --finding &lt;id&gt; --authorize\` after fixing scenario vulnerable-cross-user; actor must be denied.
Limitations: Conclusion depends on the explicitly configured synthetic users, records and expected policy.; Source reference identifies the route declaration/dispatch; it is not a complete execution-path trace.

## Coverage

| Test | Category | Status | Target | Reason |
|---|---|---|---|---|
| source:sql-construction | input\_data\_flow | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:shell-command | command\_execution | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:unsafe-deserialization | input\_data\_flow | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:dynamic-eval | input\_data\_flow | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:jwt-no-verify | authentication | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:weak-crypto | cryptography | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:debug-mode | configuration | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:unsafe-html | frontend | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:potential-secret | sensitive\_data | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:sensitive-logging | sensitive\_logging | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:cors-wildcard | cors | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:csrf-disabled | csrf | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:ssrf-interface | server\_side\_requests | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:unsafe-template | template\_rendering | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:upload-name | file\_upload | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:container-root | infrastructure | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:privileged-container | infrastructure | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| source:ai-tool-eval | ai\_security | completed | repository | Bounded syntactic rule; no whole-program data-flow proof |
| dependency-advisories | dependencies | blocked | repository | No authorized offline advisory snapshot configured; no current vulnerability claims |
| runtime-health | runtime | completed | repository |  |
| response:/health | headers | completed | /health |  |
| cors:/health | cors | completed | /health |  |
| response:/html-insecure | headers | completed | /html-insecure |  |
| cors:/html-insecure | cors | completed | /html-insecure |  |
| response:/html-secure | headers | completed | /html-secure |  |
| cors:/html-secure | cors | completed | /html-secure |  |
| response:/protected | headers | completed | /protected |  |
| response:/public | headers | completed | /public |  |
| cors:/public | cors | completed | /public |  |
| response:/records/secure/42 | headers | completed | /records/secure/42 |  |
| response:/records/vulnerable/42 | headers | completed | /records/vulnerable/42 |  |
| response:/validate | headers | completed | /validate |  |
| vulnerable-cross-user | authorization | completed | /records/vulnerable/42 |  |
| secure-cross-user | authorization | completed | /records/secure/42 |  |
| protected-anonymous | authentication | completed | /protected |  |
| invalid-input | validation | completed | /validate?id=appsec-lab-invalid |  |
| coverage:session | session | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:sensitive\_response | sensitive\_response | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:error\_handling | error\_handling | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:business\_logic | business\_logic | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:tenant\_isolation | tenant\_isolation | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |

## Limitations

- Recognition does not imply complete analysis or runtime support.
- Environment files and private-key files are excluded, never loaded into the app.
- Syntactic source checks remain candidates; manual data-flow and deployment review is required.
- Deterministic workers and verification are not independent AI reviewers.
- No current advisory coverage without a supplied offline snapshot or a successful optional scanner.
- State-changing scenarios rely on explicitly configured disposable synthetic fixtures.
- Browser automation, full business-logic inference, CVSS calculation, mobile emulation and automatic Compose provisioning are not implemented.
- macOS uses a per-port host-loopback sandbox, not a private network namespace. Aggregate RSS/process/storage limits are monitored; Docker provides stronger resource isolation. Daemonizing startup programs are unsupported.

No findings does not establish security or complete coverage.
