# Local AppSec Lab assessment

Run: 6c78c5a4487a482e9472fa98602f1592 · Mode: local-active · Status: **partial**

Repository: /assessed-project
Revision: 08e021c886560d4f3ff5344228e2356f417a6b6a
Started: 2026-10-27T12:24:27.976051+00:00 · Duration: 3.64s
Execution strategy: deterministic-workers

## Measured results

- source\_files\_inspected: 4
- dependencies\_identified: 0
- services\_identified: 3
- services\_started: 2
- routes\_discovered: 0
- routes\_tested: 1
- http\_requests: 10
- browser\_workflows: 0
- stateful\_workflows: 0
- fuzz\_properties: 0
- adaptive\_new\_coverage: 0
- dynamic\_checks\_completed: 4
- worker\_assignments\_completed: 11
- candidate\_findings: 0
- confirmed\_findings: 1
- false\_positives: 0
- blocked\_checks: 1
- not\_tested\_checks: 6
- runtime\_startup\_failed: False
- cleanup\_completed: True
- model\_tokens\_reserved: 0
- model\_cost\_upper\_bound\_usd: 0
- model\_calls: 0
- model\_reported\_tokens: None
- model\_reported\_cost\_usd: None
- native\_hard\_token\_cap: None
- analysis\_cache\_hits: 0
- analysis\_cache\_misses: 10
- analysis\_cache\_verified: True

## Findings

### Synthetic access policy violated: vulnerable-cross-user

LAB-f83eded2773d4eb4 · high potential severity · confirmed · confidence: high

Location: /records/vulnerable/42
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
    "timestamp": "2026-10-27T12:24:30.702891+00:00",
    "owner": {
      "status": 200,
      "body_sha256": "25b562d9bec6c7296370d66bb2a739bce7a06e7a2dbee859aababaece81f5468",
      "body_bytes": 55,
      "truncated": false,
      "marker_present": true,
      "security_headers": {
        "content-type": "application/json"
      }
    },
    "actor": {
      "status": 200,
      "body_sha256": "25b562d9bec6c7296370d66bb2a739bce7a06e7a2dbee859aababaece81f5468",
      "body_bytes": 55,
      "truncated": false,
      "marker_present": true,
      "security_headers": {
        "content-type": "application/json"
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
    "duration_seconds": 0.21063562499330146,
    "limitations": "Expected policy and fixture ownership are supplied by the developer."
  }
]
```
Verification:
```json
[
  {
    "reviewer": "independent-deterministic-verifier",
    "timestamp": "2026-10-27T12:24:30.906403+00:00",
    "previous_state": "candidate",
    "conclusion": "confirmed",
    "new_observation": {
      "test_id": "vulnerable-cross-user",
      "category": "authorization",
      "method": "GET",
      "path": "/records/vulnerable/42",
      "timestamp": "2026-10-27T12:24:31.116525+00:00",
      "owner": {
        "status": 200,
        "body_sha256": "25b562d9bec6c7296370d66bb2a739bce7a06e7a2dbee859aababaece81f5468",
        "body_bytes": 55,
        "truncated": false,
        "marker_present": true,
        "security_headers": {
          "content-type": "application/json"
        }
      },
      "actor": {
        "status": 200,
        "body_sha256": "25b562d9bec6c7296370d66bb2a739bce7a06e7a2dbee859aababaece81f5468",
        "body_bytes": 55,
        "truncated": false,
        "marker_present": true,
        "security_headers": {
          "content-type": "application/json"
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
      "duration_seconds": 0.2101504170059343,
      "limitations": "Expected policy and fixture ownership are supplied by the developer."
    }
  }
]
```
Remediation: Enforce the configured ownership/role/input policy at the server-side resource boundary.
Regression: Run \`appsec-lab verify --finding &lt;id&gt; --authorize\` after fixing scenario vulnerable-cross-user; actor must be denied.
CVSS v4: not assigned; no supported vector supplied.
Engineering guidance:
```json
{
  "affected_component": "/records/vulnerable/42",
  "root_cause": "Exact source-level cause is not established by the available evidence.",
  "impact": "The configured lower-trust synthetic actor received the prohibited fixture response.",
  "recommended_fix": "Enforce the configured ownership/role/input policy at the server-side resource boundary.",
  "regression": "Run `appsec-lab verify --finding <id> --authorize` after fixing scenario vulnerable-cross-user; actor must be denied.",
  "framework_context": {},
  "compatibility": "Review existing callers and deployment controls; run application regression tests before release.",
  "verification": "Repeat the recorded check with the same synthetic fixtures and verify both the denied actor and allowed owner controls.",
  "alternative_mitigation": "Constrain the affected interface while a source correction is reviewed; deployment controls need independent validation.",
  "references": [
    "https://cwe.mitre.org/data/definitions/862.html"
  ]
}
```
Limitations: Conclusion depends on the explicitly configured synthetic users, records and expected policy.

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
| python-dataflow | input\_data\_flow | completed | repository | Bounded AST provenance and interprocedural summaries; candidates require contextual verification |
| dependency-advisories | dependencies | blocked | repository | No authorized offline advisory snapshot configured; no current vulnerability claims |
| runtime-health | runtime | completed | repository |  |
| response:/health | headers | completed | /health |  |
| cors:/health | cors | completed | /health |  |
| vulnerable-cross-user | authorization | completed | /records/vulnerable/42 |  |
| secure-cross-user | authorization | completed | /records/secure/42 |  |
| coverage:session | session | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:sensitive\_response | sensitive\_response | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
| coverage:validation | validation | not_tested | repository | No applicable implemented check or configured synthetic scenario executed |
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
- Data-flow analysis is bounded and conservative; unsupported dynamic dispatch and languages need specialist review. Mobile emulation and automatic business-policy inference are not provided.

No findings does not establish security or complete coverage.
