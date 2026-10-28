# Project understanding and component routing

Inspect the requested root before choosing scan scopes. Use actual locations
from the user and inventory; do not assume folders named api, backend, ui or src
exist. Documentation paths are placeholders, not discovered target directories. Use the component map,
manifest evidence, routes and dependency graph to understand the actual stack.
The map is conservative: a manifest or startup string is a candidate, not proof
that dependencies, health settings or a disposable runtime are ready. Confirm
ambiguous classification by reading source; do not execute package scripts to
discover their meaning. Tests/examples and arbitrary CLI jobs are not web services
merely because they have an entry point.

Select actions from the user's request:

| Component | Source request | Authorized live request |
|---|---|---|
| API/application | Source, dependency and requested AI review | Prepare/review startup; run HTTP and configured synthetic API checks |
| Frontend/static pages | Source/configuration review | Prepared hosting plus configured browser workflows; API requests alone are not browser coverage |
| Database/cache/storage | Configuration/dependency review | Start as a disposable supporting service inside the reviewed Compose group; do not scan as an HTTP app |
| Library/shared code | Applicable source/dependency checks | Source review unless an actual relevant test harness is configured |
| CI/deployment/configuration | Configuration/security review | Review declarations; do not execute CI or deploy infrastructure |
| Documentation/assets | Inspect relevant exposure/references | No invented application startup |
| Unknown/missing prerequisites | Explain uncertainty and continue source work | Report blocked work, exact prerequisite and proposed reviewed setup |

For independent subprojects, prepare each scope's configuration and plan, then
run the appropriate CLI scan for each scope covered by the request. The CLI runs
one selected startup profile or one constrained Compose group per scan; the skill
coordinates multiple scans. Keep shared application/database dependencies in one
reviewed Compose group instead of treating every service as an isolated web app.
Do not start all discovered candidates indiscriminately. Honor explicit exclusions.

`init --project PATH --native-host HOST` can prepare new commented configuration.
Existing configurations must be edited without overwriting user choices. Review
runtime candidates against manifests, actual entry points, required packages,
database connections, port and health endpoint. Propose concrete configuration and
prepared-runtime requirements for missing setup; do not invent credentials or user
permissions. Child project configurations are not inherited from the parent.
Maintain source review of parent deployment files and dependency manifests when
narrowing the runtime scope, so splitting a monorepo does not hide those surfaces.

Plan with the requested mode. Present the concrete commands, images, services,
synthetic identities, tests, limits and missing prerequisites. Authorization may
already cover the exact proposed environment; do not ask again if it does. Model
transmission, downloads and execution remain separate explicit permissions.
Use fresh plan digests after configuration changes. An existing localhost service
requires its explicit instance identity and manifest approval.

For each approved ready profile, run `scan --mode local-passive` or `local-active`
with its authorization/digest, plus the selected native host/model consent when
AI review is requested. Browser and synthetic access-policy workflows must actually
be configured to claim those checks. If one profile cannot run, retain its source
results and blocked reason and continue other independent authorized scopes.

Summarize each component: classification/evidence, source checks, actual model
calls, successful runtime starts, HTTP requests, browser workflows, findings,
blocked/not-tested work and report path. Report aggregate and per-run results
without claiming every discovered file/route was semantically reviewed or tested.
Do not call an overall live assessment complete when requested profiles remain
blocked. Cleanup only resources owned by the scans.
