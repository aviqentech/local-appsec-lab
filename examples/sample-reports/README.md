# Real synthetic-fixture assessment reports

These files are engine-generated assessments of the actual local Node and Flask
fixtures. Shareable export generalizes only local repository/operator metadata;
measured evidence and outcomes remain unchanged. JSON and SARIF validate against
the published schemas. HTML includes no external resources.

- [Node HTML](javascript-api/report.html), [Markdown](javascript-api/report.md),
  [JSON](javascript-api/report.json), [SARIF](javascript-api/report.sarif).
- [Flask HTML](python-api/report.html), [Markdown](python-api/report.md),
  [JSON](python-api/report.json), [SARIF](python-api/report.sarif).

Each app had one confirmed synthetic cross-user access violation, while its secure
negative control was not reported. Both assessments remain partial because advisory
intelligence and several categories were not tested. See docs/validation.md and
examples/validation-summary.json for real measured counts. Do not use these reports
as evidence of complete security coverage.
