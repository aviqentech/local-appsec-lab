"""Runs only owned synthetic fixtures through the actual engine."""

import json
import shutil
import tempfile
from pathlib import Path

from local_appsec_lab.configuration import load
from local_appsec_lab.engine import scan

ROOT = Path(__file__).resolve().parent.parent


def main():
    results = []
    for case in json.loads((ROOT / "benchmarks/manifest.json").read_text())["cases"]:
        with tempfile.TemporaryDirectory(prefix="appsec-benchmark-") as temporary:
            root = Path(temporary).resolve() / "fixture"
            shutil.copytree(
                ROOT / "tests/fixtures" / case["fixture"],
                root,
                ignore=shutil.ignore_patterns(".appsec-lab", "__pycache__"),
            )
            report, _ = scan(root, root, load(root), case["mode"], case["mode"] != "review")
            rules = {f.rule for f in report.findings if f.state == "confirmed"}
            actual = {f.rule for f in report.findings}
            passed = (
                set(case["expected_confirmed_rules"]) <= rules
                and not set(case["negative_rules"]) & actual
            )
            results.append(
                {
                    "fixture": case["fixture"],
                    "passed": passed,
                    "confirmed": sorted(rules),
                    "metrics": report.metrics,
                }
            )
    output = ROOT / "benchmarks/expected-results/latest.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
