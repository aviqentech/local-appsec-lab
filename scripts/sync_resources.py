"""Keep published schemas and wheel-bundled skill identical to authoritative source."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from local_appsec_lab.authorization import Approval  # noqa: E402
from local_appsec_lab.configuration import Config  # noqa: E402
from local_appsec_lab.dynamic_tests.catalog import TestDefinition, catalog  # noqa: E402
from local_appsec_lab.models import Check, Finding, Report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = {}
    for model, name in [
        (Config, "config"),
        (Approval, "scope"),
        (Finding, "finding"),
        (Report, "report"),
        (Report, "run"),
        (Check, "check"),
        (TestDefinition, "test"),
    ]:
        schema = model.model_json_schema()
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        expected[ROOT / "schemas" / f"{name}.schema.json"] = (
            json.dumps(schema, indent=2) + "\n"
        ).encode()
    expected[ROOT / "src/local_appsec_lab/data/test-catalog.json"] = (
        json.dumps(catalog(), indent=2) + "\n"
    ).encode()
    for destination, content in expected.items():
        if args.check:
            if not destination.exists() or destination.read_bytes() != content:
                raise SystemExit(f"Resource is stale: {destination.relative_to(ROOT)}")
        else:
            destination.write_bytes(content)
    pairs = [
        (ROOT / "schemas", ROOT / "skill/local-appsec-lab/assets/schemas"),
        (ROOT / "adapters", ROOT / "skill/local-appsec-lab/assets/adapters"),
        (ROOT / "skill/local-appsec-lab", ROOT / "src/local_appsec_lab/data/skill"),
    ]
    for source, destination in pairs:
        if args.check:
            source_files = {
                p.relative_to(source): p.read_bytes()
                for p in source.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts
            }
            dest_files = {
                p.relative_to(destination): p.read_bytes()
                for p in destination.rglob("*")
                if p.is_file() and "__pycache__" not in p.parts
            }
            if source_files != dest_files:
                raise SystemExit(f"Bundled resource differs: {destination.relative_to(ROOT)}")
        else:
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__"))
    print("Schemas and bundled skill are synchronized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
