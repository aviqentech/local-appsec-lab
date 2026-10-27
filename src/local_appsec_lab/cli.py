from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from local_appsec_lab import __version__
from local_appsec_lab.configuration import CONFIG_FILE, load, template
from local_appsec_lab.engine import clean, doctor, exit_code, plan, scan, state_path
from local_appsec_lab.errors import ConfigError, LabError
from local_appsec_lab.findings import RunStore
from local_appsec_lab.install import host_locations
from local_appsec_lab.reporting import compare, render, shareable
from local_appsec_lab.utilities.files import inside
from local_appsec_lab.utilities.redaction import redact


def common(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--project",
        type=Path,
        default=argparse.SUPPRESS,
        help="Repository directory (default: current directory)",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=argparse.SUPPRESS,
        help="Explicit authorized workspace root",
    )
    parser.add_argument(
        "--config", default=argparse.SUPPRESS, help="Project-relative YAML configuration"
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="appsec-lab", description="Authorized, local-first application security assessments"
    )
    root.add_argument("--version", action="version", version=__version__)
    common(root)
    commands = root.add_subparsers(dest="command", required=True)
    for name in [
        "doctor",
        "init",
        "inspect",
        "plan",
        "scan",
        "status",
        "runs",
        "report",
        "verify",
        "compare",
        "clean",
        "config",
        "skills",
    ]:
        command = commands.add_parser(name)
        common(command)
        if name in {"scan", "verify"}:
            command.add_argument(
                "--authorize",
                action="store_true",
                help="Acknowledge local execution and bounded testing for this run",
            )
            command.add_argument(
                "--existing-manifest-digest",
                help="Explicit approval of the existing service manifest printed by plan",
            )
            command.add_argument(
                "--allow-model-requests",
                action="store_true",
                help="Allow selected redacted source to be sent to the configured HTTPS model endpoint",
            )
            command.add_argument("--model-price-per-million", type=float, default=0)
            command.add_argument(
                "--model-key-env",
                help="Trusted CLI selection of a credential environment variable for the reviewed model endpoint",
            )
            command.add_argument(
                "--host-results", help="Repository-relative JSON results of native host assignments"
            )
        if name == "scan":
            command.add_argument(
                "--mode", choices=["review", "local-passive", "local-active"], default="review"
            )
            command.add_argument(
                "--fail-on", choices=["informational", "low", "medium", "high", "critical"]
            )
        if name in {"report", "verify"}:
            command.add_argument("--run", default="latest")
        if name == "report":
            command.add_argument(
                "--shareable",
                action="store_true",
                help="Generalize local repository/operator metadata; review before sharing",
            )
            command.add_argument(
                "--format", choices=["json", "markdown", "html", "sarif", "all"], default="all"
            )
        if name == "verify":
            command.add_argument("--finding", required=True)
        if name == "compare":
            command.add_argument("old")
            command.add_argument("new")
        if name == "config":
            command.add_argument("operation", choices=["validate"])
        if name == "skills":
            command.add_argument("operation", choices=["doctor"])
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = None
    try:
        root = getattr(args, "project", Path.cwd()).resolve(strict=True)
        workspace = getattr(args, "workspace", root).resolve(strict=True)
        if not root.is_dir() or not root.is_relative_to(workspace):
            raise ConfigError("Project must be a directory within the authorized workspace")
        config = load(
            root,
            getattr(args, "config", None),
            {"fail_on": args.fail_on} if getattr(args, "fail_on", None) else None,
        )
        command, code = args.command, 0
        if command == "init":
            destination = inside(root, Path(CONFIG_FILE))
            if destination.exists():
                raise ConfigError("Configuration already exists; no files overwritten")
            destination.write_text(template())
            ignore = inside(root, Path(".gitignore"))
            existing = ignore.read_text() if ignore.exists() else ""
            if ".appsec-lab/" not in existing:
                ignore.write_text(existing + "\n# Private security assessments\n.appsec-lab/\n")
            result = {"configuration": str(destination), "authorized": False}
        elif command == "config":
            result = {
                "valid": True,
                "schema_version": config.version,
                "configuration": getattr(args, "config", CONFIG_FILE),
            }
        elif command == "doctor":
            result = doctor(root, config)
        elif command == "skills":
            result = {"user": host_locations(Path.home()), "project": host_locations(root)}
        elif command == "inspect":
            from local_appsec_lab.discovery import inspect

            result = inspect(root)
        elif command == "plan":
            result = plan(root, config)
        elif command == "clean":
            result = {"resources": clean(root, config)}
        elif command in {"scan", "verify"}:
            finding = None
            mode = getattr(args, "mode", "review")
            if command == "verify":
                store = RunStore(state_path(root, config))
                original = store.read(args.run)
                finding = next(
                    (
                        f
                        for f in original.findings
                        if f.id == args.finding or f.fingerprint == args.finding
                    ),
                    None,
                )
                if not finding:
                    raise ConfigError("Finding does not exist in the selected run")
                if original.repository != str(root):
                    raise ConfigError("Finding belongs to another repository")
                mode = original.mode
                store.close()
                store = None
            report, outputs = scan(
                root,
                workspace,
                config,
                mode,
                args.authorize,
                args.existing_manifest_digest,
                args.allow_model_requests,
                args.model_price_per_million,
                args.host_results,
                finding,
                args.model_key_env,
            )
            result = {
                "run_id": report.run_id,
                "status": report.status,
                "metrics": report.metrics,
                "outputs": outputs,
            }
            if command == "verify":
                result["finding"] = report.findings[0].model_dump() if report.findings else None
            code = exit_code(report, config)
        elif command in {"runs", "status", "report", "compare"}:
            store = RunStore(state_path(root, config))
            if command == "runs":
                result = store.runs()
            elif command == "status":
                runs = store.runs()
                result = runs[0] if runs else {"state": "idle"}
                if result.get("state") == "running" and result.get("pid"):
                    try:
                        os.kill(result["pid"], 0)
                    except (ProcessLookupError, PermissionError):
                        result = {
                            **result,
                            "state": "interrupted",
                            "remediation": "Run clean to recover exact owned resources",
                        }
            elif command == "report":
                report = store.read(args.run)
                if args.shareable:
                    report = shareable(report)
                result = render(
                    report,
                    state_path(root, config)
                    / "reports"
                    / report.run_id
                    / ("shareable" if args.shareable else "."),
                    None if args.format == "all" else [args.format],
                )
            else:
                result = compare(store.read(args.old), store.read(args.new))
        else:
            raise ConfigError("Unknown command")
        print(json.dumps(redact(result), indent=2))
        return code
    except KeyboardInterrupt:
        print(json.dumps({"error": "Cancelled", "exit_code": 130}), file=sys.stderr)
        return 130
    except (LabError, OSError, ValueError, KeyError) as exc:
        code = exc.code if isinstance(exc, LabError) else 3
        # Avoid echoing raw parser/OS errors containing untrusted values or secrets.
        message = (
            str(exc)
            if isinstance(exc, LabError)
            else f"{type(exc).__name__}; check configuration, paths, and installed dependencies"
        )
        print(json.dumps({"error": redact(message), "exit_code": code}), file=sys.stderr)
        return code
    except Exception as exc:
        print(
            json.dumps({"error": "Internal error: " + type(exc).__name__, "exit_code": 70}),
            file=sys.stderr,
        )
        return 70
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
