"""Bounded Python AST flow propagation, including local/imported function summaries.

Static source-to-sink traces remain candidates, not dynamic exploitation claims.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from local_appsec_lab.models import Check, Finding, Source
from local_appsec_lab.utilities.files import read_text
from local_appsec_lab.utilities.redaction import redact

SINKS = {
    "eval": ("CWE-95", "input_data_flow"),
    "exec": ("CWE-95", "input_data_flow"),
    "os.system": ("CWE-78", "command_execution"),
    "os.popen": ("CWE-78", "command_execution"),
    "render_template_string": ("CWE-1336", "template_rendering"),
    "requests.get": ("CWE-918", "server_side_requests"),
    "requests.post": ("CWE-918", "server_side_requests"),
    "httpx.get": ("CWE-918", "server_side_requests"),
    "urllib.request.urlopen": ("CWE-918", "server_side_requests"),
    "open": ("CWE-22", "file_upload"),
}


class BoundedObservations(list):
    truncated = False

    def append(self, item):
        if len(self) < 2000:
            path, line, sink, labels = item
            super().append((path, line, sink, set(sorted(labels)[:64])))
        else:
            self.truncated = True


def name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name(node.value) + "." + node.attr
    return ""


class Analyzer:
    def __init__(self, root: Path, inventory: dict):
        self.root = root
        self.modules = {}
        self.functions = {}
        self.aliases = {}
        self.summaries = {}
        self.texts = {}
        self.nodes = 0
        for relative in inventory["files"]:
            if not relative.endswith(".py"):
                continue
            text = read_text(root, relative)
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            self.nodes += sum(1 for _ in ast.walk(tree))
            if self.nodes > 100_000:
                break
            module = relative[:-3].replace("/", ".").removesuffix(".__init__")
            self.modules[module] = (relative, tree)
            self.texts[relative] = text
            aliases = {}
            for node in tree.body:
                if isinstance(node, ast.Import):
                    aliases.update({a.asname or a.name: a.name for a in node.names})
                elif isinstance(node, ast.ImportFrom):
                    aliases.update(
                        {a.asname or a.name: (node.module or "") + "." + a.name for a in node.names}
                    )
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions[module + "." + node.name] = (relative, module, node)
            self.aliases[module] = aliases

    def resolved(self, expression: ast.AST, module: str) -> str:
        value = name(expression)
        first, _, rest = value.partition(".")
        if first in self.aliases[module]:
            return self.aliases[module][first] + ("." + rest if rest else "")
        return module + "." + value if module + "." + value in self.functions else value

    def block(self, statements, env, relative, module, sinks, returns):
        def value(node):
            if node is None or isinstance(node, ast.Constant):
                return set()
            if isinstance(node, ast.Name):
                return set(env.get(node.id, set()))
            if isinstance(node, ast.Call):
                target = self.resolved(node.func, module)
                raw = name(node.func)
                arguments = [value(arg) for arg in node.args]
                keywords = {k.arg: value(k.value) for k in node.keywords if k.arg}
                combined = (
                    set().union(*arguments, *keywords.values()) if arguments or keywords else set()
                )
                if raw.startswith(
                    (
                        "request.args",
                        "request.form",
                        "request.json",
                        "request.get_json",
                        "request.headers",
                        "request.cookies",
                        "request.GET",
                        "request.POST",
                        "request.get_data",
                    )
                ) or raw in {"input"}:
                    return {f"{relative}:{node.lineno}:request-input"}
                summary = self.summaries.get(target)
                if summary:
                    params = [p.arg for p in self.functions[target][2].args.args]
                    supplied = dict(zip(params, arguments, strict=False)) | keywords

                    def replace(labels):
                        result = set()
                        for label in labels:
                            result |= (
                                supplied.get(label[1:], set()) if label.startswith("$") else {label}
                            )
                        return result

                    for path, line, sink, labels in summary[1]:
                        translated = replace(labels)
                        if translated:
                            sinks.append((path, line, sink, translated))
                    return replace(summary[0])
                sink = target if target in SINKS else None
                if raw.endswith((".execute", ".executemany", ".raw")):
                    sink = "database.execute"
                if target.startswith("subprocess.") and any(
                    k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords
                ):
                    sink = "shell.subprocess"
                if sink and arguments and arguments[0]:
                    sinks.append((relative, node.lineno, sink, arguments[0]))
                if raw.endswith((".escape", ".quote", ".quote_plus", ".secure_filename")):
                    # Sanitization effectiveness depends on its eventual context; keep provenance.
                    return combined
                return (
                    combined | value(node.func.value)
                    if isinstance(node.func, ast.Attribute)
                    else combined
                )
            if isinstance(node, ast.Attribute):
                if name(node).startswith(("request.", "sys.argv")):
                    return {f"{relative}:{node.lineno}:request-input"}
            if isinstance(node, ast.Subscript) and name(node.value).startswith(
                ("request.", "sys.argv")
            ):
                return {f"{relative}:{node.lineno}:request-input"}
            children = [value(child) for child in ast.iter_child_nodes(node)]
            return set().union(*children) if children else set()

        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                labels = value(node.value)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for binding in ast.walk(target):
                        if isinstance(binding, ast.Name):
                            env[binding.id] = labels
            elif isinstance(node, ast.AugAssign):
                env[name(node.target)] = env.get(name(node.target), set()) | value(node.value)
            elif isinstance(node, ast.Return):
                returns.update(value(node.value))
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try)):
                value(getattr(node, "test", None))
                branches = [
                    getattr(node, "body", []),
                    getattr(node, "orelse", []),
                    getattr(node, "finalbody", []),
                ]
                branches += [handler.body for handler in getattr(node, "handlers", [])]
                for branch in branches:
                    local = {key: set(labels) for key, labels in env.items()}
                    self.block(branch, local, relative, module, sinks, returns)
                    for key, labels in local.items():
                        env[key] = env.get(key, set()) | labels
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    value(item.context_expr)
                self.block(node.body, env, relative, module, sinks, returns)
            else:
                value(node)

    def run(self):
        for _ in range(12):
            changed = False
            for key, (relative, module, node) in self.functions.items():
                env = {p.arg: {"$" + p.arg} for p in node.args.args}
                sinks, returns = BoundedObservations(), set()
                self.block(node.body, env, relative, module, sinks, returns)
                summary = (returns, sinks[:200])
                if summary != self.summaries.get(key):
                    self.summaries[key] = summary
                    changed = True
            if not changed:
                break
        observations = BoundedObservations()
        for module, (relative, tree) in self.modules.items():
            self.block(tree.body, {}, relative, module, observations, set())
        for relative, module, node in self.functions.values():
            route = any(
                any(
                    part in ast.unparse(d)
                    for part in (".route(", ".get(", ".post(", ".put(", ".delete(", ".patch(")
                )
                for d in node.decorator_list
            )
            env = (
                {
                    p.arg: {f"{relative}:{node.lineno}:handler-parameter:{p.arg}"}
                    for p in node.args.args
                }
                if route
                else {p.arg: {"$" + p.arg} for p in node.args.args}
            )
            self.block(node.body, env, relative, module, observations, set())
        findings, seen = [], set()
        for relative, line, sink, labels in observations:
            sources = sorted(label for label in labels if not label.startswith("$"))
            if not sources or (relative, line, sink) in seen:
                continue
            seen.add((relative, line, sink))
            cwe, category = SINKS.get(
                sink,
                ("CWE-89", "input_data_flow")
                if sink == "database.execute"
                else ("CWE-78", "command_execution"),
            )
            text = self.texts[relative]
            if len(findings) >= 200:
                observations.truncated = True
                break
            findings.append(
                Finding(
                    rule="dataflow:" + sink,
                    title="Untrusted input reaches " + sink,
                    category=category,
                    severity="high",
                    severity_reason="Static data flow crosses an input-to-sensitive-operation boundary; dynamic impact requires verification.",
                    confidence="medium",
                    cwe=cwe,
                    source=Source(
                        path=relative,
                        line=line,
                        end_line=line,
                        excerpt=redact(text.splitlines()[line - 1]),
                        sha256=hashlib.sha256(text.encode()).hexdigest(),
                    ),
                    description="Bounded AST propagation connects request input to a sensitive operation, including supported function/import summaries.",
                    expected="Bind values or validate the specific operation and resource before a sensitive sink.",
                    observed="Static source-to-sink flow found.",
                    evidence=[
                        {
                            "method": "python-interprocedural-dataflow",
                            "sources": sources,
                            "sink": sink,
                            "sink_path": relative,
                            "sink_line": line,
                        }
                    ],
                    root_cause="Input provenance propagates through supported expressions and function calls to the identified sink.",
                    remediation="Replace string-built sensitive operations with typed APIs and context-specific allowlists; add a negative regression for this source-to-sink path.",
                    limitations=[
                        "Conservative bounded static analysis; dynamic dispatch, decorators, implicit framework validation and external library semantics may affect applicability. No runtime exploitation claim."
                    ],
                )
            )
        return findings, [
            Check(
                id="python-dataflow",
                category="input_data_flow",
                status="completed",
                reason="Bounded AST provenance and interprocedural summaries; candidates require contextual verification",
                observations=[
                    {
                        "functions_analyzed": len(self.functions),
                        "ast_nodes": self.nodes,
                        "flows": len(findings),
                        "truncated": observations.truncated or self.nodes > 100_000,
                    }
                ],
            )
        ]


def analyze(root: Path, inventory: dict):
    return Analyzer(root, inventory).run()
