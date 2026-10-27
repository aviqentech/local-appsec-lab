"""Bounded source hints, never runtime observations or authorization decisions."""

from __future__ import annotations

import ast
import ipaddress
import posixpath
import re
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

URL = re.compile(r"https?://[^\s'\"<>)}]+", re.I)
BINARY_SUFFIXES = {
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".br",
    ".exe",
    ".dll",
    ".so",
    ".wasm",
    ".mp4",
    ".webp",
}
CODE_SUFFIXES = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".php",
    ".java",
    ".kt",
    ".go",
    ".cs",
    ".rb",
    ".rs",
    ".sh",
    ".tf",
}
RUNTIME_KINDS = {"network_call", "script_resource", "stylesheet", "resource", "form_action"}


def text_content(relative: str, raw: bytes) -> str | None:
    if PurePosixPath(relative).suffix.lower() in BINARY_SUFFIXES or b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def hostname(value: str) -> str | None:
    """Reject template authorities and malformed DNS rather than guessing a host."""
    if re.search(r"[\x00-\x20\x7f]", value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or parsed.username is not None:
            return None
        host = parsed.hostname
        if not host or parsed.port == 0 or re.search(r"[%{}$;\\\s]", parsed.netloc):
            return None
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            address = ipaddress.ip_address(host)
            return None if address.is_loopback or address.is_unspecified else host
        except ValueError:
            if host == "localhost" or host.endswith(".localhost") or len(host) > 253:
                return None
            if all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in host.split(".")
            ):
                return host
    except (ValueError, UnicodeError):
        pass
    return None


class References:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str, str], dict] = {}
        self.truncated = False

    def add(self, value: str, source: str, kind: str, line: int) -> None:
        if value.startswith("//"):
            value = "https:" + value
        host = hostname(value)
        if not host:
            return
        key = (host, source, kind)
        if key not in self.items:
            if len(self.items) >= 512:
                self.truncated = True
                return
            self.items[key] = dict(host=host, source=source, kind=kind, occurrences=0, lines=[])
        item = self.items[key]
        item["occurrences"] += 1
        if line not in item["lines"] and len(item["lines"]) < 8:
            item["lines"].append(line)

    def scan(self, text: str, source: str, kind: str, line: int = 1) -> None:
        previous = 0
        for match in URL.finditer(text):
            line += text.count("\n", previous, match.start())
            self.add(match[0], source, kind, line)
            previous = match.start()


def reasons(text: str) -> list[dict]:
    signals = [
        (
            r"\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b",
            "dom_sink",
            "HTML-writing DOM operation; trace input before concluding XSS.",
        ),
        (
            r"\b(?:subprocess\.(?:run|Popen|call)|os\.system|eval|exec)\s*\(",
            "execution",
            "Process or dynamic-code execution boundary.",
        ),
        (
            r"(?<![a-z0-9])(?:auth|authorization|authenticate|password|session|csrf|tenant|api_key|access_token|GITHUB_TOKEN)(?![a-z0-9])",
            "identity_or_credentials",
            "Identity, session or credential-related code marker.",
        ),
        (
            r"\b(?:fetch|urlopen|requests\.(?:get|post)|httpx\.(?:get|post))\s*\(",
            "network_client",
            "Outbound network client call.",
        ),
    ]
    result = []
    for pattern, category, reason in signals:
        match = re.search(pattern, text, re.I)
        if match:
            result.append(
                dict(category=category, line=text.count("\n", 0, match.start()) + 1, reason=reason)
            )
    return result


class Markup(HTMLParser):
    def __init__(self, source: str, refs: References) -> None:
        super().__init__(convert_charrefs=True)
        self.source, self.refs = source, refs
        self.resources: list[str] = []
        self.signals: list[dict] = []
        self.script_kind: str | None = None
        self.malformed = False

    def parse_html_declaration(self, i: int) -> int:
        # Older CPython raises on non-CDATA marked sections; patched releases skip
        # them as bogus comments. Flag them here so coverage is reported either way.
        if self.rawdata.startswith("<![", i) and not self.rawdata.startswith("<![CDATA[", i):
            self.malformed = True
        return super().parse_html_declaration(i)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        line = self.getpos()[0]
        if tag == "script":
            script_type = (values.get("type") or "").lower()
            self.script_kind = (
                "schema_reference"
                if script_type == "application/ld+json"
                else "code"
                if script_type in {"", "module", "text/javascript", "application/javascript"}
                else "metadata"
            )
        for key, value in attrs:
            if not value:
                continue
            kind = None
            if key.startswith("xmlns") or key == "itemtype":
                kind = "schema_reference"
            elif key == "href":
                kind = (
                    "navigation"
                    if tag in {"a", "area"}
                    else (
                        "stylesheet"
                        if "stylesheet" in (values.get("rel") or "").split()
                        else "metadata"
                    )
                )
            elif key == "src":
                kind = "script_resource" if tag == "script" else "resource"
            elif key == "action" and tag == "form":
                kind = "form_action"
            elif key == "content" and tag == "meta":
                kind = "metadata"
            elif key.startswith("on"):
                self.signals.append(
                    dict(
                        category="inline_handler",
                        line=line,
                        reason="Executable inline event handler.",
                    )
                )
            if kind:
                self.refs.add(value, self.source, kind, line)
                if kind in RUNTIME_KINDS and not re.match(r"[\w+.-]+:|//", value):
                    self.resources.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self.script_kind = None

    def handle_data(self, data: str) -> None:
        if self.script_kind == "code":
            for signal in reasons(data):
                signal["line"] += self.getpos()[0] - 1
                self.signals.append(signal)
            code_references(data, self.source, self.refs, self.getpos()[0])
        elif self.script_kind:
            self.refs.scan(data, self.source, self.script_kind, self.getpos()[0])


def code_references(text: str, source: str, refs: References, line: int = 1) -> None:
    # A call-site hint, not a full language parser. Arbitrary literals remain references.
    previous = 0
    for match in URL.finditer(text):
        line += text.count("\n", previous, match.start())
        previous = match.start()
        prefix = text[max(0, match.start() - 100) : match.start()]
        call = re.search(
            r"\b(?:fetch|axios(?:\.\w+)?|requests\.\w+|httpx\.\w+|urlopen|getJSON)"
            r"\(\s*[fFrR]?['\"]$",
            prefix,
        )
        refs.add(
            match[0],
            source,
            "network_call" if call else "code_reference",
            line,
        )


def python_network_calls(text: str, source: str, refs: References) -> None:
    """Recognize direct clients and local wrappers containing a client or curl invocation."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        return

    def client(call: ast.Call) -> bool:
        name = ast.unparse(call.func)
        if name in {"urlopen", "urllib.request.urlopen"} or re.fullmatch(
            r"(?:requests|httpx)\.(?:get|post|put|patch|delete|request)", name
        ):
            return True
        return name in {"subprocess.run", "subprocess.Popen", "subprocess.check_output"} and bool(
            call.args
            and isinstance(call.args[0], (ast.List, ast.Tuple))
            and call.args[0].elts
            and isinstance(call.args[0].elts[0], ast.Constant)
            and call.args[0].elts[0].value == "curl"
        )

    wrappers = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(child, ast.Call) and client(child) for child in ast.walk(node))
    }
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not (
            client(call) or ast.unparse(call.func) in wrappers
        ):
            continue
        for argument in [*call.args, *(k.value for k in call.keywords if k.arg == "url")]:
            for node in ast.walk(argument):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    refs.scan(node.value, source, "network_call", node.lineno)


def apache_rules(text: str) -> list[dict]:
    result = []
    conditional = False
    for line, content in enumerate(text.splitlines(), 1):
        if re.match(r"\s*RewriteCond\b", content, re.I):
            conditional = True
        match = re.match(r"\s*RewriteRule\s+(\S+)\s+(\S+)", content, re.I)
        if not match:
            continue
        pattern, target = match.groups()
        literal = pattern.removeprefix("^").removesuffix("$").replace(r"\.", ".")
        source_path = "/" + literal if re.fullmatch(r"[\w./-]+", literal) else None
        target_path = target if re.fullmatch(r"/[\w./-]*", target) else None
        result.append(
            dict(
                line=line,
                conditional=conditional,
                source_path=source_path,
                target_path=target_path,
                dynamic_substitution=bool(re.search(r"[%$]", target)),
            )
        )
        conditional = False
        if len(result) >= 100:
            break
    return result


def enrich(texts: dict[str, str], inventory: list[str], services: list[dict]) -> dict:
    refs = References()
    known_files = set(inventory)
    details, infra, hosting, ci = [], [], [], []
    unparsed_markup = []
    resources: dict[str, list[str]] = {}
    pages = [p for p in texts if PurePosixPath(p).suffix.lower() in {".html", ".htm"}]
    # Only a root-level static site is inferred; nested docs/templates are not deployment roots.
    static = "index.html" in pages and not services
    routes = []
    entries = []
    for source, text in texts.items():
        path = PurePosixPath(source)
        signals = []
        if path.suffix.lower() in {".html", ".htm", ".svg"}:
            parser = Markup(source, refs)
            try:
                parser.feed(text)
                parser.close()
            except (ValueError, AssertionError):
                # HTMLParser can reject malformed marked declarations. Keep partial hints explicit.
                parser.malformed = True
            if parser.malformed:
                unparsed_markup.append(source)
            signals = parser.signals
            local = []
            for value in parser.resources:
                raw_path = value.split("?", 1)[0].split("#", 1)[0]
                target = posixpath.normpath(
                    raw_path.lstrip("/")
                    if raw_path.startswith("/")
                    else posixpath.join(path.parent.as_posix(), raw_path)
                )
                if target in known_files and target not in local:
                    local.append(target)
            resources[source] = local
            if (
                static
                and path.parent == PurePosixPath(".")
                and source in pages
                and re.fullmatch(r"[A-Za-z0-9_.-]+", source)
            ):
                entries.append(source)
                for route in ["/", "/index.html"] if source == "index.html" else ["/" + source]:
                    routes.append(
                        dict(
                            method="GET",
                            path=route,
                            source=source,
                            line=1,
                            authentication="unknown",
                            kind="static_file",
                        )
                    )
        elif path.name == ".htaccess":
            hosting.append(
                dict(
                    source=source,
                    syntax="Apache-compatible",
                    rewrite_rules=apache_rules(text),
                    directives=[
                        dict(name=m[1], line=text.count("\n", 0, m.start()) + 1)
                        for m in re.finditer(
                            r"(?m)^\s*(RewriteRule|RewriteCond|Header|ErrorDocument|Options)\b",
                            text,
                        )
                    ][:100],
                )
            )
            infra.append(source)
            signals = [
                dict(
                    category="server_configuration",
                    line=1,
                    reason="Server headers, redirects or access directives require review.",
                )
            ]
            # CSP source expressions end at semicolons. Rewrite substitutions remain templates.
            for number, content in enumerate(text.splitlines(), 1):
                if re.match(r"\s*Header\b", content, re.I):
                    refs.scan(content.replace(";", " "), source, "policy_reference", number)
        elif source.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            ci.append("GitHub Actions")
            infra.append(source)
            signals = [
                dict(
                    category="ci_automation",
                    line=1,
                    reason="CI automation can execute code and use repository credentials.",
                )
            ]
            refs.scan(text, source, "infrastructure_reference")
        elif path.suffix.lower() in CODE_SUFFIXES:
            signals = reasons(text)
            if path.suffix.lower() == ".py":
                refs.scan(text, source, "code_reference")
                python_network_calls(text, source, refs)
            else:
                code_references(text, source, refs)
        else:
            refs.scan(text, source, "text_reference")
        if signals:
            details.append(dict(source=source, reasons=signals))
    if static:
        for page in list(entries):
            entries.extend(p for p in resources.get(page, []) if p.endswith((".js", ".mjs")))
    # Workflow-linked scripts are entry points, not automatically runnable application services.
    workflow_text = "\n".join(texts[p] for p in infra if p.startswith(".github/workflows/"))
    entries.extend(
        p
        for p in texts
        if p.endswith(".py")
        and re.search(r"\bpython(?:3)?\s+(?:\./)?" + re.escape(p) + r"(?=\s|$)", workflow_text)
    )
    all_refs = list(refs.items.values())
    integrations = [r for r in all_refs if r["kind"] in RUNTIME_KINDS]
    return dict(
        project_type="static_website" if static else "application_or_library",
        static_routes=routes,
        external_references=all_refs,
        external_integrations=integrations[:100],
        security_sensitive_details=details,
        security_sensitive_files=[d["source"] for d in details],
        infrastructure=infra,
        server_configuration=hosting,
        ci_cd=sorted(set(ci)),
        entry_points=sorted(set(entries)),
        resource_graph={s: r for s, r in resources.items() if r},
        security_test_targets=sorted(
            {reason["category"] for d in details for reason in d["reasons"]}
        ),
        runtime_requirements=(
            {
                "web_server": "Reviewed static hosting required for browser testing",
                **(
                    {
                        "apache_configuration": "Apache-compatible hosting is required to apply .htaccess"
                    }
                    if hosting
                    else {}
                ),
            }
            if static
            else {}
        ),
        references_truncated=refs.truncated or len(integrations) > 100,
        partially_parsed_markup=unparsed_markup,
    )
