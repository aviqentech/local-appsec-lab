from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

from local_appsec_lab.utilities.files import files, read_bytes
from local_appsec_lab.utilities.yaml import safe_yaml

from .context import CODE_SUFFIXES, enrich, text_content
from .components import components

LANGUAGES = {
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".py": "Python",
    ".php": "PHP",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".cs": "C#",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".dart": "Dart",
    ".html": "HTML",
    ".css": "CSS",
    ".sh": "Shell",
    ".tf": "Terraform",
    ".yaml": "YAML",
    ".yml": "YAML",
}
MANAGERS = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "Yarn",
    "bun.lockb": "Bun",
    "bun.lock": "Bun",
    "requirements.txt": "pip",
    "poetry.lock": "Poetry",
    "uv.lock": "uv",
    "Pipfile.lock": "pipenv",
    "composer.lock": "Composer",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "Cargo.lock": "Cargo",
    "go.mod": "Go modules",
    "Gemfile.lock": "Bundler",
    "packages.lock.json": "NuGet",
    "pubspec.lock": "Flutter pub",
}
FRAMEWORKS = {
    "next": "Next.js",
    "react": "React",
    "vite": "Vite",
    "vue": "Vue",
    "nuxt": "Nuxt",
    "@angular/core": "Angular",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "fastify": "Fastify",
    "@sveltejs/kit": "SvelteKit",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "laravel/framework": "Laravel",
    "symfony/framework-bundle": "Symfony",
    "spring-boot": "Spring Boot",
    "rails": "Ruby on Rails",
    "flutter": "Flutter",
}
ROUTE = re.compile(
    r"""(?:@\w+\.(get|post|put|patch|delete|route)|\b\w+\.(get|post|put|patch|delete))\(\s*['"]([^'"\n]+)['"]""",
    re.I,
)


def inspect(root: Path, output: str = ".appsec-lab") -> dict[str, Any]:
    root = root.resolve(strict=True)
    inventory = files(root, excluded_paths=[output])
    languages: dict[str, list[str]] = {}
    frameworks: dict[str, list[str]] = {}
    managers: dict[str, list[str]] = {}
    services, routes, dependencies, infra = [], [], [], []
    texts: dict[str, str] = {}
    binary_files = []
    limitations = []
    for relative in inventory:
        path = Path(relative)
        text = text_content(relative, read_bytes(root, relative))
        if text is None:
            binary_files.append(relative)
            continue
        texts[relative] = text
        language = LANGUAGES.get(path.suffix)
        if language:
            languages.setdefault(language, []).append(relative)
        if path.name in MANAGERS:
            managers.setdefault(MANAGERS[path.name], []).append(relative)
        if path.suffix == ".csproj":
            managers.setdefault("NuGet", []).append(relative)
            if "Microsoft.NET.Sdk.Web" in text:
                frameworks.setdefault("ASP.NET Core", []).append(relative)
        if (
            path.name
            in {
                "Dockerfile",
                "compose.yaml",
                "docker-compose.yml",
                "compose.yml",
                "docker-compose.yaml",
            }
            or path.suffix == ".tf"
        ):
            infra.append(relative)
        if path.name == "package.json":
            try:
                data = json.loads(text)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for name, version in deps.items():
                    dependencies.append(
                        {
                            "name": name,
                            "version": str(version),
                            "ecosystem": "npm",
                            "source": relative,
                            "locked": False,
                        }
                    )
                    if name in FRAMEWORKS:
                        frameworks.setdefault(FRAMEWORKS[name], []).append(relative)
                scripts = data.get("scripts", {})
                startup = scripts.get("dev") or scripts.get("start")
                services.append(
                    {
                        "id": path.parent.as_posix(),
                        "kind": "javascript",
                        "source": relative,
                        "scripts": scripts,
                        "startup": startup,
                        "command": ["node", "server.js"]
                        if (root / path.parent / "server.js").is_file()
                        else [],
                        "dependencies": [],
                    }
                )
                if data.get("workspaces"):
                    infra.append(relative + ":workspaces")
            except (ValueError, TypeError):
                limitations.append(f"Malformed package manifest: {relative}")
        if path.name in {
            "pyproject.toml",
            "requirements.txt",
            "composer.json",
            "Gemfile",
            "pom.xml",
            "build.gradle",
            "pubspec.yaml",
        }:
            for key, framework in FRAMEWORKS.items():
                if re.search(r"(?i)(?<![a-z])" + re.escape(key) + r"(?![a-z])", text):
                    frameworks.setdefault(framework, []).append(relative)
        if path.name == "package-lock.json":
            try:
                for name, dep in json.loads(text).get("packages", {}).items():
                    if name and dep.get("version"):
                        dependencies.append(
                            {
                                "name": name.split("node_modules/")[-1],
                                "version": dep["version"],
                                "ecosystem": "npm",
                                "source": relative,
                                "locked": True,
                            }
                        )
            except (ValueError, AttributeError):
                limitations.append(f"Malformed lockfile: {relative}")
        if path.name == "requirements.txt":
            for name, version in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\s;]+)", text):
                dependencies.append(
                    {
                        "name": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "source": relative,
                        "locked": True,
                    }
                )
        if path.name in {"pyproject.toml", "uv.lock"}:
            try:
                data = tomllib.loads(text)
                for dep in data.get("package", []):
                    if isinstance(dep, dict) and dep.get("name") and dep.get("version"):
                        dependencies.append(
                            {
                                "name": dep["name"],
                                "version": dep["version"],
                                "ecosystem": "PyPI",
                                "source": relative,
                                "locked": True,
                            }
                        )
            except ValueError:
                limitations.append(f"Malformed TOML: {relative}")
        if path.name in {
            "compose.yaml",
            "compose.yml",
            "docker-compose.yml",
            "docker-compose.yaml",
        }:
            try:
                data = safe_yaml(text) or {}
                for name, service in data.get("services", {}).items():
                    services.append(
                        {
                            "id": name,
                            "kind": "compose",
                            "source": relative,
                            "image": service.get("image"),
                            "dependencies": list(service.get("depends_on", [])),
                            "command": [],
                        }
                    )
            except (yaml.YAMLError, TypeError, AttributeError):
                limitations.append(f"Malformed compose inventory: {relative}")
        if path.suffix == ".py" and path.name in {"app.py", "server.py", "main.py", "manage.py"}:
            try:
                ast.parse(text)
                services.append(
                    {
                        "id": path.parent.as_posix(),
                        "kind": "python",
                        "source": relative,
                        "command": ["python", path.name],
                        "dependencies": [],
                    }
                )
            except SyntaxError:
                limitations.append(f"Python syntax could not be parsed: {relative}")
        for match in ROUTE.finditer(text if path.suffix.lower() in CODE_SUFFIXES else ""):
            method = (match[1] or match[2]).upper()
            route = match[3]
            if route.startswith("/"):
                routes.append(
                    {
                        "method": "GET" if method == "ROUTE" else method,
                        "path": route,
                        "source": relative,
                        "line": text[: match.start()].count("\n") + 1,
                        "authentication": "unknown",
                    }
                )
        if path.name.lower() in {"openapi.json", "swagger.json", "openapi.yaml", "openapi.yml"}:
            try:
                spec = json.loads(text) if path.suffix == ".json" else safe_yaml(text)
                for route, operations in spec.get("paths", {}).items():
                    for method in operations:
                        if method.lower() in {"get", "post", "put", "delete", "patch"}:
                            routes.append(
                                {
                                    "method": method.upper(),
                                    "path": route,
                                    "source": relative,
                                    "line": 1,
                                    "authentication": "unknown",
                                }
                            )
            except (ValueError, yaml.YAMLError, AttributeError):
                limitations.append(f"Malformed API definition: {relative}")
        if "wp-config" in relative or "wp-content/" in relative:
            frameworks.setdefault("WordPress", []).append(relative)
        if path.suffix == ".go" and '"net/http"' in text:
            frameworks.setdefault("Go HTTP", []).append(relative)
    context = enrich(texts, inventory, services)
    routes.extend(context.pop("static_routes"))
    infra.extend(context.pop("infrastructure"))
    result = {
        **context,
        "files": inventory,
        "binary_files": binary_files,
        "languages": languages,
        "frameworks": frameworks,
        "package_managers": managers,
        "services": services,
        "routes": list({(r["method"], r["path"], r["source"]): r for r in routes}.values()),
        "dependencies": dependencies,
        "infrastructure": infra,
        "service_graph": {s["id"]: s["dependencies"] for s in services},
        "limitations": limitations
        + [
            "Recognition does not imply complete analysis or runtime support.",
            "Routes, network calls and review reasons are source hints, not runtime observations or vulnerabilities.",
            "Static routes assume a root document directory; conditional Apache rewrites are not resolved.",
            "Text analysis skips binary and non-UTF-8 files; they remain in the inventory and approval fingerprint.",
            "External references are capped at 512; integrations at 100, after deduplication.",
            "Environment files and private-key files are excluded, never loaded into the app.",
        ],
    }

    result["components"] = components(result)
    return result
