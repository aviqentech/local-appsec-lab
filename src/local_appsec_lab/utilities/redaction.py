from __future__ import annotations

import re
from typing import Any

SECRET_KEYS = re.compile(
    r"(?i)(password|passwd|secret|token|authorization|cookie|api[_-]?key|credential)"
)
PATTERNS = [
    re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"),
    re.compile(
        r"""(?ix)(?:["']?[a-z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|credential|authorization|cookie)[a-z0-9_-]*["']?)\s*[=:]\s*(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;}]+)"""
    ),
    re.compile(r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@"),
]


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]"
            if SECRET_KEYS.search(str(k)) and isinstance(v, str)
            else redact(v, secrets)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    value = "".join(c if c in "\n\t" or ord(c) >= 32 else "?" for c in value)
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    for pattern in PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value[:32_000]
