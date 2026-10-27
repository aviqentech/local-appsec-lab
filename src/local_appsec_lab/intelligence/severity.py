"""CVSS v4 calculation only from explicit vectors; no inferred metric values."""

from cvss import CVSS4

from local_appsec_lab.errors import ConfigError


def calculate(vector: str, provenance: str) -> dict:
    try:
        value = CVSS4(vector)
    except Exception as exc:
        raise ConfigError("Invalid or incomplete CVSS v4 vector") from exc
    return {
        "version": "4.0",
        "vector": value.clean_vector(),
        "score": value.scores()[0],
        "severity": value.severities()[0].lower(),
        "source": provenance,
        "calculator": "cvss.CVSS4",
        "applicability": "Vector provenance does not establish application exposure or exploitability",
    }
