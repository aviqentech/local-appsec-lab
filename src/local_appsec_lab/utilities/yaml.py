"""Bound YAML parsing before constructing repository-controlled object graphs."""

from __future__ import annotations

import yaml

from local_appsec_lab.errors import ConfigError


def safe_yaml(text: str):
    for count, event in enumerate(yaml.parse(text)):
        if isinstance(event, yaml.AliasEvent):
            raise ConfigError("YAML aliases are unsupported; use explicit bounded configuration")
        if count > 20_000:
            raise ConfigError("YAML event budget exceeded")
    return yaml.safe_load(text)
