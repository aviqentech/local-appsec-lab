import yaml
import pytest

from local_appsec_lab.configuration import Config, template
from local_appsec_lab.errors import ScopeError
from local_appsec_lab.initialization import initialize, review_budget


@pytest.mark.parametrize("count,expected", [(1, "small"), (101, "medium"), (501, "large")])
def test_project_size_sets_reported_native_limits(tmp_path, count, expected):
    for i in range(count):
        (tmp_path / f"source-{i}.txt").write_text("source\n")
    # Assets are inventoried, but should not inflate AI source-context sizing.
    (tmp_path / "font.woff2").write_bytes(b"font" * 1000)
    result = initialize(tmp_path, "claude")
    settings = result["configured_settings"]
    assert settings["sizing"]["project_size"] == expected
    assert settings["sizing"]["source_files"] == count
    config = yaml.safe_load((tmp_path / "appsec-lab.yaml").read_text())
    assert settings["limits"] == config["limits"]
    assert Config.model_validate(config).ai.strategy == "native"
    if expected == "large":
        assert config["limits"]["model_tokens"] == 1_000_000
        assert config["limits"]["model_calls"] == 32
        assert config["limits"]["duration_seconds"] == 900


def test_large_source_content_and_unknown_inventory():
    assert review_budget(1, 10_000_001)["project_size"] == "large"
    assert review_budget(1, 1_000_001)["project_size"] == "medium"
    assert review_budget(None, None)["project_size"] == "unknown"


def test_incomplete_discovery_is_reported_with_conservative_limits(tmp_path, monkeypatch):
    def unavailable(*args):
        raise ScopeError("Inventory budget exceeded")

    monkeypatch.setattr("local_appsec_lab.initialization.inspect", unavailable)
    result = initialize(tmp_path, "gemini")
    settings = result["configured_settings"]
    assert settings["sizing"]["project_size"] == "unknown"
    assert settings["limits"]["model_tokens"] == 200_000
    assert "discovery incomplete" in result["live_testing"]["remaining_setup"][0]


def test_each_ai_and_limits_field_has_an_explanatory_comment():
    text = template()
    config = yaml.safe_load(text)
    assert config == Config().model_dump()
    for section in ("ai", "limits"):
        section_text = text.split("\n" + section + ":\n", 1)[1].split("\n#", 1)[0]
        lines = section_text.splitlines()
        for field in config[section]:
            index = next(i for i, line in enumerate(lines) if line.startswith("  " + field + ":"))
            assert index > 0 and lines[index - 1].startswith("  # ")
