"""Configuration precedence, strict validation, and secret-free configuration.

The tests cover defaults, layering, environment and CLI overrides, and
rejection of unknown or invalid values.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from localagent.config import ConfigError, load_config, validate


# ---------- configuration layers ----------

def test_defaults_workspace_root_is_absolute(workspace):
    c = load_config(str(workspace))
    assert Path(c["permissions"]["workspace_root"]).is_absolute()
    assert Path(c["permissions"]["workspace_root"]) == workspace.resolve()


def test_workspace_yaml_overrides_defaults(workspace):
    (workspace / ".agent" / "config.yaml").write_text(
        yaml.safe_dump({"agent": {"max_steps": 7}}), encoding="utf-8"
    )
    c = load_config(str(workspace))
    assert c["agent"]["max_steps"] == 7
    assert c["agent"]["max_tool_calls"] == 120


def test_global_config_is_layered_below_workspace(tmp_path, monkeypatch, workspace):
    """Project configuration overrides global configuration."""
    fake_home = tmp_path / "home"
    (fake_home / ".config" / "localagent").mkdir(parents=True)
    (fake_home / ".config" / "localagent" / "config.yaml").write_text(
        yaml.safe_dump({"agent": {"max_steps": 11}}), encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(fake_home / ".config"))
    (workspace / ".agent" / "config.yaml").write_text(
        yaml.safe_dump({"agent": {"max_steps": 22}}), encoding="utf-8"
    )
    c = load_config(str(workspace))
    assert c["agent"]["max_steps"] == 22


def test_env_override_nested(workspace, monkeypatch):
    monkeypatch.setenv("LOCALAGENT_AGENT__MAX_STEPS", "42")
    assert load_config(str(workspace))["agent"]["max_steps"] == 42


def test_cli_overrides_env_and_yaml(workspace, monkeypatch):
    monkeypatch.setenv("LOCALAGENT_AGENT__MAX_STEPS", "42")
    c = load_config(str(workspace), cli={"agent": {"max_steps": 5}})
    assert c["agent"]["max_steps"] == 5


# ---------- strict validation ----------

def test_unknown_keys_are_rejected(workspace):
    (workspace / ".agent" / "config.yaml").write_text(
        yaml.safe_dump({"agent": {"unknown_new_key": 1}}), encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_config(str(workspace))


def test_invalid_confirm_mode_raises(workspace):
    with pytest.raises(ConfigError):
        load_config(str(workspace), cli={"permissions": {"confirm": "yes-please"}})


def test_invalid_compact_ratio_raises(workspace):
    with pytest.raises(ConfigError):
        load_config(str(workspace), cli={"agent": {"context_compact_ratio": 1.5}})


def test_reasoning_format_defaults_to_chat_template(workspace):
    c = load_config(str(workspace))
    assert c["llm"]["reasoning_format"] == "chat_template"


def test_reasoning_format_accepts_openrouter(workspace):
    c = load_config(str(workspace), cli={"llm": {"reasoning_format": "openrouter"}})
    assert c["llm"]["reasoning_format"] == "openrouter"


def test_verify_ssl_false_requires_trusted_host(workspace):
    from localagent.config import ConfigError
    with pytest.raises(ConfigError, match="trusted_hosts"):
        load_config(str(workspace), cli={"llm": {"verify_ssl": False}})
    cfg = load_config(str(workspace), cli={"llm": {"verify_ssl": False, "trusted_hosts": ["127.0.0.1"]}})
    assert cfg["llm"]["verify_ssl"] is False


def test_invalid_reasoning_format_raises(workspace):
    with pytest.raises(ConfigError, match="reasoning_format"):
        load_config(str(workspace), cli={"llm": {"reasoning_format": "unknown"}})


def test_openrouter_headers_default_to_null(workspace):
    c = load_config(str(workspace))
    assert c["llm"]["http_referer"] is None
    assert c["llm"]["x_title"] is None


def test_openrouter_headers_accept_strings_and_reject_other_types(workspace):
    c = load_config(str(workspace), cli={"llm": {"http_referer": "https://example.test", "x_title": "localagent"}})
    assert c["llm"]["http_referer"] == "https://example.test"
    assert c["llm"]["x_title"] == "localagent"
    for key in ("http_referer", "x_title"):
        with pytest.raises(ConfigError, match=key):
            load_config(str(workspace), cli={"llm": {key: 123}})


def test_invalid_reasoning_effort_raises(workspace):
    c = load_config(str(workspace))
    c["llm"]["profiles"]["DeepSeek-V4-Flash-0731"]["default_reasoning_effort"] = "meduim"
    with pytest.raises(ConfigError):
        validate(c)


def test_timeouts_must_be_positive(workspace):
    with pytest.raises(ConfigError):
        load_config(str(workspace), cli={"llm": {"idle_timeout_s": 0}})


def test_error_message_includes_key_path(workspace):
    """Validation errors identify the relevant configuration key."""
    with pytest.raises(ConfigError) as ei:
        load_config(str(workspace), cli={"permissions": {"confirm": "bogus"}})
    assert "confirm" in str(ei.value)


def test_workspace_bound_paths_are_rejected(workspace):
    for section, key in (("kb", "path"), ("logging", "dir")):
        with pytest.raises(ConfigError, match=key):
            load_config(str(workspace), cli={section: {key: "../outside"}})
        with pytest.raises(ConfigError, match=key):
            load_config(str(workspace), cli={section: {key: "/tmp/outside"}})



# ---------- model profiles ----------

def test_deepseek_profile_matches_tz(workspace):
    p = load_config(str(workspace))["llm"]["profiles"]["DeepSeek-V4-Flash-0731"]
    assert set(p["reasoning_efforts"]) == {"low", "high", "max"}
    assert p["default_reasoning_effort"] == "high"
    assert p["context_window"] == 1_048_576
    assert p["max_output"] == 32_768
    assert p["sampling"]["temperature"] == 1.0
    assert p["sampling"]["top_p"] == 1.0


def test_openrouter_deepseek_chat_profile_matches_openrouter(workspace):
    p = load_config(str(workspace))["llm"]["profiles"]["deepseek/deepseek-chat-v3.1"]
    assert p["reasoning_efforts"] == ["low", "medium", "high"]
    assert p["default_reasoning_effort"] == "medium"
    assert p["context_window"] == 163_840
    assert p["max_output"] == 32_768
    assert p["sampling"] == {"temperature": 1.0, "top_p": 1.0}
    assert p["max_tokens"] == {"low": 4096, "medium": 16_384, "high": 32_768}
    assert p["chars_per_token"] == 3.5


def test_qwen_profile_matches_tz(workspace):
    p = load_config(str(workspace))["llm"]["profiles"]["Qwen3.8-Flash"]
    assert set(p["reasoning_efforts"]) == {"low", "medium", "xhigh"}
    assert p["default_reasoning_effort"] == "medium"
    assert p["context_window"] == 262_144
    assert p["max_output"] == 8192
    assert p["sampling"]["temperature"] == 1.0
    assert p["sampling"]["top_p"] == 0.95
    assert p["sampling"]["top_k"] == 20


def test_profile_max_tokens_must_cover_every_reasoning_effort(workspace):
    c = load_config(str(workspace))
    p = c["llm"]["profiles"]["deepseek/deepseek-chat-v3.1"]
    p["max_tokens"].pop("high")
    with pytest.raises(ConfigError, match="exactly one budget per reasoning effort"):
        validate(c)


# ---------- secret-free configuration ----------

def test_config_does_not_hold_secret(workspace, monkeypatch):
    monkeypatch.setenv("LOCALAGENT_LLM__API_KEY_ENV", "MY_KEY_ENV")
    c = load_config(str(workspace))
    # api_key_env — это имя переменной, а не значение
    assert c["llm"].get("api_key_env") == "MY_KEY_ENV"
    assert "api_key" not in c["llm"] or c["llm"].get("api_key") in (None, "")


def test_subagent_limits_have_one_configuration_owner(workspace):
    cfg = load_config(str(workspace))
    assert "max_depth" not in cfg["agent"]
    assert "max_subagents" not in cfg["agent"]
    assert cfg["subagents"]["max_depth"] == 2
    assert cfg["subagents"]["max_subagents"] == 20


def test_legacy_agent_subagent_limit_keys_are_rejected(workspace):
    with pytest.raises(ConfigError):
        load_config(str(workspace), cli={"agent": {"max_depth": 1}})
