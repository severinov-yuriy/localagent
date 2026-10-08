"""Configuration loading, environment overrides, defaults, and validation.

Configuration is assembled from package defaults, an optional global YAML file,
the workspace ``.agent/config.yaml``, ``LOCALAGENT_*`` environment variables,
and finally CLI overrides.  Later sources win over earlier ones.
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

import yaml


DEFAULTS = {
    "llm": {
        "base_url": "http://127.0.0.1:8000/v1",
        "api_key_env": "GENOPS_API_KEY",
        "api_key_file": None,
        "http_referer": None,
        "x_title": None,
        "reasoning_format": "chat_template",
        "connect_timeout_s": 10,
        "idle_timeout_s": 55,
        "verify_ssl": True,
        "trusted_hosts": [],
        "allow_external": False,
        "ca_bundle": None,
        "proxy": None,
        "retry": {"max_attempts": 3, "backoff_s": 1.0, "statuses": [429, 500, 502, 503, 504]},
        "models": {
            "default": "DeepSeek-V4-Flash-0731",
            "qwen": "Qwen3.8-Flash",
        },
        "profiles": {
            "DeepSeek-V4-Flash-0731": {
                "reasoning_efforts": ["low", "high", "max"],
                "default_reasoning_effort": "high",
                "sampling": {"temperature": 1.0, "top_p": 1.0},
                "context_window": 1_048_576,
                "max_output": 32_768,
                "max_tokens": {"low": 32768, "high": 131000, "max": 384000},
                "chars_per_token": 3.09,
            },
            "deepseek/deepseek-chat-v3.1": {
                "reasoning_efforts": ["low", "medium", "high"],
                "default_reasoning_effort": "medium",
                "context_window": 163_840,
                "max_output": 32_768,
                "sampling": {"temperature": 1.0, "top_p": 1.0},
                "max_tokens": {"low": 4096, "medium": 16_384, "high": 32_768},
                "chars_per_token": 3.5,
            },
            "Qwen3.8-Flash": {
                "reasoning_efforts": ["low", "medium", "xhigh"],
                "default_reasoning_effort": "medium",
                "context_window": 262_144,
                "max_output": 8192,
                "sampling": {"temperature": 1.0, "top_p": 0.95, "top_k": 20},
                "max_tokens": {"low": 4096, "medium": 8192, "xhigh": 8192},
                "chars_per_token": 64.0,
            },
        },
        "sampling": {"temperature": 1.0, "top_p": 0.95},
        "max_tokens": {"low": 4096, "medium": 8192, "high": 16384},
    },
    "agent": {
        "max_steps": 80,
        "max_tool_calls": 120,
        "subagent_budget": 30,
        "context_compact_ratio": 0.70,
        "history_max_messages": 200,
        "max_context_tokens": 30000,
        "loop_detection": {"repeat": 3},
        "continue_on_length": True,
        "reasoning_effort": None,
        "mode": "interactive",
        "max_wall_time_s": 900,
        "max_tool_errors_in_row": 5,
        "max_invalid_calls": 5,
    },
    "subagents": {"max_depth": 2, "max_subagents": 20},
    "permissions": {
        "workspace_root": ".",
        "allow_write": True,
        "allow_delete": False,
        "confirm": "ask",
        "deny": [],
        "control_plane": ["AGENTS.md", "agents", "agents/**", "skills", "skills/**", ".pi", ".pi/**", ".agent", ".agent/**"],
        # Empty by default: application source/tests/scripts are work-zone writable.
        # Global administrators may explicitly add protected paths, but workspace config
        # is never allowed to remove them.
        "control_plane_write": [],
        "deny_patterns": [
            ".env*", "*.pem", "*.key", "id_rsa*", "credentials*", "secrets*",
            ".agent", ".agent.*", "*.agent.bak", "*.tmp-*",
        ],
        "backup": True,
        "max_file_bytes": 2_000_000,
        "max_read_bytes": 2_000_000,
        "max_changes": 200,
    },
    "exec": {
        "mode": "off",
        "enabled": False,  # legacy compatibility; runtime uses mode
        "isolation": "best_effort",
        "timeout_s": 120,
        "output_limit": 12000,
        "python": None,
        "cpu_s": 120,
        "fsize_bytes": 50_000_000,
        "nofile": 4096,
        "allow_module": True,
        "pythonpath": [],
        "java_home": None,
        "spark_home": None,
    },
    "kb": {"path": ".agent/kb.sqlite", "chunk_chars": 1800},
    "logging": {"dir": ".agent/logs", "redact_keys": ["api_key", "authorization", "token", "password", "secret"]},
}


class ConfigError(ValueError):
    """Raised when the resolved configuration is structurally invalid."""


def merge(a, b):
    """Deep-merge mapping ``b`` into a copy of mapping ``a``.

    Nested dictionaries are merged recursively; every other value replaces the
    value from ``a``.  The input objects are not mutated.
    """
    if not isinstance(a, dict):
        raise ConfigError("configuration base must be a mapping")
    if b is None:
        b = {}
    if not isinstance(b, dict):
        raise ConfigError("configuration source must be a mapping")
    out = deepcopy(a)
    for k, v in b.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _env(d):
    """Apply only operator-safe environment overrides. Execution is config-file-only."""
    blocked_roots = {"exec", "config"}
    for k, v in os.environ.items():
        if not k.startswith("LOCALAGENT_"):
            continue
        parts = k[len("LOCALAGENT_"):].lower().split("__")
        if not parts or parts[0] in blocked_roots or k == "LOCALAGENT_CONFIG":
            continue
        cur = d
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = yaml.safe_load(v)
    return d


def _keys(mapping, allowed, path):
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ConfigError(f"unknown configuration key(s) at {path}: {', '.join(unknown)}")


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _list_of(mapping, key, path, item_type=str):
    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(x, item_type) and not isinstance(x, bool) for x in value):
        raise ConfigError(f"{path}.{key} must be a list of {item_type.__name__}")


def _workspace_relative_path(value, key):
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{key} must be a non-empty workspace-relative path")
    candidate = Path(value)
    if candidate.is_absolute() or "\\" in value or ".." in candidate.parts:
        raise ConfigError(f"{key} must be workspace-relative and may not contain '..'")


def validate(c):
    """Strictly validate every supported configuration key and cross-field invariant."""
    top = {"llm", "agent", "subagents", "permissions", "exec", "kb", "logging"}
    _keys(c, top, "config")
    for sec in top:
        if not isinstance(c.get(sec), dict):
            raise ConfigError(f"{sec} must be a mapping")

    llm = c["llm"]
    _keys(llm, {"base_url", "api_key_env", "api_key_file", "http_referer", "x_title", "connect_timeout_s", "idle_timeout_s",
                "verify_ssl", "trusted_hosts", "allow_external", "ca_bundle", "proxy", "retry", "models", "profiles", "sampling", "max_tokens",
                "reasoning_format"}, "llm")
    for key in ("base_url", "api_key_env"):
        if not isinstance(llm[key], str) or not llm[key]:
            raise ConfigError(f"llm.{key} must be a non-empty string")
    if llm["reasoning_format"] not in {"chat_template", "openrouter"}:
        raise ConfigError("llm.reasoning_format must be 'chat_template' or 'openrouter'")
    for key in ("api_key_file", "ca_bundle", "proxy", "http_referer", "x_title"):
        if llm[key] is not None and not isinstance(llm[key], str):
            raise ConfigError(f"llm.{key} must be string or null")
    if not isinstance(llm.get("allow_external", False), bool):
        raise ConfigError("llm.allow_external must be boolean")
    if not isinstance(llm["trusted_hosts"], list) or not all(isinstance(x, str) and x for x in llm["trusted_hosts"]):
        raise ConfigError("llm.trusted_hosts must be a list of non-empty hostnames")
    if not llm["verify_ssl"]:
        hostname = (urlparse(llm["base_url"]).hostname or "").lower()
        trusted = {str(x).lower() for x in llm["trusted_hosts"]}
        if not hostname or hostname not in trusted:
            raise ConfigError("llm.verify_ssl=false requires llm.base_url hostname in llm.trusted_hosts")
    if llm["api_key_file"]:
        key_path = Path(llm["api_key_file"]).expanduser()
        if not key_path.is_file():
            raise ConfigError("llm.api_key_file must point to an existing file")
        if key_path.stat().st_mode & 0o077:
            raise ConfigError("llm.api_key_file must not be readable by group or other users")
    if llm["ca_bundle"]:
        ca_path = Path(llm["ca_bundle"]).expanduser()
        if not ca_path.is_file():
            raise ConfigError("llm.ca_bundle must point to an existing file")
    for key in ("connect_timeout_s", "idle_timeout_s"):
        if not _is_number(llm[key]) or llm[key] <= 0:
            raise ConfigError(f"llm.{key} must be > 0")
    if not isinstance(llm["verify_ssl"], bool):
        raise ConfigError("llm.verify_ssl must be boolean")

    retry = llm["retry"]
    _keys(retry, {"max_attempts", "backoff_s", "statuses"}, "llm.retry")
    if not isinstance(retry["max_attempts"], int) or isinstance(retry["max_attempts"], bool) or retry["max_attempts"] < 1:
        raise ConfigError("llm.retry.max_attempts must be >= 1")
    if not _is_number(retry["backoff_s"]) or retry["backoff_s"] < 0:
        raise ConfigError("llm.retry.backoff_s must be >= 0")
    _list_of(retry, "statuses", "llm.retry", int)
    if not all(100 <= x <= 599 for x in retry["statuses"]):
        raise ConfigError("llm.retry.statuses must contain HTTP status codes")

    models = llm["models"]
    _keys(models, {"default", "qwen"}, "llm.models")
    for key in models:
        if not isinstance(models[key], str) or not models[key]:
            raise ConfigError(f"llm.models.{key} must be a non-empty string")

    sampling = llm["sampling"]
    _keys(sampling, {"temperature", "top_p"}, "llm.sampling")
    if not _is_number(sampling["temperature"]) or sampling["temperature"] < 0:
        raise ConfigError("llm.sampling.temperature must be >= 0")
    if not _is_number(sampling["top_p"]) or not 0 <= sampling["top_p"] <= 1:
        raise ConfigError("llm.sampling.top_p must be in [0,1]")

    max_tokens = llm["max_tokens"]
    if not isinstance(max_tokens, dict) or not max_tokens:
        raise ConfigError("llm.max_tokens must be a non-empty mapping")
    for effort, budget in max_tokens.items():
        if not isinstance(effort, str) or not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
            raise ConfigError("llm.max_tokens values must be positive integers")

    profiles = llm["profiles"]
    if not isinstance(profiles, dict) or not profiles:
        raise ConfigError("llm.profiles must be a non-empty mapping")
    for model, profile in profiles.items():
        if not isinstance(model, str) or not model:
            raise ConfigError("llm.profiles keys must be non-empty strings")
        if not isinstance(profile, dict):
            raise ConfigError(f"llm.profiles.{model} must be a mapping")
        _keys(profile, {"reasoning_efforts", "default_reasoning_effort", "sampling", "context_window",
                        "max_output", "max_tokens", "chars_per_token"}, f"llm.profiles.{model}")
        _list_of(profile, "reasoning_efforts", f"llm.profiles.{model}", str)
        if not profile["reasoning_efforts"]:
            raise ConfigError(f"llm.profiles.{model}.reasoning_efforts must not be empty")
        if profile["default_reasoning_effort"] not in profile["reasoning_efforts"]:
            raise ConfigError(f"invalid default_reasoning_effort for {model}")
        if not isinstance(profile["context_window"], int) or profile["context_window"] <= 0:
            raise ConfigError(f"llm.profiles.{model}.context_window invalid")
        if not isinstance(profile["max_output"], int) or profile["max_output"] <= 0:
            raise ConfigError(f"llm.profiles.{model}.max_output invalid")
        if profile["max_output"] > profile["context_window"]:
            raise ConfigError(f"llm.profiles.{model}.max_output exceeds context_window")
        if not _is_number(profile["chars_per_token"]) or profile["chars_per_token"] <= 0:
            raise ConfigError(f"llm.profiles.{model}.chars_per_token invalid")
        ps = profile["sampling"]
        _keys(ps, {"temperature", "top_p", "top_k"}, f"llm.profiles.{model}.sampling")
        if not _is_number(ps["temperature"]) or ps["temperature"] < 0:
            raise ConfigError(f"llm.profiles.{model}.sampling.temperature invalid")
        if not _is_number(ps["top_p"]) or not 0 <= ps["top_p"] <= 1:
            raise ConfigError(f"llm.profiles.{model}.sampling.top_p invalid")
        if "top_k" in ps and (not isinstance(ps["top_k"], int) or ps["top_k"] < 1):
            raise ConfigError(f"llm.profiles.{model}.sampling.top_k invalid")
        if not isinstance(profile["max_tokens"], dict):
            raise ConfigError(f"llm.profiles.{model}.max_tokens must be a mapping")
        effort_names = set(profile["reasoning_efforts"])
        if set(profile["max_tokens"]) != effort_names:
            raise ConfigError(f"llm.profiles.{model}.max_tokens must define exactly one budget per reasoning effort")
        for effort, budget in profile["max_tokens"].items():
            if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
                raise ConfigError(f"llm.profiles.{model}.max_tokens.{effort} invalid")
    for name in {models["default"], models["qwen"]}:
        if name not in profiles:
            raise ConfigError(f"llm model {name!r} has no local profile")

    agent = c["agent"]
    _keys(agent, {"max_steps", "max_tool_calls", "subagent_budget",
                  "context_compact_ratio", "history_max_messages", "max_context_tokens", "loop_detection",
                  "continue_on_length", "reasoning_effort", "mode", "max_wall_time_s",
                  "max_tool_errors_in_row", "max_invalid_calls"}, "agent")
    for key in ("max_steps", "max_tool_calls", "subagent_budget",
                "history_max_messages", "max_context_tokens",
                "max_tool_errors_in_row", "max_invalid_calls"):
        value = agent[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ConfigError(f"agent.{key} must be a positive integer")
    if not _is_number(agent["max_wall_time_s"]) or agent["max_wall_time_s"] <= 0:
        raise ConfigError("agent.max_wall_time_s must be > 0")
    if not _is_number(agent["context_compact_ratio"]) or not 0 < agent["context_compact_ratio"] < 1:
        raise ConfigError("agent.context_compact_ratio must be in (0,1)")
    if agent["reasoning_effort"] is not None and not isinstance(agent["reasoning_effort"], str):
        raise ConfigError("agent.reasoning_effort must be string or null")
    if agent["mode"] not in {"interactive", "headless"}:
        raise ConfigError("agent.mode must be interactive|headless")
    if not isinstance(agent["continue_on_length"], bool):
        raise ConfigError("agent.continue_on_length must be boolean")
    _keys(agent["loop_detection"], {"repeat"}, "agent.loop_detection")
    if not isinstance(agent["loop_detection"]["repeat"], int) or isinstance(agent["loop_detection"]["repeat"], bool) or agent["loop_detection"]["repeat"] < 1:
        raise ConfigError("agent.loop_detection.repeat must be >= 1")

    sub = c["subagents"]
    _keys(sub, {"max_depth", "max_subagents"}, "subagents")
    if not isinstance(sub["max_depth"], int) or sub["max_depth"] < 0:
        raise ConfigError("subagents.max_depth must be >= 0")
    if not isinstance(sub["max_subagents"], int) or sub["max_subagents"] < 0:
        raise ConfigError("subagents.max_subagents must be >= 0")

    perms = c["permissions"]
    _keys(perms, {"workspace_root", "allow_write", "allow_delete", "confirm",
                  "deny_patterns", "deny", "control_plane", "control_plane_write", "backup", "max_file_bytes",
                  "max_read_bytes", "max_changes"}, "permissions")
    if not isinstance(perms["workspace_root"], str):
        raise ConfigError("permissions.workspace_root must be a string")
    _list_of(perms, "deny_patterns", "permissions", str)
    for key in ("deny", "control_plane", "control_plane_write"):
        if key in perms:
            _list_of(perms, key, "permissions", str)
    for key in ("allow_write", "allow_delete", "backup"):
        if not isinstance(perms[key], bool):
            raise ConfigError(f"permissions.{key} must be boolean")
    if perms["confirm"] not in {"ask", "auto_edit", "auto"}:
        raise ConfigError("permissions.confirm must be ask|auto_edit|auto")
    for key in ("max_file_bytes", "max_read_bytes", "max_changes"):
        if not isinstance(perms[key], int) or perms[key] < 1:
            raise ConfigError(f"permissions.{key} must be >= 1")

    execution = c["exec"]
    _keys(execution, {"mode", "enabled", "timeout_s", "output_limit", "python", "cpu_s", "fsize_bytes", "nofile", "as_bytes", "nproc", "allow_module", "pythonpath", "java_home", "spark_home", "isolation", "rw_dirs", "ro_paths"}, "exec")
    if not isinstance(execution.get("enabled", False), bool):
        raise ConfigError("exec.enabled must be boolean")
    if not isinstance(execution.get("allow_module", False), bool):
        raise ConfigError("exec.allow_module must be boolean")
    if not isinstance(execution.get("pythonpath", []), list) or not all(isinstance(x, str) and x for x in execution.get("pythonpath", [])):
        raise ConfigError("exec.pythonpath must be a list of non-empty strings")
    for key in ("java_home", "spark_home"):
        if execution.get(key) is not None and (not isinstance(execution[key], str) or not execution[key]):
            raise ConfigError(f"exec.{key} must be a non-empty string or null")
    for key in ("as_bytes", "nproc"):
        if key in execution and (not isinstance(execution[key], int) or execution[key] < 1):
            raise ConfigError(f"exec.{key} must be >= 1")
    isolation = execution.get("isolation", "best_effort")
    if isolation not in {"kernel", "best_effort", "app"}:
        raise ConfigError("exec.isolation must be kernel|best_effort|app")
    for key in ("rw_dirs", "ro_paths"):
        if key in execution and (not isinstance(execution[key], list) or not all(isinstance(x, str) and x for x in execution[key])):
            raise ConfigError(f"exec.{key} must be a list of non-empty strings")
    if execution.get("mode", "off") not in {"off", "ask", "auto"}:
        raise ConfigError("exec.mode must be off|ask|auto")
    if not _is_number(execution["timeout_s"]) or execution["timeout_s"] <= 0:
        raise ConfigError("exec.timeout_s must be > 0")
    if not isinstance(execution["output_limit"], int) or execution["output_limit"] < 1:
        raise ConfigError("exec.output_limit must be >= 1")
    kb = c["kb"]
    _keys(kb, {"path", "chunk_chars"}, "kb")
    _workspace_relative_path(kb["path"], "kb.path")
    if not isinstance(kb["chunk_chars"], int) or kb["chunk_chars"] < 1:
        raise ConfigError("kb.chunk_chars must be >= 1")

    logging = c["logging"]
    _keys(logging, {"dir", "redact_keys"}, "logging")
    _workspace_relative_path(logging["dir"], "logging.dir")
    _list_of(logging, "redact_keys", "logging", str)


def _migrate_legacy_agent_config(data: dict) -> None:
    """Normalize the removed loop_repeat alias without retaining a second runtime setting."""
    agent = data.get("agent")
    if not isinstance(agent, dict) or "loop_repeat" not in agent:
        return
    legacy = agent.pop("loop_repeat")
    loop_detection = agent.setdefault("loop_detection", {})
    if not isinstance(loop_detection, dict):
        raise ConfigError("agent.loop_detection must be a mapping")
    current = loop_detection.get("repeat")
    if current is not None and current != legacy:
        raise ConfigError("agent.loop_repeat conflicts with agent.loop_detection.repeat")
    loop_detection["repeat"] = legacy




def _load_yaml_mapping(path: Path, *, root: Path, required_name: str) -> dict:
    """Load a YAML mapping, rejecting workspace config symlinks that escape the workspace."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"cannot resolve {required_name}") from exc
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ConfigError(f"{required_name} must remain inside the workspace")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {required_name}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{required_name} must contain a mapping at the top level")
    return raw


def load_config(workspace=".", cli=None):
    """Resolve and validate configuration for ``workspace``.

    The load order is defaults -> global config -> workspace config ->
    environment overrides -> explicit ``cli`` mapping.  The resulting
    ``permissions.workspace_root`` is always replaced with the absolute
    workspace path. A removed ``agent.loop_repeat`` alias is migrated only when
    it does not conflict with the canonical ``agent.loop_detection.repeat`` value.
    """
    root = Path(workspace).resolve()
    data = deepcopy(DEFAULTS)
    global_cfg = Path(os.environ.get("LOCALAGENT_CONFIG", "~/.config/localagent/config.yaml")).expanduser()
    for p in (global_cfg, root / ".agent/config.yaml"):
        if p.exists():
            if p == root / ".agent/config.yaml":
                source = _load_yaml_mapping(p, root=root, required_name="workspace config")
                # Security-sensitive sections are administrative.  Validate their
                # shape so typos are not silently accepted, then discard their
                # values so an untrusted repository cannot weaken the policy.
                if "permissions" in source and isinstance(source["permissions"], dict):
                    _keys(source["permissions"], {"workspace_root", "allow_write", "allow_delete", "confirm",
                                                   "deny_patterns", "deny", "control_plane", "control_plane_write",
                                                   "backup", "max_file_bytes", "max_read_bytes", "max_changes"},
                          "workspace permissions")
                    # Workspace config may only add protected paths; it cannot remove
                    # administrator-controlled control-plane protections.
                    workspace_perms = source["permissions"]
                    source["permissions"] = {
                        "control_plane": list(dict.fromkeys(
                            data["permissions"]["control_plane"] + workspace_perms.get("control_plane", [])
                        )),
                        "control_plane_write": list(dict.fromkeys(
                            data["permissions"]["control_plane_write"] + workspace_perms.get("control_plane_write", [])
                        )),
                    }
                for section in ("exec", "llm", "logging", "kb"):
                    source.pop(section, None)
            else:
                try:
                    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
                    raise ConfigError("cannot read global config") from exc
                if raw is None:
                    source = {}
                elif isinstance(raw, dict):
                    source = raw
                else:
                    raise ConfigError("global config must contain a mapping at the top level")
            data = merge(data, source)
    data = _env(data)
    data = merge(data, cli or {})
    _migrate_legacy_agent_config(data)
    validate(data)
    data["permissions"]["workspace_root"] = str(root)
    return data
