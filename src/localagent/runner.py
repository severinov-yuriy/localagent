"""Runtime assembly helpers for tools and role prompts."""

from __future__ import annotations

from pathlib import Path

import yaml

from .config import load_config
from .knowledge import KnowledgeBase
from .policy import FilesystemPolicy, Policy
from .security import DLPPolicy
from .tools.exec import RunModule, RunScript, RunTests
from .tools.syntax import CheckSyntax
from .tools.fs import ApplyPatch, Delete, EditFile, Glob, Grep, ListDir, MakeDir, Move, ReadFile, Undo, ViewImage, WriteFile
from .tools.kb import KBAdd, KBRead, KBSearch, ReadSkill
from .tools.meta import AskUser, Finish, Todo
from .tools.subagent import SpawnAgent


def build_tools(cfg, subagent_runner=None, policy=None, allowed_tool_names=None):
    """Construct the configured tool registry for one agent instance."""
    p = policy or Policy(cfg)
    dlp = DLPPolicy()
    root = Path(cfg["permissions"]["workspace_root"])
    kb = KnowledgeBase(root / cfg["kb"]["path"], cfg["kb"]["chunk_chars"], policy=p)
    skill_roots = [x for x in (root / "skills", root / ".pi" / "skills") if x.is_dir()]
    ts = [
        ReadFile(p, dlp), CheckSyntax(p), ListDir(p, dlp), Glob(p, dlp), Grep(p, dlp), WriteFile(p, dlp), EditFile(p, dlp),
        ApplyPatch(p, dlp), MakeDir(p, dlp), Move(p, dlp), Delete(p, dlp), Undo(p, dlp), ViewImage(p, dlp),
        Finish(), Todo(), AskUser(), ReadSkill(skill_roots, p, dlp), KBSearch(kb, dlp), KBRead(kb, p, dlp), KBAdd(kb, p, dlp),
    ]
    exec_cfg = cfg.get("exec", {})
    exec_mode = exec_cfg.get("mode", "off")
    if exec_mode != "off" or exec_cfg.get("enabled", False):
        ts.extend([RunScript(cfg, p, dlp), RunTests(cfg, p, dlp)])
        if exec_cfg.get("allow_module", True):
            ts.append(RunModule(cfg, p, dlp))
    if subagent_runner:
        ts.append(SpawnAgent(subagent_runner))
    tools = {t.name: t for t in ts}
    if allowed_tool_names is not None:
        allowed = set(allowed_tool_names)
        tools = {name: tool for name, tool in tools.items() if name in allowed}
    if cfg["agent"].get("mode") == "headless":
        tools.pop("ask_user", None)
    return tools


def _policy_for_root(root):
    return Policy(load_config(str(Path(root).resolve())))


def _role_path(root, role):
    if not role or "/" in role or "\\" in role or role in {".", ".."}:
        raise ValueError("invalid role name")
    return Path(root) / "agents" / f"{role}.md"


def load_role(root, role, policy: FilesystemPolicy | None = None):
    """Load and validate an ``agents/<role>.md`` YAML front matter block."""
    p = _role_path(root, role)
    runtime_policy = policy or _policy_for_root(root)
    try:
        authorized = runtime_policy.authorize(p, "read", actor="runtime")
    except (OSError, PermissionError) as exc:
        raise ValueError("role file access denied") from exc
    if not authorized.is_file():
        return {"name": role, "description": "", "tools": None, "permissions": {},
                "model": None, "reasoning_effort": None, "body": f"Role: {role}"}
    try:
        text = authorized.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("role file cannot be read") from exc
    metadata = {"name": role, "description": "", "tools": None, "permissions": {},
                "model": None, "reasoning_effort": None}
    body = text
    if text.startswith("---\n"):
        marker = text.find("\n---", 4)
        if marker < 0:
            raise ValueError(f"malformed role front matter: {role}")
        raw = text[4:marker]
        try:
            parsed = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"malformed role front matter: {role}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("role front matter must be a mapping")
        body = text[marker + len("\n---"):].lstrip("\n")
        for key in ("name", "description", "tools", "permissions", "model", "reasoning_effort"):
            if key in parsed:
                metadata[key] = parsed[key]
    elif text.startswith("---"):
        raise ValueError(f"malformed role front matter: {role}")
    if not isinstance(metadata["name"], str) or not metadata["name"]:
        raise ValueError("role.name must be a string")
    if not isinstance(metadata["description"], str):
        raise ValueError("role.description must be a string")
    if metadata["tools"] is not None and (not isinstance(metadata["tools"], list) or not all(isinstance(x, str) for x in metadata["tools"])):
        raise ValueError("role.tools must be a list of strings")
    if not isinstance(metadata["permissions"], dict):
        raise ValueError("role.permissions must be a mapping")
    for key in ("read", "write", "deny"):
        if key in metadata["permissions"] and (not isinstance(metadata["permissions"][key], list) or not all(isinstance(x, str) for x in metadata["permissions"][key])):
            raise ValueError(f"role.permissions.{key} must be a list of strings")
    if metadata["model"] is not None and not isinstance(metadata["model"], str):
        raise ValueError("role.model must be a string")
    if metadata["reasoning_effort"] is not None and not isinstance(metadata["reasoning_effort"], str):
        raise ValueError("role.reasoning_effort must be a string")
    metadata["body"] = body
    return metadata


def discover_role_names(root, policy: FilesystemPolicy | None = None):
    """Return role names from the same policy-controlled directory used by ``load_role``."""
    roles_root = Path(root) / "agents"
    names = []
    for candidate in sorted(roles_root.glob("*.md")):
        try:
            authorized = (policy or _policy_for_root(root)).authorize(candidate, "read", actor="runtime")
        except (OSError, PermissionError):
            continue
        if authorized.is_file():
            names.append(authorized.stem)
    return names
