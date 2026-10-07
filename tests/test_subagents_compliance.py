"""Subagents, roles, budgets, history isolation, and parent linkage."""
from __future__ import annotations

import json

import pytest

from localagent.agent import Agent
from localagent.llm import LLMResponse, ToolCall
from localagent.runner import build_tools, load_role


# ---------- role front matter ----------

def test_role_frontmatter_is_parsed(workspace):
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\nmodel: deepseek\n"
        "tools: [read_file, finish]\n"
        "permissions:\n  write: []\n"
        "---\nBody\n",
        encoding="utf-8",
    )
    role = load_role(workspace, "reviewer")
    assert role["name"] == "reviewer"
    assert set(role["tools"]) == {"read_file", "finish"}
    assert role["permissions"]["write"] == []


def test_load_role_blocks_traversal(workspace):
    with pytest.raises(ValueError):
        load_role(workspace, "../secret")


def test_role_name_contract_allows_internal_dots_and_blocks_paths(workspace):
    role_path = workspace / "agents" / "my.role.md"
    role_path.write_text("---\nname: my.role\n---\nR\n", encoding="utf-8")
    assert load_role(workspace, "my.role")["name"] == "my.role"
    for bad in (".", "..", "../x", "x/y", "x\\y", ""):
        with pytest.raises(ValueError):
            load_role(workspace, bad)


# ---------- structured result ----------

def test_spawn_agent_returns_structured_result(workspace, cfg, ui, fake_llm):
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [read_file, finish]\npermissions:\n  write: []\n---\nR\n",
        encoding="utf-8",
    )
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="finish",
                    arguments='{"status":"done","summary":"ok","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    parent = Agent(cfg, llm, build_tools(cfg), ui)
    result = parent.subagent("reviewer", "review")
    assert isinstance(result, dict)
    for k in ("status", "summary", "artifacts", "notes", "agent_id"):
        assert k in result, f"missing {k}"


# ---------- policy intersection ----------

def test_child_policy_is_intersection(workspace, cfg, ui, fake_llm):
    """Ребёнок-ревьюер не может писать, даже если родитель может."""
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [read_file, write_file, finish]\n"
        "permissions:\n  write: []\n---\nR\n",
        encoding="utf-8",
    )
    (workspace / "x.txt").write_text("hi")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="write_file",
                    arguments='{"path":"x.txt","content":"y"}')],
                    finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="2", name="finish",
                    arguments='{"status":"done","summary":"","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    parent = Agent(cfg, llm, build_tools(cfg), ui)
    parent.subagent("reviewer", "review")
    child_logs = list((workspace / ".agent" / "logs").rglob("*.jsonl"))
    text = "\n".join(p.read_text(encoding="utf-8") for p in child_logs)
    assert "permission_denied" in text


# ---------- history isolation ----------

def test_parent_does_not_see_child_history(workspace, cfg, ui, fake_llm):
    """The parent receives the child's structured result, not the child's history."""
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [finish]\n---\nR\n", encoding="utf-8"
    )
    llm = fake_llm([
        LLMResponse(text="PUBLIC_SUMMARY", finish_reason="stop"),
    ])
    parent = Agent(cfg, llm, build_tools(cfg), ui)
    result = parent.subagent("reviewer", "PRIVATE_CHILD_HISTORY")

    assert result["status"] == "ok"
    assert result["summary"] == "PUBLIC_SUMMARY"
    flat = json.dumps(parent.messages, ensure_ascii=False)
    assert "PRIVATE_CHILD_HISTORY" not in flat


# ---------- limits ----------

def test_subagent_depth_limit(workspace, cfg, ui, fake_llm):
    cfg["subagents"]["max_depth"] = 1
    (workspace / "agents" / "a.md").write_text(
        "---\nname: a\ntools: [spawn_agent, finish]\n---\nA\n", encoding="utf-8"
    )
    (workspace / "agents" / "b.md").write_text(
        "---\nname: b\ntools: [spawn_agent, finish]\n---\nB\n", encoding="utf-8"
    )
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="spawn_agent",
                    arguments='{"role":"b","task":"x"}')], finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="2", name="spawn_agent",
                    arguments='{"role":"a","task":"y"}')], finish_reason="tool_calls"),
    ])
    parent_role = {"name": "parent", "tools": ["spawn_agent", "finish"], "permissions": {}}
    holder = {}
    tools = build_tools(cfg, subagent_runner=lambda role, task: holder["agent"].subagent(role, task))
    holder["agent"] = Agent(cfg, llm, tools, ui, role_object=parent_role)
    with pytest.raises(RuntimeError, match="subagent depth limit reached"):
        holder["agent"].subagent("a", "deep")


# ---------- parent linkage in audit ----------

def test_child_events_have_parent_id(workspace, cfg, ui, fake_llm):
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [finish]\n---\nR\n", encoding="utf-8"
    )
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="finish",
                    arguments='{"status":"done","summary":"","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    parent = Agent(cfg, llm, build_tools(cfg), ui)
    parent.subagent("reviewer", "review")
    for f in (workspace / ".agent" / "logs").rglob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            ev = json.loads(line)
            if ev.get("agent_id") != parent.agent_id:
                assert ev.get("parent_id") == parent.agent_id, f"missing parent_id in {ev}"


# ---------- headless behavior ----------

def test_headless_child_confirm_denied(workspace, cfg, ui, fake_llm):
    cfg["agent"]["mode"] = "headless"
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [write_file, finish]\n---\nR\n", encoding="utf-8"
    )
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="write_file",
                    arguments='{"path":"x.txt","content":"y"}')],
                    finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="2", name="finish",
                    arguments='{"status":"done","summary":"","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    cfg["permissions"]["confirm"] = "ask"
    result = Agent(cfg, llm, build_tools(cfg), ui).subagent("reviewer", "x")
    # Не зависает, возвращает результат
    assert isinstance(result, dict)
