"""End-to-end acceptance scenarios for the public runtime contract."""
from __future__ import annotations

import json

import pytest

from localagent.agent import Agent
from localagent.llm import LLMResponse, ToolCall
from localagent.runner import build_tools
from localagent.tools.sandbox import backend_status


# ---------- filesystem boundary ----------

def test_ac3_out_of_workspace_rejected_with_event(workspace, cfg, ui, fake_llm):
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="read_file",
                    arguments='{"path":"../etc/passwd"}')],
                    finish_reason="tool_calls"),
        LLMResponse(text="ok", finish_reason="stop"),
    ])
    Agent(cfg, llm, build_tools(cfg), ui).run("x")
    text = "\n".join(p.read_text(encoding="utf-8")
                     for p in (workspace / ".agent" / "logs").rglob("*.jsonl"))
    assert "permission_denied" in text


# ---------- backup and undo ----------

def test_ac4_backup_and_undo_is_bit_exact(workspace, cfg):
    t = build_tools(cfg)
    original = b"line1\r\nline2\r\n"
    (workspace / "a.txt").write_bytes(original)
    t["edit_file"].run({"path": "a.txt", "old": "line2", "new": "CHANGED"})
    t["undo"].run({"path": "a.txt"})
    assert (workspace / "a.txt").read_bytes() == original


# ---------- end-to-end module execution ----------

@pytest.mark.timeout(60)
def test_ac5_write_artifact_and_run_trusted_tests(workspace, cfg, ui, fake_llm):
    """A trusted pre-existing test may execute, while agent-written tests cannot."""
    if not backend_status()["ready"]:
        pytest.skip("Linux kernel lacks the required Landlock + seccomp execution sandbox")
    cfg["exec"]["mode"] = "auto"
    (workspace / "tests" / "test_trusted_target.py").write_text(
        "from pathlib import Path\n\n"
        "def test_trusted_target():\n"
        "    assert Path('agent_payload.txt').read_text(encoding='utf-8') == 'payload'\n"
        "    Path('pytest-executed.marker').write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="write_file",
                    arguments=json.dumps({"path": "agent_payload.txt", "content": "payload"}))],
                    finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="2", name="run_tests",
                    arguments=json.dumps({"targets": ["tests/test_trusted_target.py"]}))],
                    finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="3", name="finish",
                    arguments='{"status":"done","summary":"verified","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    result = Agent(cfg, llm, build_tools(cfg), ui).run("create the payload and verify it")
    assert result["status"] == "ok"
    assert (workspace / "pytest-executed.marker").read_text(encoding="utf-8") == "executed"


# ---------- read-only reviewer subagent ----------

def test_ac6_reviewer_cannot_write(workspace, cfg, ui, fake_llm):
    (workspace / "agents" / "reviewer.md").write_text(
        "---\nname: reviewer\ntools: [read_file, write_file, finish]\n"
        "permissions:\n  write: []\n---\nR\n", encoding="utf-8",
    )
    (workspace / "x.txt").write_text("hi")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="write_file",
                    arguments='{"path":"x.txt","content":"bad"}')],
                    finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(id="2", name="finish",
                    arguments='{"status":"done","summary":"ok","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    parent = Agent(cfg, llm, build_tools(cfg), ui)
    result = parent.subagent("reviewer", "review")
    assert isinstance(result, dict) and result.get("status") in ("ok", "failed")
    assert (workspace / "x.txt").read_text() == "hi"  # не изменён


# ---------- resume ----------

def test_ac8_resume_continues(workspace, cfg, ui, fake_llm):
    llm = fake_llm([LLMResponse(text="one", finish_reason="stop"),
                    LLMResponse(text="two", finish_reason="stop")])
    a1 = Agent(cfg, llm, build_tools(cfg), ui)
    a1.run("hi")
    a2 = Agent.resume(cfg, llm, build_tools(cfg), ui, a1.session_id)
    assert a2.messages == a1.messages
    assert a2.session_id == a1.session_id


def test_ac7_resume_preserves_saved_tool_acl(workspace, cfg, ui, fake_llm):
    """Resume restores the persisted tool ACL and cannot gain spawn_agent from the CLI/runtime."""
    llm = fake_llm([LLMResponse(text="saved", finish_reason="stop")])
    a1 = Agent(cfg, llm, build_tools(cfg), ui)
    assert "spawn_agent" not in a1.effective_tool_names
    a1.run("save")

    holder = {}
    tools = build_tools(cfg, subagent_runner=lambda role, task: holder["agent"].subagent(role, task))
    resumed = Agent.resume(cfg, fake_llm([LLMResponse(text="resumed", finish_reason="stop")]), tools, ui, a1.session_id)
    assert "spawn_agent" not in resumed.effective_tool_names
    assert resumed.model == a1.model
    assert resumed.effort == a1.effort


# ---------- secret persistence ----------

def test_ac9_no_api_key_in_agent_dir(workspace, cfg, monkeypatch, ui, fake_llm):
    monkeypatch.setenv("GENOPS_API_KEY", "KEY-TEST-SECRET")
    Agent(cfg, fake_llm([LLMResponse(text="ok", finish_reason="stop")]),
          build_tools(cfg), ui).run("hi")
    for f in (workspace / ".agent").rglob("*"):
        if f.is_file():
            try:
                assert "KEY-TEST-SECRET" not in f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                pass
