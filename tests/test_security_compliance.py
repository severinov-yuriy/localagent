"""Сквозные инварианты безопасности."""
from __future__ import annotations

import json

import pytest

from localagent.agent import Agent
from localagent.llm import LLMResponse, ToolCall
from localagent.runner import build_tools


@pytest.mark.parametrize("path", ["../x", "../../etc/passwd", ".env",
                                  "key.pem", ".agent/config.yaml"])
def test_sensitive_or_outside_paths_rejected(workspace, cfg, path):
    with pytest.raises(PermissionError):
        build_tools(cfg)["read_file"].run({"path": path})


def test_permission_denied_event_logged(workspace, cfg, ui, fake_llm):
    """Permission-denied operations are recorded in the audit log."""
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


def test_api_key_never_in_journal(workspace, cfg, monkeypatch, ui, fake_llm):
    """."""
    monkeypatch.setenv("GENOPS_API_KEY", "SUPER-SECRET-KEY-42")
    Agent(cfg, fake_llm([LLMResponse(text="ok", finish_reason="stop")]),
          build_tools(cfg), ui).run("hi")
    for f in (workspace / ".agent").rglob("*.jsonl"):
        text = f.read_text(encoding="utf-8")
        assert "SUPER-SECRET-KEY-42" not in text
        assert text.strip(), "журнал не должен быть пустым"


def test_write_outside_workspace_rejected(workspace, cfg, tmp_path):
    with pytest.raises(PermissionError):
        build_tools(cfg)["write_file"].run(
            {"path": str(tmp_path / "out.txt"), "content": "x"})


def test_write_to_agents_dir_rejected(workspace, cfg):
    """Policy files are not writable by the agent."""
    with pytest.raises(PermissionError):
        build_tools(cfg)["write_file"].run(
            {"path": "agents/coder.md", "content": "x"})


def test_agents_md_write_rejected(workspace, cfg):
    """AGENTS.md is read-only for the agent."""
    with pytest.raises(PermissionError):
        build_tools(cfg)["write_file"].run(
            {"path": "AGENTS.md", "content": "x"})


def test_denied_confirmation_is_error_result(workspace, cfg, ui, fake_llm, monkeypatch):
    (workspace / "x.txt").write_text("hi")
    cfg["permissions"]["confirm"] = "ask"
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="write_file",
                    arguments='{"path":"x.txt","content":"y"}')],
                    finish_reason="tool_calls"),
        LLMResponse(text="ok", finish_reason="stop"),
    ])
    monkeypatch.setattr(ui, "confirm", lambda *a, **k: False)
    assert Agent(cfg, llm, build_tools(cfg), ui).run("do")["summary"] == "ok"


def test_tls_verification_off_warns_and_logs(workspace, cfg, ui, fake_llm):
    """Disabling TLS verification emits a security warning."""
    cfg["llm"]["verify_ssl"] = False
    Agent(cfg, fake_llm([LLMResponse(text="ok", finish_reason="stop")]),
          build_tools(cfg), ui).run("hi")
    text = "\n".join(p.read_text(encoding="utf-8")
                     for p in (workspace / ".agent" / "logs").rglob("*.jsonl"))
    assert "verify_ssl" in text or "ssl" in text.lower()


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("move", {"src": "a.txt", "dst": "b.txt"}),
        ("make_dir", {"path": "new-dir"}),
        ("apply_patch", {"patch": "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-a\n+b\n"}),
    ],
)
def test_mutation_permission_errors_are_audited(workspace, cfg, ui, fake_llm, monkeypatch, tool_name, arguments):
    tool = build_tools(cfg)[tool_name]
    monkeypatch.setattr(tool.p, "authorize", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("denied")))
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name=tool_name, arguments=json.dumps(arguments))], finish_reason="tool_calls"),
        LLMResponse(text="ok", finish_reason="stop"),
    ])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.tools[tool_name] = tool
    result = agent.run("mutate")
    assert result["summary"] == "ok"
    log = "\n".join(p.read_text(encoding="utf-8") for p in (workspace / ".agent" / "logs").rglob("*.jsonl"))
    assert any(json.loads(line).get("type") == "permission_denied" for line in log.splitlines())
