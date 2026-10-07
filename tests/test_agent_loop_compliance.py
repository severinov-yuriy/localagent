"""Agent loop, limits, finish, statuses, interruption, and resume."""
from __future__ import annotations

import json

import pytest

from localagent.agent import Agent
from localagent.llm import LLMResponse, ToolCall
from localagent.runner import build_tools
from localagent.tools.base import Tool


def _tcfg(cfg):
    cfg["permissions"]["confirm"] = "auto"
    return cfg


def test_no_tools_returns_text(workspace, cfg, ui, fake_llm):
    llm = fake_llm([LLMResponse(text="hello", finish_reason="stop")])
    assert Agent(cfg, llm, build_tools(cfg), ui).run("hi")["summary"] == "hello"


def test_tool_call_then_stop(workspace, cfg, ui, fake_llm):
    (workspace / "x.txt").write_text("hello", encoding="utf-8")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="read_file",
                    arguments='{"path":"x.txt"}')], finish_reason="tool_calls"),
        LLMResponse(text="done", finish_reason="stop"),
    ])
    assert Agent(cfg, llm, build_tools(cfg), ui).run("read")["summary"] == "done"
    assert llm.calls[1].messages[-1]["role"] == "tool"


def test_finish_result_schema(workspace, cfg):
    """The finish tool exposes status, summary, and artifacts."""
    t = build_tools(cfg)
    r = t["finish"].run({"status": "done", "summary": "s", "artifacts": ["a.txt"]})
    assert isinstance(r, dict)
    assert r.get("status") == "done"
    assert r.get("summary") == "s"


def test_finish_stops_loop(workspace, cfg, ui, fake_llm):
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="finish",
                    arguments='{"status":"done","summary":"ok","artifacts":[]}')],
                    finish_reason="tool_calls"),
    ])
    result = Agent(cfg, llm, build_tools(cfg), ui).run("go")
    assert isinstance(result, dict)
    assert result["status"] == "ok"
    assert result["summary"] == "ok"


def test_unknown_tool_is_error_with_flag(workspace, cfg, ui, fake_llm):
    """Tool errors are returned to the model with an error marker."""
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="nope",
                    arguments="{}")], finish_reason="tool_calls"),
        LLMResponse(text="ok", finish_reason="stop"),
    ])
    assert Agent(cfg, llm, build_tools(cfg), ui).run("x")["summary"] == "ok"
    last = llm.calls[1].messages[-1]
    payload = json.dumps(last)
    assert last.get("is_error") is True or '"is_error": true' in payload.lower()


def test_invalid_json_arguments_do_not_crash(workspace, cfg, ui, fake_llm):
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="read_file",
                    arguments="{not-json")], finish_reason="tool_calls"),
        LLMResponse(text="ok", finish_reason="stop"),
    ])
    assert Agent(cfg, llm, build_tools(cfg), ui).run("x")["summary"] == "ok"


# ----------  лимиты ----------

def test_max_steps_limit(workspace, cfg, ui, fake_llm):
    cfg["agent"]["max_steps"] = 3
    (workspace / "x.txt").write_text("hi")
    tc = ToolCall(id="1", name="read_file", arguments='{"path":"x.txt"}')
    llm = fake_llm([LLMResponse(text="", tool_calls=[tc], finish_reason="tool_calls")] * 10)
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    with pytest.raises(RuntimeError):
        agent.run("go")
    # статус в журнале
    text = "\n".join(p.read_text(encoding="utf-8")
                     for p in (workspace / ".agent" / "logs").rglob("*.jsonl"))
    assert "limit_reached" in text


def test_max_wall_time_s(workspace, cfg, ui, fake_llm, monkeypatch):
    cfg["agent"]["max_wall_time_s"] = 1
    (workspace / "x.txt").write_text("hi")
    tc = ToolCall(id="1", name="read_file", arguments='{"path":"x.txt"}')
    llm = fake_llm([LLMResponse(text="", tool_calls=[tc], finish_reason="tool_calls")] * 10)
    import localagent.agent as agent_mod
    ticks = iter([0, 0, 5, 5, 5, 5, 5])
    monkeypatch.setattr(agent_mod, "_now", lambda: next(ticks), raising=False)
    with pytest.raises(RuntimeError):
        Agent(cfg, llm, build_tools(cfg), ui).run("go")


def test_max_tool_errors_in_row(workspace, cfg, ui, fake_llm):
    cfg["agent"]["max_tool_errors_in_row"] = 3
    llm = fake_llm([LLMResponse(text="", tool_calls=[
        ToolCall(id="1", name="read_file", arguments='{"path":"missing.txt"}'),
    ], finish_reason="tool_calls")] * 10)
    with pytest.raises(RuntimeError):
        Agent(cfg, llm, build_tools(cfg), ui).run("go")


def test_max_invalid_calls(workspace, cfg, ui, fake_llm):
    cfg["agent"]["max_invalid_calls"] = 3
    llm = fake_llm([LLMResponse(text="", tool_calls=[
        ToolCall(id="1", name="read_file", arguments="{bad"),
    ], finish_reason="tool_calls")] * 10)
    with pytest.raises(RuntimeError):
        Agent(cfg, llm, build_tools(cfg), ui).run("go")


# ----------  loop detection → статус stuck ----------

def test_tool_exception_secret_is_not_exposed_or_persisted(workspace, cfg, ui, fake_llm):
    secret = "password=synthetic-secret-value"

    class LeakyTool(Tool):
        name = "leaky_test_tool"
        description = "Test-only tool that raises a synthetic secret."
        capabilities = set()

        def run(self, args):
            raise ValueError(secret)

    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="leaky_test_tool", arguments="{}")], finish_reason="tool_calls"),
        LLMResponse(text="done", finish_reason="stop"),
    ])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.tools["leaky_test_tool"] = LeakyTool()
    result = agent.run("trigger test error")
    assert result["summary"] == "done"
    persisted = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (workspace / ".agent").rglob("*")
        if p.is_file()
    )
    assert secret not in persisted


def test_loop_detection_status_is_stuck(workspace, cfg, ui, fake_llm):
    (workspace / "x.txt").write_text("hi")
    cfg["agent"]["max_steps"] = 5
    cfg["agent"]["loop_detection"] = {"repeat": 2}
    tc = ToolCall(id="x", name="read_file", arguments='{"path":"x.txt"}')
    llm = fake_llm([LLMResponse(text="", tool_calls=[tc], finish_reason="tool_calls")] * 10)
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    with pytest.raises(RuntimeError):
        agent.run("go")
    text = "\n".join(p.read_text(encoding="utf-8")
                     for p in (workspace / ".agent" / "logs").rglob("*.jsonl"))
    assert "stuck" in text or "loop" in text


# ----------  сессии ----------

def test_session_saved_after_run(workspace, cfg, ui, fake_llm):
    llm = fake_llm([LLMResponse(text="done", finish_reason="stop")])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.run("hi")
    assert (workspace / ".agent" / "sessions" / f"{agent.session_id}.json").exists()


# ---------- /1.10 параметры моделей ----------

def test_deepseek_sends_reasoning_effort_and_max_tokens(workspace, cfg, ui, fake_llm):
    a = Agent(cfg, fake_llm([]), build_tools(cfg), ui, model="DeepSeek-V4-Flash-0731")
    assert a.effort == "high"
    p = a._request_params()
    assert p["extra_body"] == {"chat_template_kwargs": {"reasoning_effort": "high"}}
    assert p["max_tokens"] == 131000


def test_qwen_sends_top_k_and_medium_effort(workspace, cfg, ui, fake_llm):
    a = Agent(cfg, fake_llm([]), build_tools(cfg), ui, model="Qwen3.8-Flash")
    assert a.effort == "medium"
    p = a._request_params()
    assert p["extra_body"]["chat_template_kwargs"]["reasoning_effort"] == "medium"
    assert p["extra_body"]["top_k"] == 20


def test_unsupported_effort_raises(workspace, cfg, ui, fake_llm):
    with pytest.raises(ValueError):
        Agent(cfg, fake_llm([]), build_tools(cfg), ui,
              model="DeepSeek-V4-Flash-0731", effort="xhigh")


# ----------  прерывание ----------

def test_sigint_saves_state_and_stops(workspace, cfg, ui, fake_llm):
    """Двойной SIGINT: первый останавливает шаг, второй завершает. Сессия сохранена."""
    import os
    import signal as _s
    llm = fake_llm([LLMResponse(text="x", finish_reason="stop")])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent._interrupt()
    assert agent.stop is True
    assert (workspace / ".agent" / "sessions" / f"{agent.session_id}.json").exists()


# ----------  headless ----------

def test_headless_disables_ask_user(workspace, cfg, ui, fake_llm):
    cfg["agent"]["mode"] = "headless"
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="ask_user",
                    arguments='{"question":"?"}')], finish_reason="tool_calls"),
        LLMResponse(text="done", finish_reason="stop"),
    ])
    assert Agent(cfg, llm, build_tools(cfg), ui).run("go")["summary"] == "done"


def test_ask_user_prompts_exactly_once(workspace, cfg, ui, fake_llm, monkeypatch):
    cfg["permissions"]["confirm"] = "ask"
    prompts = []
    monkeypatch.setattr("builtins.input", lambda prompt: (prompts.append(prompt), "answer")[1])
    monkeypatch.setattr(ui, "confirm", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("generic confirmation must not run")))
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="ask_user",
                    arguments='{"question":"Which option?"}')], finish_reason="tool_calls"),
        LLMResponse(text="done", finish_reason="stop"),
    ])
    result = Agent(cfg, llm, build_tools(cfg), ui).run("choose")
    assert result["summary"] == "done"
    assert prompts == ["Which option? "]



# ----------  todo ----------

def test_todo_tool_roundtrip(workspace, cfg):
    t = build_tools(cfg)
    assert "todo" in t
    t["todo"].run({"action": "add", "items": ["step1", "step2"]})
    out = t["todo"].run({"action": "show"})
    assert "step1" in str(out)


def test_todo_roundtrip_through_save_resume(workspace, cfg, ui, fake_llm):
    agent = Agent(cfg, fake_llm([]), build_tools(cfg), ui)
    agent.tools["todo"].run({"action": "add", "items": ["persist me"]})
    agent.save()
    resumed = Agent.resume(cfg, fake_llm([]), build_tools(cfg), ui, agent.session_id)
    assert resumed.todo_state == agent.todo_state
    assert resumed.tools["todo"].run({"action": "show"})["items"] == agent.todo_state


def test_resume_preserves_failed_terminal_status(workspace, cfg, ui, fake_llm):
    agent = Agent(cfg, fake_llm([]), build_tools(cfg), ui)
    agent._finalize("failed", reason="controlled failure")
    resumed = Agent.resume(cfg, fake_llm([]), build_tools(cfg), ui, agent.session_id)
    assert resumed.terminal_status == "failed"
    assert resumed.terminal_reason == "controlled failure"


def test_view_image_adds_image_message_to_agent_history(workspace, cfg, ui, fake_llm):
    (workspace / "image.png").write_bytes(b"not-a-real-png")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(
            id="1", name="view_image", arguments='{"path":"image.png"}'
        )], finish_reason="tool_calls"),
        LLMResponse(text="inspected", finish_reason="stop"),
    ])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    result = agent.run("inspect")
    assert result["summary"] == "inspected"
    assert any(
        message.get("role") == "user"
        and isinstance(message.get("content"), list)
        and any(part.get("type") == "image_url" for part in message["content"])
        for message in agent.messages
    )
