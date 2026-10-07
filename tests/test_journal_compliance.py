"""Audit event schema, required event types, redaction, and reports."""
from __future__ import annotations

import json

import pytest

from localagent.agent import Agent
from localagent.events import EventLog
from localagent.llm import LLMResponse, ToolCall
from localagent.runner import build_tools
from localagent.session import SessionStore


# ---------- EventLog базовое ----------

def test_event_has_required_fields(tmp_path):
    log = EventLog(tmp_path / "logs", session="s1", agent_id="a1",
                   parent_id=None, redact_keys=["api_key"])
    log.emit("tool_call", tool="read_file", args={"path": "x"})
    row = json.loads(next((tmp_path / "logs").rglob("s1.jsonl"))
                     .read_text(encoding="utf-8").splitlines()[0])
    for k in ("ts", "session_id", "agent_id", "parent_id", "seq", "step", "type", "data"):
        assert k in row, f"missing {k}"


def test_emit_flushes_immediately(tmp_path):
    """: журнал должен пережить аварию — flush после emit."""
    log = EventLog(tmp_path / "logs", session="s1", redact_keys=[])
    log.emit("a")
    f = next((tmp_path / "logs").rglob("s1.jsonl"))
    assert f.read_text(encoding="utf-8").strip()


# ---------- redaction ----------

def test_redacts_configured_keys(tmp_path):
    log = EventLog(tmp_path / "logs", session="s1", redact_keys=["api_key", "token"])
    log.emit("call", api_key="SECRET-1", nested={"token": "SECRET-2"})
    text = next((tmp_path / "logs").rglob("s1.jsonl")).read_text(encoding="utf-8")
    assert "SECRET-1" not in text and "SECRET-2" not in text
    assert "[REDACTED]" in text


def test_redacts_kv_strings(tmp_path):
    log = EventLog(tmp_path / "logs", session="s1", redact_keys=["token"])
    log.emit("note", msg="bearer token=abc123 end")
    text = next((tmp_path / "logs").rglob("s1.jsonl")).read_text(encoding="utf-8")
    assert "abc123" not in text


# ---------- required event types ----------

def test_required_event_types_present(workspace, cfg, ui, fake_llm):
    (workspace / "x.txt").write_text("hi")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(id="1", name="read_file",
                    arguments='{"path":"x.txt"}')], finish_reason="tool_calls"),
        LLMResponse(text="done", finish_reason="stop"),
    ])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.run("read")
    path = next((workspace / ".agent" / "logs").rglob(f"{agent.session_id}.jsonl"))
    types = {json.loads(l)["type"] for l in path.read_text(encoding="utf-8").splitlines()}
    for t in ("session_start", "llm_request", "llm_response", "tool_call",
              "tool_result", "session_end"):
        assert t in types, f"missing {t}"


# ---------- log path ----------

def test_log_path_has_date_dir(workspace, cfg, ui, fake_llm):
    llm = fake_llm([LLMResponse(text="x", finish_reason="stop")])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.run("hi")
    f = next((workspace / ".agent" / "logs").rglob(f"{agent.session_id}.jsonl"))
    # родитель — YYYY-MM-DD
    parent = f.parent.name
    assert len(parent) == 10 and parent[4] == "-" and parent[7] == "-"


# ---------- session report ----------

def test_session_report_written(workspace, cfg, ui, fake_llm):
    llm = fake_llm([LLMResponse(text="x", finish_reason="stop")])
    agent = Agent(cfg, llm, build_tools(cfg), ui)
    agent.run("hi")
    reports = list((workspace / ".agent").rglob(f"{agent.session_id}.report.md"))
    assert reports, "session report should be written"


def test_terminal_reason_and_result_are_redacted_from_persistence(workspace, cfg, ui, fake_llm):
    secret = "Bearer SYNTHETIC_SECRET_TOKEN_1234567890"
    agent = Agent(cfg, fake_llm([]), build_tools(cfg), ui)
    agent._finalize("failed", reason=secret, result=secret)
    persisted = "\n".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (workspace / ".agent").rglob("*")
        if p.is_file() and p.suffix in {".json", ".jsonl", ".md"}
    )
    assert secret not in persisted
    assert "content blocked by security policy" in persisted


def test_data_url_is_not_persisted_in_audit_log(tmp_path):
    import base64
    payload = base64.b64encode(b"synthetic image data").decode()
    data_url = "data:image/png;base64," + payload
    log = EventLog(tmp_path / "logs", session="image", redact_keys=[])
    log.emit("tool_result", result={"data_url": data_url})
    text = log.path.read_text(encoding="utf-8")
    assert payload not in text
    assert "[REDACTED]" in text



# ---------- SessionStore ----------

def test_session_id_validation(tmp_path):
    s = SessionStore(tmp_path)
    with pytest.raises(ValueError):
        s.save("../../escape", {})
    with pytest.raises(ValueError):
        s.save("bad id", {})


def test_session_roundtrip(tmp_path):
    s = SessionStore(tmp_path)
    s.save("abc", {"x": 1, "nested": {"y": "z"}})
    assert s.load("abc") == {"x": 1, "nested": {"y": "z"}}


def test_session_save_leaves_no_tmp(tmp_path):
    s = SessionStore(tmp_path)
    s.save("abc", {"x": 1})
    assert not list((tmp_path / ".agent" / "sessions").glob("*.tmp"))
