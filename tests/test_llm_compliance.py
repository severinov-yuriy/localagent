"""SSE parsing, accumulation, retries, structured outputs, and secret handling."""
from __future__ import annotations


import json

import pytest

from localagent.llm import (
    Accumulator,
    ChatRequest,
    OpenAICompatClient,
    validate_json,
)


# ---------- accumulator ----------

def test_accumulator_text_reasoning_toolcalls_usage():
    a = Accumulator()
    a.add({"text": "hi"})
    a.add({"reasoning": "thinking"})
    a.add({"tool_call": {"index": 0, "id": "1", "name": "read_file", "arguments": '{"path":'}})
    a.add({"tool_call": {"index": 0, "arguments": '"x"}'}, "finish_reason": "tool_calls",
          "usage": {"total_tokens": 4}})
    r = a.result()
    assert r.text == "hi"
    assert r.reasoning == "thinking"
    assert r.tool_calls[0].arguments == '{"path":"x"}'
    assert r.finish_reason == "tool_calls"
    assert r.usage["total_tokens"] == 4


def test_accumulator_two_tool_calls_in_one_response():
    """Multiple tool calls in one response are accumulated."""
    a = Accumulator()
    a.add({"tool_call": {"index": 0, "id": "a", "name": "read_file",
                         "arguments": '{"path":"a.txt"}'}})
    a.add({"tool_call": {"index": 1, "id": "b", "name": "list_dir",
                         "arguments": '{"path":"."}'}})
    r = a.result()
    assert [tc.name for tc in r.tool_calls] == ["read_file", "list_dir"]
    assert [tc.id for tc in r.tool_calls] == ["a", "b"]


def test_accumulator_parses_openai_style_chunks():
    a = Accumulator()
    a.add_chunk({"choices": [{"delta": {"content": "he"}}]})
    a.add_chunk({"choices": [{"delta": {"content": "llo"}}]})
    a.add_chunk({"choices": [{"delta": {}, "finish_reason": "stop"}],
                 "usage": {"total_tokens": 3}})
    r = a.result()
    assert r.text == "hello" and r.finish_reason == "stop"


# ---------- SSE edge cases ----------

def test_sse_keeps_keepalive_and_empty_lines(workspace, cfg, sse):
    chunks = [{"choices": [{"delta": {"content": "hi"}}]}]
    with sse(chunks, keepalive=True) as (url, _):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            r = c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert r.text == "hi"


def test_sse_bad_json_skipped_not_fatal(workspace, cfg, sse):
    """Malformed JSON chunks are logged without crashing the request."""
    chunks = [{"choices": [{"delta": {"content": "ok"}}]}]
    with sse(chunks, bad_json_once=True) as (url, _):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            r = c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert r.text == "ok"


def test_openrouter_headers_and_bearer_are_sent(workspace, cfg, sse, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    cfg["llm"]["api_key_env"] = "OPENROUTER_API_KEY"
    cfg["llm"]["http_referer"] = "https://example.test/localagent"
    cfg["llm"]["x_title"] = "localagent tests"
    with sse([{"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}]}]) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["reasoning_format"] = "openrouter"
        c = OpenAICompatClient(cfg)
        try:
            r = c.complete(ChatRequest(
                [{"role": "user", "content": "x"}],
                model="deepseek/deepseek-chat-v3.1",
                max_tokens=4096,
                extra_body={"reasoning": {"effort": "medium"}, "top_k": 99},
            ))
        finally:
            c.close()
    body = json.loads(H.last_body)
    assert H.last_headers["Authorization"] == "Bearer test-openrouter-key"
    assert H.last_headers["HTTP-Referer"] == "https://example.test/localagent"
    assert H.last_headers["X-Title"] == "localagent tests"
    assert body["model"] == "deepseek/deepseek-chat-v3.1"
    assert body["stream"] is True
    assert body["reasoning"] == {"effort": "medium"}
    assert "top_k" not in body
    assert r.text == "ok"


def test_optional_openrouter_headers_are_omitted_by_default(workspace, cfg):
    c = OpenAICompatClient(cfg)
    try:
        headers = {k.lower(): v for k, v in c.client.headers.items()}
    finally:
        c.close()
    assert "http-referer" not in headers
    assert "x-title" not in headers


def test_openrouter_base_url_is_used_verbatim(workspace, cfg):
    cfg["llm"]["base_url"] = "https://openrouter.ai/api/v1"
    c = OpenAICompatClient(cfg)
    try:
        request_url = cfg["llm"]["base_url"].rstrip("/") + "/chat/completions"
        assert request_url == "https://openrouter.ai/api/v1/chat/completions"
    finally:
        c.close()


# ---------- retries ----------

def test_retries_on_503_then_succeeds(workspace, cfg, sse):
    chunks = [{"choices": [{"delta": {"content": "ok"}}]}]
    with sse(chunks, first_status=503) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            r = c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert r.text == "ok" and H.calls == 2


@pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
def test_retries_on_retryable_codes(workspace, cfg, sse, code):
    chunks = [{"choices": [{"delta": {"content": "ok"}}]}]
    with sse(chunks, first_status=code) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert H.calls == 2


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
def test_no_retry_on_client_errors(workspace, cfg, sse, code):
    with sse([], status=code) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        cfg["llm"]["retry"]["max_attempts"] = 3
        c = OpenAICompatClient(cfg)
        try:
            with pytest.raises(Exception):
                c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert H.calls == 1


def test_fails_after_max_attempts_on_stream_truncation(workspace, cfg, sse):
    """An incomplete stream retries as a whole and eventually raises."""
    with sse([{"choices": [{"delta": {"content": "partial"}}]}], close_early=True) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        cfg["llm"]["retry"]["max_attempts"] = 3
        c = OpenAICompatClient(cfg)
        try:
            with pytest.raises(Exception):
                c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert H.calls == 3


# ---------- length finish ----------

def test_length_finish_reason_is_surfaced(workspace, cfg, sse):
    chunks = [{"choices": [{"delta": {"content": "partial"}, "finish_reason": "length"}]}]
    with sse(chunks) as (url, _):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            r = c.complete(ChatRequest([{"role": "user", "content": "x"}]))
        finally:
            c.close()
    assert r.finish_reason == "length"


# ---------- structured outputs ----------

def test_complete_json_returns_object(workspace, cfg, sse):
    chunks = [{"choices": [{"delta": {"content": '{"summary":"ok"}'},
                            "finish_reason": "stop"}]}]
    with sse(chunks) as (url, H):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        c = OpenAICompatClient(cfg)
        try:
            obj = c.complete_json(
                [{"role": "user", "content": "x"}],
                {"type": "object", "required": ["summary"],
                 "properties": {"summary": {"type": "string"}}},
            )
        finally:
            c.close()
    assert obj == {"summary": "ok"}
    body = json.loads(H.last_body)
    assert body["response_format"] == {"type": "json_object"}


def test_complete_json_failure_does_not_echo_sensitive_output(workspace, cfg):
    import localagent.llm as mod

    c = OpenAICompatClient(cfg)
    secret = "Bearer SENSITIVE_PROVIDER_TOKEN_1234567890"
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(c, "complete", lambda *args, **kwargs: mod.LLMResponse(text=secret))
        with pytest.raises(ValueError, match="invalid structured output") as exc_info:
            c.complete_json(
                [{"role": "user", "content": "x"}],
                {"type": "object", "required": ["summary"], "properties": {"summary": {"type": "string"}}},
                max_attempts=1,
            )
        assert secret not in str(exc_info.value)
    finally:
        monkey.undo()
        c.close()


def test_validate_json_missing_required():
    with pytest.raises(ValueError):
        validate_json({}, {"type": "object", "required": ["x"]})


def test_validate_json_wrong_type():
    with pytest.raises(ValueError):
        validate_json({"x": 1},
                      {"type": "object", "properties": {"x": {"type": "string"}}})


def test_validate_json_accepts_valid():
    validate_json({"x": "s"},
                  {"type": "object", "required": ["x"],
                   "properties": {"x": {"type": "string"}}})


# ---------- secret is excluded from errors ----------

def test_api_key_not_in_error_messages(workspace, cfg, sse, monkeypatch):
    monkeypatch.setenv("GENOPS_API_KEY", "SECRET-KEY-XYZ")
    with sse([], status=500) as (url, _):
        cfg["llm"]["base_url"] = url
        cfg["llm"]["retry"]["backoff_s"] = 0.01
        cfg["llm"]["retry"]["max_attempts"] = 1
        c = OpenAICompatClient(cfg)
        try:
            with pytest.raises(Exception) as exc_info:
                c.complete(ChatRequest([{"role": "user", "content": "x"}]))
            assert "SECRET-KEY-XYZ" not in str(exc_info.value)
        finally:
            c.close()
