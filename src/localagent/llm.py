"""OpenAI-compatible chat client with SSE accumulation and retry behavior."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import ConfigError
from typing import Any

import httpx


@dataclass
class ToolCall:
    """A reconstructed tool call assembled from one or more streamed deltas."""

    id: str = ""
    name: str = ""
    arguments: str = ""
    index: int = 0


@dataclass
class ChatRequest:
    """Logical chat-completion request accepted by :class:`OpenAICompatClient`."""

    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]] | None = None
    model: str | None = None
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    response_format: dict | None = None
    extra_body: dict[str, Any] | None = None
    timeout_s: float | None = None


@dataclass
class LLMResponse:
    """Normalized response returned by the LLM client."""

    text: str = ""
    reasoning: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    raw: dict | None = None
    streamed: bool = False


class Accumulator:
    """Incrementally combine streamed or synthetic response fragments."""

    def __init__(self):
        """Initialize an empty response accumulator."""
        self.text = ""
        self.reasoning = ""
        self.calls = {}
        self.finish_reason = None
        self.usage = {}
        self.raw = {}

    def add_chunk(self, obj):
        """Consume one OpenAI-compatible SSE JSON object."""
        if obj.get("usage"):
            self.usage.update(obj["usage"])
        for ch in obj.get("choices") or []:
            d = ch.get("delta") or {}
            content = d.get("content")
            if isinstance(content, str):
                self.text += content
            reasoning = d.get("reasoning_content") or d.get("reasoning")
            if isinstance(reasoning, str):
                self.reasoning += reasoning
            for tc in d.get("tool_calls") or []:
                i = int(tc.get("index", 0))
                c = self.calls.setdefault(i, ToolCall(index=i))
                if tc.get("id"):
                    c.id = tc["id"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    c.name = fn["name"]
                if fn.get("arguments"):
                    c.arguments += fn["arguments"]
            if ch.get("finish_reason") is not None:
                self.finish_reason = ch["finish_reason"]
        self.raw = obj

    def add(self, e):
        """Consume a normalized fragment used by tests and internal callers."""
        if e.get("text"):
            self.text += e["text"]
        if e.get("reasoning"):
            self.reasoning += e["reasoning"]
        if e.get("usage"):
            self.usage.update(e["usage"])
        if e.get("finish_reason") is not None:
            self.finish_reason = e["finish_reason"]
        tc = e.get("tool_call")
        if tc:
            i = int(tc.get("index", 0))
            c = self.calls.setdefault(i, ToolCall(index=i))
            c.id = tc.get("id", c.id)
            c.name = tc.get("name", c.name)
            c.arguments += tc.get("arguments") or ""

    def result(self, streamed=True):
        """Return the accumulated state as an :class:`LLMResponse`."""
        return LLMResponse(
            self.text,
            self.reasoning,
            [self.calls[k] for k in sorted(self.calls)],
            self.finish_reason,
            self.usage,
            self.raw,
            streamed,
        )


class OpenAICompatClient:
    """HTTP client for an OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(self, cfg, ui=None):
        """Create an HTTP client using API-key, TLS, proxy, timeout, and retry settings from ``cfg``."""
        self.cfg = cfg
        self.ui = ui
        l = cfg["llm"]
        key = os.getenv(l.get("api_key_env", ""), "") if l.get("api_key_env") else ""
        if not key and l.get("api_key_file"):
            key = Path(l["api_key_file"]).expanduser().read_text(encoding="utf-8").strip()
        verify = l.get("ca_bundle") or l.get("verify_ssl", True)
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        if l.get("http_referer"):
            headers["HTTP-Referer"] = l["http_referer"]
        if l.get("x_title"):
            headers["X-Title"] = l["x_title"]
        self._deadline = None
        self.client = httpx.Client(
            verify=verify,
            headers=headers,
            timeout=httpx.Timeout(l["idle_timeout_s"], connect=l["connect_timeout_s"]),
            proxy=l.get("proxy"),
            trust_env=True,
        )

    def set_deadline(self, deadline):
        """Set the absolute monotonic deadline for the next blocking request."""
        self._deadline = deadline

    def close(self):
        """Close the underlying :mod:`httpx` client."""
        self.client.close()

    def _body(self, r):
        """Build the provider request body from a :class:`ChatRequest`."""
        model = r.model or self.cfg["llm"]["models"]["default"]
        profiles = self.cfg["llm"].get("profiles", {})
        if model not in profiles:
            raise ConfigError(f"llm model {model!r} has no validated profile")
        profile = profiles[model]
        b = {
            "model": model,
            "messages": r.messages,
            "stream": True,
        }
        if r.tools:
            b["tools"] = r.tools
        for k, v in (("temperature", r.temperature), ("top_p", r.top_p), ("max_tokens", r.max_tokens)):
            if v is not None:
                b[k] = v
        if b.get("max_tokens") is not None and profile.get("max_output"):
            b["max_tokens"] = min(int(b["max_tokens"]), int(profile["max_output"]))
        if r.response_format:
            b["response_format"] = r.response_format
        if r.extra_body:
            protected = {"model", "messages", "stream", "tools", "temperature", "top_p", "max_tokens", "response_format"}
            for key, value in r.extra_body.items():
                if key in protected:
                    continue
                if key == "top_k" and profile.get("sampling", {}).get("top_k") is None:
                    continue
                b[key] = value
        return b

    def stream(self, r):
        """Send one logical streaming request without exposing failed-attempt output."""
        cfg = self.cfg["llm"]
        attempts = cfg["retry"]["max_attempts"]
        back = cfg["retry"]["backoff_s"]
        statuses = set(cfg["retry"]["statuses"])
        body = self._body(r)
        last_error = None
        for attempt in range(attempts):
            acc = Accumulator()
            done = False
            try:
                remaining = r.timeout_s
                if self._deadline is not None:
                    remaining = min(
                        remaining if remaining is not None else float("inf"),
                        self._deadline - time.monotonic(),
                    )
                if remaining is not None and remaining <= 0:
                    raise TimeoutError("agent wall-time budget exhausted")
                timeout_value = min(float(cfg["idle_timeout_s"]), float(remaining)) if remaining is not None else float(cfg["idle_timeout_s"])
                connect_timeout = min(float(cfg["connect_timeout_s"]), timeout_value)
                timeout = httpx.Timeout(timeout_value, connect=connect_timeout)
                with self.client.stream(
                    "POST",
                    cfg["base_url"].rstrip("/") + "/chat/completions",
                    json=body,
                    timeout=timeout,
                ) as resp:
                    if resp.status_code in statuses and attempt + 1 < attempts:
                        delay = back * 2**attempt
                        if self._deadline is not None:
                            delay = min(delay, max(0.0, self._deadline - time.monotonic()))
                        if delay:
                            time.sleep(delay)
                        continue
                    resp.raise_for_status()
                    last = time.monotonic()
                    for raw in resp.iter_lines():
                        now = time.monotonic()
                        if self._deadline is not None and now >= self._deadline:
                            raise TimeoutError("agent wall-time budget exhausted")
                        if now - last > min(float(cfg["idle_timeout_s"]), float(remaining or float("inf"))):
                            raise TimeoutError("SSE idle timeout")
                        last = now
                        if not raw:
                            continue
                        line = raw.decode() if isinstance(raw, bytes) else raw
                        if line.startswith("data:"):
                            line = line[5:].strip()
                        if line == "[DONE]":
                            done = True
                            continue
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        acc.add_chunk(obj)
                    result = acc.result(streamed=True)
                    # Some OpenAI-compatible gateways close a successful SSE
                    # stream without a [DONE] sentinel. A finish_reason is
                    # authoritative; only an unmarked empty/partial close is an error.
                    if not done and not result.finish_reason:
                        raise TimeoutError("incomplete SSE stream")
                result = acc.result(streamed=True)
                # Only now is the logical attempt complete; failed attempts never
                # touch the UI, so a retry cannot duplicate partial output.
                if self.ui and result.text:
                    self.ui.stream_text(result.text)
                return result
            except (httpx.TransportError, httpx.TimeoutException, TimeoutError) as e:
                last_error = e
                if attempt + 1 >= attempts:
                    raise
                delay = back * 2**attempt
                if self._deadline is not None:
                    remaining = self._deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("agent wall-time budget exhausted") from e
                    delay = min(delay, remaining)
                if delay:
                    time.sleep(delay)
        raise RuntimeError(last_error or "LLM request failed")

    complete = stream

    def complete_json(self, messages, schema, model=None, max_attempts=3):
        """Request JSON output repeatedly until it parses and passes basic local validation."""
        msgs = list(messages)
        for _ in range(max_attempts):
            r = self.complete(
                ChatRequest(msgs, model=model, max_tokens=4096, temperature=0, response_format={"type": "json_object"})
            )
            try:
                obj = json.loads(r.text)
                validate_json(obj, schema)
                return obj
            except (ValueError, TypeError, KeyError):
                msgs += [{"role": "user", "content": "Previous JSON was invalid. Return only valid JSON."}]
        # Do not include provider/model output in an exception: the caller may
        # persist or display the exception, and the output can contain sensitive data.
        raise ValueError("invalid structured output")


def validate_json(x, s):
    """Perform the small subset of JSON Schema checks implemented by localagent."""
    typ = s.get("type")
    if typ == "object" and not isinstance(x, dict):
        raise ValueError("expected object")
    if typ == "array" and not isinstance(x, list):
        raise ValueError("expected array")
    for k in s.get("required", []):
        if k not in x:
            raise ValueError(f"missing {k}")
    for k, t in s.get("properties", {}).items():
        if k in x:
            want = t.get("type")
            ok = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "object": dict, "array": list}.get(want)
            if ok and not isinstance(x[k], ok):
                raise ValueError(f"{k}: expected {want}")
