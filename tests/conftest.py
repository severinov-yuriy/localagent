"""Общие фикстуры. Никакой логики приложения — только каркас для тестов."""
from __future__ import annotations

import signal
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from localagent.config import load_config
from localagent.llm import LLMResponse
from localagent.ui import UI


@pytest.fixture(autouse=True)
def _restore_sigint():
    """Agent.__init__ перезаписывает SIGINT; вернём обработчик pytest после теста."""
    old = signal.getsignal(signal.SIGINT)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, old)


@pytest.fixture
def workspace(tmp_path):
    # Keep the workspace and an external path as sibling directories for boundary tests.
    root = tmp_path / "workspace"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "agents").mkdir()
    (root / "skills").mkdir()
    (root / "tests").mkdir()
    (root / ".agent").mkdir()
    (root / "AGENTS.md").write_text("# Project\nBe careful.\n", encoding="utf-8")
    return root


@pytest.fixture
def cfg(workspace):
    c = load_config(str(workspace))
    c["permissions"]["confirm"] = "auto"
    c["exec"]["enabled"] = True
    return c


@pytest.fixture
def ui():
    return UI()


class FakeLLM:
    """Управляемый LLM: отдаёт заранее заготовленные ответы по порядку.

    Помимо complete/stream, реализует complete_json, чтобы тесты компактизации
    и субагентов не требовали реальной модели.
    """

    def __init__(self, script=None, json_script=None):
        self.script = list(script or [])
        self.json_script = list(json_script or [])
        self.calls = []
        self.json_calls = []

    def _next(self, seq):
        if not seq:
            return LLMResponse(text="done", finish_reason="stop")
        item = seq.pop(0)
        return item(req=None) if callable(item) else item

    def complete(self, req):
        self.calls.append(req)
        return self._next(self.script)

    stream = complete

    def complete_json(self, messages, schema, model=None, max_attempts=3):
        self.json_calls.append((messages, schema, model))
        if self.json_script:
            item = self.json_script.pop(0)
            return item(messages, schema) if callable(item) else item
        return {"summary": "compacted", "status": "done", "artifacts": [], "notes": []}


@pytest.fixture
def fake_llm():
    return FakeLLM

# ---------- local SSE test server ----------

def _sse_bytes(chunks):
    out = b""
    for chunk in chunks:
        out += b"data: " + json.dumps(chunk).encode() + b"\n\n"
    return out


@contextmanager
def sse_server(
    chunks,
    *,
    status=200,
    close_early=False,
    idle_timeout=None,
    first_status=None,
    bad_json_once=False,
    keepalive=False,
):
    """Run a small local OpenAI-compatible SSE endpoint for transport tests."""

    class Handler(BaseHTTPRequestHandler):
        calls = 0
        bad_json_sent = False
        last_headers = {}
        last_body = b""

        def do_POST(self):
            Handler.calls += 1
            length = int(self.headers.get("Content-Length", 0))
            Handler.last_body = self.rfile.read(length)
            Handler.last_headers = {k: v for k, v in self.headers.items()}
            code = first_status if first_status is not None and Handler.calls == 1 else status
            self.send_response(code)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            if code >= 400:
                return
            if keepalive:
                self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
            for index, chunk in enumerate(chunks):
                if idle_timeout:
                    time.sleep(idle_timeout)
                if bad_json_once and index == 0 and not Handler.bad_json_sent:
                    Handler.bad_json_sent = True
                    self.wfile.write(b"data: {not-json}\n\n")
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                self.wfile.flush()
            if not close_early:
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        def log_message(self, *_):
            pass

    Handler.calls = 0
    Handler.bad_json_sent = False
    Handler.last_headers = {}
    Handler.last_body = b""
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/v1"
    try:
        yield url, Handler
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def sse():
    return sse_server

