"""Execution security invariants: typed tools, immutable trusted trees and kernel sandboxing."""
from __future__ import annotations

import sys
import time

import pytest

from localagent.agent import Agent
from localagent.config import load_config
from localagent.llm import LLMResponse, ToolCall
from localagent.policy import Policy, PolicyError
from localagent.runner import build_tools
from localagent.security import SecretScanner
from localagent.tools.exec import ExecutionPolicy
from localagent.tools.sandbox import backend_status


def enable(cfg, mode="auto"):
    cfg["exec"]["mode"] = mode
    cfg["exec"]["enabled"] = False
    cfg["permissions"]["confirm"] = "auto"


def require_sandbox():
    if not backend_status()["ready"]:
        pytest.skip("Linux kernel lacks the required Landlock + seccomp + network execution sandbox")


def test_typed_execution_tools(workspace, cfg):
    enable(cfg)
    tools = build_tools(cfg)
    assert {"run_script", "run_tests", "run_module"} <= set(tools)
    assert not {"run_python", "run_command", "shell"} & set(tools)


def test_module_can_be_explicitly_disabled(workspace, cfg):
    enable(cfg)
    cfg["exec"]["allow_module"] = False
    tools = build_tools(cfg)
    assert "run_module" not in tools


def test_off_is_default_and_blocks_execution(workspace, cfg):
    cfg["exec"]["mode"] = "off"
    cfg["exec"]["enabled"] = False
    assert "run_tests" not in build_tools(cfg)


def test_workspace_exec_section_is_ignored(workspace):
    (workspace / ".agent/config.yaml").write_text("exec:\n  mode: auto\n")
    c = load_config(str(workspace))
    assert c["exec"]["mode"] == "off"


def test_workspace_cannot_override_security_sections(workspace):
    (workspace / ".agent/config.yaml").write_text(
        "exec:\n  mode: auto\nllm:\n  base_url: http://evil.invalid\n"
        "logging:\n  dir: evil\nkb:\n  path: evil.sqlite\npermissions:\n  confirm: auto\n",
        encoding="utf-8",
    )
    c = load_config(str(workspace))
    assert c["exec"]["mode"] == "off"
    assert c["llm"]["base_url"] == "http://127.0.0.1:8000/v1"
    assert c["permissions"]["confirm"] == "ask"


def test_agent_work_zones_are_writable_and_control_plane_is_not(workspace, cfg):
    p = Policy(cfg)
    for path in ("src/a.py", "scripts/a.py", "tests/a.py"):
        assert p.decision(path, "read").allowed
        assert p.decision(path, "write").allowed
    for path in ("AGENTS.md", "agents/a.md", "skills/a.md", ".pi/config", ".agent/config.yaml"):
        with pytest.raises(PolicyError):
            p.authorize(path, "write")


@pytest.mark.parametrize("path", ["../x.py", "/etc/passwd", "tests/../x.py", "src/x.py", "scripts/x.py"])
def test_script_escape_and_trusted_tree_execution_denied(workspace, cfg, path):
    enable(cfg)
    with pytest.raises((PermissionError, FileNotFoundError)):
        build_tools(cfg)["run_script"].run({"path": path, "args": []})


def test_script_and_scratch_allowed(workspace, cfg):
    require_sandbox()
    enable(cfg)
    (workspace / "scratch").mkdir()
    (workspace / "scratch/x.py").write_text("print('ok')\n")
    assert build_tools(cfg)["run_script"].run({"path": "scratch/x.py", "args": []})["ok"]


def test_module_under_src_when_explicitly_enabled(workspace, cfg):
    require_sandbox()
    enable(cfg)
    cfg["exec"]["allow_module"] = True
    (workspace / "src").mkdir()
    (workspace / "src/hello.py").write_text("print('module-ok')\n")
    r = build_tools(cfg)["run_module"].run({"module": "hello", "args": []})
    assert r["ok"] and "module-ok" in r["stdout"]


def test_run_tests_can_execute_agent_modified_tests(workspace, cfg, ui, fake_llm):
    enable(cfg)
    (workspace / "tests/t.py").write_text("def test_x(): assert True\n")
    llm = fake_llm([
        LLMResponse(text="", tool_calls=[ToolCall(
            id="1", name="write_file",
            arguments='{"path":"tests/new.py","content":"def test_new(): assert True\\n"}',
        )], finish_reason="tool_calls"),
        LLMResponse(text="", tool_calls=[ToolCall(
            id="2", name="finish", arguments='{"status":"done","summary":"denied"}',
        )], finish_reason="tool_calls"),
    ])
    result = Agent(cfg, llm, build_tools(cfg), ui).run("write and run a test")
    assert result["status"] in {"ok", "failed"}
    assert (workspace / "tests/new.py").exists()


def test_shell_and_inline_code_rejected(workspace, cfg):
    enable(cfg)
    p = ExecutionPolicy(cfg, workspace)
    assert not p.decision("run_script", sys.executable, ["-c", "print(1)"], workspace, p.env(), 1).allowed
    with pytest.raises(PermissionError):
        build_tools(cfg)["run_script"].run({"path": "scratch/x.py", "args": ["-c", "x"]})


def test_environment_is_allowlisted(workspace, cfg, monkeypatch):
    enable(cfg)
    monkeypatch.setenv("SECRET_TOKEN", "bad")
    env = build_tools(cfg)["run_tests"].execution_policy.env()
    assert "SECRET_TOKEN" not in env and "HOME" not in env
    assert "PYTHONPATH" not in env
    assert "JAVA_HOME" not in env and "SPARK_HOME" not in env
    assert env["SPARK_LOCAL_IP"] == "127.0.0.1"


def test_timeout_and_stdin(workspace, cfg):
    require_sandbox()
    enable(cfg)
    cfg["exec"]["timeout_s"] = 1
    (workspace / "scratch").mkdir()
    (workspace / "scratch/h.py").write_text("import time; time.sleep(60)\n")
    t = time.monotonic()
    r = build_tools(cfg)["run_script"].run({"path": "scratch/h.py", "args": []})
    assert r["timed_out"] and time.monotonic() - t < 5
    (workspace / "scratch/i.py").write_text("input()\n")
    r = build_tools(cfg)["run_script"].run({"path": "scratch/i.py", "args": []})
    assert r["returncode"] != 0


def test_kernel_sandbox_blocks_home_access(workspace, cfg):
    require_sandbox()
    enable(cfg)
    (workspace / "scratch").mkdir()
    (workspace / "scratch/home.py").write_text(
        "from pathlib import Path\n"
        "try:\n Path('/home').iterdir()\n print('ESCAPED')\nexcept (PermissionError, OSError):\n print('BLOCKED')\n"
    )
    r = build_tools(cfg)["run_script"].run({"path": "scratch/home.py", "args": []})
    assert r["ok"] and "BLOCKED" in r["stdout"] and "ESCAPED" not in r["stdout"]



def test_kernel_sandbox_blocks_workspace_symlink_escape(workspace, cfg):
    require_sandbox()
    enable(cfg)
    outside = workspace.parent / "outside-secret.txt"
    outside.write_text("DO-NOT-READ", encoding="utf-8")
    (workspace / "scratch").mkdir()
    (workspace / "scratch/link").symlink_to(outside)
    (workspace / "scratch/link.py").write_text(
        "from pathlib import Path\n"
        "try: print(Path('scratch/link').read_text())\n"
        "except (PermissionError, OSError): print('BLOCKED')\n",
        encoding="utf-8",
    )
    r = build_tools(cfg)["run_script"].run({"path": "scratch/link.py", "args": []})
    assert r["ok"] and "BLOCKED" in r["stdout"] and "DO-NOT-READ" not in r["stdout"]


def test_kernel_sandbox_blocks_unshare_after_launcher_setup(workspace, cfg):
    require_sandbox()
    enable(cfg)
    (workspace / "scratch").mkdir()
    (workspace / "scratch/unshare.py").write_text(
        "import ctypes, errno\n"
        "libc=ctypes.CDLL(None, use_errno=True)\n"
        "r=libc.unshare(0x40000000)\n"
        "print('BLOCKED' if r == -1 and ctypes.get_errno() == errno.EPERM else 'ESCAPED')\n",
        encoding="utf-8",
    )
    r = build_tools(cfg)["run_script"].run({"path": "scratch/unshare.py", "args": []})
    assert r["ok"] and "BLOCKED" in r["stdout"] and "ESCAPED" not in r["stdout"]


def test_kernel_sandbox_blocks_host_loopback(workspace, cfg):
    require_sandbox()
    enable(cfg)
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        (workspace / "scratch").mkdir()
        (workspace / "scratch/net.py").write_text(
            "import socket\n"
            f"s=socket.socket(); s.settimeout(1)\n"
            f"try: s.connect(('127.0.0.1',{port})); print('ESCAPED')\n"
            "except OSError: print('BLOCKED')\n"
            "finally: s.close()\n",
            encoding="utf-8",
        )
        r = build_tools(cfg)["run_script"].run({"path": "scratch/net.py", "args": []})
    assert r["ok"] and "BLOCKED" in r["stdout"] and "ESCAPED" not in r["stdout"]

def test_secret_output_blocked(workspace, cfg):
    require_sandbox()
    enable(cfg)
    (workspace / "scratch").mkdir()
    (workspace / "scratch/s.py").write_text("print('Bearer SECRET_TOKEN_1234567890')\n")
    r = build_tools(cfg)["run_script"].run({"path": "scratch/s.py", "args": []})
    assert r["output_blocked"] and "SECRET_TOKEN" not in r["stdout"]


def test_secret_scanner_examples():
    for s in ["AKIA1234567890ABCDEF", "-----BEGIN PRIVATE KEY-----", "password=supersecretvalue"]:
        assert SecretScanner.scan(s)
