"""CLI commands, flags, exit codes, REPL, and @file expansion."""
from __future__ import annotations

import pytest

from localagent.cli import main


# ---------- базовые команды ----------

def test_config_check_prints_workspace_root(workspace, capsys):
    assert main(["config", "check", "--workspace", str(workspace)]) == 0
    assert "workspace_root" in capsys.readouterr().out


def test_doctor_without_live_ok(workspace, capsys):
    rc = main(["doctor", "--workspace", str(workspace)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "workspace: OK" in out
    assert "agent_dir: OK" in out


def test_doctor_exec_backend_reports_kernel_capabilities(workspace, capsys):
    rc = main(["doctor", "--exec-backend", "--workspace", str(workspace)])
    out = capsys.readouterr().out
    assert "exec.landlock:" in out
    assert "exec.seccomp:" in out
    assert "exec.ready:" in out
    assert rc in (0, 2)


def test_doctor_fails_on_missing_agents_dir(tmp_path, capsys):
    (tmp_path / "skills").mkdir()
    rc = main(["doctor", "--workspace", str(tmp_path)])
    assert rc != 0


def test_roles_lists_files(workspace, capsys):
    (workspace / "agents" / "coder.md").write_text("x")
    (workspace / "agents" / "reviewer.md").write_text("y")
    main(["roles", "list", "--workspace", str(workspace)])
    out = capsys.readouterr().out
    assert "coder" in out and "reviewer" in out


def test_skills_list_matches_runtime_discovery(workspace, capsys):
    skill = workspace / ".pi" / "skills" / "demo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\ndescription: demo\n---\nbody\n", encoding="utf-8")
    main(["skills", "list", "--workspace", str(workspace)])
    assert "demo" in capsys.readouterr().out


def test_kb_add_then_search(workspace, capsys):
    (workspace / "design.md").write_text("shuffle skew tariff")
    main(["kb", "add", "design.md", "--workspace", str(workspace)])
    capsys.readouterr()
    main(["kb", "search", "skew", "--workspace", str(workspace)])
    assert "design.md" in capsys.readouterr().out


def test_logs_list(workspace, capsys):
    d = workspace / ".agent" / "logs" / "2026-10-06"
    d.mkdir(parents=True)
    (d / "s1.jsonl").write_text("{}\n")
    main(["logs", "list", "--workspace", str(workspace)])
    assert "s1.jsonl" in capsys.readouterr().out


# ---------- CLI flags ----------

@pytest.mark.timeout(10)
def test_cli_accepts_all_flags(workspace, monkeypatch, fake_llm):
    """The documented common flags are accepted by argparse."""
    from localagent import cli as cli_mod
    # Не запускаем агента — используем пустой FakeLLM, обрывая цикл
    monkeypatch.setattr(cli_mod, "OpenAICompatClient", lambda *a, **k: type(
        "C", (), {"complete": lambda *a, **k: __import__(
            "localagent.llm", fromlist=["LLMResponse"]).LLMResponse(
                text="ok", finish_reason="stop"),
            "close": lambda *a, **k: None})())
    rc = cli_mod.main([
        "run", "hi", "--workspace", str(workspace),
        "--model", "DeepSeek-V4-Flash-0731",
        "--effort", "high", "--mode", "auto", "--headless",
        "--max-steps", "5", "--max-time", "30",
    ])
    assert rc == 0


# ----------  коды возврата ----------

def test_resume_does_not_accept_initialization_overrides(workspace):
    with pytest.raises(SystemExit) as exc:
        main(["resume", "session-1", "--workspace", str(workspace), "--role", "reviewer"])
    assert exc.value.code == 2


def test_exit_code_config_error(workspace, capsys):
    rc = main(["config", "check", "--workspace", str(workspace),
               "--config", "/nonexistent/config.yaml"])
    assert rc in (2, 1)


# ----------  @file ----------

def test_at_file_inserts_content(workspace):
    (workspace / "src.py").write_text("CONTENT_MARKER", encoding="utf-8")
    # Интеграционный тест: собираем сообщение и проверяем наличие содержимого
    from localagent.cli import _expand_at_files  # предполагаемая утилита
    msg = _expand_at_files("@src.py вопрос", workspace)
    assert "CONTENT_MARKER" in msg


def test_doctor_live_unavailable_endpoint_returns_nonzero(workspace, monkeypatch, capsys):
    from localagent import cli as cli_mod

    class BrokenClient:
        def __init__(self, *args, **kwargs):
            pass

        def complete(self, *args, **kwargs):
            raise OSError("endpoint unavailable")

    monkeypatch.setattr(cli_mod, "OpenAICompatClient", BrokenClient)
    assert main(["doctor", "--live", "--workspace", str(workspace)]) != 0
