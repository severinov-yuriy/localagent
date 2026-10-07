"""P0 application-security invariants."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from localagent.agent import Agent
from localagent.policy import Policy, PolicyError
from localagent.runner import build_tools
from localagent.security import DLPPolicy, SecretScanner
from localagent.events import EventLog


def test_workspace_is_component_aware(workspace, cfg):
    sibling = workspace.parent / "workspace-secret"
    sibling.mkdir()
    (sibling / "x").write_text("outside")
    p = Policy(cfg)
    with pytest.raises(PolicyError):
        p.authorize(str(sibling / "x"), "read")
    with pytest.raises(PolicyError):
        p.authorize("/home/anything", "read")


@pytest.mark.parametrize("operation", ["read", "list", "glob", "grep", "write", "delete", "move", "mkdir"])
def test_home_and_outside_are_denied_for_all_filesystem_operations(workspace, cfg, operation):
    p = Policy(cfg)
    with pytest.raises(PolicyError):
        p.authorize("/home/secret", operation)


def test_removed_extra_read_roots_is_rejected_by_config(workspace):
    from localagent.config import ConfigError, load_config
    config_path = workspace / ".agent" / "config.yaml"
    config_path.write_text("permissions:\n  extra_read_roots: [../outside]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown configuration key"):
        load_config(str(workspace))


def test_symlink_directory_escape_is_denied_for_all_entrypoints(workspace, cfg, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "secret.txt").write_text("SECRET")
    link = workspace / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unsupported")
    p = Policy(cfg)
    for op, path in [
        ("read", "link/secret.txt"), ("list", "link"), ("glob", "link"),
        ("grep", "link/secret.txt"), ("write", "link/new.txt"),
        ("delete", "link/secret.txt"), ("move", "link/a"), ("mkdir", "link/new"),
    ]:
        with pytest.raises(PolicyError):
            p.authorize(path, op)


def test_nested_symlink_escape_is_denied(workspace, cfg, tmp_path):
    outside = tmp_path / "outside"
    (outside / "nested").mkdir(parents=True)
    (outside / "nested" / "secret").write_text("SECRET")
    d = workspace / "nested"
    d.mkdir()
    try:
        (d / "link1").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unsupported")
    with pytest.raises(PolicyError):
        Policy(cfg).authorize("nested/link1/nested/secret", "read")


def test_secret_filenames_are_denied(workspace, cfg):
    p = Policy(cfg)
    for name in [".env", ".env.local", "x.pem", "x.key", "id_rsa", "credentials.json", "secrets.txt"]:
        with pytest.raises(PolicyError):
            p.authorize(name, "read")


def test_secret_scanner_required_matrix():
    samples = {
        "api": "api_key=ABCDEFGHIJKLMNOPQRSTUV",
        "bearer": "Bearer abcdefghijklmnopqrstuvwxyz123456",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmno.abcdefghijklmnop",
        "private": "-----BEGIN PRIVATE KEY-----",
        "password": "password=supersecret123",
        "db": "postgresql://user:supersecret@db.example/db",
        "cloud": "AKIA1234567890ABCDEF",
        "ssh": "ssh-ed25519 " + "A" * 100,
        "env": "AWS_SECRET_ACCESS_KEY=supersecret123",
        "entropy": "aB7_k9Q2xM4pL8sD3vN6cR1tY5uI9oP2",
    }
    for category, sample in samples.items():
        assert SecretScanner.scan(sample), category


def test_dlp_blocks_without_returning_secret():
    secret = "Bearer VERY_SECRET_TOKEN_1234567890"
    result = DLPPolicy().check("tool.result", secret)
    assert not result.allowed
    assert secret not in result.reason
    assert result.reason == "content blocked by security policy"


def test_event_log_never_persists_secret(tmp_path):
    secret = "-----BEGIN PRIVATE KEY-----\nVERY_SECRET"
    log = EventLog(tmp_path, redact_keys=["token", "secret"])
    log.emit("tool_result", result=secret)
    text = log.path.read_text(encoding="utf-8")
    assert secret not in text
    assert "PRIVATE KEY" not in text


def test_tool_registry_has_no_generic_execution_primitive(workspace, cfg):
    cfg["exec"]["enabled"] = True
    tools = build_tools(cfg)
    assert set(["run_python", "run_command"]).isdisjoint(tools)
    assert "run_tests" in tools


def test_no_forbidden_execution_apis_in_application_source():
    root = Path(__file__).parents[1] / "src"
    text = "\n".join(p.read_text(encoding="utf-8") for p in root.rglob("*.py"))
    assert "shell=True" not in text
    assert "os.system(" not in text
    assert "os.popen(" not in text
    assert "run_python" not in text
    assert "run_command" not in text
    assert "eval(" not in text
    assert "exec(" not in text


def test_context_result_dlp_boundary(workspace, cfg, fake_llm, ui):
    from localagent.llm import LLMResponse, ToolCall
    # The model attempts to pass a secret as a tool argument. The assistant
    # message stored in history must contain sanitized arguments.
    llm = fake_llm([LLMResponse(text="", tool_calls=[
        ToolCall(id="1", name="write_file",
                 arguments=json.dumps({"path": "x.txt", "content": "Bearer SECRET_TOKEN_1234567890"}))
    ])])
    agent = Agent(cfg, llm, build_tools(cfg), ui, role="coder")
    agent.run("write it")
    joined = json.dumps(agent.messages, ensure_ascii=False)
    assert "SECRET_TOKEN_1234567890" not in joined


def test_at_file_dlp_and_path_boundary(workspace, cfg):
    from localagent.cli import _expand_at_files
    (workspace / "safe.txt").write_text("hello")
    assert _expand_at_files("@safe.txt", workspace) == "hello"
    (workspace / ".env").write_text("TOKEN=supersecret123")
    with pytest.raises((ValueError, PolicyError)):
        _expand_at_files("@.env", workspace)


def test_broken_symlink_cannot_be_used_as_workspace_escape(workspace, cfg, tmp_path):
    outside = tmp_path / "outside-secret.txt"
    link = workspace / "broken-link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unsupported")
    with pytest.raises(PolicyError):
        Policy(cfg).authorize("broken-link", "read")


def test_path_normalization_cannot_change_authorized_target(workspace, cfg):
    (workspace / "safe.txt").write_text("safe", encoding="utf-8")
    p = Policy(cfg)
    assert p.authorize("sub/../safe.txt", "read") == (workspace / "safe.txt").resolve()
    for candidate in ("./../safe.txt", "..//safe.txt"):
        with pytest.raises(PolicyError):
            p.authorize(candidate, "read")


def test_at_file_dlp_blocks_secret_content_not_only_secret_filename(workspace, cfg):
    from localagent.cli import _expand_at_files

    (workspace / "notes.txt").write_text("token=synthetic-secret-value", encoding="utf-8")
    with pytest.raises(ValueError, match="content blocked by security policy"):
        _expand_at_files("@notes.txt", workspace)


def test_skill_dlp_blocks_sensitive_content_before_model_delivery(workspace, cfg):
    skill = workspace / "skills" / "unsafe"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("api_key=ABCDEFGHIJKLMNOPQRSTUV", encoding="utf-8")
    with pytest.raises(PermissionError, match="content blocked by security policy"):
        build_tools(cfg)["read_skill"].run({"name": "unsafe"})


def test_runtime_storage_is_not_restricted_by_agent_role_acl(workspace, cfg):
    from localagent.policy import FilesystemPolicy

    role_policy = {"write": ["src/**"]}
    policy = FilesystemPolicy(cfg, role_policies=[role_policy])
    runtime_path = workspace / ".agent" / "reports" / "session.report.md"
    assert policy.authorize(runtime_path, "write", actor="runtime") == runtime_path.resolve()
