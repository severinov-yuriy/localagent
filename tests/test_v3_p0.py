import json
import pytest

from localagent.config import load_config
from localagent.policy import PolicyError
from localagent.events import EventLog
from localagent.security import SecretScanner
from localagent.runner import build_tools

def test_v3_logic_zones_are_read_only_but_readable(workspace, cfg):
    policy = __import__("localagent.policy", fromlist=["Policy"]).Policy(cfg)
    assert policy.authorize("AGENTS.md", "read").name == "AGENTS.md"
    assert policy.authorize("agents", "read").is_dir()
    with pytest.raises(PolicyError):
        policy.authorize("AGENTS.md", "write")

def test_v3_workspace_config_can_only_add_control_plane(workspace):
    p = workspace / ".agent" / "config.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("permissions:\n  control_plane: [custom.md]\n", encoding="utf-8")
    cfg = load_config(workspace)
    assert "AGENTS.md" in cfg["permissions"]["control_plane"]
    assert "custom.md" in cfg["permissions"]["control_plane"]

def test_v3_entropy_requires_secret_context():
    token = "aB7_k9Q2xM4pL8sD3vN6cR1tY5uI9oP2"
    assert SecretScanner.scan(token) is None
    assert SecretScanner.scan("api_key=" + token) is not None

def test_v3_event_hash_chain(tmp_path):
    log = EventLog(tmp_path, session="s")
    log.emit("session_start", foo="bar")
    log.emit("tool_result", step=1, result={"ok": True})
    ok, msg = EventLog.verify(log.path)
    assert ok, msg
    rows = log.path.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[0])
    row["data"]["foo"] = "tampered"
    log.path.write_text(json.dumps(row) + "\n" + "\n".join(rows[1:]) + "\n", encoding="utf-8")
    ok, _ = EventLog.verify(log.path)
    assert not ok

def test_v3_check_syntax_tool(workspace, cfg):
    tools = build_tools(cfg)
    (workspace / "src").mkdir(parents=True, exist_ok=True)
    (workspace / "src" / "good.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "src" / "bad.py").write_text("def nope(:\n", encoding="utf-8")
    assert tools["check_syntax"].run({"path": "src/good.py"})["ok"]
    assert not tools["check_syntax"].run({"path": "src/bad.py"})["ok"]

def test_v3_run_module_is_available_by_default(workspace, cfg):
    cfg["exec"]["enabled"] = False
    cfg["exec"]["mode"] = "off"
    tools = build_tools(cfg)
    assert "run_module" not in tools
    cfg["exec"]["mode"] = "auto"
    tools = build_tools(cfg)
    assert "run_module" in tools
