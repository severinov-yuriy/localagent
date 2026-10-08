import pytest

from localagent.config import load_config
from localagent.policy import Policy, PolicyError
from localagent.runner import build_tools
from localagent.tools.exec import ExecutionPolicy, Exec
from localagent.tools.preflight import check_file


def test_exec_ask_mode_is_valid(workspace, cfg):
    cfg["exec"]["mode"] = "ask"
    cfg["exec"]["isolation"] = "app"
    ep = ExecutionPolicy(cfg, workspace)
    assert ep.backend_status() is not None
    assert Exec(cfg, Policy(cfg))._enabled()[0] == "app"


def test_run_module_uses_python_m(workspace, cfg):
    (workspace / "src").mkdir(exist_ok=True)
    (workspace / "src" / "pkg.py").write_text("print('ok')\n", encoding="utf-8")
    ep = ExecutionPolicy(cfg, workspace)
    argv = ep.module_argv("pkg", [])
    assert argv[1:3] == ["-m", "pkg"]


def test_rw_dirs_cannot_include_control_plane(workspace, cfg):
    cfg["exec"]["mode"] = "auto"
    cfg["exec"]["rw_dirs"] = ["agents"]
    with pytest.raises(PermissionError):
        Exec(cfg, Policy(cfg))._run("run_script", [str(ExecutionPolicy(cfg, workspace)._trusted_executable), str(workspace / "scratch.py")], 1)


def test_global_control_plane_cannot_be_removed(workspace):
    cfg = load_config(str(workspace))
    cfg["permissions"]["control_plane"] = []
    p = Policy(cfg)
    with pytest.raises(PolicyError):
        p.authorize("AGENTS.md", "write")
    with pytest.raises(PolicyError):
        p.authorize("agents/x.md", "write")


def test_backup_is_session_scoped_and_restore_is_exact(workspace, cfg):
    cfg["permissions"]["workspace_root"] = str(workspace)
    tools = build_tools(cfg)
    p = tools["write_file"].p
    p.session_id = "s1"
    target = workspace / "x.txt"
    target.write_bytes(b"a\r\nb\n")
    tools["edit_file"].run({"path": "x.txt", "old": "b", "new": "c"})
    assert (workspace / ".agent" / "backups" / "s1" / "x.txt").read_bytes() == b"a\r\nb\n"
    tools["undo"].run({"path": "x.txt", "session": "s1"})
    assert target.read_bytes() == b"a\r\nb\n"


def test_move_refuses_overwrite(workspace, cfg):
    tools = build_tools(cfg)
    (workspace / "a.txt").write_text("a", encoding="utf-8")
    (workspace / "b.txt").write_text("b", encoding="utf-8")
    with pytest.raises(FileExistsError):
        tools["move"].run({"src": "a.txt", "dst": "b.txt"})


def test_preflight_detects_rmtree_and_home_and_importlib(workspace):
    p = workspace / "src.py"
    p.write_text("import importlib\nimport shutil\nshutil.rmtree('/tmp/x')\nopen('$HOME/x','w')\n", encoding="utf-8")
    findings = check_file(p, workspace)
    assert any("import:importlib" in x for x in findings)
    assert any("call:rmtree" in x for x in findings)
    assert any("path:$HOME/x" in x for x in findings)
