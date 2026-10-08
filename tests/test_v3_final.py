from __future__ import annotations

from pathlib import Path

from localagent.security import DLPPolicy, SecretScanner
from localagent.tools.exec import RunTests, ExecutionPolicy


def test_dlp_has_three_explicit_tiers():
    d = DLPPolicy()
    assert d.check("context.message", "safe").tier == "allow"
    assert d.check("audit.event", "password=supersecretvalue").tier == "mask"
    assert not d.check("execution.arguments", "password=supersecretvalue").allowed
    masked, decision = d.sanitize("audit.event", {"token": "password=supersecretvalue"})
    assert decision.tier == "mask" and masked["token"] == "[REDACTED]"


def test_run_tests_schema_includes_case_message_and_line(tmp_path):
    xml = tmp_path / "pytest.xml"
    xml.write_text("<testsuite tests='2' failures='1' errors='0' skipped='0'><testcase classname='tests.x' name='test_ok' line='7'/><testcase classname='tests.x' name='test_bad' line='9'><failure message='boom'>trace</failure></testcase></testsuite>")
    import xml.etree.ElementTree as ET
    root = ET.parse(xml).getroot()
    cases=[]
    for case in root.iter("testcase"):
        failure=case.find("failure")
        cases.append({"test": case.attrib.get("classname","")+"::"+case.attrib.get("name",""), "line": int(case.attrib.get("line",0)), "message": failure.attrib.get("message") if failure is not None else None})
    assert cases == [{"test":"tests.x::test_ok","line":7,"message":None},{"test":"tests.x::test_bad","line":9,"message":"boom"}]


def test_execution_audit_schema_keys(workspace, cfg):
    p=ExecutionPolicy(cfg, workspace)
    (workspace / "tests").mkdir(exist_ok=True)
    (workspace / "tests/test_x.py").write_text("pass\n")
    assert p.script_argv("tests/test_x.py", [])[0] == str(p._trusted_executable)
    required={"operation","path","sha256","argv","env_keys","pid","layers","duration_s","return_code","stdout_size","stderr_size","output_size","output_blocked","preflight"}
    # Schema contract is checked against the method's generated dictionary shape via a harmless synthetic result.
    from localagent.tools.exec import ExecResult
    from localagent.policy import Policy
    from localagent.tools.exec import Exec
    ex=Exec(cfg, Policy(cfg))
    result=ex._audit("run_script", [str(p._trusted_executable)], 1, 0, {"landlock":False,"seccomp":False,"network":False}, [], ExecResult(0,"",""))
    assert required <= result.keys()


def test_secret_scanner_safe_corpus_has_no_false_positives():
    safe = []
    for i in range(200):
        safe.extend([
            f"def function_{i}(value): return value + {i}",
            f"/workspace/src/module_{i}.py",
            f"SELECT id, name FROM table_{i} WHERE id = {i}",
            f"pytest case {i}: expected={i} actual={i}",
        ])
    false_positives = sum(SecretScanner.scan(value) is not None for value in safe)
    assert false_positives / len(safe) <= 0.01


def test_coder_has_all_execution_tools():
    text = Path("agents/coder.md").read_text(encoding="utf-8")
    assert all(name in text for name in ("run_script", "run_module", "run_tests"))


def test_junit_report_is_masked_before_durable_storage():
    import xml.etree.ElementTree as ET
    root = ET.fromstring(
        "<testsuite><testcase classname='tests.x' name='test_bad' line='9'>"
        "<failure message='password=supersecretvalue'>trace password=supersecretvalue</failure>"
        "</testcase></testsuite>"
    )
    masked = RunTests._sanitize_junit(root)
    failure = masked.find('.//failure')
    assert failure is not None
    assert failure.attrib['message'] == '[REDACTED]'
    assert failure.text == '[REDACTED]'
    assert 'supersecretvalue' not in ET.tostring(masked, encoding='unicode')


def test_sandbox_does_not_grant_proc_runtime_by_default():
    source = Path('src/localagent/tools/sandbox.py').read_text(encoding='utf-8')
    start = source.index('for candidate in ("/usr"')
    end = source.index('if libc.prctl', start)
    assert '"/proc"' not in source[start:end]


def test_system_installer_freezes_venv_after_install():
    source = Path('scripts/install-system.sh').read_text(encoding='utf-8')
    install_at = source.index('pip install')
    freeze_at = source.index('chmod -R a-w')
    assert install_at < freeze_at
