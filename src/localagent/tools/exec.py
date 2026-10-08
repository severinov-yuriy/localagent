"""Controlled typed process execution behind a kernel-enforced Linux sandbox."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from .base import Tool
from .sandbox import backend_status
from ..security import DLPPolicy, SecurityDecision, SecretScanner


@dataclass
class ExecResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    output_blocked: bool = False
    audit: dict = None


class ExecutionPolicy:
    """Default-deny typed execution; target code always runs through the launcher."""

    ALLOWED = {"run_script", "run_module", "run_tests"}
    SCRIPT_ROOTS = ("scratch", "scripts", "src", "tests")
    MODULE_ROOT = "src"

    def __init__(self, cfg, workspace, dlp=None):
        self.cfg = cfg
        self.root = Path(workspace).resolve()
        self.dlp = dlp or DLPPolicy()
        configured = cfg.get("exec", {}).get("python")
        candidate = Path(configured).expanduser() if configured else Path(sys.executable)
        self._trusted_executable = candidate.resolve(strict=True)
        self._launcher = (Path(__file__).resolve().parent / "_launcher.py").resolve(strict=True)

    def _inside(self, candidate: Path, allowed):
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, RuntimeError, ValueError):
            return False
        return any(resolved == self.root / d or (self.root / d) in resolved.parents for d in allowed)

    def _path(self, value, allowed, must_file=True):
        p = Path(value)
        if p.is_absolute() or ".." in p.parts:
            raise PermissionError("execution path must be relative to workspace")
        candidate = self.root / p
        if not self._inside(candidate, allowed):
            raise PermissionError(f"path must remain under {', '.join(allowed)}/")
        if must_file and not candidate.resolve(strict=True).is_file():
            raise FileNotFoundError(f"execution target not found: {value}")
        return candidate.resolve(strict=True)

    def script_argv(self, path, args):
        if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
            raise ValueError("args must be a list of strings")
        target = self._path(path, self.SCRIPT_ROOTS)
        if target.suffix not in {".py", ".pyw"}:
            raise PermissionError("run_script only permits Python script files under scratch/, scripts/, src/, or tests/")
        return [str(self._trusted_executable), str(target), *args]

    def module_argv(self, module, args):
        if not self.cfg.get("exec", {}).get("allow_module", True):
            raise PermissionError("run_module is disabled by exec.allow_module=false")
        if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
            raise ValueError("args must be a list of strings")
        if not isinstance(module, str) or not module or module.startswith((".", "/")):
            raise PermissionError("invalid Python module")
        parts = module.split(".")
        if not all(x.isidentifier() for x in parts):
            raise PermissionError("invalid Python module")
        src = self.root / self.MODULE_ROOT
        candidate = src.joinpath(*parts).with_suffix(".py")
        if candidate.is_file():
            target = candidate.resolve(strict=True)
        else:
            package = src.joinpath(*parts, "__main__.py")
            if not package.is_file():
                raise FileNotFoundError(f"module not found: {module}")
            target = package.resolve(strict=True)
        if not self._inside(target, (self.MODULE_ROOT,)):
            raise PermissionError("module outside src/")
        if any(a in {"-c", "-m", "-"} or a.startswith("-c") for a in args):
            raise PermissionError("inline Python and interpreter options are forbidden")
        # Use Python's module loader so package imports and __package__ semantics
        # are preserved. The launcher keeps the interpreter itself trusted.
        return [str(self._trusted_executable), "-m", module, *args]

    def test_argv(self, targets):
        if not isinstance(targets, list) or not all(isinstance(x, str) for x in targets):
            raise ValueError("targets must be a list of strings")
        out = []
        for target in targets or ["tests"]:
            self._path(target, ("tests",), must_file=False)
            out.append(target)
        return [
            str(self._trusted_executable), "-m", "pytest",
            "-p", "no:cacheprovider",
            "--junitxml=scratch/pytest-results.xml",
            *out,
        ]

    def _configured_path(self, key):
        value = self.cfg.get("exec", {}).get(key)
        if not value:
            return None
        p = Path(value).expanduser().resolve(strict=True)
        try:
            p.relative_to(self.root)
        except ValueError:
            return p
        raise PermissionError(f"exec.{key} must not point into the writable workspace")

    def env(self):
        e = {
            "PATH": str(self._trusted_executable.parent) + os.pathsep + os.defpath,
            "PYTHONNOUSERSITE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "LANG": os.environ.get("LANG", "C"),
            "LC_ALL": os.environ.get("LC_ALL", "C"),
            "PYSPARK_PYTHON": str(self._trusted_executable),
            "SPARK_LOCAL_IP": "127.0.0.1",
            "TMPDIR": str(self.root / "scratch"),
            "SPARK_LOCAL_DIRS": str(self.root / "scratch"),
        }
        for key in ("JAVA_HOME", "SPARK_HOME"):
            value = self._configured_path(key.lower())
            if value is not None:
                e[key] = str(value)
        pythonpath = self.cfg.get("exec", {}).get("pythonpath", [])
        if pythonpath:
            trusted = []
            for value in pythonpath:
                p = Path(value).expanduser().resolve(strict=True)
                try:
                    p.relative_to(self.root)
                except ValueError:
                    trusted.append(str(p))
                else:
                    raise PermissionError("exec.pythonpath entries must not point into the writable workspace")
            e["PYTHONPATH"] = os.pathsep.join(trusted)
        return {k: v for k, v in e.items() if v != ""}

    def decision(self, operation, executable_or_argv, argv_or_cwd, cwd_or_env, env_or_timeout, timeout=None):
        if timeout is None:
            argv, cwd, env, timeout = executable_or_argv, argv_or_cwd, cwd_or_env, env_or_timeout
        else:
            executable, argv, cwd, env = executable_or_argv, argv_or_cwd, cwd_or_env, env_or_timeout
            argv = [executable, *argv]
        if operation not in self.ALLOWED:
            return SecurityDecision(False, "ExecutionPolicy", operation, "operation not allowlisted")
        if not argv or Path(argv[0]).resolve() != self._trusted_executable:
            return SecurityDecision(False, "ExecutionPolicy", operation, "executable is not the configured trusted interpreter")
        try:
            if Path(cwd).resolve() != self.root:
                return SecurityDecision(False, "ExecutionPolicy", operation, "cwd must be workspace")
        except OSError:
            return SecurityDecision(False, "ExecutionPolicy", operation, "invalid cwd")
        allowed_env = {"PATH", "PYTHONNOUSERSITE", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONPATH", "LANG", "LC_ALL",
                       "JAVA_HOME", "SPARK_HOME", "PYSPARK_PYTHON", "SPARK_LOCAL_IP", "TMPDIR", "SPARK_LOCAL_DIRS"}
        if not set(env) <= allowed_env:
            return SecurityDecision(False, "ExecutionPolicy", operation, "environment variable not allowlisted")
        if any(x in {"-c", "-", "stdin"} for x in argv[1:]) or any(x.startswith("-c") for x in argv[1:]):
            return SecurityDecision(False, "ExecutionPolicy", operation, "inline code/stdin is forbidden")
        d = self.dlp.check("execution.arguments", argv)
        if not d.allowed:
            return d
        return SecurityDecision(True, "ExecutionPolicy", operation, "allowed")

    def authorize(self, operation, argv, cwd, env, timeout):
        d = self.decision(operation, argv, cwd, env, timeout)
        if not d.allowed:
            raise PermissionError(d.reason)
        return d

    def backend_status(self):
        return backend_status()


class Exec(Tool):
    capabilities = {"process.execute"}

    def __init__(self, cfg, policy, dlp=None):
        self.cfg, self.p = cfg, policy
        self.dlp = dlp or DLPPolicy()
        self.execution_policy = ExecutionPolicy(cfg, policy.root, self.dlp)
        self._deadline = None

    def set_deadline(self, deadline):
        self._deadline = deadline

    def _enabled(self):
        mode = self.cfg["exec"].get("mode", "off")
        if mode == "off" and self.cfg["exec"].get("enabled", False):
            mode = "auto"
        if mode == "off":
            raise PermissionError("execution disabled by exec.mode=off")
        if mode not in {"auto", "ask", "on"}:
            raise PermissionError("invalid exec.mode")
        isolation = self.cfg["exec"].get("isolation", "best_effort")
        if isolation not in {"kernel", "best_effort", "app"}:
            raise PermissionError("invalid exec.isolation")
        status = self.execution_policy.backend_status()
        if isolation == "kernel" and not status["ready"]:
            raise PermissionError("kernel isolation requires Landlock, seccomp and network isolation")
        if isolation == "best_effort" and not (status["landlock"] or status["seccomp"] or status["network"]):
            raise PermissionError("best_effort isolation has no available kernel layer; use app explicitly")
        return isolation, status

    def preview(self, operation, argv):
        """Return the execution security context used for confirmation."""
        mode, status = self._enabled()
        import hashlib
        target = None
        if operation == "run_module" and len(argv) >= 3:
            module = argv[2]
            candidate = self.p.root / "src" / Path(*module.split("."))
            candidate = candidate.with_suffix(".py") if candidate.with_suffix(".py").is_file() else candidate / "__main__.py"
            if candidate.is_file():
                target = candidate.resolve()
        else:
            for value in argv[1:]:
                candidate = Path(value)
                if candidate.is_file():
                    target = candidate
                    break
        digest = None
        if target:
            h = hashlib.sha256()
            with target.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        findings = []
        if mode == "app":
            from .preflight import check_targets
            findings = check_targets([str(x) for x in argv[1:] if str(x).endswith(".py")], self.p.root)
        return {"argv": list(argv), "path": str(target) if target else None, "sha256": digest,
                "layers": [k for k,v in status.items() if k in {"landlock","seccomp","network"} and v],
                "isolation": mode, "preflight": findings}

    def _run(self, operation, argv, timeout):
        mode, status = self._enabled()
        scratch = self.p.root.joinpath("scratch")
        scratch.mkdir(exist_ok=True)
        env = self.execution_policy.env()
        if operation == "run_module":
            module_path = str(self.p.root / "src")
            env["PYTHONPATH"] = module_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        self.execution_policy.authorize(operation, argv, self.p.root, env, timeout)
        rw_dirs = list(self.cfg["exec"].get("rw_dirs", ["src", "tests", "scripts", "scratch", "data", "docs"]))
        protected = {"AGENTS.md", "agents", "skills", ".pi", ".agent"}
        if any(Path(x).is_absolute() or ".." in Path(x).parts or Path(x).parts and Path(x).parts[0] in protected for x in rw_dirs):
            raise PermissionError("exec.rw_dirs cannot include control-plane paths")
        spec = {
            "argv": argv,
            "cwd": str(self.p.root),
            "workspace": str(self.p.root),
            "scratch": str(scratch.resolve()),
            "trusted_executable": str(self.execution_policy._trusted_executable),
            "env": env,
            "cpu_s": int(self.cfg["exec"].get("cpu_s", 120)),
            "fsize_bytes": int(self.cfg["exec"].get("fsize_bytes", 50_000_000)),
            "nofile": int(self.cfg["exec"].get("nofile", 4096)),
            "isolation": mode,
            "layers": [name for name, available in status.items() if name in {"landlock", "seccomp", "network"} and available],
            "rw_dirs": rw_dirs,
            "ro_paths": self.cfg["exec"].get("ro_paths", ["AGENTS.md", "agents", "skills", ".pi", ".agent"]),
        }
        findings = []
        if mode == "app":
            from .preflight import check_targets
            targets = [str(x) for x in argv[1:] if str(x).endswith(".py")]
            findings = check_targets(targets, self.p.root)
            if findings:
                raise PermissionError("preflight blocked execution: " + "; ".join(findings[:8]))
        launcher_argv = [str(self.execution_policy._trusted_executable), str(self.execution_policy._launcher)]
        launcher_env = {"LOCALAGENT_LAUNCH_SPEC": json.dumps(spec, separators=(",", ":"))}
        started = time.monotonic()
        proc = None
        try:
            proc = subprocess.Popen(launcher_argv, cwd=self.p.root, env=launcher_env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    shell=False, start_new_session=True)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                result = self._scan_result(ExecResult(proc.returncode, stdout or "", stderr or "", False), operation, argv, started, proc.pid)
                result.audit = self._audit(operation, argv, proc.pid, started, status, findings, result)
                return result
            except subprocess.TimeoutExpired as exc:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = proc.communicate()
                result = self._scan_result(ExecResult(proc.returncode,
                    (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace"),
                    (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace"), True), operation, argv, started, proc.pid)
                result.audit = self._audit(operation, argv, proc.pid, started, status, findings, result)
                return result
        finally:
            pass

    def _audit(self, operation, argv, pid, started, status, findings, result):
        import hashlib
        target = None
        if operation == "run_module" and len(argv) >= 3:
            module = argv[2]
            candidate = self.p.root / "src" / Path(*str(module).split("."))
            py = candidate.with_suffix(".py")
            main = candidate / "__main__.py"
            if py.is_file():
                target = py.resolve()
            elif main.is_file():
                target = main.resolve()
        else:
            for value in argv[1:]:
                candidate = Path(value)
                if candidate.is_file():
                    target = candidate.resolve()
                    break
        sha256 = None
        if target is not None:
            try:
                h = hashlib.sha256()
                with target.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                sha256 = h.hexdigest()
            except OSError:
                pass
        return {
            "operation": operation, "path": str(target) if target else None, "sha256": sha256,
            "argv": list(argv), "env_keys": sorted(self.execution_policy.env().keys()), "pid": pid,
            "layers": [name for name, available in status.items() if name in {"landlock", "seccomp", "network"} and available],
            "duration_s": round(time.monotonic() - started, 6),
            "return_code": result.returncode,
            "stdout_size": len(result.stdout),
            "stderr_size": len(result.stderr),
            "output_size": len(result.stdout) + len(result.stderr),
            "output_blocked": bool(result.output_blocked),
            "dlp": "blocked" if result.output_blocked else "clear",
            "preflight": list(findings),
        }

    def _scan_result(self, result, operation, argv, started, pid):
        for field in ("stdout", "stderr"):
            value = getattr(result, field)
            if SecretScanner.scan(value):
                setattr(result, field, "content blocked by security policy")
                result.output_blocked = True
        limit = int(self.cfg["exec"].get("output_limit", 12000))
        result.stdout = result.stdout[:limit] + ("\n\noutput truncated" if len(result.stdout) > limit else "")
        result.stderr = result.stderr[:limit] + ("\n\noutput truncated" if len(result.stderr) > limit else "")
        return result


class RunScript(Exec):
    name = "run_script"
    description = "Run a Python file under scratch/ with explicit argv and kernel sandboxing."
    def run(self, a):
        argv = self.execution_policy.script_argv(a["path"], a.get("args", []))
        r = self._run("run_script", argv, self.cfg["exec"].get("timeout_s", 120))
        return {"ok": r.returncode == 0 and not r.timed_out and not r.output_blocked,
                "is_error": r.returncode != 0 or r.timed_out or r.output_blocked, **r.__dict__}


class RunModule(Exec):
    name = "run_module"
    description = "Run an existing Python module under src/."
    def run(self, a):
        argv = self.execution_policy.module_argv(a["module"], a.get("args", []))
        r = self._run("run_module", argv, self.cfg["exec"].get("timeout_s", 120))
        return {"ok": r.returncode == 0 and not r.timed_out and not r.output_blocked,
                "is_error": r.returncode != 0 or r.timed_out or r.output_blocked, **r.__dict__}


class RunTests(Exec):
    name = "run_tests"
    description = "Run pytest against tests/ in the execution sandbox."

    @staticmethod
    def _filter_output(value):
        """Remove noisy Py4J/INFO infrastructure lines from pytest tool output."""
        lines = []
        for line in str(value or "").splitlines():
            stripped = line.lstrip()
            if stripped.startswith("INFO") or stripped.startswith("Py4J") or "py4j" in stripped.lower():
                continue
            lines.append(line)
        return "\n".join(lines)
    def run(self, a):
        argv = self.execution_policy.test_argv(a["targets"])
        r = self._run("run_tests", argv, self.cfg["exec"].get("timeout_s", 120))
        r.stdout = self._filter_output(r.stdout)
        r.stderr = self._filter_output(r.stderr)
        payload = {"ok": r.returncode == 0 and not r.timed_out and not r.output_blocked,
                   "is_error": r.returncode != 0 or r.timed_out or r.output_blocked, **r.__dict__}
        report = self.p.root / "scratch" / "pytest-results.xml"
        if report.is_file():
            try:
                root = ET.parse(report).getroot()
                cases = []
                for case in root.iter("testcase"):
                    item = {"test": case.attrib.get("classname", "") + ("::" if case.attrib.get("classname") else "") + case.attrib.get("name", ""),
                            "line": int(case.attrib.get("line", 0) or 0) or None, "message": None, "status": "passed"}
                    failure = case.find("failure")
                    error = case.find("error")
                    skipped = case.find("skipped")
                    node = failure if failure is not None else error if error is not None else skipped
                    if failure is not None:
                        item["status"] = "failed"
                    elif error is not None:
                        item["status"] = "error"
                    elif skipped is not None:
                        item["status"] = "skipped"
                    if node is not None:
                        item["message"] = node.attrib.get("message") or (node.text or "").strip() or None
                    cases.append(item)
                payload["tests"] = {
                    "passed": sum(x["status"] == "passed" for x in cases),
                    "failed": sum(x["status"] == "failed" for x in cases),
                    "errors": sum(x["status"] == "error" for x in cases),
                    "skipped": sum(x["status"] == "skipped" for x in cases),
                    "total": len(cases),
                    "cases": cases,
                }
            except (OSError, ET.ParseError, ValueError):
                payload["tests"] = {"parse_error": True}
        return payload
