"""Best-effort static preflight for application-mode execution.

This is deliberately an error-protection layer, not a security boundary. It
must never be treated as a replacement for Landlock/seccomp.
"""
from __future__ import annotations

import ast
from pathlib import Path

DANGEROUS_MODULES = {
    "subprocess", "socket", "ctypes", "ssl", "urllib", "http", "requests",
    "paramiko", "pexpect", "multiprocessing", "importlib",
}
DANGEROUS_CALLS = {"system", "popen", "remove", "unlink", "rmdir", "rmtree", "execv", "execve", "spawn", "kill", "terminate"}
DYNAMIC_CALLS = {"eval", "exec", "compile", "__import__"}

def check_file(path: str | Path, workspace: str | Path) -> list[str]:
    path = Path(path).resolve()
    root = Path(workspace).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return ["target outside workspace"]
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        return [f"cannot parse target: {type(exc).__name__}"]
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in DANGEROUS_MODULES:
                    findings.append(f"import:{alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in DANGEROUS_MODULES:
                findings.append(f"import:{node.module}")
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) and fn.value.id == "os" and fn.attr == "putenv":
                findings.append("os.environ.write")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            if name in DYNAMIC_CALLS:
                findings.append(f"dynamic:{name}")
            if name in DANGEROUS_CALLS:
                findings.append(f"call:{name}")
            if isinstance(fn, ast.Name) and fn.id == "open":
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    value = node.args[0].value
                    if value.startswith(("/", "~")) or "$HOME" in value or value.startswith("${HOME}"):
                        findings.append(f"path:{value}")
                    else:
                        findings.append(f"write:{value}")
            if isinstance(fn, ast.Attribute) and fn.attr in {"open", "unlink", "remove", "rmdir", "rmtree", "rename", "replace", "write_text", "write_bytes"}:
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    value = node.args[0].value
                    if value.startswith(("/", "~")) or "$HOME" in value or value.startswith("${HOME}") or value.startswith("%USERPROFILE%"):
                        findings.append(f"path:{value}")
                    elif fn.attr in {"open", "write_text", "write_bytes", "rename", "replace", "unlink", "remove", "rmdir", "rmtree"} and isinstance(value, str):
                        findings.append(f"write:{value}")
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "os" and node.value.attr == "environ":
                findings.append("os.environ.write")
        elif isinstance(node, ast.Attribute):
            if node.attr in {"environ"} and isinstance(node.value, ast.Name) and node.value.id == "os":
                findings.append("os.environ")
    return sorted(set(findings))

def check_targets(paths: list[str], workspace: str | Path) -> list[str]:
    findings = []
    root = Path(workspace).resolve()
    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = root / p
        if p.is_file() and p.suffix == ".py":
            findings.extend(f"{p}: {item}" for item in check_file(p, root))
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        names = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module]
                    else:
                        continue
                    for name in names:
                        candidate = root / "src" / Path(*name.split("."))
                        if candidate.with_suffix(".py").is_file() and len(name.split(".")) <= 2:
                            findings.extend(f"{candidate.with_suffix('.py')}: {item}" for item in check_file(candidate.with_suffix(".py"), root))
            except (OSError, UnicodeDecodeError, SyntaxError):
                pass
    return sorted(set(findings))
