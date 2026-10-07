#!/usr/bin/env python3
"""
LocalAgent infrastructure compatibility / readiness checker.

IMPORTANT:
    This script is READ-ONLY.

It does NOT:
    - install anything
    - modify files
    - modify environment variables
    - modify kernel settings
    - create namespaces
    - install seccomp/landlock filters
    - change ulimits
    - start LocalAgent
    - execute project code
    - write network requests with POST/PUT/PATCH/DELETE
    - authenticate or send API keys unless explicitly requested by the
      read-only endpoint checks below

It only:
    - reads local information
    - imports already-installed Python packages
    - inspects Linux/kernel capabilities
    - performs harmless GET/HEAD requests to explicitly configured endpoints
    - inspects LocalAgent configuration if a project path is supplied
    - optionally performs read-only GET /v1/models requests against
      OpenAI-compatible endpoints

Usage examples:

    python3 check_localagent_environment.py

    python3 check_localagent_environment.py \
        --project-root /path/to/localagent-final-v2-hardened

    python3 check_localagent_environment.py \
        --project-root /path/to/localagent-final-v2-hardened \
        --endpoint http://127.0.0.1:8000/v1

The script prints a report and exits:
    0 = all mandatory prerequisites pass
    1 = one or more mandatory prerequisites failed
    2 = checker itself could not complete normally

No external Python packages are required by this checker.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import importlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


# ============================================================================
# Output / state
# ============================================================================

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"
SKIP = "SKIP"

results: list[dict[str, Any]] = []


def record(
    section: str,
    name: str,
    status: str,
    detail: str = "",
    mandatory: bool = False,
) -> None:
    results.append(
        {
            "section": section,
            "name": name,
            "status": status,
            "detail": detail,
            "mandatory": mandatory,
        }
    )


def line(char: str = "=", width: int = 78) -> None:
    print(char * width)


def heading(title: str) -> None:
    print()
    line()
    print(title)
    line()


def result(
    section: str,
    name: str,
    status: str,
    detail: str = "",
    mandatory: bool = False,
) -> None:
    record(section, name, status, detail, mandatory)

    marker = {
        PASS: "[PASS]",
        FAIL: "[FAIL]",
        WARN: "[WARN]",
        INFO: "[INFO]",
        SKIP: "[SKIP]",
    }.get(status, "[????]")

    suffix = f" - {detail}" if detail else ""
    print(f"{marker:8} {name}{suffix}")


# ============================================================================
# Safe helpers
# ============================================================================

def read_text(path: str | Path, max_bytes: int = 1_000_000) -> str | None:
    try:
        p = Path(path)
        with p.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


def read_int(path: str | Path) -> int | None:
    text = read_text(path, 1024)
    if text is None:
        return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def kernel_release() -> tuple[int, int, int]:
    raw = platform.release()
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", raw)
    if not m:
        return (0, 0, 0)
    return tuple(int(x) for x in m.groups())


def version_tuple(value: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", value)
    return tuple(int(x) for x in nums)


def safe_import(module_name: str) -> tuple[bool, str]:
    try:
        module = importlib.import_module(module_name)
        version = getattr(module, "__version__", None)

        if version is None:
            try:
                from importlib.metadata import version as pkg_version

                package_name = {
                    "yaml": "PyYAML",
                    "httpx": "httpx",
                }.get(module_name, module_name)
                version = pkg_version(package_name)
            except Exception:
                version = "installed"

        return True, str(version)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None

    value = value.strip().lower()

    if value in {"1", "true", "yes", "on"}:
        return True

    if value in {"0", "false", "no", "off"}:
        return False

    return None


# ============================================================================
# Python
# ============================================================================

def check_python() -> None:
    heading("PYTHON RUNTIME")

    result(
        "python",
        "Python version",
        PASS if sys.version_info >= (3, 10) else FAIL,
        f"{platform.python_version()} "
        f"(required >= 3.10)",
        mandatory=True,
    )

    result(
        "python",
        "Python executable",
        PASS,
        sys.executable,
    )

    result(
        "python",
        "Python implementation",
        PASS,
        platform.python_implementation(),
    )

    required_stdlib = [
        "ctypes",
        "ctypes.util",
        "json",
        "sqlite3",
        "ssl",
        "socket",
        "subprocess",
        "resource",
        "fcntl",
        "signal",
        "selectors",
        "pathlib",
        "urllib.request",
        "importlib.metadata",
    ]

    for module_name in required_stdlib:
        ok, detail = safe_import(module_name)

        mandatory = module_name not in {
            "resource",
            "fcntl",
        }

        result(
            "python",
            f"stdlib: {module_name}",
            PASS if ok else (FAIL if mandatory else WARN),
            detail,
            mandatory=mandatory,
        )

    for package in ["httpx", "yaml"]:
        ok, detail = safe_import(package)

        result(
            "python",
            f"package: {package}",
            PASS if ok else FAIL,
            detail,
            mandatory=True,
        )

    # Optional packages that may be useful for LocalAgent features.
    optional_packages = [
        "pytest",
        "pydantic",
        "fastapi",
        "uvicorn",
        "openai",
        "httpcore",
        "anyio",
        "certifi",
        "idna",
    ]

    for package in optional_packages:
        ok, detail = safe_import(package)

        result(
            "python",
            f"optional package: {package}",
            PASS if ok else INFO,
            detail if ok else "not installed",
            mandatory=False,
        )


# ============================================================================
# Operating system
# ============================================================================

def check_os() -> None:
    heading("OPERATING SYSTEM")

    result("os", "OS", PASS, platform.system())

    result("os", "Kernel", PASS, platform.release())

    result("os", "Architecture", PASS, platform.machine())

    if platform.system() != "Linux":
        result(
            "os",
            "Linux",
            FAIL,
            "LocalAgent sandbox requires Linux",
            mandatory=True,
        )
        return

    major, minor, patch = kernel_release()

    result(
        "os",
        "Linux kernel version",
        PASS,
        f"{major}.{minor}.{patch}",
        mandatory=True,
    )

    result(
        "os",
        "procfs",
        PASS if Path("/proc").is_dir() else FAIL,
        "/proc available" if Path("/proc").is_dir() else "/proc unavailable",
        mandatory=True,
    )

    result(
        "os",
        "sysfs",
        PASS if Path("/sys").is_dir() else WARN,
        "/sys available" if Path("/sys").is_dir() else "/sys unavailable",
    )


# ============================================================================
# User permissions / identity
# ============================================================================

def check_identity() -> None:
    heading("CURRENT USER / PRIVILEGES")

    if hasattr(os, "getuid"):
        uid = os.getuid()
        gid = os.getgid()

        result("identity", "UID", INFO, str(uid))
        result("identity", "GID", INFO, str(gid))

        if uid == 0:
            result(
                "identity",
                "root",
                WARN,
                "Running as root; this is NOT required by LocalAgent",
            )
        else:
            result(
                "identity",
                "non-root execution",
                PASS,
                "ordinary user is sufficient",
            )

    # Capabilities, if available.
    status = read_text("/proc/self/status")

    if status:
        cap_eff = None

        for line_text in status.splitlines():
            if line_text.startswith("CapEff:"):
                cap_eff = line_text.split(":", 1)[1].strip()
                break

        if cap_eff is not None:
            result(
                "identity",
                "Linux effective capabilities",
                INFO,
                f"CapEff={cap_eff}",
            )

        no_new_privs = None

        for line_text in status.splitlines():
            if line_text.startswith("NoNewPrivs:"):
                no_new_privs = line_text.split(":", 1)[1].strip()
                break

        if no_new_privs is not None:
            result(
                "identity",
                "current NoNewPrivs",
                INFO,
                no_new_privs,
            )


# ============================================================================
# Filesystem
# ============================================================================

def check_path_access(
    path: Path,
    read: bool = False,
    write: bool = False,
    execute: bool = False,
) -> tuple[bool, str]:
    if not path.exists():
        return False, "does not exist"

    try:
        if read and not os.access(path, os.R_OK):
            return False, "not readable"

        if write and not os.access(path, os.W_OK):
            return False, "not writable"

        if execute and not os.access(path, os.X_OK):
            return False, "not executable"

        return True, "accessible"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def check_filesystem(project_root: Path | None) -> None:
    heading("FILESYSTEM")

    cwd = Path.cwd().resolve()

    result(
        "filesystem",
        "current working directory",
        PASS,
        str(cwd),
    )

    ok, detail = check_path_access(cwd, read=True, execute=True)

    result(
        "filesystem",
        "current directory readable/executable",
        PASS if ok else FAIL,
        detail,
        mandatory=True,
    )

    if project_root is None:
        result(
            "filesystem",
            "project root",
            INFO,
            "not supplied; use --project-root to validate the actual project",
        )
        return

    try:
        project_root = project_root.resolve()
    except Exception as exc:
        result(
            "filesystem",
            "project root resolution",
            FAIL,
            str(exc),
            mandatory=True,
        )
        return

    result(
        "filesystem",
        "project root exists",
        PASS if project_root.is_dir() else FAIL,
        str(project_root),
        mandatory=True,
    )

    if not project_root.is_dir():
        return

    ok, detail = check_path_access(
        project_root,
        read=True,
        write=True,
        execute=True,
    )

    result(
        "filesystem",
        "project root read/write/execute",
        PASS if ok else FAIL,
        detail,
        mandatory=True,
    )

    expected_dirs = [
        "src",
        "scripts",
        "tests",
        "scratch",
        ".agent",
    ]

    for dirname in expected_dirs:
        path = project_root / dirname

        if path.exists():
            ok, detail = check_path_access(
                path,
                read=True,
                execute=True,
            )

            result(
                "filesystem",
                f"project/{dirname}",
                PASS if ok else FAIL,
                detail,
            )
        else:
            result(
                "filesystem",
                f"project/{dirname}",
                INFO,
                "directory does not exist",
            )

    # Check the user's HOME without reading anything inside it.
    home = Path.home()

    result(
        "filesystem",
        "user HOME exists",
        PASS if home.is_dir() else WARN,
        str(home),
    )

    # We intentionally do NOT try to read arbitrary files under HOME.
    # The real sandbox test must verify that an execution child cannot
    # access HOME. This checker only verifies that HOME is known.
    result(
        "filesystem",
        "HOME contents",
        INFO,
        "not inspected by this diagnostic",
    )


# ============================================================================
# Kernel syscall helpers
# ============================================================================

libc = None


def get_libc():
    global libc

    if libc is not None:
        return libc

    libc_path = ctypes.util.find_library("c")

    if not libc_path:
        return None

    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
        return libc
    except Exception:
        return None


def syscall_number(name: str) -> int | None:
    """
    Return known syscall numbers for common Linux architectures.

    These are used only for a harmless capability probe where supported.
    """

    machine = platform.machine().lower()

    tables = {
        "x86_64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
        "amd64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
        "aarch64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
        "arm64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
    }

    return tables.get(machine, {}).get(name)


# ============================================================================
# Landlock
# ============================================================================

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0


def probe_landlock() -> tuple[str, str]:
    """
    Read-only Landlock ABI probe.

    Calling landlock_create_ruleset(NULL, 0, VERSION) only queries the
    kernel ABI and does not install or change a ruleset.
    """

    if platform.system() != "Linux":
        return FAIL, "Linux required"

    libc_obj = get_libc()

    if libc_obj is None:
        return FAIL, "libc unavailable"

    nr = syscall_number("landlock_create_ruleset")

    if nr is None:
        return WARN, f"unsupported architecture: {platform.machine()}"

    libc_obj.syscall.restype = ctypes.c_long
    libc_obj.syscall.argtypes = [
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
    ]

    ctypes.set_errno(0)

    fd_or_version = libc_obj.syscall(
        nr,
        None,
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )

    if fd_or_version >= 0:
        return PASS, f"Landlock ABI {fd_or_version}"

    errno_value = ctypes.get_errno()

    # EOPNOTSUPP means the kernel does not provide Landlock.
    if errno_value == 95:
        return FAIL, "Landlock syscall exists but kernel does not support it"

    # ENOSYS means syscall unavailable.
    if errno_value == 38:
        return FAIL, "Landlock syscall unavailable"

    # EFAULT/other errors can indicate a restricted environment, but
    # distinguish them from a completely missing syscall.
    return WARN, f"syscall returned errno={errno_value}"


def check_landlock() -> None:
    heading("LANDLOCK")

    status, detail = probe_landlock()

    result(
        "landlock",
        "Landlock ABI query",
        status,
        detail,
        mandatory=True,
    )

    abi_file = "/sys/kernel/security/landlock/features"

    if Path(abi_file).exists():
        text = read_text(abi_file)
        result(
            "landlock",
            "Landlock securityfs",
            PASS,
            text.strip() if text else "available",
        )
    else:
        result(
            "landlock",
            "Landlock securityfs",
            INFO,
            "not exposed; syscall result is authoritative",
        )


# ============================================================================
# Seccomp
# ============================================================================

PR_GET_SECCOMP = 21
PR_SET_NO_NEW_PRIVS = 38


def prctl_call(option: int, arg2: int = 0) -> tuple[int, int]:
    libc_obj = get_libc()

    if libc_obj is None:
        return -1, 0

    libc_obj.prctl.restype = ctypes.c_int
    libc_obj.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]

    ctypes.set_errno(0)

    value = libc_obj.prctl(
        option,
        arg2,
        0,
        0,
        0,
    )

    return value, ctypes.get_errno()


def check_seccomp() -> None:
    heading("SECCOMP")

    if platform.system() != "Linux":
        result(
            "seccomp",
            "Linux",
            FAIL,
            "Linux required",
            mandatory=True,
        )
        return

    status = read_text("/proc/self/status")

    if status:
        seccomp_mode = None

        for line_text in status.splitlines():
            if line_text.startswith("Seccomp:"):
                seccomp_mode = line_text.split(":", 1)[1].strip()
                break

        result(
            "seccomp",
            "current seccomp mode",
            INFO,
            seccomp_mode if seccomp_mode is not None else "unknown",
        )

    value, errno_value = prctl_call(PR_GET_SECCOMP)

    if value >= 0:
        result(
            "seccomp",
            "PR_GET_SECCOMP",
            PASS,
            f"mode={value}",
            mandatory=True,
        )
    else:
        result(
            "seccomp",
            "PR_GET_SECCOMP",
            FAIL,
            f"errno={errno_value}",
            mandatory=True,
        )

    actions_file = Path("/proc/sys/kernel/seccomp/actions_avail")

    if actions_file.exists():
        actions = read_text(actions_file)

        result(
            "seccomp",
            "kernel seccomp actions",
            PASS if actions else WARN,
            actions.strip() if actions else "unable to read",
        )
    else:
        result(
            "seccomp",
            "kernel seccomp actions",
            INFO,
            "/proc/sys/kernel/seccomp/actions_avail unavailable",
        )

    # IMPORTANT:
    # We DO NOT call PR_SET_NO_NEW_PRIVS here.
    # Changing NoNewPrivs would modify the state of this diagnostic process.
    result(
        "seccomp",
        "NO_NEW_PRIVS capability",
        INFO,
        "not modified; actual installation is tested only by the isolated sandbox integration suite",
    )


# ============================================================================
# User namespaces
# ============================================================================

def check_user_namespace() -> None:
    heading("USER NAMESPACE")

    if platform.system() != "Linux":
        result(
            "userns",
            "Linux",
            FAIL,
            "Linux required",
            mandatory=True,
        )
        return

    settings = [
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/user/max_user_namespaces",
    ]

    found = False

    for path in settings:
        if Path(path).exists():
            found = True
            value = read_text(path)

            result(
                "userns",
                path,
                INFO,
                value.strip() if value else "unreadable",
            )

    if not found:
        result(
            "userns",
            "kernel user namespace policy",
            INFO,
            "no standard policy file exposed",
        )

    # DO NOT call unshare().
    #
    # unshare(CLONE_NEWUSER) changes process namespaces.
    # This diagnostic must be completely side-effect-free.
    result(
        "userns",
        "actual userns creation",
        INFO,
        "not attempted because it changes process state; sandbox integration test performs this in a disposable child",
    )


# ============================================================================
# Network namespace
# ============================================================================

def check_network_namespace() -> None:
    heading("NETWORK NAMESPACE")

    if platform.system() != "Linux":
        result(
            "netns",
            "Linux",
            FAIL,
            "Linux required",
            mandatory=True,
        )
        return

    result(
        "netns",
        "network namespace",
        INFO,
        "not created by diagnostic because namespace creation changes process state",
    )

    result(
        "netns",
        "actual netns isolation",
        INFO,
        "must be verified by disposable sandbox integration test",
    )


# ============================================================================
# Resource limits
# ============================================================================

def check_rlimits() -> None:
    heading("RESOURCE LIMITS")

    try:
        import resource
    except ImportError:
        result(
            "rlimits",
            "resource module",
            FAIL,
            "not available",
            mandatory=True,
        )
        return

    names = [
        "RLIMIT_CPU",
        "RLIMIT_FSIZE",
        "RLIMIT_NOFILE",
        "RLIMIT_AS",
        "RLIMIT_NPROC",
        "RLIMIT_CORE",
    ]

    for name in names:
        constant = getattr(resource, name, None)

        if constant is None:
            result(
                "rlimits",
                name,
                WARN,
                "not available on this platform",
            )
            continue

        try:
            soft, hard = resource.getrlimit(constant)

            def fmt(value: int) -> str:
                if value == resource.RLIM_INFINITY:
                    return "unlimited"
                return str(value)

            result(
                "rlimits",
                name,
                PASS,
                f"soft={fmt(soft)}, hard={fmt(hard)}",
            )
        except Exception as exc:
            result(
                "rlimits",
                name,
                WARN,
                str(exc),
            )


# ============================================================================
# Tools / executables
# ============================================================================

def check_tools(project_root: Path | None) -> None:
    heading("SYSTEM TOOLS")

    tools = [
        "python",
        "python3",
        "pytest",
        "git",
        "java",
        "javac",
        "bash",
        "sh",
        "curl",
        "openssl",
    ]

    for tool in tools:
        path = shutil.which(tool)

        if path:
            detail = path

            try:
                proc = subprocess.run(
                    [path, "--version"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=3,
                    check=False,
                )

                version = proc.stdout.strip().splitlines()

                if version:
                    detail += f" ({version[0][:200]})"
            except Exception:
                pass

            result(
                "tools",
                tool,
                PASS,
                detail,
            )
        else:
            result(
                "tools",
                tool,
                INFO,
                "not installed",
            )

    # Project-local helper discovery.
    if project_root:
        candidates = [
            project_root / ".venv" / "bin" / "python",
            project_root / ".venv" / "bin" / "pytest",
            project_root / "venv" / "bin" / "python",
            project_root / "venv" / "bin" / "pytest",
        ]

        for candidate in candidates:
            result(
                "tools",
                f"project-local {candidate.name}",
                PASS if candidate.exists() else INFO,
                str(candidate),
            )


# ============================================================================
# LocalAgent project inspection
# ============================================================================

def load_yaml_safely(path: Path) -> dict[str, Any] | None:
    try:
        import yaml
    except Exception:
        return None

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return data if isinstance(data, dict) else {}
    except Exception:
        return None


def find_project_config(project_root: Path) -> list[Path]:
    candidates = [
        project_root / "config.yaml",
        project_root / "config.yml",
        project_root / ".agent" / "config.yaml",
        project_root / ".agent" / "config.yml",
    ]

    return [p for p in candidates if p.is_file()]


def check_project(project_root: Path | None) -> None:
    heading("LOCALAGENT PROJECT")

    if project_root is None:
        result(
            "project",
            "project root",
            INFO,
            "not supplied",
        )
        return

    pyproject = project_root / "pyproject.toml"

    result(
        "project",
        "pyproject.toml",
        PASS if pyproject.is_file() else FAIL,
        str(pyproject),
        mandatory=True,
    )

    source_root = project_root / "src" / "localagent"

    result(
        "project",
        "src/localagent",
        PASS if source_root.is_dir() else FAIL,
        str(source_root),
        mandatory=True,
    )

    expected_modules = [
        "config.py",
        "policy.py",
        "security.py",
        "agent.py",
        "runner.py",
        "tools",
    ]

    for module in expected_modules:
        path = source_root / module

        result(
            "project",
            f"localagent/{module}",
            PASS if path.exists() else FAIL,
            str(path),
            mandatory=True,
        )

    configs = find_project_config(project_root)

    if configs:
        for config_path in configs:
            result(
                "project",
                "configuration file",
                INFO,
                str(config_path),
            )

            data = load_yaml_safely(config_path)

            if data is None:
                result(
                    "project",
                    f"parse {config_path.name}",
                    WARN,
                    "could not parse with installed PyYAML",
                )
                continue

            inspect_config(data, str(config_path))
    else:
        result(
            "project",
            "configuration file",
            INFO,
            "no standard project config found",
        )


def inspect_config(data: dict[str, Any], source: str) -> None:
    exec_cfg = data.get("exec")

    if isinstance(exec_cfg, dict):
        result(
            "config",
            f"{source}: exec configuration",
            INFO,
            json.dumps(exec_cfg, ensure_ascii=False, sort_keys=True),
        )

        mode = exec_cfg.get("mode")

        if mode == "auto":
            result(
                "config",
                f"{source}: exec.mode=auto",
                WARN,
                "auto requires a fully usable sandbox on the target machine",
            )

    llm = data.get("llm")

    if isinstance(llm, dict):
        result(
            "config",
            f"{source}: LLM configuration",
            INFO,
            "LLM section found",
        )

        base_url = llm.get("base_url")

        if base_url:
            result(
                "config",
                f"{source}: LLM base_url",
                INFO,
                str(base_url),
            )

        model = llm.get("model")

        if model:
            result(
                "config",
                f"{source}: LLM model",
                INFO,
                str(model),
            )

    permissions = data.get("permissions")

    if isinstance(permissions, dict):
        result(
            "config",
            f"{source}: permissions configuration",
            INFO,
            "permissions section found",
        )


# ============================================================================
# Environment
# ============================================================================

def check_environment() -> None:
    heading("LOCALAGENT ENVIRONMENT VARIABLES")

    relevant = sorted(
        key
        for key in os.environ
        if key.startswith("LOCALAGENT_")
        or key
        in {
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "JAVA_HOME",
            "SPARK_HOME",
            "PYTHONPATH",
            "PYTHONNOUSERSITE",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        }
    )

    if not relevant:
        result(
            "environment",
            "relevant environment variables",
            INFO,
            "none found",
        )
        return

    secret_patterns = (
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASS",
    )

    for key in relevant:
        value = os.environ.get(key, "")

        if any(part in key.upper() for part in secret_patterns):
            display = "<present; value intentionally not printed>"
        else:
            display = value[:500]

        result(
            "environment",
            key,
            INFO,
            display,
        )


# ============================================================================
# HTTP endpoint checks
# ============================================================================

def normalize_base_url(url: str) -> str:
    return url.rstrip("/")


def safe_http_get(
    url: str,
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
) -> tuple[int | None, str, str]:
    """
    READ-ONLY HTTP GET.

    No POST/PUT/PATCH/DELETE is ever performed.
    """

    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "LocalAgent-environment-check/1.0",
            **(headers or {}),
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(256 * 1024)
            text = body.decode("utf-8", errors="replace")
            return response.status, response.headers.get("Content-Type", ""), text

    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(32 * 1024)
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        return exc.code, exc.headers.get("Content-Type", ""), text

    except Exception as exc:
        return None, "", f"{type(exc).__name__}: {exc}"


def check_endpoint(
    endpoint: str,
    timeout: float,
    api_key: str | None = None,
) -> None:
    heading(f"ENDPOINT: {endpoint}")

    base = normalize_base_url(endpoint)

    parsed = urllib.parse.urlparse(base)

    if parsed.scheme not in {"http", "https"}:
        result(
            "endpoint",
            "URL scheme",
            FAIL,
            f"unsupported scheme: {parsed.scheme}",
            mandatory=True,
        )
        return

    result(
        "endpoint",
        "URL syntax",
        PASS,
        f"{parsed.scheme}://{parsed.netloc}",
    )

    # DNS resolution only.
    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )

        unique_addresses = sorted(
            {
                str(item[4][0])
                for item in addresses
                if item[4]
            }
        )

        result(
            "endpoint",
            "DNS resolution",
            PASS,
            ", ".join(unique_addresses[:20]),
        )
    except Exception as exc:
        result(
            "endpoint",
            "DNS resolution",
            FAIL,
            str(exc),
            mandatory=True,
        )
        return

    # Root GET.
    headers: dict[str, str] = {}

    # If explicitly supplied by the user/environment, authentication is
    # allowed for the READ-ONLY /models request below. Never print the key.
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    status, content_type, body = safe_http_get(
        base,
        timeout=timeout,
    )

    if status is not None:
        result(
            "endpoint",
            "GET base endpoint",
            PASS if 200 <= status < 500 else FAIL,
            f"HTTP {status}, content-type={content_type or 'unknown'}",
        )
    else:
        result(
            "endpoint",
            "GET base endpoint",
            FAIL,
            body,
            mandatory=True,
        )

    # OpenAI-compatible model discovery.
    models_url = base.rstrip("/") + "/models"

    status, content_type, body = safe_http_get(
        models_url,
        timeout=timeout,
        headers=headers,
    )

    if status is None:
        result(
            "endpoint",
            "GET /models",
            WARN,
            body,
        )
        return

    if status in {401, 403} and not api_key:
        result(
            "endpoint",
            "GET /models",
            WARN,
            f"HTTP {status}; endpoint appears protected. "
            f"Set --api-key-env NAME if you want a read-only authenticated check.",
        )
        return

    if status != 200:
        result(
            "endpoint",
            "GET /models",
            WARN,
            f"HTTP {status}",
        )
        return

    result(
        "endpoint",
        "GET /models",
        PASS,
        f"HTTP {status}",
    )

    try:
        payload = json.loads(body)
    except Exception:
        result(
            "endpoint",
            "OpenAI-compatible /models JSON",
            FAIL,
            "response is not valid JSON",
        )
        return

    data = payload.get("data")

    if not isinstance(data, list):
        result(
            "endpoint",
            "OpenAI-compatible model list",
            WARN,
            "JSON returned but no data[] array",
        )
        return

    model_ids: list[str] = []

    for item in data:
        if isinstance(item, dict) and item.get("id"):
            model_ids.append(str(item["id"]))

    result(
        "endpoint",
        "available models",
        PASS,
        ", ".join(model_ids[:100]) if model_ids else "empty model list",
    )


def check_configured_endpoints(
    project_root: Path | None,
    timeout: float,
) -> None:
    heading("CONFIGURED ENDPOINTS")

    endpoints: list[str] = []

    # Explicit command-line endpoints are added separately in main().
    env_candidates = [
        "OPENAI_BASE_URL",
        "LOCALAGENT_LLM__BASE_URL",
        "LOCALAGENT_LLM__API_BASE",
    ]

    for name in env_candidates:
        value = os.environ.get(name)

        if value:
            endpoints.append(value)

    if project_root:
        for config_path in find_project_config(project_root):
            data = load_yaml_safely(config_path)

            if not data:
                continue

            llm = data.get("llm")

            if isinstance(llm, dict):
                for key in ("base_url", "api_base", "endpoint"):
                    value = llm.get(key)

                    if isinstance(value, str) and value:
                        endpoints.append(value)

    # De-duplicate while preserving order.
    unique: list[str] = []

    for endpoint in endpoints:
        if endpoint not in unique:
            unique.append(endpoint)

    if not unique:
        result(
            "endpoint",
            "configured endpoints",
            INFO,
            "none discovered",
        )
        return

    for endpoint in unique:
        # Do NOT automatically send secrets from environment.
        check_endpoint(
            endpoint,
            timeout,
            api_key=None,
        )


# ============================================================================
# Model / tool capability inspection
# ============================================================================

def inspect_model_payload(
    payload: dict[str, Any],
    expected_tools: list[str] | None = None,
) -> None:
    expected_tools = expected_tools or []

    data = payload.get("data")

    if not isinstance(data, list):
        return

    for model in data:
        if not isinstance(model, dict):
            continue

        model_id = model.get("id", "<unknown>")

        capabilities = model.get("capabilities")

        if isinstance(capabilities, dict):
            tools = capabilities.get("tools")
            tool_choice = capabilities.get("tool_choice")
            structured = capabilities.get("structured_outputs")

            if tools is not None:
                result(
                    "model",
                    f"{model_id}: tools",
                    INFO,
                    str(tools),
                )

            if tool_choice is not None:
                result(
                    "model",
                    f"{model_id}: tool_choice",
                    INFO,
                    str(tool_choice),
                )

            if structured is not None:
                result(
                    "model",
                    f"{model_id}: structured_outputs",
                    INFO,
                    str(structured),
                )

        # OpenAI-compatible metadata can expose supported modalities.
        for key in (
            "input_modalities",
            "output_modalities",
            "modalities",
            "reasoning",
            "supports_reasoning",
        ):
            if key in model:
                result(
                    "model",
                    f"{model_id}: {key}",
                    INFO,
                    str(model[key]),
                )


def check_models_with_api_key(
    endpoint: str,
    api_key: str,
    timeout: float,
) -> None:
    base = normalize_base_url(endpoint)
    url = base + "/models"

    status, _, body = safe_http_get(
        url,
        timeout=timeout,
        headers={
            "Authorization": f"Bearer {api_key}",
        },
    )

    if status != 200:
        result(
            "model",
            "authenticated model discovery",
            WARN,
            f"HTTP {status}" if status else body,
        )
        return

    try:
        payload = json.loads(body)
    except Exception:
        result(
            "model",
            "authenticated model discovery JSON",
            WARN,
            "invalid JSON",
        )
        return

    inspect_model_payload(payload)


# ============================================================================
# Project dependency metadata
# ============================================================================

def inspect_pyproject(project_root: Path | None) -> None:
    heading("PROJECT DEPENDENCIES")

    if project_root is None:
        result(
            "dependencies",
            "pyproject.toml",
            INFO,
            "project root not supplied",
        )
        return

    path = project_root / "pyproject.toml"

    if not path.is_file():
        result(
            "dependencies",
            "pyproject.toml",
            FAIL,
            "not found",
            mandatory=True,
        )
        return

    text = read_text(path)

    if text is None:
        result(
            "dependencies",
            "pyproject.toml",
            FAIL,
            "cannot read",
            mandatory=True,
        )
        return

    result(
        "dependencies",
        "pyproject.toml readable",
        PASS,
    )

    # Extract dependency declarations without importing anything.
    dependency_lines: list[str] = []

    in_dependencies = False

    for line_text in text.splitlines():
        stripped = line_text.strip()

        if stripped.startswith("dependencies"):
            in_dependencies = True

        if in_dependencies:
            if stripped.startswith("]"):
                in_dependencies = False
            elif stripped.startswith('"') or stripped.startswith("'"):
                dependency_lines.append(stripped)

    if dependency_lines:
        for dep in dependency_lines:
            result(
                "dependencies",
                "declared dependency",
                INFO,
                dep[:500],
            )
    else:
        result(
            "dependencies",
            "declared dependencies",
            INFO,
            "could not extract automatically; inspect pyproject manually",
        )


# ============================================================================
# Security policy consistency checks
# ============================================================================

def check_security_files(project_root: Path | None) -> None:
    heading("SECURITY IMPLEMENTATION")

    if project_root is None:
        result(
            "security",
            "security source inspection",
            INFO,
            "project root not supplied",
        )
        return

    source_root = project_root / "src" / "localagent"

    expected = {
        "policy.py": [
            "control_plane",
        ],
        "security.py": [
            "SecretScanner",
        ],
        "tools" / "exec.py": [
            "ExecutionPolicy",
        ],
    }

    for relative, markers in expected.items():
        path = source_root / relative

        if not path.is_file():
            result(
                "security",
                str(relative),
                WARN,
                "file not found",
            )
            continue

        text = read_text(path)

        if text is None:
            result(
                "security",
                str(relative),
                WARN,
                "cannot read",
            )
            continue

        for marker in markers:
            result(
                "security",
                f"{relative}: {marker}",
                PASS if marker in text else WARN,
                "marker found" if marker in text else "marker not found",
            )

    exec_path = source_root / "tools" / "exec.py"

    if exec_path.is_file():
        text = read_text(exec_path) or ""

        forbidden_patterns = [
            "preexec_fn=",
            "shell=True",
            "os.system(",
            "eval(",
            "exec(",
        ]

        for pattern in forbidden_patterns:
            found = pattern in text

            result(
                "security",
                f"dangerous pattern: {pattern}",
                FAIL if found else PASS,
                "found" if found else "not found",
                mandatory=True,
            )


# ============================================================================
# Network environment
# ============================================================================

def check_network_basics() -> None:
    heading("NETWORK BASICS")

    try:
        hostname = socket.gethostname()

        result(
            "network",
            "hostname",
            PASS,
            hostname,
        )
    except Exception as exc:
        result(
            "network",
            "hostname",
            WARN,
            str(exc),
        )

    # DNS resolution only. No outbound connection.
    for host in ("localhost", "127.0.0.1"):
        try:
            socket.getaddrinfo(host, None)

            result(
                "network",
                f"resolve {host}",
                PASS,
            )
        except Exception as exc:
            result(
                "network",
                f"resolve {host}",
                WARN,
                str(exc),
            )


# ============================================================================
# TLS
# ============================================================================

def check_tls() -> None:
    heading("TLS")

    try:
        import ssl

        context = ssl.create_default_context()

        result(
            "tls",
            "Python SSL",
            PASS,
            ssl.OPENSSL_VERSION,
            mandatory=True,
        )

        result(
            "tls",
            "default CA paths",
            PASS,
            str(context.get_ca_certs.__name__),
        )

        paths = ssl.get_default_verify_paths()

        for field in (
            "cafile",
            "capath",
            "openssl_cafile",
            "openssl_capath",
        ):
            value = getattr(paths, field, None)

            if value:
                result(
                    "tls",
                    field,
                    PASS if Path(value).exists() else WARN,
                    str(value),
                )

    except Exception as exc:
        result(
            "tls",
            "TLS initialization",
            FAIL,
            str(exc),
            mandatory=True,
        )


# ============================================================================
# Report
# ============================================================================

def print_summary() -> int:
    heading("SUMMARY")

    mandatory_failures = [
        item
        for item in results
        if item["mandatory"] and item["status"] == FAIL
    ]

    warnings = [
        item
        for item in results
        if item["status"] == WARN
    ]

    passed = sum(1 for item in results if item["status"] == PASS)
    failed = sum(1 for item in results if item["status"] == FAIL)
    skipped = sum(1 for item in results if item["status"] == SKIP)

    print(f"PASS:     {passed}")
    print(f"FAIL:     {failed}")
    print(f"WARN:     {len(warnings)}")
    print(f"SKIP:     {skipped}")
    print()

    if mandatory_failures:
        print("MANDATORY FAILURES:")
        for item in mandatory_failures:
            print(
                f"  - {item['section']}: "
                f"{item['name']} -> {item['detail']}"
            )

        print()
        print("RESULT: NOT READY")
        print()
        print(
            "The environment does not currently satisfy all mandatory "
            "LocalAgent prerequisites."
        )

        return 1

    print("RESULT: BASIC ENVIRONMENT READY")
    print()
    print(
        "IMPORTANT: this does NOT prove that the kernel sandbox is "
        "actually usable."
    )
    print(
        "The destructive/state-changing primitives such as userns, "
        "netns, Landlock restriction and seccomp installation are "
        "intentionally NOT executed by this checker."
    )
    print(
        "Run the dedicated disposable sandbox integration tests on the "
        "target machine to prove those guarantees."
    )

    return 0


# ============================================================================
# JSON report
# ============================================================================

def save_json_report(path: Path) -> None:
    """
    Optional report export.

    This DOES write a file, so it is only called when the user explicitly
    provides --json-report.
    """

    payload = {
        "timestamp": time.time(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "results": results,
    }

    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only LocalAgent infrastructure compatibility checker."
    )

    parser.add_argument(
        "--project-root",
        type=Path,
        help="Path to the LocalAgent project.",
    )

    parser.add_argument(
        "--endpoint",
        action="append",
        default=[],
        help=(
            "OpenAI-compatible endpoint to check using READ-ONLY GET "
            "requests. Can be specified multiple times."
        ),
    )

    parser.add_argument(
        "--api-key-env",
        action="append",
        default=[],
        help=(
            "Environment variable containing an API key. "
            "The key is never printed. It is used only for GET /models."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout for read-only endpoint checks.",
    )

    parser.add_argument(
        "--json-report",
        type=Path,
        help=(
            "OPTIONAL: save the diagnostic report to this path. "
            "Without this option the script does not write files."
        ),
    )

    args = parser.parse_args()

    print()
    line()
    print("LocalAgent infrastructure compatibility checker")
    print("READ-ONLY DIAGNOSTIC")
    line()
    print()
    print("No packages will be installed.")
    print("No kernel settings will be changed.")
    print("No namespaces will be created.")
    print("No seccomp/landlock filters will be installed.")
    print("No files will be modified unless --json-report is explicitly used.")
    print()

    try:
        check_python()
        check_os()
        check_identity()
        check_filesystem(args.project_root)
        check_landlock()
        check_seccomp()
        check_user_namespace()
        check_network_namespace()
        check_rlimits()
        check_tools(args.project_root)
        check_project(args.project_root)
        inspect_pyproject(args.project_root)
        check_security_files(args.project_root)
        check_environment()
        check_network_basics()
        check_tls()

        # Explicit endpoints requested by the user.
        for endpoint in args.endpoint:
            api_key = None

            # API keys are ONLY read from the explicitly named environment
            # variables. They are never printed.
            for env_name in args.api_key_env:
                value = os.environ.get(env_name)

                if value:
                    api_key = value
                    break

            check_endpoint(
                endpoint,
                args.timeout,
                api_key=api_key,
            )

            if api_key:
                check_models_with_api_key(
                    endpoint,
                    api_key,
                    args.timeout,
                )

        check_configured_endpoints(
            args.project_root,
            args.timeout,
        )

        exit_code = print_summary()

        if args.json_report:
            save_json_report(args.json_report)
            print()
            print(f"JSON report saved to: {args.json_report}")

        return exit_code

    except KeyboardInterrupt:
        print()
        print("Interrupted.")
        return 2

    except Exception as exc:
        print()
        line("!")
        print("DIAGNOSTIC ERROR")
        line("!")
        print(f"{type(exc).__name__}: {exc}")
        print()
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
