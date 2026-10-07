"""Trusted execution launcher; never import from the workspace."""
from __future__ import annotations

import json
import os
import resource
import signal
import sys
from pathlib import Path

from sandbox import apply_landlock, apply_seccomp, setup_network_namespace


def _pdeathsig() -> None:
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _limits(spec: dict) -> None:
    cpu = int(spec.get("cpu_s", 120))
    fsize = int(spec.get("fsize_bytes", 50_000_000))
    nofile = max(4096, int(spec.get("nofile", 4096)))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    if hasattr(resource, "RLIMIT_AS"):
        address_space = int(spec.get("as_bytes", 2 * 1024 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))
    if hasattr(resource, "RLIMIT_NPROC"):
        nproc = int(spec.get("nproc", 128))
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    if hasattr(resource, "RLIMIT_CORE"):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main() -> int:
    raw = os.environ.get("LOCALAGENT_LAUNCH_SPEC")
    if not raw:
        return 125
    try:
        spec = json.loads(raw)
        argv = spec["argv"]
        cwd = Path(spec["cwd"]).resolve(strict=True)
        workspace = Path(spec["workspace"]).resolve(strict=True)
        scratch = Path(spec["scratch"]).resolve(strict=True)
        trusted = Path(spec["trusted_executable"]).resolve(strict=True)
        env = spec["env"]
    except (KeyError, TypeError, ValueError, OSError):
        return 125
    if not isinstance(argv, list) or not argv or argv[0] != str(trusted):
        return 125
    if cwd != workspace or not workspace.is_dir() or not scratch.is_dir():
        return 125
    if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
        return 125
    try:
        _pdeathsig()
        _limits(spec)
        # Network isolation is established before filesystem/seccomp policy.
        setup_network_namespace()
        # Filesystem isolation is mandatory before target code starts.
        apply_landlock(workspace, scratch, trusted)
        # Seccomp is installed last because launcher setup may require syscalls
        # which must not remain available to the target.
        apply_seccomp()
        os.chdir(workspace)
        os.execve(str(trusted), [str(x) for x in argv], env)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"execution sandbox unavailable: {exc}", file=sys.stderr)
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
