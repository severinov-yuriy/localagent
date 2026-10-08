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
        mode = spec.get("isolation", "best_effort")
        layers = set(spec.get("layers", []))
        if mode in {"kernel", "best_effort"}:
            if "network" in layers:
                setup_network_namespace()
            if "landlock" in layers:
                apply_landlock(
                    workspace, scratch, trusted,
                    rw_dirs=spec.get("rw_dirs"),
                    ro_paths=spec.get("ro_paths"),
                )
            if "seccomp" in layers:
                apply_seccomp()
            if mode == "kernel" and layers != {"network", "landlock", "seccomp"}:
                raise RuntimeError("kernel isolation requested but required layers are unavailable")
        os.chdir(workspace)
        os.execve(str(trusted), [str(x) for x in argv], env)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"execution sandbox unavailable: {exc}", file=sys.stderr)
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
