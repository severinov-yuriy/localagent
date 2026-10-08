"""Small Linux kernel sandbox primitives used by the execution launcher.

The sandbox is deliberately fail-closed: unsupported kernels/architectures do
not get treated as "sandboxed".  No third-party dependency is required.
"""
from __future__ import annotations

import ctypes
import fcntl
import errno
import os
import platform
import socket
import struct
from pathlib import Path

# Linux syscalls/prctl constants used by this module.
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
SYS_SECCOMP = 317 if platform.machine() == "x86_64" else 277 if platform.machine() == "aarch64" else None
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_TSYNC = 1

LANDLOCK_RULE_TYPE_PATH_BENEATH = 1
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
LANDLOCK_CREATE_RULESET_VERSION = 1

# ABI v1 filesystem rights.
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_ABI1_FS = (1 << 13) - 1
LANDLOCK_ALL_FS = LANDLOCK_ABI1_FS
LANDLOCK_READ_ONLY_FS = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
LANDLOCK_RW_FS = LANDLOCK_ALL_FS

# Classic BPF / seccomp constants.
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06
BPF_ALU = 0x04
BPF_AND = 0x50
BPF_STMT = lambda code, k: (code, 0, 0, k)
BPF_JUMP = lambda code, k, jt, jf: (code, jt, jf, k)

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}

# Syscalls which must not be available to the executed program after the
# launcher has established namespaces.  The list is intentionally focused on
# privilege/sandbox escape primitives; normal Python/JVM operation remains
# possible.
_BLOCKED_SYSCALLS_X86_64 = {
    16,    # ioctl (device/kernel interfaces; ordinary file I/O does not need it)
    101,   # ptrace
    165,   # mount
    166,   # umount2
    155,   # pivot_root
    272,   # unshare
    308,   # setns
    321,   # bpf
    246,   # kexec_load
    320,   # kexec_file_load
    167,   # swapon
    168,   # swapoff
    169,   # reboot
    175,   # init_module
    176,   # delete_module
    310,   # process_vm_readv
    311,   # process_vm_writev
    252,   # ioperm
    153,   # iopl
    298,   # perf_event_open
    250,   # keyctl
}
_BLOCKED_SYSCALLS_AARCH64 = {
    29,    # ioctl
    117,   # ptrace
    40,    # mount
    39,    # umount2
    41,    # pivot_root
    97,    # unshare
    268,   # setns
    280,   # bpf
    104,   # kexec_load
    294,   # kexec_file_load
    224,   # swapon
    225,   # swapoff
    142,   # reboot
    105,   # init_module
    106,   # delete_module
    270,   # process_vm_readv
    271,   # process_vm_writev
    172,   # ioperm
    241,   # perf_event_open
    219,   # keyctl
}


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("parent_fd", ctypes.c_int), ("allowed_access", ctypes.c_uint64)]


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _syscall(libc, number, *args):
    result = libc.syscall(number, *args)
    if result == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return result


def landlock_abi() -> int:
    if os.name != "posix" or not sys_is_linux():
        return 0
    try:
        libc = _libc()
        attr = _LandlockRulesetAttr()
        return int(_syscall(libc, SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), LANDLOCK_CREATE_RULESET_VERSION))
    except (OSError, AttributeError):
        return 0


def landlock_supported() -> bool:
    return landlock_abi() >= 1


def sys_is_linux() -> bool:
    return platform.system().lower() == "linux"



def _unshare(flags: int) -> None:
    libc = _libc()
    if not hasattr(libc, "unshare"):
        raise RuntimeError("unshare is unavailable")
    if libc.unshare(flags) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _write_proc(path: str, value: str) -> None:
    with open(path, "w", encoding="ascii") as fh:
        fh.write(value)


def setup_network_namespace() -> None:
    """Create an isolated user+network namespace and bring loopback up."""
    _unshare(CLONE_NEWUSER | CLONE_NEWNET)
    uid = os.getuid()
    gid = os.getgid()
    setgroups = Path("/proc/self/setgroups")
    if setgroups.exists():
        try:
            _write_proc(str(setgroups), "deny\n")
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.ENOENT):
                raise
    _write_proc("/proc/self/uid_map", f"0 {uid} 1\n")
    _write_proc("/proc/self/gid_map", f"0 {gid} 1\n")

    # The new network namespace starts with loopback down.  Spark/Python
    # local services rely on 127.0.0.1, so enable only that interface.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        ifreq = struct.pack("16sH14x", b"lo", 0)
        current = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
        flags = struct.unpack("16sH14x", current)[1]
        fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP))


def userns_network_supported() -> bool:
    if not sys_is_linux() or not hasattr(_libc(), "unshare"):
        return False
    # This is intentionally conservative. The launcher performs the real
    # unshare and still fails closed if the host/container rejects it.
    probe = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if probe.exists():
        try:
            return probe.read_text(encoding="ascii").strip() == "1"
        except OSError:
            return False
    # Some kernels omit this knob (notably when user namespaces are governed
    # by another policy). Do not claim readiness for an unprivileged process.
    return os.geteuid() == 0


def _add_path_rule(fd: int, path: Path, access: int) -> None:
    resolved = path.resolve(strict=True)
    parent = os.open(resolved, os.O_PATH | os.O_CLOEXEC)
    try:
        attr = _LandlockPathBeneathAttr(parent_fd=parent, allowed_access=access)
        _syscall(_libc(), SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_TYPE_PATH_BENEATH, ctypes.byref(attr), 0)
    finally:
        os.close(parent)


def apply_landlock(workspace: Path, scratch: Path, trusted_executable: Path, rw_dirs=None, ro_paths=None) -> None:
    """Restrict filesystem access to workspace + trusted runtime trees.

    The absence of a rule means all handled filesystem rights are denied.
    Read-only rules grant *only* execute/read rights; in particular they do not
    grant deletion/creation through an accidental bitmask complement.
    """
    if not landlock_supported():
        raise RuntimeError("Landlock is unavailable")
    libc = _libc()
    abi = landlock_abi()
    handled = LANDLOCK_ABI1_FS
    if abi >= 2:
        handled |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE
    attr = _LandlockRulesetAttr(handled_access_fs=handled, handled_access_net=0)
    ruleset = _syscall(libc, SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)

    writable = LANDLOCK_ABI1_FS
    if abi >= 2:
        writable |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        writable |= LANDLOCK_ACCESS_FS_TRUNCATE
    # Workspace is read-only by default. Only explicit work-zone directories
    # receive write/create/delete rights.
    _add_path_rule(ruleset, workspace, LANDLOCK_READ_ONLY_FS)
    rw_dirs = list(rw_dirs or ("src", "tests", "scripts", "scratch", "data", "docs"))
    for rel in rw_dirs:
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise RuntimeError(f"invalid rw_dirs entry: {rel}")
        target = (workspace / candidate).resolve(strict=False)
        if target.exists() and target.is_dir():
            _add_path_rule(ruleset, target, writable)
    if scratch.exists():
        _add_path_rule(ruleset, scratch, writable)
    for rel in (ro_paths or ()):
        candidate = Path(rel)
        target = candidate if candidate.is_absolute() else workspace / candidate
        if target.exists():
            _add_path_rule(ruleset, target.resolve(strict=True), LANDLOCK_READ_ONLY_FS)

    # Permit the trusted interpreter and its read-only runtime tree.  This is
    # intentionally narrower than granting all of /home; a venv under /home
    # therefore works without exposing sibling secrets.
    exe = trusted_executable.resolve(strict=True)
    runtime_root = exe.parent
    for parent in [exe.parent, *exe.parents]:
        if (parent / "pyvenv.cfg").is_file():
            runtime_root = parent
            break
        if parent in {Path("/usr"), Path("/opt"), Path("/")}:
            runtime_root = parent
            break
    if runtime_root != Path("/"):
        _add_path_rule(ruleset, runtime_root, LANDLOCK_READ_ONLY_FS)

    # Standard system runtime files/libraries.  Missing paths are harmless;
    # the interpreter's own tree above is still required.
    for candidate in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/dev"):
        p = Path(candidate)
        if p.exists():
            _add_path_rule(ruleset, p, LANDLOCK_READ_ONLY_FS)

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    _syscall(libc, SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0)
    os.close(ruleset)


def seccomp_supported() -> bool:
    return bool(sys_is_linux() and SYS_SECCOMP is not None and platform.machine() in AUDIT_ARCH)


def _seccomp_program() -> list[tuple[int, int, int, int]]:
    arch = AUDIT_ARCH[platform.machine()]
    blocked = _BLOCKED_SYSCALLS_X86_64 if platform.machine() == "x86_64" else _BLOCKED_SYSCALLS_AARCH64
    program = [BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4), BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS), BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0)]
    for syscall_nr in sorted(blocked):
        program.extend([BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | errno.EPERM)])
    program.append(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    return program


def apply_seccomp() -> None:
    if not seccomp_supported():
        raise RuntimeError("seccomp is unavailable on this architecture")
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    raw = _seccomp_program()
    filters = (_SockFilter * len(raw))(*[_SockFilter(*item) for item in raw])
    prog = _SockFprog(len=len(raw), filter=ctypes.cast(filters, ctypes.POINTER(_SockFilter)))
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, ctypes.byref(prog)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def backend_status() -> dict[str, bool]:
    landlock = landlock_supported()
    seccomp = seccomp_supported()
    network = userns_network_supported()
    return {
        "landlock": landlock,
        "seccomp": seccomp,
        "network": network,
        "ready": landlock and seccomp and network,
    }
