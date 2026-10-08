"""Centralized application-level filesystem authorization and safe runtime storage."""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path
import shutil
import uuid
from typing import Any

from .security import SecurityDecision, SecretScanner


class PolicyError(PermissionError):
    """Raised when a filesystem operation violates policy."""


class FilesystemPolicy:
    """Single authorization boundary for every agent-controlled filesystem path."""

    WRITE_OPS = frozenset({"write", "delete", "move", "patch", "mkdir", "backup"})
    READ_OPS = frozenset({"read", "list", "glob", "grep", "search", "metadata"})
    OPS = READ_OPS | WRITE_OPS
    _RUNTIME_STATE_PATHS = (
        ".agent/artifacts",
        ".agent/trash",
        ".agent/sessions",
        ".agent/kb.sqlite",
        ".agent/reports",
        ".agent/logs",
    )
    _DEFAULT_CONTROL_PLANE = ("AGENTS.md", "agents", "agents/**", "skills", "skills/**", ".pi", ".pi/**", ".agent", ".agent/**")
    _PROTECTED_AGENT_PATHS = (".agent", ".agent.*")
    _PROTECTED_PI_PATHS = (".pi", ".pi.*")

    def __init__(
        self,
        cfg: dict[str, Any],
        role_policies: list[dict[str, Any]] | None = None,
        role_policy: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> None:
        self.cfg = cfg
        self.root = Path(cfg["permissions"]["workspace_root"]).resolve()
        inherited = role_policies if role_policies is not None else ([] if role_policy is None else [role_policy])
        self.role_policies = [policy for policy in inherited if policy]
        self.role_policy = self.role_policies[-1] if self.role_policies else {}
        self.actor = actor

    @staticmethod
    def _inside(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    def _candidate(self, path: str | os.PathLike[str] | Path) -> Path:
        candidate = Path(path).expanduser()
        return self.root / candidate if not candidate.is_absolute() else candidate

    def _matches(self, path: Path, patterns: list[str] | tuple[str, ...] | None) -> bool:
        if not patterns:
            return False
        try:
            relative = path.relative_to(self.root).as_posix()
        except ValueError:
            relative = None
        values = [path.as_posix(), *path.parts]
        if relative is not None:
            values.extend((relative, *relative.split("/")))
        return any(fnmatch.fnmatch(value, pattern) for value in values for pattern in patterns)

    def _denied(self, real: Path, operation: str, actor: str | None) -> bool:
        perms = self.cfg["permissions"]
        internal_runtime = any(self._inside(real, self.root / part) for part in self._RUNTIME_STATE_PATHS)
        if actor == "runtime" and (operation == "backup" or internal_runtime):
            return False
        if actor != "runtime":
            if operation in self.WRITE_OPS:
                if SecretScanner.filename_blocked(real.name):
                    return True
                if self._matches(real, self._PROTECTED_AGENT_PATHS):
                    return True
                if self._matches(real, self._PROTECTED_PI_PATHS):
                    return True
        if self._matches(real, perms.get("deny_patterns", [])):
            return True
        if self._matches(real, perms.get("deny", [])):
            return True
        if actor != "runtime":
            control = perms.get("control_plane", list(self._DEFAULT_CONTROL_PLANE))
            if operation in self.WRITE_OPS and self._matches(real, control):
                return True
            if operation in self.WRITE_OPS:
                control_write = perms.get("control_plane_write", ())
                if self._matches(real, control_write):
                    return True
        for role_policy in self.role_policies:
            if self._matches(real, role_policy.get("deny", [])):
                return True
        return False

    def _role_allows(self, real: Path, operation: str) -> bool:
        key = "write" if operation in self.WRITE_OPS else "read"
        for role_policy in self.role_policies:
            patterns = role_policy.get(key)
            if patterns is not None and (not patterns or not self._matches(real, patterns)):
                return False
        return True

    def decision(self, requested_path: str | os.PathLike[str], operation: str, actor: str | None = None) -> SecurityDecision:
        """Return a path authorization decision without touching the target."""
        actor = actor if actor is not None else self.actor
        if operation not in self.OPS:
            return SecurityDecision(False, "FilesystemPolicy", operation, "unsupported operation")
        if not isinstance(requested_path, (str, os.PathLike)):
            return SecurityDecision(False, "FilesystemPolicy", operation, "path must be a string")
        if operation in self.WRITE_OPS and actor != "runtime" and not self.cfg["permissions"].get("allow_write", True):
            return SecurityDecision(False, "FilesystemPolicy", operation, "writes disabled by policy")
        candidate = self._candidate(requested_path)
        try:
            real = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            return SecurityDecision(False, "FilesystemPolicy", operation, "path resolution failed")
        if not self._inside(real, self.root):
            return SecurityDecision(False, "FilesystemPolicy", operation, "path outside workspace")
        if self._denied(real, operation, actor):
            return SecurityDecision(False, "FilesystemPolicy", operation, "path denied by policy")
        if actor != "runtime" and not self._role_allows(real, operation):
            return SecurityDecision(False, "FilesystemPolicy", operation, "role policy denied")
        return SecurityDecision(True, "FilesystemPolicy", operation, "allowed")

    def authorize(self, path: str | os.PathLike[str], operation: str, actor: str | None = None) -> Path:
        """Authorize and return the current canonical path."""
        decision = self.decision(path, operation, actor)
        if not decision.allowed:
            raise PolicyError(decision.reason)
        return self._candidate(path).resolve(strict=False)

    def derive_child(self, role_policy: dict[str, Any] | None = None) -> "FilesystemPolicy":
        """Derive a child policy by intersecting the already-effective parent policy."""
        policies = list(self.role_policies)
        if role_policy:
            policies.append(role_policy)
        child = type(self)(self.cfg, role_policies=policies, actor=self.actor)
        child.session_id = getattr(self, "session_id", None)
        return child

    def path(
        self,
        path: str | os.PathLike[str],
        write: bool = False,
        allow_missing: bool = True,
        actor: str | None = None,
    ) -> Path:
        """Compatibility wrapper; internal runtime code should use :meth:`authorize`."""
        operation = "write" if write else "read"
        real = self.authorize(path, operation, actor=actor)
        if not allow_missing and not real.exists():
            raise PolicyError("path does not exist")
        return real

    def max_read_bytes(self) -> int:
        """Return the configured maximum read size."""
        return int(self.cfg["permissions"].get("max_read_bytes", 2_000_000))

    def artifact(self, text: str, session: str | None = None, label: str = "output") -> str:
        """Persist a runtime-owned text artifact under the current workspace."""
        if SecretScanner.scan(text):
            raise PolicyError("content blocked by security policy")
        safe_label = Path(label).name or "output"
        sid = session or getattr(self, "session_id", "default")
        directory = self.authorize(self.root / ".agent" / "artifacts" / sid, "write", actor="runtime")
        directory.mkdir(parents=True, exist_ok=True)
        path = self.authorize(directory / f"{safe_label}-{uuid.uuid4().hex[:10]}.txt", "write", actor="runtime")
        path.write_text(text, encoding="utf-8")
        return path.relative_to(self.root).as_posix()

    def trash(self, path: str | os.PathLike[str] | Path, session: str | None = None) -> Path:
        """Move an authorized path into runtime-owned session trash."""
        sid = session or getattr(self, "session_id", "default")
        directory = self.authorize(self.root / ".agent" / "trash" / sid, "write", actor="runtime")
        directory.mkdir(parents=True, exist_ok=True)
        source = self.authorize(path, "delete")
        rel = source.relative_to(self.root)
        target = directory / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            target = target.with_name(target.name + "-" + uuid.uuid4().hex[:8])
        shutil.move(str(source), str(target))
        return target

    def backup(self, path: Path) -> Path | None:
        """Create a single runtime-owned sibling backup when enabled."""
        if not self.cfg["permissions"].get("backup", True):
            return None
        source = self.authorize(path, "backup", actor="runtime")
        if not source.exists() or not source.is_file():
            return None
        backup_path = source.with_name(source.name + ".agent.bak")
        self.authorize(backup_path, "backup", actor="runtime")
        shutil.copy2(source, backup_path)
        return backup_path


# Existing code/tests import Policy; keep it as the central implementation.
Policy = FilesystemPolicy


def atomic_write(path: str | os.PathLike[str] | Path, data: bytes) -> None:
    """Atomically replace a file using a temporary file in the same directory."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + f".tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    try:
        tmp.write_bytes(data)
        os.replace(tmp, target)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
