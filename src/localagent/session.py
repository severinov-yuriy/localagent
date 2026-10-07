"""Filesystem-backed persistence for resumable agent sessions."""

from __future__ import annotations

from pathlib import Path

from .policy import FilesystemPolicy
import json
import re


class SessionStore:
    """Save and load session state as atomically replaced JSON files under ``.agent/sessions``."""

    def __init__(self, root, policy: FilesystemPolicy | None = None):
        """Create a session store rooted at the workspace ``root``."""
        candidate = Path(root) / ".agent/sessions"
        self.policy = policy
        self.root = (policy.authorize(candidate, "write", actor="runtime") if policy else candidate)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_id(sid):
        """Validate the restricted session identifier syntax."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", sid):
            raise ValueError("invalid session id")
        return sid

    def save(self, sid, state):
        """Atomically save arbitrary JSON-serializable session ``state`` and return its path."""
        sid = self._validate_id(sid)
        p = self.root / (sid + ".json")
        if self.policy:
            p = self.policy.authorize(p, "write", actor="runtime")
        tmp = p.with_suffix(".tmp")
        if self.policy:
            tmp = self.policy.authorize(tmp, "write", actor="runtime")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)
        return p

    def load(self, sid):
        """Load and decode a previously saved session state."""
        sid = self._validate_id(sid)
        p = self.root / (sid + ".json")
        if self.policy:
            p = self.policy.authorize(p, "read", actor="runtime")
        return json.loads(p.read_text(encoding="utf-8"))

    def list(self):
        """Return session JSON files newest first by modification time."""
        paths = sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if self.policy:
            return [self.policy.authorize(p, "read", actor="runtime") for p in paths]
        return paths
