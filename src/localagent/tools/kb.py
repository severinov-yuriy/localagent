"""Knowledge-base and skill-reading tools."""

from __future__ import annotations

from pathlib import Path

from .base import Tool
from ..security import DLPPolicy


_BLOCKED = "content blocked by security policy"


class KBSearch(Tool):
    """Search the local SQLite/FTS5 knowledge base."""

    name = "kb_search"
    description = "Search project knowledge base."

    def __init__(self, kb, dlp=None):
        self.kb = kb
        self.dlp = dlp or DLPPolicy()

    def run(self, a):
        query = a["query"]
        if not self.dlp.check("kb.query", query).allowed:
            raise PermissionError(_BLOCKED)
        result = self.kb.search(query, int(a.get("limit", 8)))
        if not self.dlp.check("kb.result", result).allowed:
            raise PermissionError(_BLOCKED)
        return result


class KBRead(Tool):
    """Read the full stored contents of one exact knowledge-base path."""

    name = "kb_read"
    description = "Read a knowledge-base document."

    def __init__(self, kb, policy=None, dlp=None):
        self.kb = kb
        self.policy = policy
        self.dlp = dlp or DLPPolicy()

    def run(self, a):
        if self.policy:
            self.policy.authorize(a["path"], "read")
        row = self.kb.read(a["path"])
        value = row[0] if row else ""
        if not self.dlp.check("kb.read", value).allowed:
            raise PermissionError(_BLOCKED)
        return value


class KBAdd(Tool):
    """Index a workspace file or inline text under an optional logical path."""

    name = "kb_add"
    description = "Index a workspace file or supplied text in the knowledge base."

    def __init__(self, kb, policy=None, dlp=None):
        self.kb = kb
        self.policy = policy
        self.dlp = dlp or DLPPolicy()

    def run(self, a):
        has_path = "path" in a and a.get("path") not in (None, "")
        has_content = "content" in a and a.get("content") is not None
        if not has_path and not has_content:
            raise ValueError("kb_add requires path or content")

        payload = dict(a)
        if has_content:
            content = payload["content"]
            if not self.dlp.check("kb.add.content", content).allowed:
                raise PermissionError(_BLOCKED)
            if has_path and self.policy:
                decision = self.policy.decision(a["path"], "read")
                if not decision.allowed:
                    raise PermissionError(decision.reason)
                payload["path"] = a["path"]
            elif not has_path:
                import hashlib
                payload["path"] = f"inline/{hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]}.md"
        else:
            if not self.policy:
                raise PermissionError(_BLOCKED)
            source = self.policy.authorize(a["path"], "read")
            try:
                if source.stat().st_size > self.policy.max_read_bytes():
                    raise ValueError("source exceeds max_read_bytes")
                content = source.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ValueError("knowledge-base source cannot be read") from exc
            if not self.dlp.check("kb.add.source", content).allowed:
                raise PermissionError(_BLOCKED)
            payload["path"] = a["path"]
            payload["content"] = content

        if self.policy:
            self.policy.authorize(self.kb.path, "write", actor="runtime")
        self.kb.add(payload["path"], payload.get("content"))
        return "indexed"


class ReadSkill(Tool):
    """Read an explicit skill from the supported workspace skill roots."""

    name = "read_skill"
    description = "Read an explicit skill file from skills/ or .pi/skills/."

    def __init__(self, roots, policy, dlp=None):
        self.roots = [Path(root) for root in roots]
        self.policy = policy
        self.dlp = dlp or DLPPolicy()

    def run(self, a):
        name = a["name"].strip()
        candidates = []
        for root in self.roots:
            candidates.extend((root / name, root / name / "SKILL.md"))
        for candidate in candidates:
            try:
                path = self.policy.authorize(candidate, "read")
            except PermissionError:
                continue
            try:
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if not self.dlp.check("skill.read", text).allowed:
                raise PermissionError(_BLOCKED)
            return text
        raise FileNotFoundError(_BLOCKED)
