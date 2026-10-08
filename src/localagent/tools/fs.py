"""Filesystem tools constrained by :class:`localagent.policy.Policy`."""

from __future__ import annotations

import base64
import mimetypes
import re
import shutil
from pathlib import Path

from .base import Tool
from ..policy import atomic_write
from ..security import DLPPolicy


class FS(Tool):
    """Shared path resolution helper for filesystem-oriented tools."""

    def __init__(self, p, dlp=None):
        """Attach the shared filesystem policy and DLP gate to the tool."""
        self.p = p
        self.dlp = dlp or DLPPolicy()

    def path(self, a, key="path", write=False, operation=None):
        """Resolve an argument through the central authorization boundary."""
        if operation is None:
            operation = "write" if write else "read"
        return self.p.authorize(a[key], operation)


class ReadFile(FS):
    """Read a UTF-8 text file, optionally restricted to an inclusive line range."""

    name = "read_file"
    description = "Read a UTF-8 text file, optionally by line range."

    def run(self, a):
        """Read one file while enforcing ``max_read_bytes``."""
        p = self.p.authorize(a["path"], "read")
        max_bytes = self.p.max_read_bytes()
        data = p.read_bytes()
        if len(data) > max_bytes:
            raise ValueError(f"file exceeds max_read_bytes={max_bytes}")
        if b"\x00" in data[:8192]:
            raise ValueError("binary file cannot be read as text")
        try:
            text = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            try:
                text = data.decode("cp1251")
                encoding = "cp1251"
            except UnicodeDecodeError as e:
                raise ValueError("unsupported text encoding") from e
        if not self.dlp.check("filesystem.read_file", text).allowed:
            raise PermissionError("content blocked by security policy")
        if len(text) > 12000 and "start_line" not in a and "end_line" not in a:
            rel = self.p.artifact(text)
            return f"output truncated; full output: {rel}\n\n{text[:4000]}\n...\n{text[-4000:]}"
        lines = text.splitlines()
        if "start_line" in a or "end_line" in a:
            return "\n".join(lines[max(0, int(a.get("start_line", 1)) - 1): int(a.get("end_line", len(lines)))])
        return text


class ListDir(FS):
    """List up to 2000 entries in a directory."""

    name = "list_dir"
    description = "List directory entries."

    def run(self, a):
        """Return sorted names, authorizing each entry before metadata access."""
        base = self.p.authorize(a["path"], "list")
        entries = []
        for entry in base.iterdir():
            try:
                checked = self.p.authorize(entry, "metadata")
            except (OSError, PermissionError):
                continue
            suffix = "/" if checked.is_dir() else ""
            entries.append(checked.name + suffix)
        return "\n".join(sorted(entries)[:2000])


class Glob(FS):
    """Find regular files matching a pathlib glob within allowed read roots."""

    name = "glob"
    description = "Find files matching a glob within allowed read roots."

    def run(self, a):
        """Return up to 2000 matching file paths after re-checking each result by policy."""
        base = self.p.authorize(a["path"], "read")
        pat = a.get("pattern", "**/*")
        out = []
        for x in base.glob(pat):
            try:
                checked = self.p.authorize(x, "read")
            except (OSError, PermissionError):
                continue
            if not checked.is_file():
                continue
            try:
                label = str(checked.relative_to(self.p.root))
            except ValueError:
                label = str(checked)
            out.append(label)
            if len(out) >= 2000:
                break
        return "\n".join(out)


class Grep(FS):
    """Search readable text files using substring or optional regex matching, excluding generated/vendor trees."""

    name = "grep"
    description = "Search text in workspace files."

    def run(self, a):
        """Return matching lines, capped by ``max_results`` and a per-file size limit."""
        q = a["pattern"]
        regex = bool(a.get("regex", False))
        rx = re.compile(q, re.IGNORECASE) if regex else None
        out = []
        roots = [self.p.root]
        excluded = {".git", ".venv", "node_modules", "__pycache__"}
        for root in roots:
            for p in root.rglob("*"):
                if any(part in excluded for part in p.parts):
                    continue
                try:
                    checked = self.p.authorize(p, "read")
                    if not checked.is_file() or checked.stat().st_size > min(2_000_000, self.p.max_read_bytes()):
                        continue
                    text = checked.read_text(encoding="utf-8", errors="replace")
                except (OSError, PermissionError):
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if (rx.search(line) if rx else q.lower() in line.lower()):
                        if not self.dlp.check("filesystem.grep.result", line).allowed:
                            return "content blocked by security policy"
                        try:
                            label = str(checked.relative_to(self.p.root))
                        except ValueError:
                            label = str(checked)
                        out.append(f"{label}:{i}:{line[:500]}")
                        if len(out) >= int(a.get("max_results", 200)):
                            return "\n".join(out)
        return "\n".join(out)


class WriteFile(FS):
    """Atomically replace or create a UTF-8 file, optionally making a backup."""

    name = "write_file"
    description = "Atomically write a UTF-8 file."

    def run(self, a):
        """Write the supplied UTF-8 content after size and policy checks."""
        p = self.p.authorize(a["path"], "write")
        data = a.get("content", "").encode("utf-8")
        if len(data) > self.p.cfg["permissions"]["max_file_bytes"]:
            raise ValueError("file too large")
        self.p.backup(p)
        atomic_write(p, data)
        return f"wrote {p.relative_to(self.p.root)}"


class EditFile(FS):
    """Replace exactly one occurrence of a UTF-8 text fragment in a file."""

    name = "edit_file"
    description = "Replace exactly one occurrence of old text with new text."

    def run(self, a):
        """Perform an exact single-match text replacement and preserve one backup."""
        p = self.p.authorize(a["path"], "write")
        data = p.read_bytes()
        if len(data) > self.p.cfg["permissions"]["max_read_bytes"]:
            raise ValueError("file too large")
        if b"\x00" in data[:8192]:
            raise ValueError("binary file cannot be edited as text")
        try:
            old = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            old = data.decode("cp1251")
            encoding = "cp1251"
        if not self.dlp.check("filesystem.edit_file.source", old).allowed:
            raise PermissionError("content blocked by security policy")
        n = old.count(a["old"])
        replace_all = bool(a.get("replace_all", False))
        if not replace_all and n != 1:
            raise ValueError(f"expected exactly one match, got {n}")
        if replace_all and n == 0:
            raise ValueError("expected at least one match, got 0")
        replaced = old.replace(a["old"], a["new"], -1 if replace_all else 1)
        new = replaced.encode(encoding)
        if len(new) > self.p.cfg["permissions"]["max_file_bytes"]:
            raise ValueError("file too large")
        self.p.backup(p)
        atomic_write(p, new)
        return {"path": str(p.relative_to(self.p.root)), "replacements": n}


class ApplyPatch(FS):
    """Apply simple unified-diff hunks to workspace files."""

    name = "apply_patch"
    description = "Apply a unified diff to workspace files."

    def run(self, a):
        """Apply validated context/removal/addition hunks without invoking a shell or patch executable."""
        lines = a["patch"].splitlines(True)
        i = 0
        changed = 0
        while i < len(lines):
            if not lines[i].startswith("--- "):
                i += 1
                continue
            old_name = lines[i][4:].strip().split("\t")[0]
            i += 1
            if i >= len(lines) or not lines[i].startswith("+++ "):
                raise ValueError("invalid unified patch")
            new_name = lines[i][4:].strip().split("\t")[0]
            i += 1
            target = new_name[2:] if new_name.startswith("b/") else (old_name[2:] if old_name.startswith("a/") else new_name)
            p = self.p.authorize(target, "patch")
            original = p.read_text(encoding="utf-8").splitlines(True) if p.exists() else []
            out = []
            pos = 0
            hunk_count = 0
            while i < len(lines) and lines[i].startswith("@@"):
                m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", lines[i])
                if not m:
                    raise ValueError("invalid hunk")
                old_start = int(m.group(1)) - 1
                if old_start < pos or old_start > len(original):
                    raise ValueError("invalid hunk position")
                out.extend(original[pos:old_start])
                pos = old_start
                i += 1
                while i < len(lines) and not lines[i].startswith(("--- ", "@@")):
                    line = lines[i]
                    i += 1
                    if line.startswith(" "):
                        if pos >= len(original) or original[pos].rstrip("\n") != line[1:].rstrip("\n"):
                            raise ValueError("patch context mismatch")
                        out.append(original[pos])
                        pos += 1
                    elif line.startswith("-"):
                        if pos >= len(original) or original[pos].rstrip("\n") != line[1:].rstrip("\n"):
                            raise ValueError("patch removal mismatch")
                        pos += 1
                    elif line.startswith("+"):
                        out.append(line[1:])
                    elif line.startswith("\\"):
                        pass
                    else:
                        raise ValueError("invalid patch line")
                hunk_count += 1
            if not hunk_count:
                raise ValueError("file patch has no hunks")
            out.extend(original[pos:])
            original_text = "".join(original)
            if not self.dlp.check("filesystem.apply_patch.source", original_text).allowed:
                raise PermissionError("content blocked by security policy")
            data = "".join(out).encode("utf-8")
            if len(data) > self.p.cfg["permissions"]["max_file_bytes"]:
                raise ValueError("file too large")
            self.p.backup(p)
            atomic_write(p, data)
            changed += 1
        if not changed:
            raise ValueError("no patch hunks found")
        return {"changed_files": changed, "status": "applied"}


class MakeDir(FS):
    """Create a workspace directory recursively."""

    name = "make_dir"
    description = "Create a directory."

    def run(self, a):
        """Create the requested directory and any missing parents."""
        self.p.authorize(a["path"], "write").mkdir(parents=True, exist_ok=True)
        return "created"


class Move(FS):
    """Move a file or directory entirely within the workspace."""

    name = "move"
    description = "Move a file or directory within the workspace."

    def run(self, a):
        """Resolve both source and destination under write policy and use ``shutil.move``."""
        s = self.p.authorize(a["src"], "move")
        d = self.p.authorize(a["dst"], "move")
        if d.exists() or d.is_symlink():
            raise FileExistsError(f"destination exists: {d.relative_to(self.p.root)}")
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(s), str(d))
        return "moved"


class Delete(FS):
    """Delete a file or an empty directory when explicitly enabled by policy."""

    name = "delete"
    description = "Delete a file or an empty directory."

    def run(self, a):
        """Delete one path after checking ``allow_delete`` and workspace policy."""
        if not self.p.cfg["permissions"].get("allow_delete", False):
            raise PermissionError("delete disabled by policy")
        p = self.p.authorize(a["path"], "delete")
        trashed = self.p.trash(p)
        return f"deleted to {trashed.relative_to(self.p.root)}"


class Undo(FS):
    """Restore a session-scoped backup from ``.agent/backups/<session>``."""

    name = "undo"
    description = "Restore a previous session backup for a workspace path."

    def run(self, a):
        p = self.p.authorize(a["path"], "write")
        session = a.get("session") or getattr(self.p, "session_id", "default")
        try:
            rel = p.relative_to(self.p.root)
        except ValueError as exc:
            raise PermissionError("path outside workspace") from exc
        bak = self.p.root / ".agent" / "backups" / Path(session).name / rel
        bak = self.p.authorize(bak, "backup", actor="runtime")
        if not bak.is_file():
            raise FileNotFoundError("backup not found")
        shutil.copy2(bak, p)
        return {"restored": str(p.relative_to(self.p.root)), "session": Path(session).name}


class ViewImage(FS):
    """Read an allowed file and expose its bytes as a MIME-aware data URL."""

    def __init__(self, p, dlp=None):
        super().__init__(p)
        self.dlp = dlp or DLPPolicy()

    name = "view_image"
    description = "Read an image as a data URL for multimodal models."

    def run(self, a):
        """Return ``mime`` and base64 ``data_url`` without writing any file."""
        p = self.p.authorize(a["path"], "read")
        data = p.read_bytes()
        if len(data) > self.p.max_read_bytes():
            raise ValueError("image exceeds max_read_bytes")
        if not self.dlp.check("filesystem.image", data).allowed:
            raise PermissionError("content blocked by security policy")
        mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        return {"mime": mime, "data_url": f"data:{mime};base64," + base64.b64encode(data).decode()}
