"""Syntax-only validation without importing or executing target code."""
from __future__ import annotations

import ast

from .base import FS_READ, Tool


class CheckSyntax(Tool):
    name = "check_syntax"
    description = "Parse Python files without executing them."
    capabilities = {FS_READ}

    def __init__(self, policy):
        self.p = policy

    def run(self, a):
        path = self.p.authorize(a["path"], "read")
        if path.suffix != ".py":
            return {"ok": False, "is_error": True, "error": "Python file required"}
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            return {"ok": True, "is_error": False}
        except (SyntaxError, UnicodeDecodeError) as exc:
            return {"ok": False, "is_error": True, "error": str(exc)}
