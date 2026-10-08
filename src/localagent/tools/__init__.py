"""Tool package exports and shared tool exception type."""

from .base import Tool
from .fs import ReadFile, ListDir, Glob, Grep, WriteFile, EditFile, ApplyPatch, MakeDir, Move, Delete, Undo, ViewImage


class ToolError(Exception):
    """Raised when a tool cannot execute because of a local policy or tool constraint."""


__all__ = [
    "Tool", "ToolError", "ReadFile", "ListDir", "Glob", "Grep", "WriteFile", "EditFile",
    "ApplyPatch", "MakeDir", "Move", "Delete", "Undo", "ViewImage",
]
