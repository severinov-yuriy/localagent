"""Tool protocol, capability taxonomy, schemas, and deterministic argument validation."""
from __future__ import annotations

import math

# Capability taxonomy is authoritative for authorization and accounting.
FS_READ = "filesystem.read"
FS_WRITE = "filesystem.write"
FS_DELETE = "filesystem.delete"
PROCESS_EXECUTE = "process.execute"
INTERACTION_USER = "interaction.user"
KB_WRITE = "kb.write"
SUBAGENT_SPAWN = "subagent.spawn"

SCHEMAS = {
    "read_file": {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
    "list_dir": {"path": {"type": "string"}},
    "glob": {"path": {"type": "string"}, "pattern": {"type": "string"}},
    "grep": {"pattern": {"type": "string"}, "max_results": {"type": "integer"}},
    "write_file": {"path": {"type": "string"}, "content": {"type": "string"}},
    "edit_file": {"path": {"type": "string"}, "old": {"type": "string"}, "new": {"type": "string"}, "replace_all": {"type": "boolean"}},
    "apply_patch": {"patch": {"type": "string"}},
    "make_dir": {"path": {"type": "string"}},
    "move": {"src": {"type": "string"}, "dst": {"type": "string"}},
    "delete": {"path": {"type": "string"}},
    "undo": {"path": {"type": "string"}},
    "view_image": {"path": {"type": "string"}},
    "run_script": {"path": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}},
    "run_module": {"module": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}},
    "run_tests": {"targets": {"type": "array", "items": {"type": "string"}}},
    "check_syntax": {"path": {"type": "string"}},
    "finish": {"result": {"type": "string"}, "summary": {"type": "string"}, "status": {"type": "string"}, "artifacts": {"type": "array", "items": {"type": "string"}}, "notes": {"type": "array", "items": {"type": "string"}}},
    "todo": {"action": {"type": "string"}, "items": {"type": "array", "items": {"type": "object"}}, "item": {"type": "object"}, "id": {"type": "string"}},
    "ask_user": {"question": {"type": "string"}},
    "read_skill": {"name": {"type": "string"}},
    "kb_search": {"query": {"type": "string"}, "limit": {"type": "integer"}},
    "kb_read": {"path": {"type": "string"}},
    "kb_add": {"path": {"type": "string"}, "content": {"type": "string"}},
    "spawn_agent": {"role": {"type": "string"}, "task": {"type": "string"}},
}

# Required arguments are kept separate for the flat schemas above. ``kb_add``
# accepts either a path or inline content, and may accept both when a logical
# source path is useful as metadata.

REQUIRED = {
    "read_file": {"path"},
    "list_dir": {"path"},
    "glob": {"path"},
    "grep": {"pattern"},
    "write_file": {"path", "content"},
    "edit_file": {"path", "old", "new"},
    "apply_patch": {"patch"},
    "make_dir": {"path"},
    "move": {"src", "dst"},
    "delete": {"path"},
    "undo": {"path"},
    "view_image": {"path"}, "check_syntax": {"path"},
    "run_script": {"path"}, "run_module": {"module"}, "run_tests": {"targets"},
    "read_skill": {"name"},
    "kb_search": {"query"},
    "kb_read": {"path"},
    "spawn_agent": {"role", "task"},
    "ask_user": {"question"},
}


def _type_matches(value, expected):
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    raise ValueError(f"unsupported schema type: {expected}")


def _validate_properties(properties, args):
    for key, value in args.items():
        spec = properties.get(key)
        if not spec:
            continue
        expected = spec.get("type")
        if expected and not _type_matches(value, expected):
            raise ValueError(f"{key}: expected {expected}")
        if expected == "array" and "items" in spec:
            item_type = spec["items"].get("type")
            for index, item in enumerate(value):
                if item_type and not _type_matches(item, item_type):
                    raise ValueError(f"{key}[{index}]: expected {item_type}")
        if expected == "object" and "properties" in spec:
            nested_properties = spec["properties"]
            for nested_key, nested_spec in nested_properties.items():
                if nested_key in value and nested_spec.get("type") and not _type_matches(value[nested_key], nested_spec["type"]):
                    raise ValueError(f"{key}.{nested_key}: expected {nested_spec['type']}")


def validate_tool_arguments(name, args):
    """Validate the supported JSON-schema subset before a tool can run."""
    if not isinstance(args, dict):
        raise ValueError("tool arguments must be a JSON object")
    if name == "kb_add":
        has_path = "path" in args and args.get("path") not in (None, "")
        has_content = "content" in args and args.get("content") is not None
        if not has_path and not has_content:
            raise ValueError("kb_add requires path or content")
    schema = SCHEMAS.get(name, {})
    if schema.get("type") == "object":
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", False)
    else:
        properties = schema
        additional = False
    required = set(REQUIRED.get(name, ())) | set(schema.get("required", ()))
    for key in required:
        if key not in args:
            raise ValueError(f"missing required argument: {key}")
    if not additional:
        unknown = sorted(set(args) - set(properties))
        if unknown:
            raise ValueError(f"unknown argument(s): {', '.join(unknown)}")
    _validate_properties(properties, args)
    return args


CAPABILITIES = {
    "read_file": {FS_READ}, "list_dir": {FS_READ}, "glob": {FS_READ}, "grep": {FS_READ},
    "view_image": {FS_READ}, "read_skill": {FS_READ}, "kb_search": {FS_READ}, "kb_read": {FS_READ},
    "write_file": {FS_WRITE}, "edit_file": {FS_WRITE}, "apply_patch": {FS_WRITE},
    "make_dir": {FS_WRITE}, "move": {FS_WRITE}, "delete": {FS_DELETE}, "undo": {FS_WRITE},
    "run_script": {PROCESS_EXECUTE}, "run_module": {PROCESS_EXECUTE}, "run_tests": {PROCESS_EXECUTE}, "check_syntax": {FS_READ},
    "ask_user": {INTERACTION_USER}, "kb_add": {KB_WRITE, FS_READ}, "spawn_agent": {SUBAGENT_SPAWN},
    "finish": set(), "todo": set(),
}


class Tool:
    """Base tool for OpenAI-compatible function calls."""
    name = ""
    description = ""
    capabilities = None

    def schema(self):
        """Return the OpenAI-compatible function declaration for this tool."""
        declared = SCHEMAS.get(self.name, {})
        if declared.get("type") == "object":
            schema = dict(declared)
        else:
            schema = {
                "type": "object",
                "properties": declared,
                "additionalProperties": False,
            }
        required = REQUIRED.get(self.name)
        if required:
            schema["required"] = sorted(required)
        if self.name == "kb_add":
            schema["anyOf"] = [
                {"required": ["path"]},
                {"required": ["content"]},
            ]
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": schema,
            },
        }

    def get_capabilities(self):
        """Return the immutable capability set used by policy/confirmation logic."""
        return frozenset(self.capabilities if self.capabilities is not None else CAPABILITIES.get(self.name, {FS_READ}))

    def run(self, args):
        """Execute the tool against an argument mapping; subclasses must implement this method."""
        raise NotImplementedError
