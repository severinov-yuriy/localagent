# Tool Reference

The tool registry is created per agent. Role ACLs can reduce the registry further. Tool arguments are validated against the schema before execution, and the agent applies DLP checks to tool-call arguments and results.

## Filesystem tools

| Tool | Arguments | Purpose |
|---|---|---|
| `read_file` | `path`, optional `start_line`, `end_line` | Read a UTF-8/CP1251 text file through `FilesystemPolicy`; sensitive content is blocked. |
| `list_dir` | `path` | List visible entries inside the workspace policy boundary. |
| `glob` | `path`, `pattern` | Find files under an authorized directory; each result is checked before use. |
| `grep` | `pattern`, optional `path`, `max_results` | Search authorized text files; sensitive matches are blocked. |
| `write_file` | `path`, `content` | Write text after policy and confirmation checks. |
| `edit_file` | `path`, `old`, `new`, optional `replace_all` | Apply a textual edit with backup support. |
| `apply_patch` | `patch` | Apply an in-process unified patch; target paths stay inside the workspace. |
| `make_dir` | `path` | Create a directory inside the workspace. |
| `move` | `src`, `dst` | Move an authorized file within the workspace. |
| `delete` | `path` | Move an authorized file to runtime-owned trash when deletion is enabled. |
| `undo` | `path` | Restore the most recent applicable backup. |
| `view_image` | `path` | Read an image through the filesystem policy and DLP boundary; the model receives a multimodal data URL only after the security check passes. |

## Execution

### `run_tests`

Execution is disabled by default. When enabled, the tool accepts:

```json
{"targets": ["tests/test_example.py", "tests/integration"]}
```

Targets must be relative and start under `tests/`. pytest options, shell commands, arbitrary executables, environment injection, and newly created/modified Python execution surfaces are rejected. The runtime invokes only the application interpreter with the fixed `python -m pytest` entrypoint.

## Knowledge base

### `kb_search`

```json
{"query": "search terms", "limit": 10}
```

Searches the workspace-local SQLite/FTS5 knowledge base. Query and returned content are subject to DLP.

### `kb_read`

```json
{"path": "docs/example.md"}
```

Reads a single indexed file through the central filesystem policy and DLP.

### `kb_add`

At least one of `path` and `content` is required. Both may be supplied together.

Examples:

```json
{"path": "docs/example.md"}
{"content": "inline searchable note"}
{"path": "notes/example.md", "content": "inline searchable note"}
```

A path is authorized and scanned before its contents enter the database. Inline content is scanned before persistence. Invalid input fails validation before database mutation.

## Skills and interaction

| Tool | Arguments | Purpose |
|---|---|---|
| `read_skill` | `name` | Read a complete `SKILL.md` from `skills/` or `.pi/skills/` after policy checks. |
| `finish` | `status`, `summary`, optional `artifacts`, `notes` | End the current agent run with a structured result. |
| `todo` | action-specific fields | Maintain durable task state in the session. |
| `ask_user` | `question` | Request one user decision; headless agents cannot use it. |
| `spawn_agent` | `role`, `task` | Start a bounded child agent when the current ACL and depth/count budgets allow it. |

## Capability model

There is intentionally no generic command runner. The absence of a capability from the registry is part of the security model, not a UI limitation.
