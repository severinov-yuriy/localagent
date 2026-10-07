# Roles, Project Instructions, and Skills

## Roles

Roles are Markdown files under:

```text
<workspace>/agents/<role>.md
```

Role names may contain ordinary dots such as `my.role`, but may not be empty, `.`, `..`, `/`, `\\`, or path-traversal forms. Missing role files use a safe fallback role object rather than reading outside the workspace.

The repository ships example roles such as `coder`, `explorer`, `reviewer`, `summarizer`, and `tester`.

### Front matter

A role can declare:

```yaml
---
name: coder
description: Python implementation agent
model: deepseek
reasoning_effort: high
tools: [read_file, write_file, finish]
permissions:
  write: ["src/**"]
---
Role instructions
```

The runtime validates the supported fields. Tool restrictions and filesystem permissions are intersected with the global and parent-effective security policy.

## `AGENTS.md`

Only `<workspace>/AGENTS.md` is loaded automatically. Parent-directory files are intentionally ignored. Its content is data supplied to the system prompt; project text does not gain tool or policy privileges merely by being read.

## Skills

The runtime discovers skills from both:

```text
<workspace>/skills/<name>/SKILL.md
<workspace>/.pi/skills/<name>/SKILL.md
```

The CLI and context builder use the same discovery roots. The system prompt receives skill descriptions/index data, while `read_skill` reads the complete file on demand through `FilesystemPolicy` and DLP.

Only the `.pi/skills` subtree is supported under `.pi`; other `.pi` content remains protected from the agent.

Skills are model guidance. They are not an execution capability and cannot expand filesystem or tool permissions.
