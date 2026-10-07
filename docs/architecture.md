# Architecture

`localagent` is intentionally small. A normal run is a synchronous loop with explicit security boundaries rather than a distributed agent runtime.

```text
CLI
 │
 ├── load_config()
 ├── build_tools()
 └── Agent.run()
       │
       ├── Context ──────── system prompt / compaction / DLP
       ├── LLM client ───── SSE streaming / retries
       ├── Tool registry ── filesystem / KB / skills / interaction / run_tests
       ├── FilesystemPolicy ─ containment / deny rules / role ACL
       ├── DLPPolicy ─────── secret detection
       ├── EventLog ──────── redacted JSONL audit
       └── SessionStore ──── redacted resumable state
```

## Agent lifecycle

For each request the agent:

1. builds/refreshes the current context;
2. sends the history and current tool schemas to the LLM;
3. stores a sanitized assistant response;
4. validates the requested tool and its arguments;
5. checks DLP before arguments cross into the tool boundary;
6. checks ACL, confirmation, and resource budgets;
7. executes the tool;
8. sanitizes the tool result before it re-enters history;
9. repeats until `finish`, a configured limit, or a terminal error;
10. persists session/report state through redacted durable sinks.

Agent step count, tool-call count, subagent count, wall time, consecutive errors, invalid calls, and mutation count are independent budgets.

## Security ownership

### `policy.py`

`FilesystemPolicy` is the single path authorization implementation. It canonicalizes paths and applies workspace containment, built-in secret/control-plane protection, configured deny rules, and role-policy intersections. `Policy` is only a compatibility alias.

### `security.py`

`SecretScanner` is the only authoritative detector. `DLPPolicy` exposes security decisions; `SecretScanner.redact()` is the single recursive redaction primitive for durable/user-visible data.

### `tools/exec.py`

The execution layer intentionally contains only the typed `run_tests` capability. `TrustedTestSurface` prevents an agent-created or modified Python file from becoming executable through pytest's import, plugin, fixture, or configuration mechanisms. `ExecutionPolicy` constrains executable identity, argv, cwd, environment, and timeout.

### `context.py`

`Context` loads only `<workspace>/AGENTS.md` plus skill indexes from both `skills/` and `.pi/skills/`. Full skills are available through `read_skill`. All agent-controlled file reads use the same policy and DLP objects.

### `runner.py`

`build_tools()` creates the per-agent registry and injects the shared filesystem policy and DLP object. Role loading and discovery use the workspace policy boundary.

### `agent.py`

`Agent` owns lifecycle, tool orchestration, confirmation, loop/resource limits, subagents, persistence, and report generation. Resume reconstructs the effective saved security state instead of applying CLI capability overrides.

### `events.py` and `session.py`

Audit events and session state are durable runtime data. Both use bounded, redacted representations and live under `.agent/`.

## Trust boundaries

```text
user/config bootstrap
        │ trusted runtime input
        ▼
Agent process ── DLP ── LLM messages ── DLP ── tool args
        │                                  │
        │                                  ├── FilesystemPolicy ── workspace
        │                                  ├── KB policy/DLP
        │                                  ├── Skill policy/DLP
        │                                  └── run_tests ExecutionPolicy
        │
        ├── redacted EventLog
        ├── redacted SessionStore
        └── redacted report
```

The model does not select credentials, executables, interpreter paths, arbitrary cwd values, or external filesystem roots.

## Subagents

A child receives an isolated message history and an effective policy that is the intersection of parent and child capabilities. The child may return a structured result, but its internal history is not copied into the parent's history. Parent/child relationships are recorded in audit events.

## Intentional limitations

- The runtime is not an OS sandbox and does not protect against a compromised host process or kernel.
- `run_tests` trusts the pre-existing test surface at agent start; concurrent privileged modifications after the check are outside application-only guarantees.
- The tool-schema validator implements the subset required by the built-in registry rather than a general JSON Schema engine.
- The CLI exposes `kb add` but not a separate indexing subcommand.
- The interactive chat mode provides `/exit`, `/quit`, and `/save`.

## Context compaction

`Context.compact()` uses the LLM client `complete_json()` path to summarize older history as structured state. Structured output is best-effort: if the selected model/provider rejects `response_format: {type: json_object}` or otherwise fails the structured request, compaction falls back to a text summary and preserves durable todo state. This fallback is part of the agent lifecycle so a provider capability mismatch does not abort `Agent.run()`.
