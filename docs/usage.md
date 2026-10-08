# Usage Guide

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests
mypy src
python -m build
```

The package requires Python `>=3.10`. CI exercises Python 3.10 and 3.13.

## Basic commands

### One-shot run

```bash
agent run "Inspect the repository and summarize the main risks" --workspace .
agent run "Implement the requested change" --role coder --model DeepSeek-V4-Flash-0731 --effort high
```

### Interactive chat

```bash
agent chat --workspace .
```

Within interactive chat:

- `/exit` and `/quit` exit;
- `/save` persists the current session;
- a message beginning with `@path/to/file` is replaced with the file's UTF-8 contents when that path exists from the CLI process's current directory.

### Resume a session

```bash
agent resume <session-id> --workspace .
```

The resumed agent restores the saved role/model/effort, messages, step count, tool-call count, and change count, then asks the model to continue the previous task.

## Inspection commands

```bash
agent roles --workspace .
agent skills list --workspace .
agent config show --workspace .
agent config check --workspace .
agent doctor --workspace .
agent doctor --live --workspace .
```

`config show` and `config check` currently produce the same resolved YAML after validation.

`doctor` checks Python/dependencies, FTS5, TLS CA availability, workspace structure and, with `--exec-backend`, all execution isolation layers. `doctor --live` additionally probes the configured API, streaming, tool calling and structured output; it reports proxy configuration without exposing credentials.

## Logs

```bash
agent logs list --workspace .
agent logs show --session <id> --workspace .
agent logs tail --session <id> --n 100 --workspace .
agent logs export --session <id> --output audit.jsonl --workspace .
agent logs prune --n 30 --workspace .
```

`logs` searches the configured logging directory and sorts files by modification time. Without `--session`, `show`, `tail`, and `export` operate on the newest log file. `prune --n N` keeps the newest `N` log files from that list. Log file directories use the host-local calendar date, while each event's `ts` field is UTC.

## Knowledge base

```bash
agent kb add docs/design.md --workspace .
agent kb search "shuffle skew" --workspace .
```

Agent-side `kb_add` and the CLI `kb add` both pass file reads through the active filesystem policy before indexing. Inline content supplied to the agent is indexed without creating a workspace file.

## Tool loop lifecycle

A typical request looks like:

```text
User → Agent
      ↓
  LLM response
      ↓
  tool call(s)? ── no ──→ final response
      │
     yes
      ↓
 policy + confirmation
      ↓
 tool result
      ↓
 history update
      ↓
   next LLM step
```

Tool errors are converted to structured tool results in history so the model can react. Repeated identical tool calls are detected. Step, tool-call, subagent, and change budgets bound execution.

## Images

A multimodal model can call `view_image`. The file bytes are returned as a base64 data URL, then appended to history as an image-bearing user message for the next model request.

## Development

Run the complete test suite from the repository root:

```bash
pytest -q
```

The tests cover filesystem operations, policy boundaries, execution gating, SSE retries/accumulation, configuration, knowledge base, CLI behavior, sessions, reasoning-effort selection, and agent-loop history handling.

## OpenRouter

Set the provider endpoint and key in `.agent/config.yaml` / the environment, then choose the model explicitly:

```bash
export OPENROUTER_API_KEY='…'
agent doctor --workspace .
agent run "Review the current project status" --model deepseek/deepseek-chat-v3.1 --workspace .
```

For OpenRouter models that use its reasoning request format, set `llm.reasoning_format: openrouter`. The key is never passed through agent tool arguments or persisted in the session.
