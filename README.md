# localagent 0.2.0

`localagent` is a small terminal autonomous LLM agent for a closed corporate contour. It uses one synchronous agent loop, an OpenAI-compatible streaming client, policy-controlled local tools, JSONL audit logs, resumable sessions, and a SQLite/FTS5 knowledge base.

The package supports **Python 3.10 and newer CPython versions supported by the test matrix**. It can connect to an internal OpenAI-compatible LLM gateway instead of a public agent platform.

## Documentation

- [Usage](docs/usage.md) — installation, CLI workflows, sessions, logs, KB, and development.
- [Configuration](docs/configuration.md) — complete validated configuration reference.
- [Tools](docs/tools.md) — built-in tool contracts and capability boundaries.
- [Security model](docs/security.md) — current application-level security model and threat model.
- [Roles and skills](docs/roles-and-skills.md) — role ACLs, `AGENTS.md`, and skill discovery.
- [Architecture](docs/architecture.md) — runtime components, lifecycle, and data flow.

## Install

For normal use:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

For development and all local quality checks:

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check src tests
mypy src
python -m build
```

Configure the internal LLM endpoint in `.agent/config.yaml`. Authentication can use the environment variable named by `llm.api_key_env` (default `GENOPS_API_KEY`) or the trusted runtime-only `llm.api_key_file` setting. Credentials are never copied into agent context or audit records.

## Using OpenRouter

`localagent` can use OpenRouter through its OpenAI-compatible Chat Completions endpoint. Set `llm.base_url`, point `llm.api_key_env` at `OPENROUTER_API_KEY`, and select an OpenRouter model profile.

```yaml
llm:
  base_url: https://openrouter.ai/api/v1
  api_key_env: OPENROUTER_API_KEY
  reasoning_format: openrouter
  models:
    default: deepseek/deepseek-chat-v3.1
  profiles:
    deepseek/deepseek-chat-v3.1:
      reasoning_efforts: [low, medium, high]
      default_reasoning_effort: medium
      context_window: 163840
      max_output: 32768
      sampling: {temperature: 1.0, top_p: 1.0}
      max_tokens: {low: 4096, medium: 16384, high: 32768}
      chars_per_token: 3.5
```

```bash
export OPENROUTER_API_KEY='…'
agent run "Explain the architecture of this repository" --model deepseek/deepseek-chat-v3.1 --workspace .
```

`llm.http_referer` and `llm.x_title` are optional OpenRouter attribution headers. `Context.compact()` uses `complete_json` when the provider supports the requested JSON response format and falls back to text compaction when it does not.

## CLI

```text
agent run PROMPT [--role ROLE] [--model MODEL] [--effort EFFORT] [--mode auto|interactive|headless] [--headless] [--max-steps N] [--max-time SECONDS] [--workspace PATH]
agent chat [PROMPT] [same run flags] [--workspace PATH]
agent resume SESSION [--workspace PATH]
agent doctor [--live] [--exec-backend] [--workspace PATH]
agent config [show|check] [--config PATH] [--workspace PATH]
agent roles [list] [--workspace PATH]
agent skills list [--workspace PATH]
agent logs [list|show|tail|export|prune] [--session ID] [--n N] [--output PATH] [--workspace PATH]
agent kb search QUERY [--workspace PATH]
agent kb add FILE [--workspace PATH]
```

`resume` restores the persisted model, reasoning effort, role, tool ACL, and session state. It deliberately has no role/model/effort override flags because those values are part of the saved security and execution state.

## Capabilities

- bounded sequential tool loop with `finish`, `todo`, and `ask_user`;
- bounded subagents with depth, total-count, and per-child step limits;
- one centralized `FilesystemPolicy` for agent-controlled paths;
- default-deny access to control-plane and secret-like paths, including symlink/junction containment checks;
- atomic file writes, single-file backups, `undo`, and an in-process unified-patch tool;
- typed execution capabilities are sandboxed: `run_script` is limited to the configured work zones (`scratch/`, `scripts/`, `src/`, `tests/`); `run_tests` runs configured tests and writes JUnit output to `scratch/`; `run_module` is enabled by default when execution is enabled and uses `python -m` from `src/`;
- context compaction and length-limited continuation;
- SQLite/FTS5 knowledge base;
- skills under both `skills/` and `.pi/skills/`;
- JSONL audit logs and reports with centralized DLP redaction;
- resumable sessions and SIGINT state persistence;
- multimodal `view_image` with the same DLP boundary used by other data paths.

## Security posture

Filesystem operations are authorized by `FilesystemPolicy`; agent reads remain available for source, scripts, and tests, but agent logic under `AGENTS.md`, `agents/**`, `skills/**`, `.pi/**`, and `.agent/**` is protected; `src/**`, `scripts/**`, `tests/**`, `scratch/**`, `data/**`, and `docs/**` are work zones. Execution is disabled by default and fails closed unless the Linux kernel reports both Landlock and seccomp support. Every executed process is started by a trusted launcher with `start_new_session=True`, `NO_NEW_PRIVS`, resource limits, Landlock filesystem containment, and a focused seccomp filter. The sandbox does not grant access to `/home` merely because the interpreter itself lives there: a venv is allowed only through its trusted read-only tree.

Workspace `.agent/config.yaml` cannot override `exec`, `llm`, `logging`, `kb`, or `permissions`; execution environment values are administrative configuration only and are never inherited from the parent process. `agent doctor --exec-backend` reports whether the kernel execution backend is actually usable.

Secrets are screened at LLM-context, tool-argument, tool-result, terminal-output, exception, report, and audit-log boundaries. Secret-like filenames are denied before content access. Runtime-owned state under `.agent/` is inaccessible to the agent even though the application itself can persist it.

**Python-level hardening is not an OS sandbox.** The application does not provide seccomp, AppArmor, SELinux, bubblewrap, Docker isolation, or a privileged helper. Host deployment must therefore supply its own OS/user/network isolation appropriate to the closed-contour threat model.

## Workspace layout

```text
workspace/
├── .agent/
│   ├── config.yaml
│   ├── kb.sqlite
│   ├── logs/YYYY-MM-DD/<session>.jsonl
│   ├── reports/<session>.report.md
│   └── sessions/<session>.json
├── agents/*.md
├── skills/*/SKILL.md
├── .pi/skills/*/SKILL.md
├── AGENTS.md
└── project files...
```

## Python API

Primary public building blocks:

```python
from localagent.agent import Agent
from localagent.config import load_config
from localagent.llm import ChatRequest, LLMResponse, OpenAICompatClient
from localagent.policy import Policy
from localagent.runner import build_tools, load_role
from localagent.session import SessionStore
```

`Policy` remains a compatibility alias for `FilesystemPolicy`. New internal code uses explicit `authorize()` operations.
