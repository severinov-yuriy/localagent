# Configuration Reference

Configuration is assembled in this order, with later sources overriding earlier values:

```text
defaults → global YAML → <workspace>/.agent/config.yaml → LOCALAGENT_* → explicit CLI overrides
```

Unknown keys are rejected. Paths configured as `kb.path` and `logging.dir` must be workspace-relative. `permissions.workspace_root` is derived from the CLI-selected workspace and cannot be used to redirect the security boundary.

## `llm`

| Key | Default | Meaning |
|---|---|---|
| `base_url` | `http://127.0.0.1:8000/v1` | OpenAI-compatible API base URL. |
| `api_key_env` | `GENOPS_API_KEY` | Environment variable name used by the trusted runtime client. |
| `api_key_file` | `null` | Trusted runtime-only file containing the API key. It is never placed in LLM context. |
| `http_referer` | `null` | Optional `HTTP-Referer` header sent by the OpenRouter-compatible client. |
| `x_title` | `null` | Optional `X-Title` header sent by the OpenRouter-compatible client. |
| `connect_timeout_s` | `10` | Connection timeout. |
| `idle_timeout_s` | `55` | Read/idle timeout for streaming. |
| `verify_ssl` | `true` | TLS certificate verification. Disabling it emits a security warning. |
| `ca_bundle` | `null` | Optional CA bundle for the runtime HTTP client. |
| `proxy` | `null` | Optional HTTP client proxy. |
| `retry.max_attempts` | `3` | Maximum attempts for eligible retryable failures. |
| `retry.backoff_s` | `1.0` | Base retry backoff. |
| `retry.statuses` | `[429, 500, 502, 503, 504]` | HTTP statuses eligible for retry. |
| `models.default` | `DeepSeek-V4-Flash-0731` | Default model profile name. |
| `models.qwen` | `Qwen3.8-Flash` | Named Qwen model profile. |
| `sampling.temperature` | `1.0` | Default sampling temperature. |
| `sampling.top_p` | `0.95` | Default nucleus sampling value. |
| `max_tokens` | `{low: 4096, medium: 8192, high: 16384}` | Generic effort-to-token fallback mapping. |
| `reasoning_format` | `chat_template` | `chat_template` sends `chat_template_kwargs.reasoning_effort`; `openrouter` sends `reasoning.effort`. |
| `profiles.<model>` | built-in profiles | Model-specific reasoning efforts, sampling, context window, output limit, and token budgets. |

Each profile supports `reasoning_efforts`, `default_reasoning_effort`, `sampling.temperature`, `sampling.top_p`, optional `sampling.top_k`, `context_window`, `max_output`, `max_tokens`, and `chars_per_token`.

### OpenRouter

Use the OpenAI-compatible endpoint with:

```yaml
llm:
  base_url: https://openrouter.ai/api/v1
  api_key_env: OPENROUTER_API_KEY
  reasoning_format: openrouter
  http_referer: https://example.com/localagent
  x_title: localagent
  models:
    default: deepseek/deepseek-chat-v3.1
    qwen: Qwen3.8-Flash
```

`llm.api_key_env` contains the **name** of the environment variable; the key value is read only by the trusted HTTP client. `llm.http_referer` and `llm.x_title` are optional attribution headers. OpenRouter accepts the same OpenAI-compatible `/chat/completions` transport used by localagent, including streaming and tools.

The built-in `deepseek/deepseek-chat-v3.1` profile uses a 163,840-token context window and 32,768-token maximum completion and is intended for the example above. The profile should remain synchronized with the provider catalog; see the [OpenRouter model page](https://openrouter.ai/deepseek/deepseek-chat-v3.1).

Not every OpenRouter model supports every optional parameter. In particular, check the model catalog before relying on `response_format` or `top_k`. localagent sends `top_k` only when the selected model profile explicitly defines it. `Context.compact()` treats `complete_json()` as best-effort and falls back to text compaction when structured JSON output is rejected.

## `agent`

| Key | Default | Meaning |
|---|---:|---|
| `max_steps` | `80` | Maximum agent loop steps. |
| `max_tool_calls` | `120` | Maximum total tool calls. |
| `subagent_budget` | `30` | Per-child step budget. |
| `context_compact_ratio` | `0.70` | Context-compaction trigger ratio. |
| `history_max_messages` | `200` | History message limit used by compaction/limits. |
| `max_context_tokens` | `30000` | Estimated context budget used by the local context manager. |
| `loop_detection.repeat` | `3` | Number of repeated identical tool/argument calls that triggers loop detection. |
| `continue_on_length` | `true` | Continue a model response that ended because of output length when no tool call was produced. |
| `reasoning_effort` | `null` | Optional global reasoning-effort override validated against the selected model profile. |
| `mode` | `interactive` | `interactive` or `headless`. |
| `max_wall_time_s` | `900` | Whole-agent wall-time budget. |
| `max_tool_errors_in_row` | `5` | Consecutive tool-error limit. |
| `max_invalid_calls` | `5` | Invalid tool-call limit. |

`agent.loop_repeat` is accepted only as a compatibility migration alias into `agent.loop_detection.repeat`; it is not a second runtime setting. Supplying conflicting values is rejected.

## `subagents`

| Key | Default | Meaning |
|---|---:|---|
| `max_depth` | `2` | Maximum child nesting depth. |
| `max_subagents` | `20` | Maximum child agents spawned by the session. |

## `permissions`

| Key | Default | Meaning |
|---|---|---|
| `workspace_root` | derived from CLI workspace | Runtime-derived root; configuration cannot redirect it. |
| `allow_write` | `true` | Enable agent writes in allowed paths. |
| `allow_delete` | `false` | Enable deletion/move-to-trash. |
| `confirm` | `ask` | Mutation confirmation mode: `ask`, `auto_edit`, or `auto`. |
| `deny_patterns` | built-in secret/control patterns | Path patterns denied before role ACL evaluation. |
| `deny` | `[]` | Additional explicit deny patterns. |
| `control_plane` | `AGENTS.md`, `agents`, `agents/**`, `.agent/config.yaml`, `.agent/config.yml` | Paths protected from agent mutation and, where applicable, agent reads. |
| `backup` | `true` | Create a runtime-owned sibling backup before supported mutations. |
| `max_file_bytes` | `2000000` | Maximum file size accepted for mutation operations. |
| `max_read_bytes` | `2000000` | Maximum file size accepted for reads. |
| `max_changes` | `200` | Mutation budget per agent run. |

`extra_read_roots` is not supported. The security boundary is workspace-only.

## `exec`

| Key | Default | Meaning |
|---|---:|---|
| `enabled` | `false` | Expose `run_tests`. |
| `timeout_s` | `120` | Maximum execution time for one test invocation. |
| `output_limit` | `12000` | Maximum inline stdout/stderr characters per stream after DLP filtering. |

No additional executable, shell, pytest-argument, environment, or sandbox configuration exists.

## `kb`

| Key | Default | Meaning |
|---|---|---|
| `path` | `.agent/kb.sqlite` | Workspace-relative SQLite database path. |
| `chunk_chars` | `1800` | Character size used for indexed chunks. |

## `logging`

| Key | Default | Meaning |
|---|---|---|
| `dir` | `.agent/logs` | Workspace-relative audit-log directory. |
| `redact_keys` | `api_key`, `authorization`, `token`, `password`, `secret` | Additional key names treated as sensitive by durable redaction. |

## Environment overrides

Any configuration key can be overridden with `LOCALAGENT_` followed by upper-case path segments separated by `__`.

Examples:

```bash
LOCALAGENT_AGENT__MAX_STEPS=40
LOCALAGENT_LLM__VERIFY_SSL=false
LOCALAGENT_EXEC__ENABLED=true
```

Environment values are parsed as YAML scalars, so booleans and integers remain typed.
