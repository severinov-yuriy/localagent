# Security Model

## Scope

`localagent` is an application-level security boundary for an autonomous LLM agent in a closed corporate contour. It is designed to prevent an LLM or agent-controlled tool call from escaping the configured workspace, acquiring undeclared capabilities, or forwarding credential-like data to downstream sinks.

**Python-level hardening is not an OS sandbox.** The project does not use or require Docker, seccomp, AppArmor, SELinux, bubblewrap, root/admin helpers, or another mandatory OS isolation layer. OS/user/network isolation remains a deployment responsibility.

## Security invariants

### Filesystem

All agent-controlled filesystem entry points use one `FilesystemPolicy` instance and explicit operations such as `read`, `write`, `delete`, `move`, `mkdir`, `grep`, and `glob`.

Before an agent-controlled path is used, the policy:

1. joins relative paths to the workspace;
2. resolves the candidate canonically;
3. verifies containment in the workspace;
4. applies built-in secret-name protection and control-plane protection;
5. applies configured deny patterns;
6. applies role ACL intersections.

This rejects `../`, outside absolute paths, symlink/junction escapes, and control-plane paths. `.pi/skills/**` is a supported read-only skill root; other `.pi/**` paths are protected from the agent. `.agent/**` is runtime-owned state.

`Policy.path()` is retained only as a compatibility alias around `authorize()`. Internal runtime code uses explicit operations instead of boolean `write=True` semantics.

### Execution

Execution is disabled unless `exec.enabled=true`.

The only execution capability is `run_tests`, and its boundary is intentionally narrow:

- fixed executable identity equal to the canonical `sys.executable` path;
- fixed `python -m pytest` entrypoint;
- no shell;
- no arbitrary pytest options;
- targets must be relative paths under `tests/`;
- cwd is exactly the workspace;
- environment contains only `PATH`, `PYTEST_DISABLE_PLUGIN_AUTOLOAD`, and `PYTHONNOUSERSITE`;
- the Python test surface is snapshotted at tool construction and must not change before execution;
- symlinks in the execution surface must remain inside the workspace.

The trusted-surface rule matters because pytest can execute Python before a target test body through `conftest.py`, plugins, fixtures, imports, hooks, or module-level code. A newly created or modified Python file therefore does not become executable merely because it appears under `tests/`.

This is application policy, not host isolation. A compromised host process, concurrent privileged actor, or kernel-level attacker is outside the protection model.

### ACL and lifecycle

Role ACLs are intersected with global policy and, for children, with the already-effective parent policy. Resume restores the persisted role, tool ACL, model, reasoning effort, and session state. The CLI does not add capabilities after resume.

`spawn_agent` is only exposed when the current effective tool set permits it. Child depth and count limits are enforced in the runtime.

`ask_user` is a single interaction primitive. It does not perform an additional generic write confirmation internally; mutation confirmation belongs to the capability policy for the operation being confirmed.

### DLP

`SecretScanner` is the authoritative detector. `SecretScanner.redact()` is the corresponding durable/user-visible redaction primitive. `DLPPolicy.check()` turns a scan into an allow/block decision without returning sensitive material.

The same detector is used across these boundaries:

```text
filesystem read / skill / KB / @file
        ↓
context and model messages
        ↓
tool arguments
        ↓
tool results / image data
        ↓
stdout / stderr / exceptions
        ↓
agent result / report / session / audit log
```

Durable sinks redact; sensitive content that cannot be safely exposed is blocked before persistence. Data URLs are treated as sensitive transport objects for durable sinks and never written to audit records in raw form.

## Threat model

### Protected assets

- API keys, tokens, passwords, private keys, and credential-like files;
- workspace integrity and control-plane files;
- agent capabilities and role ACLs;
- session state and audit logs;
- LLM context and tool arguments;
- host resources reachable through execution tools.

### Trusted actors

- the user starting the application;
- the local application process;
- pre-existing trusted project/test code on the execution surface;
- configuration supplied outside the LLM/tool-call channel.

### Agent/LLM capabilities assumed

The model may request any registered tool, choose arbitrary string arguments, emit prompt-injection-like text, attempt path traversal, provide malicious test targets, or attempt to smuggle secrets into arguments and summaries. It may not directly invoke an unregistered capability.

### Out of scope

OS/kernel compromise, malicious code already running in the same Python interpreter, administrator/root compromise, filesystem changes by a privileged concurrent process after a policy check, and deployment-specific network isolation are not fully solved by the application layer.

## Regression evidence

Security invariants are covered by focused tests in:

- `tests/test_p0_security.py` — central P0 security invariants;
- `tests/test_policy_compliance.py` — path authorization and containment;
- `tests/test_exec_compliance.py` — execution identity, environment, pytest surface, and end-to-end test execution;
- `tests/test_context_compliance.py` — context/skill boundary and compaction DLP;
- `tests/test_fs_tools_compliance.py` — file/image data DLP;
- `tests/test_skills_kb_compliance.py` — skill and KB security;
- `tests/test_journal_compliance.py` — durable redaction and session persistence;
- `tests/test_agent_loop_compliance.py` and `tests/test_acceptance.py` — lifecycle, resume, subagents, confirmation, and end-to-end flows.

The regression suite intentionally tests both positive behavior and the absence of sensitive values in downstream sinks.


## Execution v3 security model

`exec.isolation` is `kernel`, `best_effort`, or explicitly weaker `app`. `kernel` requires Landlock, seccomp, and loopback-only network namespace support. `best_effort` uses available kernel layers and refuses to run when none are available. `app` relies on typed execution policy and static preflight and is not an OS security boundary.

The agent control plane (`AGENTS.md`, `agents/**`, `skills/**`, `.pi/**`, `.agent/**`) is protected from agent writes. Work zones are `src/**`, `tests/**`, `scripts/**`, `scratch/**`, `data/**`, and `docs/**`.
