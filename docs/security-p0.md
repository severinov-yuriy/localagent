# Historical Security Review Note

> This file is a historical engineering note. It is **not** the canonical security specification.
> The current security contract is maintained in [Security Model](security.md).

The previous review identified correctness and security gaps in filesystem authorization, test execution, DLP, resume ACL restoration, configuration, CLI semantics, and tests. Those findings were converted into the review work queue and then implemented in the current runtime.

The durable decisions from that review are now:

- one centralized `FilesystemPolicy` for agent-controlled paths;
- no generic shell or Python execution capability;
- `run_tests` is a narrowly typed capability over a trusted pre-existing test surface;
- interpreter identity is compared by canonical executable path, not basename;
- secrets use one detector/redactor path and are blocked before durable sinks;
- image/data-URL transport does not bypass DLP;
- resume restores persisted ACL/tool state without CLI capability injection;
- `agent.loop_detection.repeat` is the single runtime setting for loop detection;
- obsolete configuration such as external read roots and execution sandbox settings was removed;
- Python-level hardening is explicitly not an OS sandbox.

For current behavior, acceptance evidence, and residual risks, use `docs/security.md` and the executable regression tests listed there.
