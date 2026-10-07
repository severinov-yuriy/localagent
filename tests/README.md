# Test ownership

The suite is grouped by behavior rather than implementation-only detail.

| Suite | Owner boundary |
|---|---|
| `test_p0_security.py` | Cross-cutting security invariants and threat-boundary regressions. |
| `test_policy_compliance.py` | `FilesystemPolicy` unit behavior and path containment. |
| `test_exec_compliance.py` | `run_tests` schema/execution policy and trusted pytest surface. |
| `test_context_compliance.py` | Context loading, skill discovery, compaction, and prompt-data boundaries. |
| `test_fs_tools_compliance.py` | Filesystem tool behavior and file/image DLP. |
| `test_skills_kb_compliance.py` | Skill and knowledge-base contracts. |
| `test_agent_loop_compliance.py` | Agent lifecycle, budgets, confirmation, loop detection, and persistence mechanics. |
| `test_subagents_compliance.py` | Role ACL intersection, history isolation, child limits, and parent linkage. |
| `test_acceptance.py` | Small end-to-end public workflows, including dispatch, resume, and reviewer restrictions. |
| `test_journal_compliance.py` | Audit event schema and durable redaction. |
| `test_config_compliance.py` | Configuration schema, migrations, and path semantics. |
| `test_cli_compliance.py` | Public CLI parsing and discovery parity. |
| `test_llm_compliance.py` | OpenAI-compatible streaming, retries, timeouts, and response reconstruction. |
| `test_security_and_features.py` | Compatibility/feature smoke coverage that is not owned by a narrower security suite. |

When two tests resemble each other, the owner suite should contain the invariant assertion and the other test should remain only when it exercises a distinct integration boundary.
