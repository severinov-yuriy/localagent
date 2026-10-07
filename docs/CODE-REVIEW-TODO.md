# Code Review Work Queue — Completed

This document records the disposition of the independent code-review backlog. The active security and runtime specifications are the canonical documentation under `docs/security.md`, `docs/tools.md`, `docs/configuration.md`, and `docs/architecture.md`.

## P0

| Item | Status | Outcome |
|---|---|---|
| P0-FUNC-001 | DONE | `run_tests` schema, required arguments, validation, implementation, documentation, and dispatch tests use `targets`. |
| P0-FUNC-002 | DONE | Acceptance now proves a real Agent → tool dispatch → pytest execution → structured result cycle. |
| P0-EXEC-003 | DONE | Execution is limited to a trusted pre-existing pytest surface; new/modified Python, plugins, fixtures, hooks, options, shell paths, and environment injection are blocked. |
| P0-EXEC-004 | DONE | Interpreter identity is compared by canonical resolved path, with regression coverage for same-basename impostors and aliases. |
| P0-FUNC-005 | DONE | `kb_add` requires at least one of `path`/`content`, validates combinations before mutation, and supports path-only/content-only/both. |
| P0-FS-006 | DONE | Context, skills, filesystem tools, and KB file imports use the same workspace policy boundary and symlink containment checks. |
| P0-DLP-007 | DONE | Image/file transport goes through DLP; sensitive image payloads and data URLs cannot bypass the security sink. |
| P0-DLP-008 | DONE | Error reasons, final results, reports, sessions, and audit records are sanitized before persistence. |
| P0-DLP-009 | DONE | `SecretScanner` is the sole detector/redactor implementation; duplicate security APIs were removed. |
| P0-POLICY-010 | DONE | External read roots were removed; workspace-only filesystem semantics are explicit and documented. |
| P0-ACL-011 | DONE | Resume restores saved role/tool/model/effort state; the CLI cannot add capabilities after restore. Unsupported resume overrides were removed. |
| P0-UX-012 | DONE | `ask_user` uses one confirmation/interaction mechanism without a second hidden confirmation. |
| P0-POLICY-013 | DONE | Global permission read/write keys were removed in favor of the validated policy schema. |
| P0-CONFIG-014 | DONE | `agent.loop_detection.repeat` is the only runtime setting; the old name is migration-only and conflicts are rejected. |

## P1

| Item | Status | Outcome |
|---|---|---|
| P1-CLI-015 | DONE | CLI skill listing uses the same `skills/` + `.pi/skills/` discovery model as runtime context. |
| P1-CLI-016 | DONE | Role-name contract allows internal dots and rejects path separators/traversal; docs and tests match. |
| P1-TEST-017 | DONE | Parent/child history test checks forbidden private data and allowed structured results directly. |
| P1-TEST-018 | DONE | Depth-limit test asserts the actual `RuntimeError` contract. |
| P1-TEST-019 | DONE | Duplicate session/resume checks were consolidated; remaining similar tests exercise distinct boundaries. Test ownership is documented in `tests/README.md`. |
| P1-TEST-020 | DONE | Execution-environment test observes actual child-process environment/call semantics rather than only an authorization decision. |
| P1-TEST-021 | DONE | Source/release caches are removed and `.gitignore` covers pytest, Python, coverage, lint, mypy, build, and egg-info artifacts. |
| P1-DOC-022 | DONE | Canonical docs describe one application-level security model with no OS sandbox claims. |
| P1-DOC-023 | DONE | All live validated keys are documented; removed options are explicitly identified as unsupported. |
| P1-DOC-024 | DONE | The previous security note is historical; current behavior and threat model live in `docs/security.md`. |
| P1-OSS-025 | DONE | License, contributor guidance, changelog, CI, typed-package marker, and package metadata were added. |
| P1-OSS-026 | DONE | Dev dependencies are installed from `pyproject.toml`, the documented quality workflow matches CI, and package build/release hygiene are checked. |
| P1-CODE-027 | DONE | Dead imports and unused in-repository security compatibility APIs were removed after call-site review. |
| P1-CODE-028 | DONE | Internal callers use explicit `authorize()` operations; `Policy.path()` remains only as a documented compatibility shim. |
| P1-CODE-029 | DONE | Security-critical functions have explicit types where they cross module boundaries; mypy is a required quality gate. |
| P1-CODE-030 | DONE | No large extraction was forced: current lifecycle/policy/DLP boundaries are explicit, and unnecessary architectural churn was avoided. |

## P2

| Item | Status | Outcome |
|---|---|---|
| P2-TEST-031 | DONE | Test ownership is documented and end-to-end dispatch/policy/DLP flows are covered without needless directory churn. |
| P2-TEST-032 | DONE | Security regression matrix covers execution surface, interpreter identity, symlinks, DLP, persistence, path normalization, environment, and agent laundering attempts. |
| P2-QUALITY-033 | DONE | CI runs tests, lint, typing, build integrity, and coverage threshold checks. |
| P2-QUALITY-034 | DONE | Runtime version derives from package metadata; package version has one authoritative source. |

## Closed-state validation

The queue is considered closed only after the repository passes the validation protocol recorded in the final engineering report. The repository intentionally does **not** claim OS-level isolation; application-level controls and their residual risks are described in `docs/security.md`.
