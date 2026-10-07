# Changelog

## Unreleased

Security and quality hardening from the code-review backlog:

- narrowed test execution to a trusted pre-existing pytest surface;
- added canonical interpreter identity checks and cleaned execution environment;
- centralized filesystem authorization and secret detection/redaction;
- protected context, skills, KB imports, image payloads, exceptions, reports, sessions, and audit logs with the same security boundary;
- fixed resume capability restoration and removed unsupported CLI overrides;
- consolidated loop-detection configuration and removed dead external-read/execution settings;
- added OpenRouter-compatible configuration, reasoning payloads, attribution headers, and a built-in DeepSeek Chat V3.1 profile;
- refreshed security/configuration/tool/architecture documentation;
- added reproducible development/packaging workflow and CI quality gates.

## 0.2.0

Initial compact terminal agent implementation with streaming LLM client, local tools, roles, skills, sessions, audit logging, and SQLite knowledge base.
