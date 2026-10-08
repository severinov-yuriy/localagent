"""Core autonomous agent loop: policy, lifecycle, tools, LLM transport, and persistence."""
from __future__ import annotations

import json
import signal
import time
import uuid
from pathlib import Path

from .config import ConfigError
from .context import Context
from .events import EventLog, redact_data
from .llm import ChatRequest
from .policy import Policy
from .security import DLPPolicy
from .runner import load_role, build_tools
from .session import SessionStore
from .tools import ToolError
from .tools.base import (
    FS_DELETE, FS_WRITE, INTERACTION_USER, KB_WRITE, PROCESS_EXECUTE,
    SUBAGENT_SPAWN, validate_tool_arguments,
)


def _now():
    return time.monotonic()


class AgentResult(dict):
    """Canonical, dict-compatible result returned by every completed agent run."""

    def __init__(self, *, status, summary="", result="", artifacts=None, notes=None):
        super().__init__(
            status=status,
            summary=summary,
            result=result,
            artifacts=list(artifacts or []),
            notes=list(notes or []),
        )

    @property
    def status(self):
        return self["status"]

    def __str__(self):
        return str(self.get("summary") or self.get("result") or "")


class Agent:
    """Run a bounded agent conversation with centralized policy enforcement."""

    _agent_counter = 0
    _signal_owner = None
    _signal_previous = None
    _signal_stack = []
    TERMINAL_STATUSES = {"ok", "failed", "limit_reached", "stuck", "interrupted"}

    def __init__(
        self, cfg, llm, tools, ui, role="coder", session_id=None, depth=0,
        subagent_count=None, model=None, effort=None, role_object=None,
        parent_id=None, agent_id=None, effective_policy=None, allowed_tool_names=None,
    ):
        self.cfg = cfg
        self.llm = llm
        self.ui = ui
        self.depth = depth
        self.subagent_count = subagent_count if subagent_count is not None else [0]
        self.stop = False
        self.tool_calls = 0
        self.steps = 0
        self.changes = 0
        self.step_budget = int(cfg["agent"].get("max_steps", 80))
        self.tool_errors_in_row = 0
        self.invalid_calls = 0
        self.current_task = ""
        self.todo_state = []
        self.session_id = session_id or uuid.uuid4().hex[:12]
        Agent._agent_counter += 1
        self.agent_id = agent_id or f"a{Agent._agent_counter}"
        self.parent_id = parent_id
        self.terminal_status = None
        self.terminal_reason = None
        self.terminal_result = None
        self._ended = False
        self._oldint = None
        self._signal_installed = False
        self._pending_tool_calls = {}

        root = cfg["permissions"]["workspace_root"]
        self.dlp = DLPPolicy()
        base_policy = effective_policy or next(
            (getattr(t, "p", None) for t in tools.values() if getattr(t, "p", None)), None
        ) or Policy(cfg)
        self.role_object = role_object or (role if isinstance(role, dict) else load_role(root, role, base_policy))
        self.role = self.role_object.get("name", role if isinstance(role, str) else "coder")

        configured_model = model
        role_model = self.role_object.get("model")
        if configured_model is None and role_model:
            aliases = {
                "deepseek": cfg["llm"]["models"].get("default"),
                "qwen": cfg["llm"]["models"].get("qwen"),
            }
            configured_model = aliases.get(role_model, role_model)
        self.model = configured_model or cfg["llm"]["models"]["default"]
        profiles = cfg["llm"].get("profiles", {})
        if self.model not in profiles:
            raise ConfigError(f"llm model {self.model!r} has no validated profile")
        self.effort = effort or self.role_object.get("reasoning_effort") or cfg["agent"].get("reasoning_effort")
        self._profile = self.model_profile()
        self.effort = self.effort or self._profile.get("default_reasoning_effort")
        if self.effort not in self._profile.get("reasoning_efforts", []):
            raise ValueError(f"reasoning_effort {self.effort!r} unsupported for model {self.model}")

        inherited_roles = list(getattr(base_policy, "role_policies", []))
        role_permissions = self.role_object.get("permissions") or {}
        self.policy = effective_policy or Policy(
            cfg,
            role_policies=[*inherited_roles, role_permissions] if role_permissions else inherited_roles,
        )
        self.policy.session_id = self.session_id
        self.ctx = Context(
            root,
            cfg["agent"]["context_compact_ratio"],
            cfg["agent"]["max_context_tokens"],
            context_window=self._profile.get("context_window"),
            max_output=self._profile.get("max_output", 0),
            dlp=self.dlp,
            policy=self.policy,
        )
        log_dir = Path(root) / cfg["logging"]["dir"]
        self.log = EventLog(
            log_dir, self.session_id, self.agent_id, self.parent_id, cfg["logging"]["redact_keys"], policy=self.policy
        )
        self.store = SessionStore(root, policy=self.policy)

        candidate_tools = dict(tools)
        if allowed_tool_names is not None:
            allowed = set(allowed_tool_names)
            candidate_tools = {name: tool for name, tool in candidate_tools.items() if name in allowed}
        for tool in candidate_tools.values():
            if hasattr(tool, "p"):
                tool.p = self.policy
            if hasattr(tool, "policy"):
                tool.policy = self.policy
            if hasattr(tool, "dlp"):
                tool.dlp = self.dlp
            execution_policy = getattr(tool, "execution_policy", None)
            if execution_policy is not None:
                execution_policy.dlp = self.dlp
            if getattr(tool, "name", None) == "todo" and hasattr(tool, "bind"):
                tool.bind(self.todo_state)

        allowed_tools = self.role_object.get("tools")
        if allowed_tools is not None:
            allowed = set(allowed_tools)
            candidate_tools = {name: tool for name, tool in candidate_tools.items() if name in allowed}
        if cfg["agent"].get("mode") == "headless":
            candidate_tools.pop("ask_user", None)
        self.tools = candidate_tools
        self.effective_tool_names = frozenset(self.tools)
        self.effective_capabilities = frozenset(
            capability
            for tool in self.tools.values()
            for capability in tool.get_capabilities()
        )

        role_body = self.role_object.get("body", "")
        if not self.dlp.check("context.role_instructions", role_body).allowed:
            role_body = "Role instructions blocked by security policy"
        self.messages = [{"role": "system", "content": self.ctx.system(self.role) + "\n\nROLE INSTRUCTIONS:\n" + role_body}]

        # Complete audit initialization before touching process-global signal state.
        self.log.emit("session_start", role=self.role, model=self.model, depth=self.depth)
        if not cfg["llm"].get("verify_ssl", True):
            self.log.emit("security_warning", verify_ssl=False, message="TLS certificate verification is disabled")
        # SIGINT is process-global. Keep one dispatcher installed and track
        # nested agents explicitly so child agents cannot corrupt restoration.
        self._oldint = signal.getsignal(signal.SIGINT)
        if Agent._signal_owner is None:
            Agent._signal_previous = self._oldint
            signal.signal(signal.SIGINT, Agent._dispatch_signal)
        Agent._signal_stack.append(self)
        Agent._signal_owner = self
        self._signal_installed = True

    def model_profile(self):
        return self.cfg["llm"].get("profiles", {}).get(self.model, {})

    def _request_params(self):
        profile = self.model_profile()
        sampling = profile.get("sampling", self.cfg["llm"].get("sampling", {}))
        max_tokens = profile.get("max_tokens", self.cfg["llm"]["max_tokens"])
        budget = int(max_tokens[self.effort])
        if self.cfg["llm"].get("reasoning_format", "chat_template") == "openrouter":
            extra = {"reasoning": {"effort": self.effort}}
        else:
            extra = {"chat_template_kwargs": {"reasoning_effort": self.effort}}
        if profile.get("sampling", {}).get("top_k") is not None:
            extra["top_k"] = profile["sampling"]["top_k"]
        return {
            "max_tokens": budget,
            "temperature": sampling.get("temperature"),
            "top_p": sampling.get("top_p"),
            "extra_body": extra,
            "chars_per_token": float(profile.get("chars_per_token", 4.0)),
        }

    def _interrupt(self, *_):
        if self.stop:
            raise KeyboardInterrupt
        self.stop = True
        try:
            self.save()
        finally:
            self.ui.print_final("Interrupted. Session saved; run resume " + self.session_id + " to continue.")

    def _canonical_status(self, status):
        if status in {"ok", "done", "completed", "success"}:
            return "ok"
        if status in {"limit", "limit_reached", "error"}:
            return "limit_reached" if status != "error" else "failed"
        if status in self.TERMINAL_STATUSES:
            return status
        return "failed"

    def _report(self):
        """Write a report only from the canonical terminal state."""
        status = self.terminal_status or "failed"
        report = Path(self.cfg["permissions"]["workspace_root"]) / ".agent" / "reports" / f"{self.session_id}.report.md"
        report = self.policy.authorize(report, "write", actor="runtime")
        report.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# Session {self.session_id}", "",
            f"- Agent: `{self.agent_id}`",
            f"- Role: `{self.role}`",
            f"- Model: `{self.model}`",
            f"- Status: `{status}`",
            f"- Reason: `{self.terminal_reason or ''}`",
            f"- Steps: `{self.steps}`",
            f"- Tool calls: `{self.tool_calls}`",
            f"- Changes: `{self.changes}`",
            f"- Invalid calls: `{self.invalid_calls}`",
        ]
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def save(self):
        """Persist resumable state with secrets redacted at serialization time."""
        state = {
            "role": self.role,
            "role_object": self.role_object,
            "model": self.model,
            "effort": self.effort,
            "messages": self.messages,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "tool_errors_in_row": self.tool_errors_in_row,
            "invalid_calls": self.invalid_calls,
            "changes": self.changes,
            "todo": self.todo_state,
            "current_task": self.current_task,
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "effective_tool_names": sorted(self.effective_tool_names),
            "effective_policy_roles": self.policy.role_policies,
            "terminal_status": self.terminal_status,
            "terminal_reason": self.terminal_reason,
        }
        state = redact_data(state, self.cfg["logging"]["redact_keys"])
        self.store.save(self.session_id, state)
        if self.terminal_status:
            self._report()

    @classmethod
    def resume(cls, cfg, llm, tools, ui, sid):
        root = cfg["permissions"]["workspace_root"]
        st = SessionStore(root).load(sid)
        stored_roles = st.get("effective_policy_roles")
        if not isinstance(stored_roles, list):
            raise ValueError("session is missing persisted security policy")
        saved_tools = st.get("effective_tool_names")
        if not isinstance(saved_tools, list):
            raise ValueError("session is missing persisted tool ACL")
        resume_policy = Policy(cfg, role_policies=stored_roles)
        role_object = st.get("role_object") or load_role(root, st.get("role", "coder"), resume_policy)
        a = cls(
            cfg, llm, tools, ui, role_object, sid, model=st.get("model"),
            effort=st.get("effort"), agent_id=st.get("agent_id"),
            parent_id=st.get("parent_id"), effective_policy=resume_policy,
            allowed_tool_names=saved_tools,
        )
        a.messages = st["messages"]
        a.steps = st.get("steps", 0)
        a.tool_calls = st.get("tool_calls", 0)
        a.tool_errors_in_row = st.get("tool_errors_in_row", 0)
        a.invalid_calls = st.get("invalid_calls", 0)
        a.changes = st.get("changes", 0)
        a.todo_state[:] = st.get("todo", [])
        a.current_task = st.get("current_task", "")
        a.terminal_status = st.get("terminal_status")
        a.terminal_reason = st.get("terminal_reason")
        return a

    def _subagent_config(self):
        return self.cfg.get("subagents", self.cfg["agent"])

    def subagent(self, role, task):
        limits = self._subagent_config()
        max_depth = int(limits["max_depth"])
        max_children = int(limits["max_subagents"])
        if self.depth + 1 > max_depth:
            self.log.emit("limit_reached", reason="subagent_depth", depth=self.depth + 1)
            raise RuntimeError("subagent depth limit reached")
        if self.subagent_count[0] >= max_children:
            self.log.emit("limit_reached", reason="max_subagents", count=self.subagent_count[0])
            raise RuntimeError("subagent limit reached")
        self.subagent_count[0] += 1

        role_object = load_role(self.cfg["permissions"]["workspace_root"], role, self.policy)
        role_policy = role_object.get("permissions") or {}
        child_policy = self.policy.derive_child(role_policy)
        child_ref = {}
        def child_spawn(child_role, child_task):
            return child_ref["agent"].subagent(child_role, child_task)

        child_tools = build_tools(
            self.cfg,
            subagent_runner=child_spawn if "spawn_agent" in self.effective_tool_names else None,
            policy=child_policy,
            allowed_tool_names=self.effective_tool_names,
        )
        child = Agent(
            self.cfg, self.llm, child_tools, self.ui, role_object,
            depth=self.depth + 1, subagent_count=self.subagent_count,
            model=None, effort=None, role_object=role_object,
            parent_id=self.agent_id,
            effective_policy=child_policy,
            allowed_tool_names=self.effective_tool_names,
        )
        child_ref["agent"] = child
        child.step_budget = min(child.step_budget, int(self.cfg["agent"].get("subagent_budget", child.step_budget)))
        result = child.run(task)
        if isinstance(result, dict):
            return {
                "status": result.get("status", "failed"),
                "summary": result.get("summary", result.get("result", "")),
                "artifacts": result.get("artifacts", []),
                "notes": result.get("notes", []),
                "agent_id": child.agent_id,
            }
        return {"status": getattr(result, "status", "ok"), "summary": str(result), "artifacts": [], "notes": [], "agent_id": child.agent_id}

    def _compact_if_needed(self):
        chars_per_token = self._request_params()["chars_per_token"]
        tokens = self.ctx.estimate_tokens(self.messages, chars_per_token)
        if len(self.messages) > self.cfg["agent"]["history_max_messages"] or tokens > self.ctx.budget_tokens * self.cfg["agent"]["context_compact_ratio"]:
            self.messages = self.ctx.compact(self.messages, self.llm, self.todo_state, self.current_task)
            self.log.emit("compaction", step=self.steps, token_estimate=tokens)

    def _confirmation(self, tool, args):
        capabilities = tool.get_capabilities()
        if INTERACTION_USER in capabilities:
            allowed = self.cfg["agent"].get("mode") != "headless"
            self.log.emit("user_confirm", tool=tool.name, capabilities=sorted(capabilities), allowed=allowed, confirmation="tool_interaction")
            return allowed

        risky = bool(capabilities & {FS_WRITE, FS_DELETE, PROCESS_EXECUTE, KB_WRITE, SUBAGENT_SPAWN})
        if not risky:
            return True
        # Process execution has its own administrative mode. It cannot be
        # silently enabled by a workspace config or by permissions.confirm.
        if PROCESS_EXECUTE in capabilities:
            exec_cfg = self.cfg.get("exec", {})
            exec_mode = exec_cfg.get("mode", "off")
            if exec_mode == "off" and exec_cfg.get("enabled", False):
                exec_mode = "auto"
            if exec_mode == "off":
                allowed = False
            elif exec_mode == "ask":
                if self.cfg["agent"].get("mode") == "headless":
                    allowed = False
                else:
                    confirm_args = dict(args)
                    preview = getattr(tool, "preview", None)
                    if preview is not None:
                        confirm_args["_security"] = preview(tool.name, getattr(tool, "execution_policy").script_argv(args["path"], args.get("args", [])) if tool.name == "run_script" else getattr(tool, "execution_policy").module_argv(args["module"], args.get("args", [])) if tool.name == "run_module" else getattr(tool, "execution_policy").test_argv(args.get("targets", [])))
                    allowed = self.ui.confirm(tool.name, confirm_args)
            else:  # auto
                if self.cfg["agent"].get("mode") != "headless":
                    allowed = True
                elif PROCESS_EXECUTE in capabilities:
                    preview = getattr(tool, "preview", None)
                    if preview is not None:
                        try:
                            op = tool.name
                            ep = tool.execution_policy
                            argv = ep.script_argv(args["path"], args.get("args", [])) if op == "run_script" else ep.module_argv(args["module"], args.get("args", [])) if op == "run_module" else ep.test_argv(args.get("targets", []))
                            ctx = preview(op, argv)
                            allowed = ctx["isolation"] == "app" or bool(ctx["layers"])
                        except Exception:
                            allowed = False
                    else:
                        allowed = False
                else:
                    allowed = True
            self.log.emit("user_confirm", tool=tool.name, capabilities=sorted(capabilities),
                          allowed=allowed, confirmation=f"exec.{exec_mode}")
            return allowed
        mode = self.cfg["permissions"]["confirm"]
        if self.cfg["agent"].get("mode") == "headless":
            allowed = mode == "auto"
        elif mode == "auto":
            allowed = True
        elif mode == "auto_edit" and capabilities <= {FS_WRITE}:
            allowed = True
        else:
            allowed = self.ui.confirm(tool.name, args)
        self.log.emit("user_confirm", tool=tool.name, capabilities=sorted(capabilities), allowed=allowed)
        return allowed

    def _limits(self, deadline):
        if self.stop:
            raise RuntimeError("interrupted")
        if self.steps >= self.step_budget:
            raise RuntimeError("agent step limit reached")
        if _now() >= deadline:
            raise RuntimeError("max_wall_time_s exceeded")
        if self.tool_calls >= int(self.cfg["agent"].get("max_tool_calls", 120)):
            raise RuntimeError("tool-call limit reached")
        if self.tool_errors_in_row >= int(self.cfg["agent"].get("max_tool_errors_in_row", 5)):
            raise RuntimeError("max_tool_errors_in_row exceeded")
        if self.invalid_calls >= int(self.cfg["agent"].get("max_invalid_calls", 5)):
            raise RuntimeError("max_invalid_calls exceeded")
        if self.changes >= int(self.cfg["permissions"].get("max_changes", 200)):
            raise RuntimeError("max_changes exceeded")

    def _set_deadline(self, deadline):
        remaining = max(0.0, deadline - _now())
        setter = getattr(self.llm, "set_deadline", None)
        if callable(setter):
            setter(deadline)
        for tool in self.tools.values():
            setter = getattr(tool, "set_deadline", None)
            if callable(setter):
                setter(deadline)
        return remaining

    def _successful_changes(self, tool, result):
        """Count one successful mutation invocation, including multi-file patches."""
        if not (tool.get_capabilities() & {FS_WRITE, FS_DELETE, KB_WRITE}):
            return 0
        return 0 if isinstance(result, dict) and result.get("is_error") else 1

    def _finalize(self, status, *, reason=None, result=None):
        """Persist state/report and emit exactly one terminal audit event."""
        if self._ended:
            return
        safe_reason, _ = self._dlp_context("terminal.reason", reason or "")
        safe_result, _ = self._dlp_context("terminal.result", result)
        self.terminal_status = self._canonical_status(status)
        self.terminal_reason = safe_reason
        self.terminal_result = safe_result
        cleanup_error = None
        try:
            self.save()
        except Exception as exc:  # cleanup must not mask the primary terminal outcome
            cleanup_error = exc
        try:
            self.log.emit(
                "session_end",
                status=self.terminal_status,
                reason=self.terminal_reason,
                result=self.terminal_result,
                step=self.steps,
            )
        except Exception:  # audit write failure cannot mask the primary terminal outcome
            pass
        self._ended = True
        if cleanup_error is not None:
            # Cleanup failures must never mask the primary run exception. The
            # audit event above remains the durable terminal indication.
            self.terminal_cleanup_error = str(cleanup_error)

    def _answer_pending_tool_calls(self, reason):
        if not self._pending_tool_calls:
            return
        safe_reason, _ = self._dlp_context("tool.skipped.reason", reason)
        for call_id, name in list(self._pending_tool_calls.items()):
            result = {"skipped": True, "is_error": True, "error": safe_reason}
            self.messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "content": json.dumps(result, ensure_ascii=False),
                "is_error": True,
            })
            self.log.emit("tool_result", step=self.steps, name=name, result=result, skipped=True)
        self._pending_tool_calls.clear()

    def _terminate(self, reason, *, event="limit_reached", status=None):
        safe_reason, _ = self._dlp_context("termination.reason", reason)
        self._answer_pending_tool_calls("skipped: " + safe_reason)
        self.log.emit(event, reason=safe_reason, step=self.steps)
        terminal = status or ("stuck" if event == "stuck" else "limit_reached")
        self._finalize(terminal, reason=safe_reason)
        raise RuntimeError(safe_reason)

    @classmethod
    def _dispatch_signal(cls, signum, frame):
        owner = cls._signal_owner
        if owner is not None:
            owner._interrupt(signum, frame)
        elif cls._signal_previous not in (None, cls._dispatch_signal):
            cls._signal_previous(signum, frame)

    def _restore_signal(self):
        if not self._signal_installed:
            return
        try:
            if self in Agent._signal_stack:
                Agent._signal_stack.remove(self)
            if Agent._signal_owner is self:
                Agent._signal_owner = Agent._signal_stack[-1] if Agent._signal_stack else None
            if Agent._signal_owner is None:
                previous = Agent._signal_previous
                Agent._signal_previous = None
                if previous is not None:
                    signal.signal(signal.SIGINT, previous)
        finally:
            self._signal_installed = False

    def _dlp_context(self, operation, value):
        """Return model-safe data; raw blocked content never enters messages/logs."""
        decision = self.dlp.check(operation, value)
        if decision.allowed:
            return value, True
        try:
            self.log.emit("dlp_masked", operation=operation, reason=decision.reason, step=self.steps)
        except Exception:
            pass
        return "content blocked by security policy", False

    def _sanitize_tool_calls_for_context(self, tool_calls):
        safe = []
        blocked = set()
        for tc in tool_calls:
            raw = tc.arguments or "{}"
            _, allowed = self._dlp_context("llm.tool_arguments", raw)
            args = raw if allowed else "{}"
            if not allowed:
                blocked.add(tc.id)
            safe.append({"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": args}})
        return safe, blocked

    def run(self, user):
        self._ended = False
        self.terminal_status = None
        self.terminal_reason = None
        self.terminal_result = None
        safe_user, user_allowed = self._dlp_context("llm.user", user)
        if not user_allowed:
            self.current_task = "content blocked by security policy"
            self._finalize("failed", reason="user input blocked by security policy")
            return AgentResult(status="failed", summary="content blocked by security policy")
        self.current_task = safe_user
        self.messages.append({"role": "user", "content": safe_user})
        self.log.emit("user", content=safe_user)
        deadline = _now() + float(self.cfg["agent"].get("max_wall_time_s", 900))
        seen = {}
        try:
            while True:
                try:
                    self._limits(deadline)
                except RuntimeError as e:
                    self._terminate(str(e), event="limit_reached")
                self.steps += 1
                self._compact_if_needed()
                params = self._request_params()
                self._set_deadline(deadline)
                self.log.emit("llm_request", step=self.steps, model=self.model, effort=self.effort)
                r = self.llm.complete(ChatRequest(
                    list(self.messages),
                    [t.schema() for t in self.tools.values()],
                    model=self.model,
                    max_tokens=params["max_tokens"],
                    temperature=params["temperature"],
                    top_p=params["top_p"],
                    extra_body=params["extra_body"],
                    timeout_s=max(0.001, deadline - _now()),
                ))
                self.log.emit("llm_response", step=self.steps, finish_reason=r.finish_reason, usage=r.usage, reasoning_chars=len(r.reasoning))
                safe_text, _ = self._dlp_context("llm.response", r.text)
                assistant = {"role": "assistant", "content": safe_text}
                blocked_tool_calls = set()
                if r.tool_calls:
                    safe_calls, blocked_tool_calls = self._sanitize_tool_calls_for_context(r.tool_calls)
                    assistant["tool_calls"] = safe_calls
                self.messages.append(assistant)
                if r.finish_reason == "length" and self.cfg["agent"]["continue_on_length"] and not r.tool_calls:
                    self.messages.append({"role": "user", "content": "Continue from exactly where you stopped. Do not repeat completed text."})
                    continue
                if not r.tool_calls:
                    if not getattr(r, "streamed", False):
                        self.ui.print_final(safe_text)
                    else:
                        self.ui.print_final("")
                    self._finalize("ok", result=safe_text)
                    return AgentResult(status="ok", summary=safe_text, result=safe_text)

                self._pending_tool_calls = {tc.id: tc.name for tc in r.tool_calls}
                for tc in r.tool_calls:
                    try:
                        self._limits(deadline)
                    except RuntimeError as e:
                        self._terminate(str(e), event="limit_reached")
                    self._set_deadline(deadline)
                    self.tool_calls += 1
                    tool = self.tools.get(tc.name)
                    args = {}
                    invalid = False
                    result = {}
                    permission_denied = False
                    try:
                        if not tool:
                            invalid = True
                            raise ValueError("unknown tool " + tc.name)
                        if tc.id in blocked_tool_calls:
                            raise PermissionError("content blocked by security policy")
                        try:
                            args = json.loads(tc.arguments or "{}")
                        except json.JSONDecodeError as exc:
                            invalid = True
                            raise ValueError(f"invalid JSON arguments: {exc.msg}") from exc
                        dlp_decision = self.dlp.check("tool.arguments", args)
                        if not dlp_decision.allowed:
                            raise PermissionError("content blocked by security policy")
                        validate_tool_arguments(tc.name, args)
                        key = (tc.name, json.dumps(args, sort_keys=True, ensure_ascii=True))
                        seen[key] = seen.get(key, 0) + 1
                        repeat_limit = int(self.cfg["agent"]["loop_detection"]["repeat"])
                        if seen[key] >= repeat_limit:
                            self.log.emit("stuck", reason="loop", tool=tc.name, count=seen[key], step=self.steps)
                            self._terminate(f"loop detected: {tc.name}", event="stuck", status="stuck")
                        if not self._confirmation(tool, args):
                            result = {"is_error": True, "error": "user denied"}
                        else:
                            self.log.emit("tool_call", step=self.steps, name=tc.name, arguments=args, capabilities=sorted(tool.get_capabilities()))
                            result = tool.run(args)
                            if PROCESS_EXECUTE in tool.get_capabilities() and isinstance(result, dict) and result.get("audit"):
                                audit = dict(result["audit"])
                                audit["return_code"] = result.get("returncode")
                                audit["output_size"] = len(result.get("stdout", "")) + len(result.get("stderr", ""))
                                audit["dlp_blocked"] = bool(result.get("output_blocked"))
                                self.log.emit("exec", step=self.steps, **audit)
                            successful = self._successful_changes(tool, result)
                            if successful:
                                seen.clear()
                                self.changes += successful
                                if self.changes > int(self.cfg["permissions"]["max_changes"]):
                                    self._terminate("max_changes exceeded", event="limit_reached")
                    except PermissionError as exc:
                        permission_denied = True
                        safe_error, allowed = self._dlp_context("permission.error", str(exc))
                        if not allowed:
                            safe_error = "operation denied by security policy"
                        result = {"is_error": True, "error": safe_error}
                        self.log.emit("permission_denied", step=self.steps, tool=tc.name, error=safe_error)
                    except (ToolError, ValueError, OSError, TimeoutError, KeyError, TypeError) as exc:
                        safe_error, allowed = self._dlp_context("tool.error", str(exc))
                        result = {"is_error": True, "error": safe_error if allowed else "operation failed: content blocked by security policy"}
                    if invalid:
                        self.invalid_calls += 1
                    if isinstance(result, dict) and result.get("is_error"):
                        self.tool_errors_in_row += 1
                    else:
                        self.tool_errors_in_row = 0
                    if self.invalid_calls >= int(self.cfg["agent"].get("max_invalid_calls", 5)):
                        self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, ensure_ascii=False), "is_error": True})
                        self._terminate("max_invalid_calls exceeded", event="limit_reached")
                    if self.tool_errors_in_row >= int(self.cfg["agent"].get("max_tool_errors_in_row", 5)):
                        self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, ensure_ascii=False), "is_error": True})
                        self._terminate("max_tool_errors_in_row exceeded", event="limit_reached")
                    safe_result, result_allowed = self._dlp_context("tool.result", result)
                    if not result_allowed:
                        result = {"is_error": True, "error": "content blocked by security policy"}
                        self.tool_errors_in_row += 1
                    else:
                        result = safe_result
                    content = json.dumps(result, ensure_ascii=False) if not isinstance(result, str) else result
                    tool_message = {"role": "tool", "tool_call_id": tc.id, "content": content}
                    if isinstance(result, dict) and result.get("is_error"):
                        tool_message["is_error"] = True
                    self.messages.append(tool_message)
                    self._pending_tool_calls.pop(tc.id, None)
                    self.log.emit("tool_result", step=self.steps, name=tc.name, result=result, permission_denied=permission_denied)
                    if not isinstance(result, dict) or not result.get("is_error"):
                        if tool.get_capabilities() & {FS_WRITE, FS_DELETE, KB_WRITE}:
                            self.log.emit("file_change", step=self.steps, tool=tc.name, changes=self._successful_changes(tool, result))
                    if tc.name == "view_image" and isinstance(result, dict) and result.get("data_url"):
                        self.messages.append({"role": "user", "content": [
                            {"type": "text", "text": "Image data returned by view_image. Inspect it for the current task."},
                            {"type": "image_url", "image_url": {"url": result["data_url"]}},
                        ]})
                    if tc.name == "finish" and isinstance(result, dict) and result.get("finished"):
                        canonical = self._canonical_status(result.get("status", "ok"))
                        final_result = dict(result)
                        final_result["status"] = canonical
                        self.ui.print_final(final_result)
                        self._finalize(canonical, result=final_result)
                        return AgentResult(
                            status=canonical,
                            summary=final_result.get("summary", final_result.get("result", "")),
                            result=final_result.get("result", final_result.get("summary", "")),
                            artifacts=final_result.get("artifacts", []),
                            notes=final_result.get("notes", []),
                        )
                self.save()
        except KeyboardInterrupt:
            self.stop = True
            self._answer_pending_tool_calls("skipped: interrupted")
            self._finalize("interrupted", reason="signal")
            raise
        except Exception as exc:  # outer lifecycle boundary preserves unexpected failures
            safe_error, allowed = self._dlp_context("agent.exception", str(exc))
            self._answer_pending_tool_calls("skipped: " + (safe_error if allowed else "operation failed"))
            if not self._ended:
                self._finalize("failed", reason=safe_error if allowed else "operation failed: content blocked by security policy")
            if allowed:
                raise
            raise RuntimeError("operation failed: content blocked by security policy") from None
        finally:
            self._restore_signal()
