"""Command-line interface for running agents and inspecting local state."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .agent import Agent
from .config import load_config
from .context import Context
from .llm import ChatRequest, OpenAICompatClient
from .policy import Policy, PolicyError
from .runner import build_tools, discover_role_names
from .security import DLPPolicy
from .tools.kb import KBAdd, KBSearch
from .ui import UI


def _expand_at_files(message, workspace):
    """Expand @files only through the central filesystem and DLP policies."""
    cfg = load_config(workspace)
    policy = Policy(cfg)
    dlp = DLPPolicy()
    out = []
    for token in str(message).split():
        if token.startswith("@") and len(token) > 1:
            path = policy.authorize(token[1:], "read")
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                if not dlp.check("@file", text).allowed:
                    raise ValueError("content blocked by security policy")
                out.append(text)
                continue
        out.append(token)
    return " ".join(out)


def _add_run_flags(parser):
    parser.add_argument("--role", default="coder")
    parser.add_argument("--model")
    parser.add_argument("--effort")
    parser.add_argument("--mode", choices=["auto", "interactive", "headless"], default=None)
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--max-time", type=float)


def _add_workspace(parser):
    parser.add_argument("--workspace", default=".")


def _build_parser():
    parser = argparse.ArgumentParser(prog="agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run")
    run.add_argument("prompt")
    _add_run_flags(run)
    _add_workspace(run)

    chat = sub.add_parser("chat")
    chat.add_argument("prompt", nargs="?")
    _add_run_flags(chat)
    _add_workspace(chat)

    resume = sub.add_parser("resume")
    resume.add_argument("session")
    _add_workspace(resume)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--live", action="store_true")
    doctor.add_argument("--exec-backend", action="store_true", help="report kernel execution-sandbox capabilities")
    _add_workspace(doctor)

    config = sub.add_parser("config")
    config.add_argument("action", choices=["show", "check"], nargs="?", default="show")
    config.add_argument("--config")
    _add_workspace(config)

    roles = sub.add_parser("roles")
    roles.add_argument("action", choices=["list"], nargs="?", default="list")
    _add_workspace(roles)

    skills = sub.add_parser("skills")
    skills.add_argument("action", choices=["list"])
    _add_workspace(skills)

    logs = sub.add_parser("logs")
    logs.add_argument("action", choices=["list", "show", "tail", "export", "prune"], default="list", nargs="?")
    logs.add_argument("--session")
    logs.add_argument("--n", type=int, default=50)
    logs.add_argument("--output")
    _add_workspace(logs)

    kb = sub.add_parser("kb")
    kb.add_argument("action", choices=["search", "add"])
    kb.add_argument("value")
    _add_workspace(kb)
    return parser


def _load_cli_config(args):
    if not getattr(args, "config", None):
        return load_config(args.workspace)
    config_path = Path(args.config)
    if not config_path.is_file():
        raise ValueError("config file not found")
    old_cfg = os.environ.get("LOCALAGENT_CONFIG")
    os.environ["LOCALAGENT_CONFIG"] = str(config_path)
    try:
        return load_config(args.workspace)
    finally:
        if old_cfg is None:
            os.environ.pop("LOCALAGENT_CONFIG", None)
        else:
            os.environ["LOCALAGENT_CONFIG"] = old_cfg


def _apply_run_overrides(args, cfg):
    if getattr(args, "mode", None):
        if args.mode == "auto":
            cfg["permissions"]["confirm"] = "auto"
        else:
            cfg["agent"]["mode"] = args.mode
    if getattr(args, "headless", False):
        cfg["agent"]["mode"] = "headless"
    if getattr(args, "max_steps", None) is not None:
        cfg["agent"]["max_steps"] = args.max_steps
    if getattr(args, "max_time", None) is not None:
        cfg["agent"]["max_wall_time_s"] = args.max_time


def _handle_simple_commands(args, cfg):
    if args.cmd == "config":
        import yaml

        print(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
        return 0
    if args.cmd == "roles":
        print("\n".join(discover_role_names(args.workspace, Policy(cfg))))
        return 0
    if args.cmd == "skills":
        print("\n".join(Context(args.workspace, policy=Policy(cfg)).skill_names()))
        return 0
    if args.cmd == "doctor":
        checks = [
            ("config", True),
            ("workspace", Path(args.workspace).is_dir()),
            ("agent_dir", (Path(args.workspace) / "agents").is_dir()),
            ("skills_dir", (Path(args.workspace) / "skills").is_dir()),
        ]
        ok = True
        for name, value in checks:
            print(f'{name}: {"OK" if value else "FAIL"}')
            ok = ok and value
        if args.exec_backend:
            from .tools.sandbox import backend_status
            backend = backend_status()
            for name in ("landlock", "seccomp", "network", "ready"):
                print(f'exec.{name}: {"OK" if backend[name] else "FAIL"}')
            ok = ok and backend["ready"]
        if args.live:
            try:
                client = OpenAICompatClient(cfg)
                try:
                    client.complete(ChatRequest([{"role": "user", "content": "Reply only OK"}], max_tokens=16))
                finally:
                    client.close()
                print("llm: OK")
            except Exception as exc:
                print("llm: FAIL", DLPPolicy().scanner.redact(str(exc)))
                ok = False
        return 0 if ok else 2
    return None


def _handle_logs(args, cfg):
    if args.cmd != "logs":
        return None
    root = Path(args.workspace)
    policy = Policy(cfg)
    log_dir = policy.authorize(root / cfg["logging"]["dir"], "read", actor="runtime")
    paths = []
    if log_dir.exists():
        for candidate in log_dir.glob("*/*.jsonl"):
            try:
                paths.append(policy.authorize(candidate, "read", actor="runtime"))
            except PolicyError:
                continue
    paths.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    if args.action == "list":
        print("\n".join(map(str, paths)))
        return 0
    if args.session:
        paths = [path for path in paths if path.stem == args.session]
    if not paths:
        return 0
    if args.action in {"show", "tail"}:
        text = paths[0].read_text(encoding="utf-8").splitlines()
        print("\n".join(text[-args.n:] if args.action == "tail" else text))
        return 0
    if args.action == "export":
        out = Path(args.output or (root / (".agent/export-" + paths[0].stem + ".jsonl")))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(paths[0].read_text(encoding="utf-8"), encoding="utf-8")
        print(out)
        return 0
    if args.action == "prune":
        for path in paths[args.n:]:
            path.unlink()
            print("deleted", path)
        return 0
    return 0


def _handle_kb(args, cfg):
    if args.cmd != "kb":
        return None
    from .knowledge import KnowledgeBase

    policy = Policy(cfg)
    kb = KnowledgeBase(Path(args.workspace) / cfg["kb"]["path"], cfg["kb"]["chunk_chars"], policy=policy)
    if args.action == "search":
        try:
            result = KBSearch(kb, DLPPolicy()).run({"query": args.value})
        except (PermissionError, ValueError) as exc:
            print(f"kb search rejected: {DLPPolicy().scanner.redact(str(exc))}", file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    try:
        source = Path(args.value)
        if not source.is_absolute():
            source = Path(args.workspace) / source
        KBAdd(kb, policy).run({"path": str(source)})
    except (PolicyError, OSError, ValueError) as exc:
        print(f"kb import rejected: {DLPPolicy().scanner.redact(str(exc))}", file=sys.stderr)
        return 2
    print("indexed")
    return 0


def main(argv=None):
    """Dispatch the ``agent`` command and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = _load_cli_config(args)
    except (OSError, ValueError) as exc:
        print(f"configuration rejected: {DLPPolicy().scanner.redact(str(exc))}", file=sys.stderr)
        return 2

    simple_result = _handle_simple_commands(args, cfg)
    if simple_result is not None:
        return simple_result
    logs_result = _handle_logs(args, cfg)
    if logs_result is not None:
        return logs_result
    kb_result = _handle_kb(args, cfg)
    if kb_result is not None:
        return kb_result

    if args.cmd in {"run", "chat"}:
        _apply_run_overrides(args, cfg)

    ui = UI()
    llm = OpenAICompatClient(cfg, ui)
    if args.cmd == "resume":
        resumed = None

        def spawn(role, task):
            return resumed.subagent(role, task)

        resumed = Agent.resume(cfg, llm, build_tools(cfg, spawn), ui, args.session)
        resumed.run("Continue the previous task.")
        return 0

    agent = None

    def spawn(role, task):
        """Delegate a subagent request to the current parent agent."""
        return agent.subagent(role, task)

    tools = build_tools(cfg, spawn)
    agent = Agent(cfg, llm, tools, ui, args.role, model=args.model, effort=args.effort)
    if args.cmd == "chat" and not args.prompt:
        while True:
            try:
                message = input("> ")
            except (EOFError, KeyboardInterrupt):
                break
            stripped = message.strip()
            if stripped in {"/exit", "/quit"}:
                break
            if stripped == "/save":
                agent.save()
                continue
            message = _expand_at_files(message, args.workspace)
            if message.strip():
                agent.run(message)
    else:
        agent.run(_expand_at_files(args.prompt, args.workspace))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
