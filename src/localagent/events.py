"""Append-only JSONL audit logging with centralized secret redaction."""
from __future__ import annotations

from pathlib import Path
import datetime
import json
import uuid
import hashlib
from typing import Any

from .security import SecretScanner
from .policy import FilesystemPolicy


_REDACTED = SecretScanner.REDACTED


def redact_data(value: Any, keys: list[str] | tuple[str, ...] | None = None) -> Any:
    """Redact sensitive structure through the authoritative scanner."""
    return SecretScanner.redact(value, keys)


def redact_and_bound(value: Any, keys: list[str] | tuple[str, ...] | None = None, max_string: int = 4000) -> Any:
    """Redact before truncating strings so hidden sensitive tails cannot reappear."""
    value = redact_data(value, keys)
    if isinstance(value, dict):
        return {key: redact_and_bound(item, keys, max_string) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_and_bound(item, keys, max_string) for item in value]
    if isinstance(value, str) and len(value) > max_string:
        return value[:max_string] + "…"
    return value


class EventLog:
    """Write per-session audit events and flush each append immediately."""

    def __init__(
        self,
        directory: str | Path,
        session: str | None = None,
        agent_id: str = "a1",
        parent_id: str | None = None,
        redact_keys: list[str] | None = None,
        policy: FilesystemPolicy | None = None,
    ) -> None:
        self.session = session or uuid.uuid4().hex[:12]
        self.agent_id = agent_id
        self.parent_id = parent_id
        self.policy = policy
        self.dir = Path(directory)
        raw_path = self.dir / datetime.date.today().isoformat() / (self.session + ".jsonl")
        self.path = policy.authorize(raw_path, "write", actor="runtime") if policy else raw_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.keys = [str(x).lower() for x in (redact_keys or [])]
        self.seq = 0
        self.step = 0
        self._prev_hash = "0" * 64

    def _redact(self, value: Any) -> Any:
        return redact_and_bound(value, self.keys)

    def emit(self, event: str, **data: Any) -> None:
        """Append one canonical event and flush it to disk."""
        if self.policy:
            self.path = self.policy.authorize(self.path, "write", actor="runtime")
        self.seq += 1
        if event in {"llm_request", "llm_response", "tool_call", "tool_result"}:
            self.step = max(self.step, int(data.pop("step", self.step)))
        elif "step" in data:
            self.step = int(data.pop("step"))
        row = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "session_id": self.session,
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "seq": self.seq,
            "step": self.step,
            "type": event,
            "data": self._redact(data),
            "prev_hash": self._prev_hash,
        }
        canonical = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        row["hash"] = hashlib.sha256((self._prev_hash + canonical).encode("utf-8")).hexdigest()
        self._prev_hash = row["hash"]
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()

    @staticmethod
    def verify(path: str | Path) -> tuple[bool, str]:
        """Verify the per-line hash chain and sequence numbers."""
        previous = "0" * 64
        expected_seq = 1
        try:
            with Path(path).open("r", encoding="utf-8") as handle:
                for lineno, line in enumerate(handle, 1):
                    row = json.loads(line)
                    if row.get("seq") != expected_seq or row.get("prev_hash") != previous:
                        return False, f"chain break at line {lineno}"
                    supplied = row.pop("hash", None)
                    canonical = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    actual = hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest()
                    if supplied != actual:
                        return False, f"hash mismatch at line {lineno}"
                    previous = supplied
                    expected_seq += 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return False, f"invalid journal: {exc}"
        return True, "ok"
