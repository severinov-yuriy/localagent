"""Meta tools for task completion, durable todos, and user questions."""

from __future__ import annotations
import uuid

from .base import Tool


class Finish(Tool):
    name = "finish"
    description = "Finish the task and provide result."

    def run(self, a):
        return {
            "finished": True,
            "result": a.get("result", a.get("summary", "")),
            "status": a.get("status", "ok"),
            "summary": a.get("summary", a.get("result", "")),
            "artifacts": a.get("artifacts", []),
            "notes": a.get("notes", []),
        }


class Todo(Tool):
    name = "todo"
    description = "Create or update a durable task checklist."

    def __init__(self, state=None):
        self.state = state if state is not None else []

    def bind(self, state):
        self.state = state
        return self

    def run(self, a):
        action = a.get("action", "show")
        if action == "show":
            return {"items": list(self.state)}
        if action == "add":
            raw = a.get("items") or []
            for item in raw:
                if isinstance(item, str):
                    item = {"id": uuid.uuid4().hex[:8], "text": item, "status": "pending"}
                else:
                    item = dict(item)
                    item.setdefault("id", uuid.uuid4().hex[:8])
                    item.setdefault("status", "pending")
                self.state.append(item)
            return {"items": list(self.state)}
        if action == "update":
            item_id = a.get("id")
            update = dict(a.get("item") or {})
            for item in self.state:
                if item.get("id") == item_id:
                    item.update(update)
                    return {"items": list(self.state)}
            raise ValueError("todo item not found")
        if action == "complete":
            item_id = a.get("id")
            for item in self.state:
                if item.get("id") == item_id:
                    item["status"] = "done"
                    return {"items": list(self.state)}
            raise ValueError("todo item not found")
        if action == "remove":
            item_id = a.get("id")
            self.state[:] = [item for item in self.state if item.get("id") != item_id]
            return {"items": list(self.state)}
        raise ValueError(f"unknown todo action: {action}")


class AskUser(Tool):
    name = "ask_user"
    description = "Ask the user a clarification question."

    def run(self, a):
        return input(a.get("question", "") + " ")
