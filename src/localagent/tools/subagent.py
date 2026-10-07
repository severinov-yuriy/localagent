"""Tool wrapper for bounded sequential subagent execution."""

from .base import Tool


class SpawnAgent(Tool):
    """Run a named child role sequentially through the parent agent's runner."""

    name = "spawn_agent"
    description = "Run a named subagent role sequentially with a bounded task."

    def __init__(self, runner):
        """Store the callback used to construct and execute the child agent."""
        self.runner = runner

    def run(self, a):
        """Run the requested child role and return its final result."""
        return self.runner(a["role"], a["task"])
