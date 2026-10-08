"""Minimal terminal UI for streamed output, confirmations, and user questions."""


class UI:
    """Render agent output to stdout and prompt through the terminal."""

    def __init__(self):
        """Initialize output state used to separate streamed and final text."""
        self.streamed = False

    def stream_text(self, s):
        """Write one streamed text fragment without a newline."""
        self.streamed = True
        print(s, end="", flush=True)

    def stream_reasoning(self, s):
        """Render reasoning separately from user-visible answer text."""
        import sys
        if s:
            print(s, end="", flush=True, file=sys.stderr)

    def print_final(self, s):
        """Print a final response, adding a newline after streamed output."""
        if self.streamed:
            print()
        else:
            print(s)
        self.streamed = False

    def confirm(self, tool, args):
        """Prompt for confirmation of a risky tool call and accept only ``y``/``yes``."""
        return input(f"Allow {tool} {args}? [y/N] ").strip().lower() in {"y", "yes"}

    def ask(self, q):
        """Prompt the user for free-form input and return the entered string."""
        return input(q + " ")
