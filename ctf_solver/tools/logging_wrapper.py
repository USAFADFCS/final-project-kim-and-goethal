"""
Logging wrapper for CTF Solver tools.

Wraps any FAIR-compatible tool to provide:
- Logging of tool calls with truncated input
- Scanning for candidate flags in tool output
"""

import json
import re
from typing import Callable, Optional

from ctf_solver.config import DEFAULT_FLAG_REGEX


class LoggingToolWrapper:
    """
    Wrapper for any FAIR tool that:

    - Logs tool calls (tool name + truncated input).
    - Runs the underlying tool.
    - Scans the result for flags matching the configured pattern and logs any matches.
    """

    def __init__(
        self,
        inner,
        flag_regex: str = DEFAULT_FLAG_REGEX,
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize the logging wrapper.

        Args:
            inner: The wrapped tool instance
            flag_regex: Regex pattern for detecting flags in output
            log_callback: Optional callback for log messages (defaults to print)
        """
        self.inner = inner
        self.flag_regex = flag_regex
        self.log_callback = log_callback or print

        # Mirror the wrapped tool's public identity
        self.name = getattr(inner, "name", inner.__class__.__name__)
        self.description = getattr(inner, "description", "")

    def _log(self, message: str) -> None:
        """Log a message using the configured callback."""
        self.log_callback(message)

    def use(self, tool_input: str) -> str:
        """Execute the wrapped tool and log the call and any flag matches."""
        # Normalize: if the framework passed a dict/list instead of a JSON
        # string, convert it so downstream tools always receive a str.
        if isinstance(tool_input, (dict, list)):
            tool_input = json.dumps(tool_input)
        elif tool_input is None:
            tool_input = ""

        preview = tool_input
        if len(preview) > 200:
            preview = preview[:200] + "...[truncated]..."

        self._log(f"[LOG] Tool call -> {self.name}: {preview}")

        result = self.inner.use(tool_input)

        # Log potential flags in tool output
        if isinstance(result, str):
            try:
                matches = re.findall(self.flag_regex, result)
                for m in matches:
                    self._log(f"[LOG] Potential flag seen in {self.name} output: {m}")
            except re.error:
                pass  # Invalid regex, skip flag detection

        return result

    def set_flag_regex(self, pattern: str) -> None:
        """Update the flag detection regex pattern."""
        self.flag_regex = pattern
