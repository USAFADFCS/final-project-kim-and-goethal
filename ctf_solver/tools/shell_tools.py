"""
Shell execution tool for CTF solving.

Provides sandboxed command execution so the agent can run arbitrary CLI tools
(nmap, sqlmap, binwalk, strings, file, etc.) when built-in tools are insufficient.

Works on macOS and Linux (any POSIX system).
"""

import json
import os
import subprocess
from typing import Optional


class ShellExecuteTool:
    """
    ShellExecuteTool: execute shell commands in a sandboxed subprocess.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "command": "nmap -sC -sV target.com",
          "timeout": 30,                        # optional, default 30s
          "working_dir": "/tmp",                # optional, default cwd
          "max_output": 8000,                   # optional, max chars returned
          "stdin_data": "input text"             # optional, data to pipe to stdin
        }

    Security boundaries:
      - Commands run with the current user's privileges (no elevation).
      - Configurable timeout prevents runaway processes (default 30s, max 120s).
      - Output is truncated to prevent context window flooding.
      - Blocked commands list prevents accidental self-destruction.
      - Working directory is validated before use.
    """

    name: str = "shell_execute"
    description: str = (
        "Execute a shell command and return its output. Use this tool when no "
        "specialized tool exists for the task. Input must be JSON with keys: "
        "'command' (required string), 'timeout' (optional int, default 30, max 120 seconds), "
        "'working_dir' (optional string), 'max_output' (optional int, default 8000 chars), "
        "'stdin_data' (optional string to pipe to stdin). "
        "Examples: run 'nmap -sC target', 'sqlmap -u URL --batch', 'strings binary', "
        "'file unknown.bin', 'binwalk -e firmware.bin', 'python3 script.py', "
        "'curl -s URL', 'base64 -d file.txt'. "
        "Returns stdout, stderr, and the exit code. "
        "Commands are killed after the timeout. Do NOT use for long-running "
        "interactive commands."
    )

    # Commands that could damage the host system
    BLOCKED_PATTERNS = [
        "rm -rf /",
        "rm -rf /*",
        "mkfs",
        "dd if=/dev/zero",
        ":(){ :|:& };:",  # fork bomb
        "> /dev/sda",
        "chmod -R 777 /",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "init 0",
        "init 6",
    ]

    DEFAULT_TIMEOUT = 30
    MAX_TIMEOUT = 120
    DEFAULT_MAX_OUTPUT = 8000

    def __init__(
        self,
        default_timeout: int = DEFAULT_TIMEOUT,
        max_timeout: int = MAX_TIMEOUT,
        default_max_output: int = DEFAULT_MAX_OUTPUT,
        allowed_commands: Optional[list] = None,
        blocked_patterns: Optional[list] = None,
        working_dir: Optional[str] = None,
    ) -> None:
        """
        Initialize the shell execution tool.

        Args:
            default_timeout: Default command timeout in seconds.
            max_timeout: Maximum allowed timeout in seconds.
            default_max_output: Default max output characters.
            allowed_commands: If set, only these command prefixes are allowed.
            blocked_patterns: Additional blocked command patterns.
            working_dir: Default working directory for commands.
        """
        self.default_timeout = min(default_timeout, max_timeout)
        self.max_timeout = max_timeout
        self.default_max_output = default_max_output
        self.allowed_commands = allowed_commands
        self.blocked_patterns = list(self.BLOCKED_PATTERNS)
        if blocked_patterns:
            self.blocked_patterns.extend(blocked_patterns)
        self.working_dir = working_dir

    def _is_blocked(self, command: str) -> Optional[str]:
        """Check if a command matches any blocked pattern."""
        cmd_lower = command.lower().strip()
        for pattern in self.blocked_patterns:
            if pattern.lower() in cmd_lower:
                return pattern
        return None

    def _is_allowed(self, command: str) -> bool:
        """Check if command is in the allowed list (if allowlist is active)."""
        if self.allowed_commands is None:
            return True
        cmd_first = command.strip().split()[0] if command.strip() else ""
        return any(
            cmd_first == allowed or command.strip().startswith(allowed)
            for allowed in self.allowed_commands
        )

    def _truncate_output(self, text: str, max_chars: int) -> str:
        """Truncate output to max_chars, preserving head and tail."""
        if len(text) <= max_chars:
            return text
        # Keep first 60% and last 30%, with truncation notice in between
        head_size = int(max_chars * 0.6)
        tail_size = int(max_chars * 0.3)
        omitted = len(text) - head_size - tail_size
        return (
            text[:head_size]
            + f"\n\n... [{omitted} characters truncated] ...\n\n"
            + text[-tail_size:]
        )

    @staticmethod
    def _fix_json_escapes(raw: str) -> str:
        """
        Fix common invalid JSON escape sequences generated by LLMs when embedding
        Python regex patterns in JSON strings.

        Python regex patterns often contain \\{, \\}, \\[, \\], \\d, \\w, \\s, etc.
        These are valid Python regex escapes but NOT valid JSON string escapes.
        JSON only allows: \\\" \\\\ \\/ \\b \\f \\n \\r \\t \\uXXXX.

        This method replaces single backslashes before non-JSON-escape characters
        with double backslashes, making the string valid JSON.

        Only called when json.loads() fails with an escape-related error.
        """
        import re as _re

        # Replace \X (where X is not a valid JSON escape char) with \\X
        # Valid after backslash in JSON: " \\ / b f n r t u
        # Use a negative lookbehind so already-doubled \\\\ is not modified
        fixed = _re.sub(r'(?<!\\)\\([^"\\/bfnrtu\n\r\t ])', r"\\\\\1", raw)
        return fixed

    def use(self, tool_input: str) -> str:
        """Execute a shell command and return the result."""
        # Parse JSON input — with escape preprocessing fallback for Python regex patterns
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            # LLMs often embed Python regex patterns (\\{, \\[, \\d) in JSON strings.
            # These are invalid JSON escapes, causing parse failures. Try to fix them.
            exc_str = str(exc).lower()
            if "escape" in exc_str or "invalid" in exc_str:
                try:
                    fixed = self._fix_json_escapes(tool_input)
                    data = json.loads(fixed)
                except (json.JSONDecodeError, Exception):
                    return (
                        f"[ShellExecuteTool] Error: tool_input must be JSON. "
                        f"Decoding failed with: {exc}\n"
                        "Tip: JSON strings cannot contain raw backslash-brace (\\{) or "
                        "backslash-bracket (\\[) sequences. Use \\\\{ and \\\\[ instead, "
                        "or write the Python script to a file via a simpler command."
                    )
            else:
                return (
                    f"[ShellExecuteTool] Error: tool_input must be JSON. "
                    f"Decoding failed with: {exc}"
                )

        command = data.get("command")
        if not command or not isinstance(command, str):
            return (
                "[ShellExecuteTool] Error: 'command' (string) is required. "
                'Example: {"command": "nmap -sC target.com"}'
            )

        command = command.strip()
        if not command:
            return "[ShellExecuteTool] Error: 'command' cannot be empty."

        # Security: check blocked patterns
        blocked = self._is_blocked(command)
        if blocked:
            return (
                f"[ShellExecuteTool] Error: command blocked for safety. "
                f"Matched blocked pattern: '{blocked}'"
            )

        # Security: check allowed list
        if not self._is_allowed(command):
            return (
                f"[ShellExecuteTool] Error: command not in allowed list. "
                f"Allowed prefixes: {self.allowed_commands}"
            )

        # Parse optional parameters
        timeout = data.get("timeout", self.default_timeout)
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = self.default_timeout
        timeout = max(1, min(timeout, self.max_timeout))

        max_output = data.get("max_output", self.default_max_output)
        try:
            max_output = int(max_output)
        except (TypeError, ValueError):
            max_output = self.default_max_output
        max_output = max(100, min(max_output, 50000))

        working_dir = data.get("working_dir", self.working_dir)
        if working_dir and not os.path.isdir(working_dir):
            return (
                f"[ShellExecuteTool] Error: working_dir '{working_dir}' "
                f"does not exist or is not a directory."
            )

        stdin_data = data.get("stdin_data")

        # Execute the command
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                input=stdin_data,
                env={**os.environ, "TERM": "dumb"},
                # Start new process group so we can kill the whole tree
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            exit_code = result.returncode

        except subprocess.TimeoutExpired:
            return (
                f"[ShellExecuteTool] Command timed out after {timeout} seconds.\n"
                f"Command: {command}\n"
                f"Consider increasing timeout (max {self.max_timeout}s) or "
                f"breaking the command into smaller operations."
            )
        except OSError as exc:
            return (
                f"[ShellExecuteTool] OS error executing command: {exc}\n"
                f"Command: {command}"
            )
        except Exception as exc:
            return (
                f"[ShellExecuteTool] Unexpected error: {type(exc).__name__}: {exc}\n"
                f"Command: {command}"
            )

        # Build response
        parts = [f"[ShellExecuteTool] Command: {command}"]
        parts.append(f"Exit code: {exit_code}")

        if stdout.strip():
            truncated_stdout = self._truncate_output(stdout.strip(), max_output)
            parts.append(f"\n--- STDOUT ---\n{truncated_stdout}")
        else:
            parts.append("\n--- STDOUT ---\n(empty)")

        if stderr.strip():
            # Limit stderr to 20% of max_output
            stderr_limit = max(500, max_output // 5)
            truncated_stderr = self._truncate_output(stderr.strip(), stderr_limit)
            parts.append(f"\n--- STDERR ---\n{truncated_stderr}")

        return "\n".join(parts)
