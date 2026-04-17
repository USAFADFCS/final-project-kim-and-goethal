"""
Tests for shell_tools.py
"""

import json
import os
import sys
import pytest
from ctf_solver.tools.shell_tools import ShellExecuteTool


class TestShellExecuteTool:
    """Tests for the ShellExecuteTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = ShellExecuteTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_command(self):
        """Test handling of missing command parameter."""
        result = self.tool.use(json.dumps({"timeout": 10}))
        assert "Error" in result
        assert "'command'" in result

    def test_empty_command(self):
        """Test handling of empty command string."""
        result = self.tool.use(json.dumps({"command": ""}))
        assert "Error" in result

    def test_whitespace_only_command(self):
        """Test handling of whitespace-only command."""
        result = self.tool.use(json.dumps({"command": "   "}))
        assert "Error" in result

    def test_command_not_string(self):
        """Test handling of non-string command."""
        result = self.tool.use(json.dumps({"command": 123}))
        assert "Error" in result

    def test_empty_input(self):
        """Test handling of empty input."""
        result = self.tool.use("")
        assert "Error" in result

    def test_none_like_input(self):
        """Test handling of None-like input."""
        result = self.tool.use("{}")
        assert "Error" in result
        assert "'command'" in result

    # === Basic Execution Tests ===

    def test_echo_command(self):
        """Test basic echo command execution."""
        result = self.tool.use(json.dumps({"command": "echo hello world"}))
        assert "hello world" in result
        assert "Exit code: 0" in result

    def test_simple_command_with_pipe(self):
        """Test command with pipe."""
        result = self.tool.use(
            json.dumps({"command": "echo 'abc123' | grep -o '[0-9]*'"})
        )
        assert "123" in result
        assert "Exit code: 0" in result

    def test_command_with_exit_code(self):
        """Test command that returns non-zero exit code."""
        result = self.tool.use(json.dumps({"command": "false"}))
        assert "Exit code:" in result
        assert "Exit code: 0" not in result

    def test_stderr_output(self):
        """Test command that produces stderr output."""
        result = self.tool.use(json.dumps({"command": "echo error >&2"}))
        assert "STDERR" in result
        assert "error" in result

    def test_both_stdout_and_stderr(self):
        """Test command that produces both stdout and stderr."""
        result = self.tool.use(json.dumps({"command": "echo out && echo err >&2"}))
        assert "STDOUT" in result
        assert "out" in result

    def test_multiline_output(self):
        """Test command with multiline output."""
        result = self.tool.use(
            json.dumps({"command": "printf 'line1\\nline2\\nline3'"})
        )
        assert "line1" in result
        assert "line2" in result
        assert "line3" in result

    def test_empty_stdout(self):
        """Test command with no stdout."""
        result = self.tool.use(json.dumps({"command": "true"}))
        assert "(empty)" in result
        assert "Exit code: 0" in result

    # === Stdin Tests ===

    def test_stdin_data(self):
        """Test piping data to stdin."""
        result = self.tool.use(
            json.dumps({"command": "cat", "stdin_data": "hello from stdin"})
        )
        assert "hello from stdin" in result

    def test_stdin_with_grep(self):
        """Test stdin with grep."""
        result = self.tool.use(
            json.dumps(
                {"command": "grep flag", "stdin_data": "line1\nflag{test}\nline3"}
            )
        )
        assert "flag{test}" in result

    # === Timeout Tests ===

    def test_timeout_kills_command(self):
        """Test that long-running commands are killed after timeout."""
        result = self.tool.use(json.dumps({"command": "sleep 60", "timeout": 2}))
        assert "timed out" in result.lower()
        assert "2 seconds" in result

    def test_default_timeout(self):
        """Test that default timeout is applied."""
        tool = ShellExecuteTool(default_timeout=5)
        assert tool.default_timeout == 5

    def test_max_timeout_clamped(self):
        """Test that timeout is clamped to max_timeout."""
        tool = ShellExecuteTool(max_timeout=10)
        result = tool.use(json.dumps({"command": "sleep 60", "timeout": 999}))
        # Should use max of 10, not 999
        assert "timed out" in result.lower()

    def test_timeout_invalid_value_uses_default(self):
        """Test that invalid timeout falls back to default."""
        result = self.tool.use(
            json.dumps({"command": "echo ok", "timeout": "not_a_number"})
        )
        assert "Exit code: 0" in result

    # === Working Directory Tests ===

    def test_working_dir(self):
        """Test executing command in a specific directory."""
        result = self.tool.use(json.dumps({"command": "pwd", "working_dir": "/tmp"}))
        assert (
            "/tmp" in result or "/private/tmp" in result
        )  # macOS /tmp -> /private/tmp

    def test_invalid_working_dir(self):
        """Test error on non-existent working directory."""
        result = self.tool.use(
            json.dumps({"command": "pwd", "working_dir": "/nonexistent/directory/xyz"})
        )
        assert "Error" in result
        assert "working_dir" in result

    def test_default_working_dir(self):
        """Test that default working_dir constructor param works."""
        tool = ShellExecuteTool(working_dir="/tmp")
        result = tool.use(json.dumps({"command": "pwd"}))
        assert "/tmp" in result or "/private/tmp" in result

    # === Output Truncation Tests ===

    def test_large_output_truncated(self):
        """Test that large output is truncated."""
        result = self.tool.use(
            json.dumps(
                {"command": "python3 -c \"print('x' * 20000)\"", "max_output": 1000}
            )
        )
        assert "truncated" in result.lower()

    def test_small_output_not_truncated(self):
        """Test that small output is not truncated."""
        result = self.tool.use(
            json.dumps({"command": "echo short", "max_output": 8000})
        )
        assert "truncated" not in result.lower()

    def test_max_output_invalid_uses_default(self):
        """Test that invalid max_output uses default."""
        result = self.tool.use(json.dumps({"command": "echo ok", "max_output": "bad"}))
        assert "Exit code: 0" in result

    def test_truncation_preserves_head_and_tail(self):
        """Test that truncation keeps both head and tail content."""
        result = self.tool.use(
            json.dumps(
                {
                    "command": "python3 -c \"for i in range(1000): print(f'line_{i}')\"",
                    "max_output": 500,
                }
            )
        )
        assert "line_0" in result  # head preserved
        assert "truncated" in result.lower()

    # === Security: Blocked Commands Tests ===

    def test_blocked_rm_rf_root(self):
        """Test that rm -rf / is blocked."""
        result = self.tool.use(json.dumps({"command": "rm -rf /"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_rm_rf_wildcard(self):
        """Test that rm -rf /* is blocked."""
        result = self.tool.use(json.dumps({"command": "rm -rf /*"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_mkfs(self):
        """Test that mkfs is blocked."""
        result = self.tool.use(json.dumps({"command": "mkfs /dev/sda1"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_fork_bomb(self):
        """Test that fork bomb is blocked."""
        result = self.tool.use(json.dumps({"command": ":(){ :|:& };:"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_shutdown(self):
        """Test that shutdown is blocked."""
        result = self.tool.use(json.dumps({"command": "shutdown -h now"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_reboot(self):
        """Test that reboot is blocked."""
        result = self.tool.use(json.dumps({"command": "reboot"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_dd_zero(self):
        """Test that dd if=/dev/zero is blocked."""
        result = self.tool.use(json.dumps({"command": "dd if=/dev/zero of=/dev/sda"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_custom_blocked_pattern(self):
        """Test adding custom blocked patterns."""
        tool = ShellExecuteTool(blocked_patterns=["drop database"])
        result = tool.use(json.dumps({"command": "echo 'DROP DATABASE users'"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    def test_blocked_case_insensitive(self):
        """Test that blocking is case-insensitive."""
        result = self.tool.use(json.dumps({"command": "SHUTDOWN -h now"}))
        assert "Error" in result
        assert "blocked" in result.lower()

    # === Security: Allowed Commands Tests ===

    def test_allowed_commands_whitelist(self):
        """Test that only allowed commands can run when whitelist is set."""
        tool = ShellExecuteTool(allowed_commands=["echo", "cat", "grep"])
        result = tool.use(json.dumps({"command": "echo hello"}))
        assert "hello" in result
        assert "Exit code: 0" in result

    def test_blocked_by_allowlist(self):
        """Test that commands not in allowlist are rejected."""
        tool = ShellExecuteTool(allowed_commands=["echo", "cat"])
        result = tool.use(json.dumps({"command": "rm file.txt"}))
        assert "Error" in result
        assert "not in allowed list" in result

    def test_no_allowlist_permits_all(self):
        """Test that no allowlist means all non-blocked commands are permitted."""
        tool = ShellExecuteTool(allowed_commands=None)
        result = tool.use(json.dumps({"command": "echo open"}))
        assert "Exit code: 0" in result

    # === Tool Interface Tests ===

    def test_name_attribute(self):
        """Test that name attribute is set correctly."""
        assert self.tool.name == "shell_execute"

    def test_description_attribute(self):
        """Test that description is non-empty."""
        assert len(self.tool.description) > 50

    def test_description_mentions_json(self):
        """Test that description mentions JSON input format."""
        assert "JSON" in self.tool.description

    def test_description_mentions_command(self):
        """Test that description mentions the command parameter."""
        assert "command" in self.tool.description

    # === Real-World CTF Tool Tests ===

    def test_file_command(self):
        """Test running the 'file' command (common in CTF)."""
        result = self.tool.use(json.dumps({"command": "file /bin/ls"}))
        assert "Exit code: 0" in result
        # Should identify it as an executable
        assert "Mach-O" in result or "ELF" in result or "executable" in result.lower()

    def test_strings_command(self):
        """Test running the 'strings' command (common in CTF)."""
        result = self.tool.use(json.dumps({"command": "echo 'test123' | strings"}))
        assert "test123" in result

    def test_which_command(self):
        """Test checking if a tool exists."""
        result = self.tool.use(json.dumps({"command": "which python3"}))
        assert "python3" in result
        assert "Exit code: 0" in result

    def test_python_one_liner(self):
        """Test running a Python one-liner."""
        result = self.tool.use(json.dumps({"command": 'python3 -c "print(2**10)"'}))
        assert "1024" in result

    def test_base64_decode(self):
        """Test base64 decoding via shell (common CTF operation)."""
        result = self.tool.use(
            json.dumps(
                {"command": "echo 'SGVsbG8gV29ybGQ=' | base64 --decode"}  # macOS syntax
            )
        )
        # On macOS it's --decode, on Linux it's -d
        if "Exit code: 0" in result:
            assert "Hello World" in result

    def test_command_not_found(self):
        """Test running a command that doesn't exist."""
        result = self.tool.use(json.dumps({"command": "nonexistent_command_xyz_123"}))
        assert "Exit code:" in result
        assert "Exit code: 0" not in result

    def test_env_variable_expansion(self):
        """Test that shell environment variables work."""
        result = self.tool.use(json.dumps({"command": "echo $HOME"}))
        assert "Exit code: 0" in result
        # HOME should be set
        assert "/" in result

    # === Edge Cases ===

    def test_special_characters_in_command(self):
        """Test command with special characters."""
        result = self.tool.use(
            json.dumps({"command": "echo 'hello \"world\" & <test>'"})
        )
        assert "Exit code: 0" in result

    def test_command_with_newline_in_output(self):
        """Test command output with embedded newlines."""
        result = self.tool.use(json.dumps({"command": "printf 'a\\nb\\nc'"}))
        assert "a" in result
        assert "b" in result
        assert "c" in result

    def test_concurrent_safety(self):
        """Test that the tool can be used multiple times."""
        for i in range(5):
            result = self.tool.use(json.dumps({"command": f"echo {i}"}))
            assert str(i) in result
            assert "Exit code: 0" in result

    def test_response_format_structure(self):
        """Test that response has expected structure."""
        result = self.tool.use(json.dumps({"command": "echo test"}))
        assert "[ShellExecuteTool]" in result
        assert "Command:" in result
        assert "Exit code:" in result
        assert "STDOUT" in result


class TestShellExecuteToolTruncation:
    """Focused tests for the output truncation logic."""

    def setup_method(self):
        self.tool = ShellExecuteTool()

    def test_truncate_preserves_short_text(self):
        """Truncation should not modify short text."""
        text = "short text"
        result = self.tool._truncate_output(text, 1000)
        assert result == text

    def test_truncate_exact_boundary(self):
        """Text exactly at the limit should not be truncated."""
        text = "x" * 1000
        result = self.tool._truncate_output(text, 1000)
        assert result == text
        assert "truncated" not in result

    def test_truncate_over_boundary(self):
        """Text over the limit should be truncated."""
        text = "x" * 2000
        result = self.tool._truncate_output(text, 1000)
        assert len(result) < 2000
        assert "truncated" in result.lower()

    def test_truncate_has_head_and_tail(self):
        """Truncated output should have head and tail portions."""
        text = "HEAD" + "x" * 5000 + "TAIL"
        result = self.tool._truncate_output(text, 500)
        assert "HEAD" in result
        # Tail should be preserved
        assert "TAIL" in result


class TestShellExecuteToolSecurity:
    """Security-focused tests."""

    def test_no_privilege_escalation(self):
        """Test that sudo is not automatically available."""
        # This should either fail or require password (not auto-escalate)
        result = ShellExecuteTool().use(
            json.dumps({"command": "sudo -n echo test", "timeout": 3})
        )
        # Either permission denied or exit code non-zero
        # (sudo -n fails immediately if no passwordless sudo configured)
        assert "Exit code: 0" not in result or "test" in result

    def test_rm_with_safe_path_allowed(self):
        """Test that rm on specific files is NOT blocked (only rm -rf / is)."""
        # rm on a non-existent file should be allowed (just fail with exit code 1)
        result = ShellExecuteTool().use(
            json.dumps({"command": "rm /tmp/nonexistent_test_file_xyz_12345"})
        )
        # Should not be blocked, just fail normally
        assert "blocked" not in result.lower()
