"""
Tests for cmdi_tools.py — Command Injection detection and payload generation tools.
"""

import json
import time
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.cmdi_tools import (
    CommandInjectionProbeTool,
    CommandInjectionPayloadGenerator,
)


# ============================================================
# CommandInjectionProbeTool Tests
# ============================================================


class TestCommandInjectionProbeTool:
    """Tests for CommandInjectionProbeTool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = CommandInjectionProbeTool(session=self.mock_session)

    # --- Input validation ---

    def test_missing_url(self):
        """Test that 'url' is required."""
        result = self.tool.use(json.dumps({"param": "ip"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that 'param' is required."""
        result = self.tool.use(json.dumps({"url": "http://test.com/ping"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "method": "DELETE",
        }))
        assert "Error" in result
        assert "GET" in result or "POST" in result

    # --- Baseline failure ---

    def test_baseline_failure(self):
        """Test that a baseline request failure is reported."""
        self.mock_session.get.side_effect = Exception("Connection refused")
        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
        }))
        assert "Error" in result
        assert "baseline" in result.lower() or "Connection refused" in result

    # --- Output-based injection detection ---

    def test_injection_detected_output_based(self):
        """Test detection of command injection via uid= pattern in response."""
        baseline_resp = MagicMock()
        baseline_resp.text = "PING 127.0.0.1: 56 data bytes"
        baseline_resp.status_code = 200

        injected_resp = MagicMock()
        injected_resp.text = "PING 127.0.0.1: 56 data bytes\nuid=1000(user) gid=1000(user)"
        injected_resp.status_code = 200

        self.mock_session.get.return_value = injected_resp
        # First call is baseline, rest are probes
        self.mock_session.get.side_effect = [baseline_resp] + [injected_resp] * 200

        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "os_target": "linux",
        }))

        assert "INJECTION CONFIRMED" in result or "COMMAND INJECTION DETECTED" in result

    def test_injection_detected_time_based(self):
        """Test detection of command injection via time-based delay."""
        baseline_resp = MagicMock()
        baseline_resp.text = "PING result"
        baseline_resp.status_code = 200

        normal_resp = MagicMock()
        normal_resp.text = "PING result"
        normal_resp.status_code = 200

        call_count = {"n": 0}
        original_get = self.mock_session.get

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            # Return baseline for first call, normal for output probes,
            # but we'll mock time.time instead for time-based detection
            return normal_resp

        self.mock_session.get.side_effect = side_effect

        # Patch time.time to simulate delay for time-based payloads
        import ctf_solver.tools.cmdi_tools as cmdi_module
        original_time = time.time

        time_call_count = {"n": 0}

        def mock_time():
            time_call_count["n"] += 1
            # For the baseline timing pair (call 1 = before, call 2 = after)
            # we want ~0.1s. For time-based probe pairs, simulate 6s delay.
            # time.time() is called in pairs: before request, after request.
            t = time_call_count["n"]
            if t <= 2:
                # Baseline timing: 0.0, 0.1
                return 1000.0 + (t - 1) * 0.1
            else:
                # Group into pairs for each time-based probe
                pair_index = (t - 3) // 2  # which probe pair
                is_start = (t - 3) % 2 == 0
                if is_start:
                    return 2000.0 + pair_index * 10
                else:
                    # Return 6 seconds later to trigger the >4s threshold
                    return 2006.0 + pair_index * 10

        cmdi_module.time.time = mock_time
        try:
            result = self.tool.use(json.dumps({
                "url": "http://test.com/ping",
                "param": "ip",
                "os_target": "linux",
            }))
        finally:
            cmdi_module.time.time = original_time

        assert "TIME-BASED INJECTION" in result or "COMMAND INJECTION DETECTED" in result

    def test_no_injection_all_same(self):
        """Test no injection detected when all responses are the same as baseline."""
        baseline_resp = MagicMock()
        baseline_resp.text = "PING 127.0.0.1"
        baseline_resp.status_code = 200

        self.mock_session.get.return_value = baseline_resp

        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "os_target": "linux",
        }))

        assert "No command injection detected" in result

    def test_windows_payloads_when_os_windows(self):
        """Test that windows-specific payloads are used when os_target=windows."""
        baseline_resp = MagicMock()
        baseline_resp.text = "Reply from 127.0.0.1"
        baseline_resp.status_code = 200

        injected_resp = MagicMock()
        injected_resp.text = "Reply\n Volume Serial Number is ABC-123\n <DIR> somedir"
        injected_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [injected_resp] * 100

        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "os_target": "windows",
        }))

        # Should contain Windows-specific detection
        assert "Windows" in result

    def test_flag_detection(self):
        """Test that CTF flags are extracted from injection responses."""
        baseline_resp = MagicMock()
        baseline_resp.text = "PING result"
        baseline_resp.status_code = 200

        flag_resp = MagicMock()
        flag_resp.text = "uid=1000\npicoCTF{cmd_inj3cti0n_ftw}"
        flag_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [flag_resp] * 200

        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
        }))

        assert "FLAG" in result
        assert "picoCTF{cmd_inj3cti0n_ftw}" in result

    def test_passwd_content_detected(self):
        """Test that /etc/passwd content is detected as injection."""
        baseline_resp = MagicMock()
        baseline_resp.text = "PING result"
        baseline_resp.status_code = 200

        passwd_resp = MagicMock()
        passwd_resp.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
        passwd_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [passwd_resp] * 200

        result = self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
        }))

        assert "INJECTION CONFIRMED" in result or "COMMAND INJECTION DETECTED" in result

    def test_get_method(self):
        """Test that GET method uses session.get."""
        baseline_resp = MagicMock()
        baseline_resp.text = "OK"
        baseline_resp.status_code = 200
        self.mock_session.get.return_value = baseline_resp

        self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "method": "GET",
        }))

        assert self.mock_session.get.called
        assert not self.mock_session.post.called

    def test_post_method(self):
        """Test that POST method uses session.post."""
        baseline_resp = MagicMock()
        baseline_resp.text = "OK"
        baseline_resp.status_code = 200
        self.mock_session.post.return_value = baseline_resp

        self.tool.use(json.dumps({
            "url": "http://test.com/ping",
            "param": "ip",
            "method": "POST",
        }))

        assert self.mock_session.post.called
        assert not self.mock_session.get.called


# ============================================================
# CommandInjectionPayloadGenerator Tests
# ============================================================


class TestCommandInjectionPayloadGenerator:
    """Tests for CommandInjectionPayloadGenerator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = CommandInjectionPayloadGenerator()

    # --- Input validation ---

    def test_missing_operation(self):
        """Test that 'operation' is required."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of invalid operation."""
        result = self.tool.use(json.dumps({"operation": "exploit_all"}))
        assert "Error" in result
        assert "Invalid operation" in result or "operation" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not json")
        assert "Error" in result
        assert "JSON" in result

    # --- Inline payloads ---

    def test_inline_linux_payloads(self):
        """Test inline operation generates Linux payloads."""
        result = self.tool.use(json.dumps({
            "operation": "inline",
            "os_target": "linux",
        }))

        assert "Inline Payloads" in result
        assert "Linux" in result
        assert "; id" in result
        assert "| id" in result
        assert "|| id" in result
        assert "&& id" in result
        assert "`id`" in result
        assert "$(id)" in result
        assert "Semicolon" in result or "separator" in result.lower()

    def test_inline_windows_payloads(self):
        """Test inline operation generates Windows payloads."""
        result = self.tool.use(json.dumps({
            "operation": "inline",
            "os_target": "windows",
        }))

        assert "Windows" in result
        assert "& id" in result or "&id" in result
        assert "| id" in result or "|id" in result
        # Should NOT contain Linux-specific sections when os_target=windows
        assert "Backtick" not in result

    # --- Blind payloads ---

    def test_blind_sleep_payloads(self):
        """Test blind operation generates sleep-based payloads."""
        result = self.tool.use(json.dumps({
            "operation": "blind",
            "os_target": "linux",
        }))

        assert "Blind Payloads" in result
        assert "sleep 5" in result
        assert "$(sleep 5)" in result
        assert "`sleep 5`" in result

    def test_blind_ping_payloads(self):
        """Test blind operation generates ping-based payloads."""
        result = self.tool.use(json.dumps({
            "operation": "blind",
            "os_target": "linux",
        }))

        assert "ping -c 5 127.0.0.1" in result

    def test_blind_dns_exfiltration(self):
        """Test blind operation generates DNS exfiltration payloads."""
        result = self.tool.use(json.dumps({
            "operation": "blind",
            "os_target": "linux",
        }))

        assert "nslookup" in result
        assert "attacker.com" in result

    # --- Filter bypass payloads ---

    def test_filter_bypass_space(self):
        """Test filter_bypass generates space bypass techniques."""
        result = self.tool.use(json.dumps({
            "operation": "filter_bypass",
        }))

        assert "Space Bypass" in result
        assert "${IFS}" in result
        assert "$IFS$9" in result
        assert "{cat,/etc/passwd}" in result
        assert "cat</etc/passwd" in result

    def test_filter_bypass_keyword(self):
        """Test filter_bypass generates keyword bypass techniques."""
        result = self.tool.use(json.dumps({
            "operation": "filter_bypass",
        }))

        assert "Keyword Bypass" in result
        assert "/bin/c?t" in result
        assert "${not_exist}" in result

    def test_filter_bypass_encoding(self):
        """Test filter_bypass generates encoding bypass techniques."""
        result = self.tool.use(json.dumps({
            "operation": "filter_bypass",
        }))

        assert "Encoding Bypass" in result
        assert "printf" in result
        assert "base64" in result
        assert "Y2F0IC9ldGMvcGFzc3dk" in result

    # --- Custom command ---

    def test_custom_command(self):
        """Test that custom command is reflected in payloads."""
        result = self.tool.use(json.dumps({
            "operation": "inline",
            "command": "cat /etc/shadow",
            "os_target": "linux",
        }))

        assert "cat /etc/shadow" in result
        assert "; cat /etc/shadow" in result

    # --- All operations return content ---

    def test_all_operations_return_content(self):
        """Test that all valid operations return non-empty meaningful output."""
        for operation in ("inline", "blind", "filter_bypass"):
            result = self.tool.use(json.dumps({
                "operation": operation,
                "command": "whoami",
            }))
            assert "CommandInjectionPayloadGenerator" in result
            assert "Error" not in result
            assert len(result) > 100, f"Operation '{operation}' returned too little content"
