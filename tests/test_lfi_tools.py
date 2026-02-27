"""
Tests for lfi_tools.py — LfiProbeTool and LfiPayloadGenerator.
"""

import json
import pytest
from unittest.mock import MagicMock

import requests

from ctf_solver.tools.lfi_tools import LfiProbeTool, LfiPayloadGenerator


# ===========================================================================
# Tests for LfiProbeTool
# ===========================================================================


class TestLfiProbeToolValidation:
    """Input-validation tests for LfiProbeTool."""

    def setup_method(self):
        self.session = MagicMock(spec=requests.Session)
        self.tool = LfiProbeTool(session=self.session)

    def test_missing_url(self):
        """Error when 'url' is not provided."""
        result = self.tool.use(json.dumps({"param": "file"}))
        assert "[LfiProbeTool] Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Error when 'param' is not provided."""
        result = self.tool.use(json.dumps({"url": "http://target.com/page"}))
        assert "[LfiProbeTool] Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Error on malformed JSON."""
        result = self.tool.use("NOT-VALID-JSON{{{")
        assert "[LfiProbeTool] Error" in result
        assert "JSON" in result

    def test_invalid_method(self):
        """Error when method is not GET or POST."""
        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
            "method": "PATCH",
        }))
        assert "[LfiProbeTool] Error" in result
        assert "method" in result.lower()


class TestLfiProbeToolHTTP:
    """HTTP-level behaviour tests for LfiProbeTool."""

    def setup_method(self):
        self.session = MagicMock(spec=requests.Session)
        self.tool = LfiProbeTool(session=self.session)

    # -- helpers --

    def _make_response(self, text: str, status: int = 200) -> MagicMock:
        resp = MagicMock(spec=requests.Response)
        resp.text = text
        resp.status_code = status
        return resp

    # -- tests --

    def test_baseline_failure(self):
        """Graceful error when the baseline request fails."""
        self.session.get.side_effect = Exception("Connection refused")

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "[LfiProbeTool] Error" in result
        assert "baseline" in result.lower() or "Connection refused" in result

    def test_lfi_detected_linux(self):
        """Detect LFI when response contains Linux /etc/passwd content."""
        baseline = self._make_response("Normal page content")
        lfi_resp = self._make_response(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        )
        # baseline first, then every payload gets the lfi response
        self.session.get.side_effect = [baseline] + [lfi_resp] * 300

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
            "os_target": "linux",
        }))
        assert "VULNERABLE PAYLOADS" in result
        assert "passwd" in result.lower() or "/bin/bash" in result

    def test_lfi_detected_windows(self):
        """Detect LFI when response contains Windows win.ini content."""
        baseline = self._make_response("Normal page content")
        win_resp = self._make_response(
            "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]"
        )
        self.session.get.side_effect = [baseline] + [win_resp] * 300

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
            "os_target": "windows",
        }))
        assert "VULNERABLE PAYLOADS" in result
        assert "[fonts]" in result or "win.ini" in result

    def test_no_lfi_all_same_response(self):
        """No LFI detected when every response matches the baseline."""
        same = self._make_response("Same boring page")
        self.session.get.return_value = same

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "No LFI vulnerabilities detected" in result

    def test_flag_detection(self):
        """Detect CTF flag embedded in a response."""
        baseline = self._make_response("Normal")
        flag_resp = self._make_response(
            "Congratulations! picoCTF{lfi_m4st3r_2026} is your flag."
        )
        self.session.get.side_effect = [baseline] + [flag_resp] * 300

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "FLAGS FOUND" in result
        assert "picoCTF{lfi_m4st3r_2026}" in result

    def test_encoding_bypass_payloads_tested(self):
        """Payloads include encoding-bypass category."""
        baseline = self._make_response("OK")
        self.session.get.return_value = baseline

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "encoding_bypass" in result

    def test_get_method(self):
        """GET method uses session.get."""
        baseline = self._make_response("OK")
        self.session.get.return_value = baseline

        self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
            "method": "GET",
        }))
        self.session.get.assert_called()

    def test_post_method(self):
        """POST method uses session.post."""
        baseline = self._make_response("OK")
        self.session.post.return_value = baseline

        self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
            "method": "POST",
        }))
        self.session.post.assert_called()

    def test_null_byte_payloads_included(self):
        """Payloads include null-byte category."""
        baseline = self._make_response("OK")
        self.session.get.return_value = baseline

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "null_byte" in result

    def test_absolute_path_payloads_included(self):
        """Payloads include absolute_path category."""
        baseline = self._make_response("OK")
        self.session.get.return_value = baseline

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "absolute_path" in result

    def test_env_detection(self):
        """Detect environment variables in response via /proc/self/environ."""
        baseline = self._make_response("Normal page")
        env_resp = self._make_response(
            "DOCUMENT_ROOT=/var/www/html\nHTTP_HOST=target.com\nPATH=/usr/bin"
        )
        self.session.get.side_effect = [baseline] + [env_resp] * 300

        result = self.tool.use(json.dumps({
            "url": "http://target.com/page",
            "param": "file",
        }))
        assert "VULNERABLE PAYLOADS" in result


# ===========================================================================
# Tests for LfiPayloadGenerator
# ===========================================================================


class TestLfiPayloadGeneratorValidation:
    """Input-validation tests for LfiPayloadGenerator."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_missing_operation(self):
        """Error when 'operation' is not provided."""
        result = self.tool.use(json.dumps({}))
        assert "[LfiPayloadGenerator] Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Error on unknown operation name."""
        result = self.tool.use(json.dumps({"operation": "hackit"}))
        assert "[LfiPayloadGenerator] Error" in result
        assert "hackit" in result

    def test_invalid_json(self):
        """Error on malformed JSON."""
        result = self.tool.use("{{bad json!!")
        assert "[LfiPayloadGenerator] Error" in result
        assert "JSON" in result


class TestLfiPayloadGeneratorTraversal:
    """Tests for the 'traversal' operation."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_traversal_generates_payloads(self):
        """Traversal operation returns a non-empty payload list."""
        result = self.tool.use(json.dumps({"operation": "traversal"}))
        assert "TRAVERSAL" in result
        assert "../" in result
        assert "etc/passwd" in result

    def test_traversal_with_custom_depth(self):
        """Custom depth controls how many depth levels are generated."""
        result_d2 = self.tool.use(json.dumps({"operation": "traversal", "depth": 2}))
        result_d8 = self.tool.use(json.dumps({"operation": "traversal", "depth": 8}))

        # More depth means more payloads
        count_d2 = result_d2.count("../")
        count_d8 = result_d8.count("../")
        assert count_d8 > count_d2

    def test_traversal_with_target_file(self):
        """Custom target_file appears in generated payloads."""
        result = self.tool.use(json.dumps({
            "operation": "traversal",
            "target_file": "flag.txt",
        }))
        assert "flag.txt" in result


class TestLfiPayloadGeneratorPhpWrappers:
    """Tests for the 'php_wrappers' operation."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_php_wrappers_contain_filter(self):
        """php_wrappers includes php://filter base64 payload."""
        result = self.tool.use(json.dumps({"operation": "php_wrappers"}))
        assert "php://filter/convert.base64-encode" in result

    def test_php_wrappers_contain_input(self):
        """php_wrappers includes php://input payload."""
        result = self.tool.use(json.dumps({"operation": "php_wrappers"}))
        assert "php://input" in result

    def test_php_wrappers_contain_data(self):
        """php_wrappers includes data:// payload."""
        result = self.tool.use(json.dumps({"operation": "php_wrappers"}))
        assert "data://" in result

    def test_php_wrappers_contain_expect(self):
        """php_wrappers includes expect:// payload."""
        result = self.tool.use(json.dumps({"operation": "php_wrappers"}))
        assert "expect://" in result


class TestLfiPayloadGeneratorLogPoisoning:
    """Tests for the 'log_poisoning' operation."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_log_poisoning_paths(self):
        """log_poisoning returns common Apache/Nginx log paths and /proc paths."""
        result = self.tool.use(json.dumps({"operation": "log_poisoning"}))
        assert "/var/log/apache2/access.log" in result
        assert "/var/log/nginx/access.log" in result
        assert "/proc/self/environ" in result
        assert "/proc/self/fd/0" in result


class TestLfiPayloadGeneratorWindowsPaths:
    """Tests for the 'windows_paths' operation."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_windows_paths_contain_win_ini(self):
        """windows_paths includes C:\\Windows\\win.ini."""
        result = self.tool.use(json.dumps({"operation": "windows_paths"}))
        assert "win.ini" in result

    def test_windows_paths_contain_hosts(self):
        """windows_paths includes the Windows hosts file."""
        result = self.tool.use(json.dumps({"operation": "windows_paths"}))
        assert "drivers\\etc\\hosts" in result


class TestLfiPayloadGeneratorAllOperations:
    """Cross-operation test."""

    def setup_method(self):
        self.tool = LfiPayloadGenerator()

    def test_all_operations_return_content(self):
        """Every valid operation returns a non-empty, non-error result."""
        for op in LfiPayloadGenerator.VALID_OPERATIONS:
            result = self.tool.use(json.dumps({"operation": op}))
            assert "[LfiPayloadGenerator] Error" not in result, f"operation={op} returned error"
            assert len(result) > 50, f"operation={op} returned suspiciously short output"
