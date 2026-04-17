"""
Tests for Insecure Deserialization detection and payload generation tools.
"""

import json
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.deserialization_tools import (
    DeserializationProbeTool,
    DeserializationPayloadGenerator,
)


class TestDeserializationProbeTool:
    """Tests for DeserializationProbeTool."""

    def setup_method(self):
        self.mock_session = MagicMock()
        self.tool = DeserializationProbeTool(session=self.mock_session)

    # --- Validation tests ---

    def test_missing_url(self):
        """Test that 'url' is required."""
        result = self.tool.use(json.dumps({"param": "data"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that 'param' is required."""
        result = self.tool.use(json.dumps({"url": "http://test.com"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps({"url": "http://test.com", "param": "data", "method": "PATCH"})
        )
        assert "Error" in result
        assert "GET" in result or "POST" in result

    # --- Baseline failure ---

    def test_baseline_failure(self):
        """Test handling when baseline request fails."""
        self.mock_session.get.side_effect = Exception("Connection refused")
        result = self.tool.use(json.dumps({"url": "http://test.com", "param": "data"}))
        assert "Error" in result
        assert "baseline" in result.lower() or "Connection" in result

    # --- Indicator detection tests ---

    def test_php_indicators_detected(self):
        """Test detection of PHP deserialization indicators in response."""
        mock_resp = MagicMock()
        mock_resp.text = "Fatal error: unserialize() failed in /var/www/html/index.php"
        mock_resp.status_code = 500
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "php"}
            )
        )

        assert "PHP" in result
        assert "unserialize()" in result

    def test_python_indicators_detected(self):
        """Test detection of Python deserialization indicators in response."""
        mock_resp = MagicMock()
        mock_resp.text = "Error: pickle.UnpicklingError: could not find MARK"
        mock_resp.status_code = 500
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "python"}
            )
        )

        assert "PYTHON" in result
        assert "pickle" in result

    def test_java_indicators_detected(self):
        """Test detection of Java deserialization indicators in response."""
        mock_resp = MagicMock()
        mock_resp.text = (
            "java.io.ObjectInputStream: ClassNotFoundException for class Exploit"
        )
        mock_resp.status_code = 500
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "java"}
            )
        )

        assert "JAVA" in result
        assert "ObjectInputStream" in result

    def test_dotnet_indicators_detected(self):
        """Test detection of .NET deserialization indicators in response body."""
        mock_resp = MagicMock()
        mock_resp.text = (
            '<input type="hidden" name="__VIEWSTATE" value="AAEAAAD/////..." />'
        )
        mock_resp.status_code = 200
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "dotnet"}
            )
        )

        assert "DOTNET" in result or ".NET" in result
        assert "__VIEWSTATE" in result

    def test_no_deserialization_detected(self):
        """Test output when no deserialization indicators are found."""
        mock_resp = MagicMock()
        mock_resp.text = "Welcome to our website! Nothing suspicious here."
        mock_resp.status_code = 200
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps({"url": "http://test.com/safe", "param": "data"})
        )

        assert (
            "No deserialization vulnerabilities detected" in result
            or "No deserialization indicators" in result
        )

    def test_auto_format_detection(self):
        """Test that 'auto' format scans all formats."""
        mock_resp = MagicMock()
        mock_resp.text = "Error: unserialize() and ObjectInputStream both failed"
        mock_resp.status_code = 500
        mock_resp.cookies.items.return_value = []
        mock_resp.headers.items.return_value = []
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "auto"}
            )
        )

        # Auto mode should detect indicators from multiple formats
        assert "PHP" in result
        assert "JAVA" in result

    def test_flag_detection(self):
        """Test that CTF flags are detected in responses."""
        mock_baseline = MagicMock()
        mock_baseline.text = "Normal response"
        mock_baseline.status_code = 200
        mock_baseline.cookies.items.return_value = []
        mock_baseline.headers.items.return_value = []

        mock_flag_resp = MagicMock()
        mock_flag_resp.text = "Congratulations! flag{deserialize_me_123}"
        mock_flag_resp.status_code = 200
        mock_flag_resp.cookies.items.return_value = []
        mock_flag_resp.headers.items.return_value = []

        self.mock_session.get.side_effect = [mock_baseline] + [mock_flag_resp] * 30

        result = self.tool.use(
            json.dumps({"url": "http://test.com/vuln", "param": "data"})
        )

        assert "FLAG" in result
        assert "flag{deserialize_me_123}" in result

    def test_error_differential_detected(self):
        """Test detection of error differentials between baseline and malformed payloads."""
        mock_baseline = MagicMock()
        mock_baseline.text = "OK"
        mock_baseline.status_code = 200
        mock_baseline.cookies.items.return_value = []
        mock_baseline.headers.items.return_value = []

        mock_error_resp = MagicMock()
        mock_error_resp.text = "Internal Server Error: unserialize() failed"
        mock_error_resp.status_code = 500
        mock_error_resp.cookies.items.return_value = []
        mock_error_resp.headers.items.return_value = []

        # First call is baseline, rest are malformed payload tests
        self.mock_session.get.side_effect = [mock_baseline] + [mock_error_resp] * 30

        result = self.tool.use(
            json.dumps(
                {"url": "http://test.com/vuln", "param": "data", "format": "php"}
            )
        )

        assert "differential" in result.lower() or "status" in result.lower()
        assert (
            "POTENTIAL DESERIALIZATION VULNERABILITY" in result or "200->500" in result
        )


class TestDeserializationPayloadGenerator:
    """Tests for DeserializationPayloadGenerator."""

    def setup_method(self):
        self.tool = DeserializationPayloadGenerator()

    # --- Validation tests ---

    def test_missing_operation(self):
        """Test that 'operation' is required."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of invalid operation."""
        result = self.tool.use(json.dumps({"operation": "invalid_op"}))
        assert "Error" in result
        assert "Unknown" in result or "invalid_op" in result

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not json at all!!!!")
        assert "Error" in result
        assert "JSON" in result

    # --- PHP payloads ---

    def test_php_payloads_contain_magic_methods(self):
        """Test that PHP payloads include __wakeup, __destruct, __toString."""
        result = self.tool.use(json.dumps({"operation": "php_payloads"}))
        assert "__wakeup" in result
        assert "__destruct" in result
        assert "__toString" in result

    def test_php_payloads_contain_object_notation(self):
        """Test that PHP payloads include serialized object notation."""
        result = self.tool.use(json.dumps({"operation": "php_payloads"}))
        assert "O:" in result
        assert "s:" in result

    # --- Python payloads ---

    def test_python_payloads_contain_reduce(self):
        """Test that Python payloads include __reduce__ method."""
        result = self.tool.use(json.dumps({"operation": "python_payloads"}))
        assert "__reduce__" in result

    def test_python_payloads_contain_pickle(self):
        """Test that Python payloads include pickle references."""
        result = self.tool.use(json.dumps({"operation": "python_payloads"}))
        assert "pickle" in result.lower()
        assert "base64" in result.lower() or "Base64" in result

    def test_python_payloads_with_custom_command(self):
        """Test that Python payloads use the custom command."""
        result = self.tool.use(
            json.dumps({"operation": "python_payloads", "command": "cat /flag.txt"})
        )
        assert "cat /flag.txt" in result

    # --- Java references ---

    def test_java_references_contain_ysoserial(self):
        """Test that Java references include ysoserial usage."""
        result = self.tool.use(json.dumps({"operation": "java_references"}))
        assert "ysoserial" in result.lower()
        assert "java -jar ysoserial.jar" in result

    def test_java_references_contain_commons(self):
        """Test that Java references include CommonsCollections chains."""
        result = self.tool.use(json.dumps({"operation": "java_references"}))
        assert "CommonsCollections1" in result
        assert "CommonsCollections7" in result
        assert "Spring1" in result
        assert "Hibernate1" in result
        assert "JRMPClient" in result

    # --- Detection tips ---

    def test_detection_tips_content(self):
        """Test that detection tips include comprehensive guidance."""
        result = self.tool.use(json.dumps({"operation": "detection_tips"}))
        # Should cover magic bytes
        assert "rO0AB" in result
        assert "O:N:" in result or "O:4:" in result
        # Should cover common locations
        assert "cookie" in result.lower()
        assert "hidden" in result.lower()
        # Should cover indicators
        assert (
            "Content-Type" in result or "application/x-java-serialized-object" in result
        )

    # --- All operations return content ---

    def test_all_operations_return_content(self):
        """Test that all valid operations return non-empty content."""
        for operation in DeserializationPayloadGenerator.VALID_OPERATIONS:
            result = self.tool.use(json.dumps({"operation": operation}))
            # The word "Error" may appear in payload descriptions (e.g., "Error messages:")
            # so we check for the error prefix instead
            assert "[DeserializationPayloadGenerator] Error:" not in result
            assert (
                len(result) > 100
            ), f"Operation '{operation}' returned too little content"
