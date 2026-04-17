"""
Tests for diff_tools.py
"""

import json
import pytest
from unittest.mock import Mock, patch
from ctf_solver.tools.diff_tools import (
    ResponseDiffTool,
    TimingCompareTool,
    ResponseFingerprinter,
)


class TestResponseDiffTool:
    """Tests for the ResponseDiffTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = ResponseDiffTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_responses(self):
        """Test handling when responses are not strings."""
        result = self.tool.use(json.dumps({"response1": 123, "response2": "test"}))
        assert "Error" in result

    # === Basic Comparison Tests ===

    def test_identical_responses(self):
        """Test comparing identical responses."""
        response = "<html><body>Hello World</body></html>"
        result = self.tool.use(
            json.dumps({"response1": response, "response2": response})
        )
        assert "Difference: 0 bytes" in result

    def test_different_lengths(self):
        """Test comparing responses with different lengths."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Short response",
                    "response2": "This is a much longer response with more content",
                }
            )
        )
        assert "LENGTH ANALYSIS" in result
        assert "bytes" in result

    def test_length_only_mode(self):
        """Test length_only mode."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Response 1",
                    "response2": "Response 2 with more",
                    "mode": "length_only",
                }
            )
        )
        assert "LENGTH ANALYSIS" in result
        assert "KEYWORD ANALYSIS" not in result

    def test_detailed_mode(self):
        """Test detailed mode shows content differences."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Line 1\nLine 2\nLine 3",
                    "response2": "Line 1\nDifferent Line\nLine 3",
                    "mode": "detailed",
                }
            )
        )
        assert "CONTENT DIFFERENCES" in result

    # === Error Detection Tests ===

    def test_detects_error_keywords(self):
        """Test detection of error keywords in responses."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Normal page content",
                    "response2": "SQL syntax error near 'test'",
                }
            )
        )
        assert "error" in result.lower()
        assert "KEYWORD ANALYSIS" in result

    def test_error_based_heuristic(self):
        """Test error-based detection heuristic."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Welcome to the site",
                    "response2": "Error: Invalid SQL syntax",
                }
            )
        )
        assert "ERROR-BASED" in result or "error" in result.lower()

    # === Success Detection Tests ===

    def test_detects_success_keywords(self):
        """Test detection of success keywords."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Login failed",
                    "response2": "Welcome admin! Dashboard loaded.",
                }
            )
        )
        assert "welcome" in result.lower() or "success" in result.lower()

    def test_auth_difference_heuristic(self):
        """Test auth difference detection."""
        result = self.tool.use(
            json.dumps(
                {
                    "response1": "Access denied",
                    "response2": "Welcome to admin dashboard. Here is the flag: FLAG{test}",
                }
            )
        )
        assert "AUTH" in result or "success" in result.lower()

    # === Boolean SQLi Detection Tests ===

    def test_boolean_sqli_heuristic(self):
        """Test boolean-based SQLi detection heuristic."""
        # Create responses that differ slightly in content but similar structure
        response1 = "<html>" + "x" * 500 + "<p>No results found</p></html>"
        response2 = (
            "<html>"
            + "x" * 500
            + "<p>User: admin</p><p>Email: admin@test.com</p></html>"
        )

        result = self.tool.use(
            json.dumps({"response1": response1, "response2": response2})
        )
        # Should have analysis section
        assert "VULNERABILITY HEURISTICS" in result


class TestTimingCompareTool:
    """Tests for the TimingCompareTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = TimingCompareTool()

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(json.dumps({"params1": {}, "params2": {}}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps({"url": "http://example.com", "method": "INVALID"})
        )
        assert "Error" in result
        assert "method" in result.lower()

    @patch("ctf_solver.tools.diff_tools.TimingCompareTool._timed_request")
    def test_timing_comparison_no_difference(self, mock_request):
        """Test timing comparison with similar times."""
        mock_request.side_effect = [
            (0.5, 200, None),  # First request
            (0.6, 200, None),  # Second request
        ]

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://example.com/test",
                    "method": "GET",
                    "params1": {"id": "1"},
                    "params2": {"id": "2"},
                    "threshold": 3.0,
                }
            )
        )

        assert "No significant timing difference" in result

    @patch("ctf_solver.tools.diff_tools.TimingCompareTool._timed_request")
    def test_timing_comparison_with_difference(self, mock_request):
        """Test timing comparison detecting significant time difference."""
        mock_request.side_effect = [
            (0.5, 200, None),  # First request - fast
            (5.5, 200, None),  # Second request - slow (simulated SLEEP)
        ]

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://example.com/test",
                    "method": "GET",
                    "params1": {"id": "1"},
                    "params2": {"id": "1' AND SLEEP(5)--"},
                    "threshold": 3.0,
                }
            )
        )

        assert "SIGNIFICANT TIME DIFFERENCE" in result
        assert "TIME-BASED BLIND SQL INJECTION" in result

    @patch("ctf_solver.tools.diff_tools.TimingCompareTool._timed_request")
    def test_timing_comparison_with_error(self, mock_request):
        """Test timing comparison when one request fails."""
        mock_request.side_effect = [
            (0.5, 200, None),
            (0.0, None, "Connection refused"),
        ]

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://example.com/test",
                    "method": "GET",
                    "params1": {},
                    "params2": {},
                }
            )
        )

        assert "cannot compare timing" in result.lower() or "failed" in result.lower()


class TestResponseFingerprinter:
    """Tests for the ResponseFingerprinter class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = ResponseFingerprinter()

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result

    def test_fingerprint_html(self):
        """Test fingerprinting HTML content."""
        result = self.tool.use(
            json.dumps({"response": "<!DOCTYPE html><html><body>Test</body></html>"})
        )
        assert "Length:" in result
        assert "Lines:" in result
        assert "Hash" in result
        assert "HTML" in result

    def test_fingerprint_json(self):
        """Test fingerprinting JSON content."""
        result = self.tool.use(json.dumps({"response": '{"status": "ok", "data": []}'}))
        assert "JSON" in result

    def test_fingerprint_xml(self):
        """Test fingerprinting XML content."""
        result = self.tool.use(
            json.dumps(
                {"response": '<?xml version="1.0"?><root><item>test</item></root>'}
            )
        )
        assert "XML" in result

    def test_error_keyword_detection(self):
        """Test error keyword detection in fingerprint."""
        result = self.tool.use(
            json.dumps({"response": "Error: SQL syntax error in query"})
        )
        assert "contains error keywords: true" in result.lower()

    def test_success_keyword_detection(self):
        """Test success keyword detection in fingerprint."""
        result = self.tool.use(
            json.dumps({"response": "Welcome to the admin dashboard"})
        )
        assert "contains success keywords: true" in result.lower()

    def test_fingerprint_consistency(self):
        """Test that same response produces same fingerprint hash."""
        response = "Test content for hashing"

        result1 = self.tool.use(json.dumps({"response": response}))
        result2 = self.tool.use(json.dumps({"response": response}))

        # Extract hash from results
        hash1 = [line for line in result1.split("\n") if "Hash" in line][0]
        hash2 = [line for line in result2.split("\n") if "Hash" in line][0]

        assert hash1 == hash2


class TestDiffToolsCTFScenarios:
    """Test CTF-specific scenarios with diff tools."""

    def setup_method(self):
        """Set up test fixtures."""
        self.diff_tool = ResponseDiffTool()
        self.fingerprint_tool = ResponseFingerprinter()

    def test_sqli_boolean_detection_scenario(self):
        """Test detecting boolean SQLi through response differences."""
        # Simulate true condition response (data returned)
        true_response = """
        <html>
        <body>
            <h1>Search Results</h1>
            <div class="result">
                <p>Username: admin</p>
                <p>Email: admin@example.com</p>
            </div>
        </body>
        </html>
        """

        # Simulate false condition response (no data)
        false_response = """
        <html>
        <body>
            <h1>Search Results</h1>
            <p>No results found.</p>
        </body>
        </html>
        """

        result = self.diff_tool.use(
            json.dumps(
                {
                    "response1": false_response,
                    "response2": true_response,
                    "mode": "detailed",
                }
            )
        )

        # Should detect length difference and possibly flag as interesting
        assert "LENGTH ANALYSIS" in result
        assert int(result.split("Difference:")[1].split("bytes")[0].strip()) > 0

    def test_error_based_sqli_detection(self):
        """Test detecting error-based SQLi through error messages."""
        normal_response = "<html><body>Invalid username or password</body></html>"
        error_response = """
        <html><body>
        SQL Error: You have an error in your SQL syntax near ''' at line 1
        Query: SELECT * FROM users WHERE username=''' AND password='test'
        </body></html>
        """

        result = self.diff_tool.use(
            json.dumps({"response1": normal_response, "response2": error_response})
        )

        assert "error" in result.lower()
        assert "sql" in result.lower()

    def test_auth_bypass_detection(self):
        """Test detecting successful auth bypass through response differences."""
        failed_login = (
            "<html><body><p>Login failed. Please try again.</p></body></html>"
        )
        successful_login = """
        <html><body>
        <h1>Welcome admin!</h1>
        <p>Your dashboard contains the flag: picoCTF{sql_1nj3ct10n_w0rks}</p>
        </body></html>
        """

        result = self.diff_tool.use(
            json.dumps({"response1": failed_login, "response2": successful_login})
        )

        assert "welcome" in result.lower() or "success" in result.lower()
        assert "flag" in result.lower()

    def test_fingerprint_for_response_categorization(self):
        """Test using fingerprints to categorize responses."""
        # Different response types
        responses = [
            '{"error": "Invalid input"}',
            '{"status": "success", "data": {"user": "admin"}}',
            "<html><body>Error 500</body></html>",
            "<html><body>Welcome!</body></html>",
        ]

        fingerprints = []
        for resp in responses:
            result = self.fingerprint_tool.use(json.dumps({"response": resp}))
            fingerprints.append(result)

        # First response should be JSON with errors
        assert "JSON" in fingerprints[0]
        assert "contains error keywords: true" in fingerprints[0].lower()

        # Second should be JSON with success
        assert "JSON" in fingerprints[1]
        assert "contains success keywords: true" in fingerprints[1].lower()

        # Third should be HTML with errors
        assert "HTML" in fingerprints[2]
        assert "contains error keywords: true" in fingerprints[2].lower()

        # Fourth should be HTML with success
        assert "HTML" in fingerprints[3]
        assert "contains success keywords: true" in fingerprints[3].lower()
