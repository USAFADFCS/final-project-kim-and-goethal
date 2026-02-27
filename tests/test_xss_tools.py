"""
Tests for XSS tools (XssProbeTool, XssPayloadGenerator, CspAnalyzerTool).

Covers:
- XssProbeTool: reflected XSS detection, context-specific probing, error handling
- XssPayloadGenerator: filter bypass, DOM XSS, polyglot, encoding bypass, event handlers
- CspAnalyzerTool: CSP parsing, weakness detection, bypass suggestions, risk levels
"""

import json
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.xss_tools import XssProbeTool, XssPayloadGenerator, CspAnalyzerTool


# ==============================================================================
# XssProbeTool Tests
# ==============================================================================


class TestXssProbeTool:
    """Tests for the XssProbeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = XssProbeTool(session=self.mock_session)

    def test_missing_url(self):
        """Test that url is required."""
        result = self.tool.use(json.dumps({"param": "q"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that param is required."""
        result = self.tool.use(json.dumps({"url": "http://target.com/search"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_baseline_failure(self):
        """Test handling of connection error on baseline request."""
        self.mock_session.get.side_effect = ConnectionError("Connection refused")

        result = self.tool.use(json.dumps({
            "url": "http://target.com/search",
            "param": "q",
        }))

        assert "Error" in result
        assert "baseline" in result.lower()

    def test_xss_detected_reflected(self):
        """Test detection when <script>alert(1)</script> is reflected back unencoded."""
        # Baseline response (clean)
        baseline_resp = MagicMock(
            text="Search results for: test",
            status_code=200,
            headers={},
        )

        # Injection response with payload reflected in body
        payload = "<script>alert(1)</script>"
        injection_resp = MagicMock(
            text=f"Search results for: {payload}",
            status_code=200,
            headers={},
        )

        # Baseline first, then enough injection responses for all payloads
        self.mock_session.get.side_effect = [baseline_resp] + [injection_resp] * 30

        result = self.tool.use(json.dumps({
            "url": "http://target.com/search",
            "param": "q",
        }))

        assert "FULL REFLECTIONS" in result
        assert "XSS confirmed" in result or "reflected unencoded" in result.lower()

    def test_no_xss_found(self):
        """Test when payloads are HTML-encoded and no XSS is detected."""
        baseline_resp = MagicMock(
            text="Search results for: test",
            status_code=200,
            headers={},
        )

        # All injection responses are completely sanitized with no dangerous fragments.
        # The response must NOT contain any of the DANGEROUS_FRAGMENTS like "alert(",
        # "<script>", "onerror=", etc., otherwise partial reflection is detected.
        safe_resp = MagicMock(
            text="Search results for: [sanitized input removed]",
            status_code=200,
            headers={},
        )

        self.mock_session.get.side_effect = [baseline_resp] + [safe_resp] * 30

        result = self.tool.use(json.dumps({
            "url": "http://target.com/search",
            "param": "q",
        }))

        assert "No reflections detected" in result
        assert "FULL REFLECTIONS" not in result

    def test_specific_context_html(self):
        """Test with context='html', verify only html payloads are tested."""
        baseline_resp = MagicMock(
            text="baseline page",
            status_code=200,
            headers={},
        )

        safe_resp = MagicMock(
            text="safe page content",
            status_code=200,
            headers={},
        )

        # HTML_PAYLOADS has 6 payloads, so baseline + 6 injection responses
        self.mock_session.get.side_effect = [baseline_resp] + [safe_resp] * 10

        result = self.tool.use(json.dumps({
            "url": "http://target.com/search",
            "param": "q",
            "context": "html",
        }))

        # Should report testing only html context
        assert "Context(s) Tested: html" in result
        # Only 6 HTML payloads should be tested
        assert "Payloads Tested: 6" in result

    def test_tool_name_and_description(self):
        """Test that name='xss_probe' and description exists."""
        tool = XssProbeTool()
        assert tool.name == "xss_probe"
        assert isinstance(tool.description, str)
        assert len(tool.description) > 0


# ==============================================================================
# XssPayloadGenerator Tests
# ==============================================================================


class TestXssPayloadGenerator:
    """Tests for the XssPayloadGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = XssPayloadGenerator()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_filter_bypass_basic(self):
        """Test filter_bypass operation returns payloads."""
        result = self.tool.use(json.dumps({
            "operation": "filter_bypass",
        }))

        assert "Filter Bypass Payloads" in result
        assert "Tag-Based Bypasses" in result
        assert "Total payloads generated:" in result
        # Should have generated some payloads
        assert "Total payloads generated: 0" not in result

    def test_filter_bypass_with_blocked_tags(self):
        """Test filter_bypass with blocked_tags=['script'], verify no <script> in output."""
        result = self.tool.use(json.dumps({
            "operation": "filter_bypass",
            "blocked_tags": ["script"],
        }))

        assert "Filter Bypass Payloads" in result
        assert "Blocked Tags: script" in result
        # The payloads section should not contain <script> tags since they are blocked
        # Alternative tags like <svg>, <details>, etc. should be used instead
        lines = result.split("\n")
        payload_lines = [
            line.strip() for line in lines
            if line.strip().startswith("<") and "===" not in line
        ]
        for payload_line in payload_lines:
            assert "<script>" not in payload_line.lower()

    def test_dom_xss(self):
        """Test dom_xss operation returns DOM sink payloads."""
        result = self.tool.use(json.dumps({
            "operation": "dom_xss",
        }))

        assert "DOM-Based XSS Payloads" in result
        assert "Sink:" in result
        # Should contain common DOM sinks
        assert "innerHTML" in result
        assert "document.write" in result
        assert "eval" in result
        assert "location.href" in result

    def test_polyglot(self):
        """Test polyglot operation returns polyglot payloads."""
        result = self.tool.use(json.dumps({
            "operation": "polyglot",
        }))

        assert "Polyglot XSS Payloads" in result
        assert "Polyglot #1" in result
        # Should contain multiple polyglot payloads
        assert "multiple" in result.lower() or "contexts" in result.lower()

    def test_encoding_bypass(self):
        """Test encoding_bypass operation returns encoded payloads."""
        result = self.tool.use(json.dumps({
            "operation": "encoding_bypass",
        }))

        assert "Encoding Bypass Payloads" in result
        # Should contain various encoding sections
        assert "HTML Entity Encoding" in result
        assert "URL Encoding" in result
        assert "Double URL Encoding" in result
        assert "Mixed Case Bypass" in result
        assert "Null Byte Insertion" in result
        # Should have actual encoded payloads (HTML entity format)
        assert "&#" in result

    def test_event_handlers(self):
        """Test event_handlers operation returns event handler list."""
        result = self.tool.use(json.dumps({
            "operation": "event_handlers",
        }))

        assert "Event Handlers Reference" in result
        # Should have categories
        assert "MOUSE" in result
        assert "KEYBOARD" in result
        assert "FORM" in result
        assert "MEDIA" in result
        assert "MISC" in result
        # Should have common event handlers
        assert "onclick" in result
        assert "onerror" in result
        assert "onload" in result
        assert "onfocus" in result
        assert "Total event handlers:" in result

    def test_tool_name(self):
        """Test that name='xss_payload_generator'."""
        assert self.tool.name == "xss_payload_generator"


# ==============================================================================
# CspAnalyzerTool Tests
# ==============================================================================


class TestCspAnalyzerTool:
    """Tests for the CspAnalyzerTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = CspAnalyzerTool(session=self.mock_session)

    def test_missing_url_and_csp_string(self):
        """Test that either url or csp_string is required."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "url" in result.lower() or "csp_string" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_no_csp_header(self):
        """Test detection when response has no CSP header."""
        mock_resp = MagicMock()
        # Use a real dict for headers so that .get() works naturally
        mock_resp.headers = {
            "Content-Type": "text/html",
        }
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.com",
        }))

        assert "NO CONTENT-SECURITY-POLICY HEADER FOUND" in result

    def test_unsafe_inline_detected(self):
        """Test detection of unsafe-inline in script-src."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src 'self'; script-src 'unsafe-inline'",
        }))

        assert "unsafe-inline" in result
        assert "HIGH" in result
        assert "inline script" in result.lower() or "inline" in result.lower()

    def test_unsafe_eval_detected(self):
        """Test detection of unsafe-eval in script-src."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src 'self'; script-src 'unsafe-eval'",
        }))

        assert "unsafe-eval" in result
        assert "HIGH" in result
        assert "eval" in result.lower()

    def test_wildcard_detected(self):
        """Test detection of wildcard * in default-src."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src *",
        }))

        assert "Wildcard" in result or "wildcard" in result
        assert "HIGH" in result

    def test_missing_base_uri(self):
        """Test warning when CSP has no base-uri directive."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src 'self'; script-src 'self'",
        }))

        assert "base-uri" in result
        assert "Missing" in result or "missing" in result

    def test_cdn_bypass_detected(self):
        """Test detection and bypass suggestion for cdnjs.cloudflare.com."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src 'self'; script-src 'self' cdnjs.cloudflare.com",
        }))

        assert "cdnjs.cloudflare.com" in result
        assert "bypass" in result.lower() or "Angular" in result
        assert "HIGH" in result

    def test_strict_csp(self):
        """Test that a strict CSP is evaluated as LOW risk."""
        result = self.tool.use(json.dumps({
            "csp_string": "default-src 'none'; script-src 'nonce-abc123'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'",
        }))

        assert "RISK LEVEL: LOW" in result

    def test_tool_name(self):
        """Test that name='csp_analyzer'."""
        tool = CspAnalyzerTool()
        assert tool.name == "csp_analyzer"
