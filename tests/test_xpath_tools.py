"""
Tests for xpath_tools.py
"""

import json
import pytest
from unittest.mock import Mock, MagicMock

import requests

from ctf_solver.tools.xpath_tools import (
    XPathProbeTool,
    XPathBlindBooleanTool,
    XPathPayloadGenerator,
)


def _mock_response(status_code=200, text=""):
    """Create a mock requests.Response with the given status code and body text."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# TestXPathProbeTool
# ---------------------------------------------------------------------------


class TestXPathProbeTool:
    """Tests for the XPathProbeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session = MagicMock()
        self.tool = XPathProbeTool(session=self.session)

    # --- Input validation ---

    def test_missing_url_returns_error(self):
        """Test that a missing 'url' field returns an error."""
        result = self.tool.use(json.dumps({"param": "username"}))
        assert "Error" in result
        assert "'url'" in result

    def test_missing_param_returns_error(self):
        """Test that a missing 'param' field returns an error."""
        result = self.tool.use(json.dumps({"url": "http://target.com/login"}))
        assert "Error" in result
        assert "'param'" in result

    def test_invalid_method_returns_error(self):
        """Test that an invalid HTTP method returns an error."""
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "method": "DELETE",
        }))
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_json_returns_error(self):
        """Test that malformed JSON input returns an error."""
        result = self.tool.use("{not valid json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_baseline_failure_returns_error(self):
        """Test that a failed baseline request returns an error message."""
        self.session.post.side_effect = Exception("Connection refused")
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "Error" in result
        assert "baseline" in result.lower()

    def test_injection_detected_with_differentials(self):
        """Test that injection is detected when true payloads produce responses
        different from false payloads."""
        baseline = _mock_response(200, "Login page")  # 10 chars

        # True-condition probes return a long (different) response
        true_resp = _mock_response(200, "Welcome admin dashboard with lots of content here")

        # False-condition probes return short response matching baseline length
        false_resp = _mock_response(200, "Login page")

        # Error-condition probes also return baseline-like response
        error_resp = _mock_response(200, "Login page")

        def post_side_effect(**kwargs):
            payload = kwargs.get("data", {}).get("username", "")
            if payload == "test_baseline":
                return baseline
            # Identify the expected boolean via PROBE_PAYLOADS
            for p, expected, _ in XPathProbeTool.PROBE_PAYLOADS:
                if p == payload:
                    if expected == "true":
                        return true_resp
                    elif expected == "false":
                        return false_resp
                    else:
                        return error_resp
            return baseline

        self.session.post.side_effect = lambda url, **kw: post_side_effect(**kw)

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "INJECTION DETECTED" in result
        assert "DIFFERENTIAL" in result

    def test_no_injection_when_all_responses_same(self):
        """Test that no injection is reported when all responses are identical."""
        same_resp = _mock_response(200, "Login page content")
        self.session.post.return_value = same_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "No obvious XPath injection detected" in result

    def test_xpath_error_messages_detected(self):
        """Test detection of XPath error messages in response bodies."""
        baseline = _mock_response(200, "Normal page")
        error_resp = _mock_response(200, "Error: XPathException occurred at line 5")

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return error_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "INJECTION DETECTED" in result
        assert "XPath" in result

    def test_flag_detection_in_responses(self):
        """Test that CTF flags embedded in responses are extracted and reported."""
        baseline = _mock_response(200, "Normal page")
        flag_resp = _mock_response(200, "Here is your flag: picoCTF{xp4th_1nj3ct10n}")

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return flag_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "FLAGS FOUND" in result
        assert "picoCTF{xp4th_1nj3ct10n}" in result

    def test_get_method_works(self):
        """Test that GET method sends requests via session.get instead of session.post."""
        same_resp = _mock_response(200, "Page content")
        self.session.get.return_value = same_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.com/search",
            "param": "q",
            "method": "GET",
        }))
        assert "XPathProbeTool" in result
        self.session.get.assert_called()
        self.session.post.assert_not_called()


# ---------------------------------------------------------------------------
# TestXPathBlindBooleanTool
# ---------------------------------------------------------------------------


class TestXPathBlindBooleanTool:
    """Tests for the XPathBlindBooleanTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session = MagicMock()
        self.tool = XPathBlindBooleanTool(session=self.session)

    # --- Input validation ---

    def test_missing_url_returns_error(self):
        """Test that a missing 'url' field returns an error."""
        result = self.tool.use(json.dumps({
            "param": "username",
            "operation": "test_condition",
        }))
        assert "Error" in result
        assert "'url'" in result

    def test_missing_param_returns_error(self):
        """Test that a missing 'param' field returns an error."""
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "operation": "test_condition",
        }))
        assert "Error" in result
        assert "'param'" in result

    def test_missing_operation_returns_error(self):
        """Test that a missing 'operation' field returns an error."""
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
        }))
        assert "Error" in result
        assert "'operation'" in result

    def test_invalid_operation_returns_error(self):
        """Test that an unsupported operation value returns an error."""
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "drop_table",
        }))
        assert "Error" in result
        assert "'operation'" in result

    def test_invalid_json_returns_error(self):
        """Test that malformed JSON input returns an error."""
        result = self.tool.use("{{bad json")
        assert "Error" in result
        assert "JSON" in result

    def test_test_condition_operation(self):
        """Test that test_condition operation sends probes and reports results."""
        # The tool makes several requests during detect_inversion + baseline + test:
        #   detect_inversion: known-true, known-false
        #   baseline true: known-true
        #   baseline false: known-false
        #   test_condition (no explicit condition): true test, false test
        # All return different responses for true vs false so the tool can reason.
        true_resp = _mock_response(200, "Welcome user")
        false_resp = _mock_response(200, "Invalid credentials")

        def post_side_effect(url, **kw):
            payload = kw.get("data", {}).get("username", "")
            if "'1'='1" in payload:
                return true_resp
            return false_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "test_condition",
            "true_indicator": "Welcome",
            "false_indicator": "Invalid",
            "detect_inversion": True,
        }))
        assert "XPathBlindBooleanTool" in result
        assert "RESULT" in result

    def test_extract_char_requires_xpath_expression(self):
        """Test that extract_char returns an error when xpath_expression is missing."""
        # Provide enough for validation to pass up to the operation check.
        # The tool needs to make inversion-detection and baseline requests first,
        # but the xpath_expression check happens early for extract_char.
        self.session.post.return_value = _mock_response(200, "page")
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "extract_char",
            "detect_inversion": False,
        }))
        assert "Error" in result
        assert "xpath_expression" in result

    def test_extract_string_requires_xpath_expression(self):
        """Test that extract_string returns an error when xpath_expression is missing."""
        self.session.post.return_value = _mock_response(200, "page")
        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "extract_string",
            "detect_inversion": False,
        }))
        assert "Error" in result
        assert "xpath_expression" in result

    def test_oracle_inversion_detected(self):
        """Test that inverted oracle is detected when known-true gets the
        false-looking response and known-false gets the true-looking response."""
        # known-true ('1'='1) should NOT contain the true_indicator
        # known-false ('1'='2) SHOULD contain the true_indicator -> INVERTED
        true_resp = _mock_response(200, "Invalid credentials")
        false_resp = _mock_response(200, "Welcome you are on the right path")

        def post_side_effect(url, **kw):
            payload = kw.get("data", {}).get("username", "")
            if "'1'='1" in payload:
                return true_resp
            return false_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "test_condition",
            "true_indicator": "Welcome",
            "detect_inversion": True,
        }))
        assert "INVERTED ORACLE DETECTED" in result

    def test_oracle_normal_not_inverted(self):
        """Test that a non-inverted oracle is correctly identified as normal."""
        true_resp = _mock_response(200, "Welcome user dashboard")
        false_resp = _mock_response(200, "Invalid credentials")

        def post_side_effect(url, **kw):
            payload = kw.get("data", {}).get("username", "")
            if "'1'='1" in payload:
                return true_resp
            return false_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "test_condition",
            "true_indicator": "Welcome",
            "detect_inversion": True,
        }))
        assert "NORMAL" in result or "not inverted" in result.lower()
        assert "INVERTED ORACLE DETECTED" not in result

    def test_binary_search_char_extraction(self):
        """Test that _binary_search_char correctly extracts a character using
        binary search via mocked HTTP responses."""
        # We want to extract character 'f' (ASCII 102) at position 1.
        target_char = "f"
        target_ascii = ord(target_char)

        true_baseline = _mock_response(200, "Welcome user")

        def post_side_effect(url, **kw):
            payload = kw.get("data", {}).get("username", "")
            # The binary search payload looks like:
            #   ' or (substring(//user[1]/pass,1,1)>'X') or '1'='1
            # We need to parse the comparison character out.
            import re
            # Check for the empty-string verification
            if "substring" in payload and "=''" in payload:
                # Position is NOT empty (we have a char), so this should be FALSE
                return _mock_response(200, "Invalid credentials")

            m = re.search(r"substring\(.+?,\d+,1\)>'(.)'", payload)
            if m:
                test_char = m.group(1)
                test_ascii = ord(test_char)
                if target_ascii > test_ascii:
                    # True condition - matches true_baseline
                    return _mock_response(200, "Welcome user")
                else:
                    # False condition - different from true_baseline
                    return _mock_response(200, "Invalid credentials")
            # Default
            return _mock_response(200, "Welcome user")

        self.session.post.side_effect = post_side_effect

        char, logs = self.tool._binary_search_char(
            url="http://target.com/login",
            method="POST",
            param="username",
            xpath_expression="//user[1]/pass",
            position=1,
            form_data={},
            headers={},
            timeout=10,
            true_indicator="Welcome",
            false_indicator="Invalid",
            true_baseline=true_baseline,
            inverted=False,
            payload_prefix="'",
            payload_suffix="'1'='1",
        )

        assert char == target_char
        assert len(logs) > 0

    def test_extract_string_stops_on_consecutive_failures(self):
        """Test that extract_string stops after max_consecutive_failures (3)
        failed character extractions."""
        # Return the same response for everything so that the binary search
        # always gets the same boolean result, which means it cannot converge
        # on a character and returns None (triggering a failure).
        # We also ensure the string-length probe says the string is long (always TRUE).
        same_resp = _mock_response(200, "Same response for everything")
        self.session.post.return_value = same_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.com/login",
            "param": "username",
            "operation": "extract_string",
            "xpath_expression": "//user[1]/pass",
            "max_length": 10,
            "detect_inversion": False,
        }))
        assert "consecutive failures" in result.lower() or "end of string" in result.lower()


# ---------------------------------------------------------------------------
# TestXPathPayloadGenerator
# ---------------------------------------------------------------------------


class TestXPathPayloadGenerator:
    """Tests for the XPathPayloadGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = XPathPayloadGenerator()

    # --- Input validation ---

    def test_missing_operation_returns_error(self):
        """Test that a missing 'operation' field returns an error."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "'operation'" in result

    def test_invalid_operation_returns_error(self):
        """Test that an unsupported operation returns an error."""
        result = self.tool.use(json.dumps({"operation": "hack_the_planet"}))
        assert "Error" in result
        assert "hack_the_planet" in result

    def test_invalid_json_returns_error(self):
        """Test that malformed JSON input returns an error."""
        result = self.tool.use("not json at all {{{")
        assert "Error" in result
        assert "JSON" in result

    # --- auth_bypass ---

    def test_auth_bypass_generates_payloads(self):
        """Test that auth_bypass operation produces a non-empty list of payloads."""
        result = self.tool.use(json.dumps({"operation": "auth_bypass"}))
        assert "Authentication Bypass Payloads" in result
        assert "Payload:" in result
        # Should contain multiple payloads (numbered list)
        assert "1." in result
        assert "2." in result

    def test_auth_bypass_contains_known_payloads(self):
        """Test that auth_bypass includes the classic OR true payload."""
        result = self.tool.use(json.dumps({"operation": "auth_bypass"}))
        assert "' or '1'='1" in result

    # --- data_extraction ---

    def test_data_extraction_generates_templates(self):
        """Test that data_extraction operation produces extraction templates."""
        result = self.tool.use(json.dumps({"operation": "data_extraction"}))
        assert "Blind Boolean Extraction Templates" in result
        assert "Template:" in result
        assert "Common XPath Expressions" in result

    def test_data_extraction_contains_substring_templates(self):
        """Test that data_extraction includes substring-based templates."""
        result = self.tool.use(json.dumps({"operation": "data_extraction"}))
        assert "substring(" in result
        assert "string-length(" in result

    # --- enumeration ---

    def test_enumeration_generates_payloads(self):
        """Test that enumeration operation produces schema discovery payloads."""
        result = self.tool.use(json.dumps({"operation": "enumeration"}))
        assert "Schema Enumeration Payloads" in result
        assert "count(" in result
        assert "name(" in result
