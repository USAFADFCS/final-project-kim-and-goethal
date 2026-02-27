"""
Tests for new probe tools: RaceConditionTool, RequestRepeaterTool,
CrlfProbeTool, PhpTypeJugglingTool, and OpenRedirectProbeTool.

Covers tool name verification, input validation (missing fields, bad JSON),
core functionality, and edge cases (caps, filters).
"""

import json
import pytest
from unittest.mock import MagicMock, patch, Mock

from ctf_solver.tools.race_tools import RaceConditionTool
from ctf_solver.tools.fuzzer_tools import RequestRepeaterTool
from ctf_solver.tools.misc_probe_tools import (
    CrlfProbeTool,
    PhpTypeJugglingTool,
    PrototypePollutionTool,
    IdorEnumeratorTool,
    OpenRedirectProbeTool,
)


# ==============================================================================
# Helpers
# ==============================================================================


def _make_mock_response(
    text="OK",
    status_code=200,
    headers=None,
    elapsed_seconds=0.05,
):
    """Create a mock HTTP response with the attributes tools expect."""
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers if headers is not None else {}
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds = MagicMock(return_value=elapsed_seconds)
    return resp


def _make_mock_session(response=None):
    """Create a mock requests.Session that returns `response` for all methods."""
    if response is None:
        response = _make_mock_response()
    session = MagicMock()
    session.get.return_value = response
    session.post.return_value = response
    session.cookies = MagicMock()
    return session


# ==============================================================================
# TestRaceConditionTool
# ==============================================================================


class TestRaceConditionTool:
    """Tests for RaceConditionTool (session-based, name='race_condition')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = RaceConditionTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'race_condition'."""
        assert self.tool.name == "race_condition"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"method": "POST"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_concurrent_requests_sent(self):
        """Mock session constructor to verify concurrent requests are sent."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status":"success"}'
        mock_resp.headers = {}
        mock_resp.elapsed = MagicMock()
        mock_resp.elapsed.total_seconds = MagicMock(return_value=0.05)

        mock_thread_session = MagicMock()
        mock_thread_session.post.return_value = mock_resp
        mock_thread_session.cookies = MagicMock()

        with patch("ctf_solver.tools.race_tools.requests.Session") as MockSession:
            MockSession.return_value = mock_thread_session

            # Create a fresh tool (the __init__ will also call requests.Session,
            # but we override _build_thread_session behavior via the patch)
            tool = RaceConditionTool.__new__(RaceConditionTool)
            tool.session = MagicMock()
            tool.session.cookies = MagicMock()

            result = tool.use(json.dumps({
                "url": "http://target.local/transfer",
                "method": "POST",
                "data": {"amount": "100"},
                "concurrency": 5,
            }))

        assert "Results" in result or "Result" in result
        assert "200" in result

    def test_concurrency_cap(self):
        """Concurrency should be capped at 50."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_resp.headers = {}
        mock_resp.elapsed = MagicMock()
        mock_resp.elapsed.total_seconds = MagicMock(return_value=0.01)

        mock_thread_session = MagicMock()
        mock_thread_session.post.return_value = mock_resp
        mock_thread_session.cookies = MagicMock()

        with patch("ctf_solver.tools.race_tools.requests.Session") as MockSession:
            MockSession.return_value = mock_thread_session

            tool = RaceConditionTool.__new__(RaceConditionTool)
            tool.session = MagicMock()
            tool.session.cookies = MagicMock()

            result = tool.use(json.dumps({
                "url": "http://target.local/transfer",
                "concurrency": 100,
            }))

        # The output header should show "Concurrency: 50" (capped)
        assert "Concurrency: 50" in result

    def test_repeat_cap(self):
        """Repeat should be capped at 5."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_resp.headers = {}
        mock_resp.elapsed = MagicMock()
        mock_resp.elapsed.total_seconds = MagicMock(return_value=0.01)

        mock_thread_session = MagicMock()
        mock_thread_session.post.return_value = mock_resp
        mock_thread_session.cookies = MagicMock()

        with patch("ctf_solver.tools.race_tools.requests.Session") as MockSession:
            MockSession.return_value = mock_thread_session

            tool = RaceConditionTool.__new__(RaceConditionTool)
            tool.session = MagicMock()
            tool.session.cookies = MagicMock()

            result = tool.use(json.dumps({
                "url": "http://target.local/transfer",
                "repeat": 10,
                "concurrency": 2,
            }))

        # The output header should show "Rounds: 5" (capped from 10)
        assert "Rounds: 5" in result


# ==============================================================================
# TestRequestRepeaterTool
# ==============================================================================


class TestRequestRepeaterTool:
    """Tests for RequestRepeaterTool (session-based, name='request_repeater')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = RequestRepeaterTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'request_repeater'."""
        assert self.tool.name == "request_repeater"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({
            "param": "password",
            "values": ["test"],
        }))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param_and_body_template(self):
        """Either param or body_template is required."""
        result = self.tool.use(json.dumps({
            "url": "http://target.local/login",
            "values": ["test"],
        }))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not valid json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_custom_values(self):
        """Pass values=['admin', 'test', 'pass'], verify all 3 values tested."""

        def mock_post_side_effect(*args, **kwargs):
            data = kwargs.get("data", {})
            value = data.get("password", "")
            if value == "admin":
                return _make_mock_response(text="Welcome admin", status_code=200)
            elif value == "test":
                return _make_mock_response(text="Invalid", status_code=401)
            else:
                return _make_mock_response(text="Invalid", status_code=401)

        self.session.post.side_effect = mock_post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/login",
            "method": "POST",
            "param": "password",
            "values": ["admin", "test", "pass"],
            "data": {"username": "admin"},
        }))

        assert "Values tested: 3" in result
        assert "admin" in result
        assert "test" in result
        assert "pass" in result

    def test_builtin_wordlist_common_passwords(self):
        """Pass wordlist='common_passwords', verify built-in list is used."""
        result = self.tool.use(json.dumps({
            "url": "http://target.local/login",
            "method": "POST",
            "param": "password",
            "wordlist": "common_passwords",
        }))

        # The built-in common_passwords list contains "admin" and "password"
        assert "admin" in result
        assert "password" in result

    def test_match_status_filter(self):
        """Pass match_status=302; only the 302 result should appear."""
        call_count = [0]

        def mock_post_side_effect(*args, **kwargs):
            call_count[0] += 1
            data = kwargs.get("data", {})
            value = data.get("password", "")
            if value == "secret":
                return _make_mock_response(
                    text="Redirecting", status_code=302,
                    headers={"Location": "/dashboard"}
                )
            return _make_mock_response(text="Invalid", status_code=200)

        self.session.post.side_effect = mock_post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/login",
            "method": "POST",
            "param": "password",
            "values": ["admin", "test", "secret", "pass"],
            "match_status": 302,
        }))

        # The filtered results section should show only "secret" (302)
        # Total values tested is still 4
        assert "Values tested: 4" in result
        assert "filtered from" in result
        # "secret" should be in the results section
        assert "secret" in result

    def test_max_requests_cap(self):
        """Pass 300 values, verify capped at 200."""
        values_300 = [f"val_{i}" for i in range(300)]

        result = self.tool.use(json.dumps({
            "url": "http://target.local/login",
            "method": "POST",
            "param": "password",
            "values": values_300,
        }))

        # Should be capped at 200
        assert "Values tested: 200" in result


# ==============================================================================
# TestCrlfProbeTool
# ==============================================================================


class TestCrlfProbeTool:
    """Tests for CrlfProbeTool (session-based, name='crlf_probe')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = CrlfProbeTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'crlf_probe'."""
        assert self.tool.name == "crlf_probe"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"param": "url"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """param is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"url": "http://target.local/redirect"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("{bad json")
        assert "Error" in result
        assert "JSON" in result

    def test_crlf_detected(self):
        """Mock response with 'Injected-Header' in response headers to detect CRLF."""
        baseline_resp = _make_mock_response(
            text="Baseline", status_code=200,
            headers={"Content-Type": "text/html"},
        )

        # Response with injected header
        crlf_resp = _make_mock_response(
            text="Injected", status_code=200,
            headers={
                "Content-Type": "text/html",
                "Injected-Header": "true",
            },
        )

        call_count = [0]

        def mock_get_side_effect(*args, **kwargs):
            call_count[0] += 1
            # First call is the baseline
            if call_count[0] == 1:
                return baseline_resp
            # All subsequent calls return the vulnerable response
            return crlf_resp

        self.session.get.side_effect = mock_get_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/redirect",
            "param": "url",
            "method": "GET",
        }))

        assert "VULNERABLE" in result or "vulnerable" in result.lower()

    def test_no_crlf_found(self):
        """Mock responses with no header injection; should report no vulnerabilities."""
        normal_resp = _make_mock_response(
            text="Normal Response", status_code=200,
            headers={"Content-Type": "text/html"},
        )
        self.session.get.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/redirect",
            "param": "url",
            "method": "GET",
        }))

        assert "No CRLF injection vulnerabilities detected" in result


# ==============================================================================
# TestPhpTypeJugglingTool
# ==============================================================================


class TestPhpTypeJugglingTool:
    """Tests for PhpTypeJugglingTool (pure logic, name='php_type_juggling')."""

    def setup_method(self):
        self.tool = PhpTypeJugglingTool()

    def test_tool_name(self):
        """Verify tool name is 'php_type_juggling'."""
        assert self.tool.name == "php_type_juggling"

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not json!!")
        assert "Error" in result
        assert "JSON" in result

    def test_magic_hashes_md5(self):
        """operation='magic_hashes', hash_type='md5' should contain known MD5 magic values."""
        result = self.tool.use(json.dumps({
            "operation": "magic_hashes",
            "hash_type": "md5",
        }))

        assert "240610708" in result
        assert "QNKCDZO" in result
        assert "MD5" in result

    def test_magic_hashes_sha1(self):
        """operation='magic_hashes', hash_type='sha1' should contain SHA1 magic values."""
        result = self.tool.use(json.dumps({
            "operation": "magic_hashes",
            "hash_type": "sha1",
        }))

        assert "SHA1" in result
        # Verify specific SHA1 magic hash values from the tool's MAGIC_HASHES_SHA1
        assert "aaroZmOk" in result
        assert "aaK1STfY" in result

    def test_strcmp_bypass(self):
        """operation='strcmp_bypass' should return array bypass payloads."""
        result = self.tool.use(json.dumps({
            "operation": "strcmp_bypass",
        }))

        assert "strcmp" in result
        assert "password[]=" in result
        assert "array" in result.lower()

    def test_loose_comparison(self):
        """operation='loose_comparison' should return comparison table entries."""
        result = self.tool.use(json.dumps({
            "operation": "loose_comparison",
        }))

        assert "Loose Comparison" in result
        # Check for specific comparison table entries
        assert '"0" == false' in result or "0e" in result
        assert "TRUE" in result

    def test_type_coercion(self):
        """operation='type_coercion' should return intval/is_numeric bypass payloads."""
        result = self.tool.use(json.dumps({
            "operation": "type_coercion",
        }))

        assert "intval" in result
        assert "is_numeric" in result
        assert "Bypass" in result


# ==============================================================================
# TestPrototypePollutionTool
# ==============================================================================


class TestPrototypePollutionTool:
    """Tests for PrototypePollutionTool (session-based, name='prototype_pollution_probe')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = PrototypePollutionTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'prototype_pollution_probe'."""
        assert self.tool.name == "prototype_pollution_probe"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"method": "POST"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("{bad json")
        assert "Error" in result
        assert "JSON" in result

    def test_pollution_detected(self):
        """Mock different response for pollution payload vs baseline."""
        baseline_resp = _make_mock_response(
            text='{"status":"ok"}', status_code=200,
        )
        polluted_resp = _make_mock_response(
            text='{"status":"ok","polluted":"true"}', status_code=200,
        )

        call_count = [0]

        def mock_post_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return polluted_resp

        self.session.post.side_effect = mock_post_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/api/merge",
            "method": "POST",
            "content_type": "application/json",
        }))

        # Should detect that responses changed after pollution payloads
        assert "CHANGE DETECTED" in result or "change" in result.lower() or "different" in result.lower()

    def test_no_pollution(self):
        """Mock all identical responses; should report no pollution."""
        normal_resp = _make_mock_response(
            text='{"status":"ok"}', status_code=200,
        )
        self.session.post.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/api/merge",
            "method": "POST",
        }))

        assert "No prototype pollution" in result or "no changes" in result.lower() or "no pollution" in result.lower()


# ==============================================================================
# TestIdorEnumeratorTool
# ==============================================================================


class TestIdorEnumeratorTool:
    """Tests for IdorEnumeratorTool (session-based, name='idor_enumerator')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = IdorEnumeratorTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'idor_enumerator'."""
        assert self.tool.name == "idor_enumerator"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"param": "1"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """param is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"url": "http://target.local/api/user/1"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("{bad json")
        assert "Error" in result
        assert "JSON" in result

    def test_idor_enumeration_sequential(self):
        """Test sequential ID enumeration with different responses per ID."""
        def mock_get_side_effect(url, **kwargs):
            if "/user/0" in url:
                return _make_mock_response(text='{"error":"not found"}', status_code=404)
            elif "/user/1" in url:
                return _make_mock_response(
                    text='{"id":1,"name":"admin","email":"admin@test.com"}',
                    status_code=200,
                )
            elif "/user/2" in url:
                return _make_mock_response(
                    text='{"id":2,"name":"user","email":"user@test.com"}',
                    status_code=200,
                )
            else:
                return _make_mock_response(text='{"error":"not found"}', status_code=404)

        self.session.get.side_effect = mock_get_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/api/user/1",
            "param": "1",
            "param_type": "path",
            "range_start": 0,
            "range_end": 3,
        }))

        assert "admin" in result
        assert "user" in result
        assert "200" in result
        assert "404" in result

    def test_flag_detection_in_response(self):
        """Test that flag patterns are highlighted in IDOR results."""
        def mock_get_side_effect(url, **kwargs):
            if "/user/5" in url:
                return _make_mock_response(
                    text='{"id":5,"secret":"FLAG{idor_found_123}"}',
                    status_code=200,
                )
            return _make_mock_response(text='{"error":"not found"}', status_code=404)

        self.session.get.side_effect = mock_get_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/api/user/1",
            "param": "1",
            "param_type": "path",
            "range_start": 4,
            "range_end": 6,
        }))

        assert "FLAG{idor_found_123}" in result
        assert "flag" in result.lower() or "interesting" in result.lower()

    def test_range_cap(self):
        """Range should be capped to prevent excessive requests."""
        normal_resp = _make_mock_response(text='{"error":"not found"}', status_code=404)
        self.session.get.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/api/user/1",
            "param": "1",
            "param_type": "path",
            "range_start": 0,
            "range_end": 500,
        }))

        # The tool should cap the range at 100
        # Check that we didn't enumerate all 500
        call_count = self.session.get.call_count
        assert call_count <= 101  # At most 100 IDs (0-99) + possible baseline


# ==============================================================================
# TestOpenRedirectProbeTool
# ==============================================================================


class TestOpenRedirectProbeTool:
    """Tests for OpenRedirectProbeTool (session-based, name='open_redirect_probe')."""

    def setup_method(self):
        self.session = _make_mock_session()
        self.tool = OpenRedirectProbeTool(session=self.session)

    def test_tool_name(self):
        """Verify tool name is 'open_redirect_probe'."""
        assert self.tool.name == "open_redirect_probe"

    def test_missing_url(self):
        """url is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"param": "url"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """param is required; omitting it should return an error."""
        result = self.tool.use(json.dumps({"url": "http://target.local/redirect"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("{bad json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_redirect_detected(self):
        """Mock response with status 302 and Location containing 'evil.com'."""
        # Baseline: normal redirect to example.com
        baseline_resp = _make_mock_response(
            text="Redirecting", status_code=302,
            headers={"Location": "https://example.com"},
        )

        # Payload responses: redirect to evil.com
        evil_resp = _make_mock_response(
            text="Redirecting", status_code=302,
            headers={"Location": "https://evil.com"},
        )

        call_count = [0]

        def mock_get_side_effect(*args, **kwargs):
            call_count[0] += 1
            # First call is baseline
            if call_count[0] == 1:
                return baseline_resp
            return evil_resp

        self.session.get.side_effect = mock_get_side_effect

        result = self.tool.use(json.dumps({
            "url": "http://target.local/redirect",
            "param": "url",
            "method": "GET",
        }))

        assert "VULNERABLE" in result or "vulnerable" in result.lower()

    def test_no_redirect(self):
        """Mock all responses with status 200, no Location header."""
        normal_resp = _make_mock_response(
            text="Normal page", status_code=200,
            headers={},
        )
        self.session.get.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/redirect",
            "param": "url",
            "method": "GET",
        }))

        assert "No open redirect vulnerabilities detected" in result
