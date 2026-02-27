"""
Tests for JSON body injection feature across probe tools.

When a probe tool receives a `headers` dict containing
`Content-Type: application/json` (case-insensitive key lookup),
it should send the request body using `json=` instead of `data=`
in the underlying requests call.

Covers:
- SqliProbeTool._send_request  (sqli_tools.py)
- SqliColumnCounter._send_request (sqli_tools.py)
- SstiProbeTool._make_request  (ssti_tools.py)
- TimingCompareTool._timed_request (diff_tools.py)
"""

import json
import time
import pytest
from unittest.mock import Mock, patch, call

from ctf_solver.tools.sqli_tools import SqliProbeTool, SqliColumnCounter
from ctf_solver.tools.ssti_tools import SstiProbeTool
from ctf_solver.tools.diff_tools import TimingCompareTool


# ==============================================================================
# Helpers
# ==============================================================================


def _make_mock_response(text="OK", status_code=200):
    """Create a mock HTTP response with the attributes tools expect."""
    resp = Mock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {"Content-Type": "text/html"}
    resp.elapsed = Mock()
    resp.elapsed.total_seconds = Mock(return_value=0.05)
    return resp


def _make_mock_session(response=None):
    """Create a mock requests.Session that returns `response` for all methods."""
    if response is None:
        response = _make_mock_response()
    session = Mock()
    session.get.return_value = response
    session.post.return_value = response
    return session


# ==============================================================================
# TestSqliProbeJsonBody
# ==============================================================================


class TestSqliProbeJsonBody:
    """Verify SqliProbeTool sends json= when Content-Type is application/json."""

    def test_json_content_type_uses_json_param(self):
        """POST with Content-Type: application/json must use json= not data=."""
        session = _make_mock_session()
        tool = SqliProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["' OR 1=1 --"],
            "data": {"password": "test"},
            "headers": {"Content-Type": "application/json"},
        }))

        # session.post should have been called (baseline + 1 payload = 2 calls)
        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            # Every POST call must use json= keyword argument
            _, kwargs = c
            assert "json" in kwargs, "Expected json= keyword in POST call"
            assert "data" not in kwargs, "data= should NOT be present when json= is used"

    def test_no_content_type_uses_data_param(self):
        """POST without JSON content type must use data= (form-encoded)."""
        session = _make_mock_session()
        tool = SqliProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["' OR 1=1 --"],
            "data": {"password": "test"},
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "data" in kwargs, "Expected data= keyword in POST call"
            assert "json" not in kwargs, "json= should NOT be present for form-encoded requests"

    def test_case_insensitive_content_type(self):
        """Lowercase 'content-type' header key must also trigger json= mode."""
        session = _make_mock_session()
        tool = SqliProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["admin' --"],
            "data": {"password": "x"},
            "headers": {"content-type": "application/json"},
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "json" in kwargs, (
                "Lowercase 'content-type' should still trigger json= mode"
            )
            assert "data" not in kwargs


class TestSqliColumnCounterJsonBody:
    """Verify SqliColumnCounter sends json= when Content-Type is application/json."""

    def test_json_content_type_uses_json_param(self):
        """POST with Content-Type: application/json must use json= not data=."""
        session = _make_mock_session()
        tool = SqliColumnCounter(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/search",
            "method": "POST",
            "param": "id",
            "technique": "order_by",
            "headers": {"Content-Type": "application/json"},
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "json" in kwargs, "Expected json= keyword in POST call"
            assert "data" not in kwargs, "data= should NOT be present when json= is used"

    def test_no_content_type_uses_data_param(self):
        """POST without JSON content type must use data= (form-encoded)."""
        session = _make_mock_session()
        tool = SqliColumnCounter(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/search",
            "method": "POST",
            "param": "id",
            "technique": "order_by",
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "data" in kwargs, "Expected data= keyword in POST call"
            assert "json" not in kwargs


# ==============================================================================
# TestSstiProbeJsonBody
# ==============================================================================


class TestSstiProbeJsonBody:
    """Verify SstiProbeTool sends json= when Content-Type is application/json."""

    def test_json_content_type_uses_json_param(self):
        """POST with Content-Type: application/json must use json= not data=."""
        session = _make_mock_session()
        tool = SstiProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/render",
            "method": "POST",
            "param": "template",
            "headers": {"Content-Type": "application/json"},
        }))

        # SstiProbeTool makes many requests (baseline + universal + engine probes + error)
        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "json" in kwargs, "Expected json= keyword in POST call"
            assert "data" not in kwargs, "data= should NOT be present when json= is used"

    def test_default_uses_data_param(self):
        """POST without JSON content type must use data= (form-encoded)."""
        session = _make_mock_session()
        tool = SstiProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/render",
            "method": "POST",
            "param": "template",
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "data" in kwargs, "Expected data= keyword in POST call"
            assert "json" not in kwargs, "json= should NOT be present for form-encoded requests"

    def test_case_insensitive_content_type(self):
        """Mixed-case 'Content-type' header key must also trigger json= mode."""
        session = _make_mock_session()
        tool = SstiProbeTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/render",
            "method": "POST",
            "param": "template",
            "headers": {"Content-type": "application/json; charset=utf-8"},
        }))

        assert session.post.call_count >= 1

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "json" in kwargs, (
                "Mixed-case 'Content-type' with charset should still trigger json= mode"
            )
            assert "data" not in kwargs


# ==============================================================================
# TestTimingCompareEnhancements
# ==============================================================================


class TestTimingCompareEnhancements:
    """Verify TimingCompareTool honors headers parameter and JSON content type."""

    def test_headers_parameter_accepted(self):
        """Tool must accept a 'headers' key in input JSON without error."""
        session = _make_mock_session()
        tool = TimingCompareTool(session=session)

        result = tool.use(json.dumps({
            "url": "http://target.local/search",
            "method": "GET",
            "params1": {"q": "a"},
            "params2": {"q": "b"},
            "headers": {"X-Custom": "value"},
        }))

        # Should produce normal output, not an error
        assert "[TimingCompareTool] Timing Comparison Results" in result
        assert "Error" not in result or "error" not in result.split("===")[0]

    def test_json_content_type_in_timing(self):
        """POST with Content-Type: application/json must use json= not data=."""
        session = _make_mock_session()
        tool = TimingCompareTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/api/search",
            "method": "POST",
            "params1": {"q": "normal"},
            "params2": {"q": "' AND SLEEP(5)--"},
            "headers": {"Content-Type": "application/json"},
        }))

        # Two POST calls (params1 and params2)
        assert session.post.call_count == 2

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "json" in kwargs, "Expected json= keyword in POST call"
            assert "data" not in kwargs, "data= should NOT be present when json= is used"

    def test_headers_passed_to_request(self):
        """Custom headers must be forwarded to the underlying session request."""
        session = _make_mock_session()
        tool = TimingCompareTool(session=session)

        custom_headers = {
            "Authorization": "Bearer token123",
            "X-CTF-Team": "solvers",
        }

        tool.use(json.dumps({
            "url": "http://target.local/api",
            "method": "POST",
            "params1": {"a": "1"},
            "params2": {"a": "2"},
            "headers": custom_headers,
        }))

        assert session.post.call_count == 2

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "headers" in kwargs, "headers kwarg must be passed to session.post"
            passed_headers = kwargs["headers"]
            assert passed_headers.get("Authorization") == "Bearer token123"
            assert passed_headers.get("X-CTF-Team") == "solvers"

    def test_no_json_content_type_uses_data(self):
        """POST without JSON content type must use data= (form-encoded)."""
        session = _make_mock_session()
        tool = TimingCompareTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/search",
            "method": "POST",
            "params1": {"q": "a"},
            "params2": {"q": "b"},
        }))

        assert session.post.call_count == 2

        for c in session.post.call_args_list:
            _, kwargs = c
            assert "data" in kwargs, "Expected data= keyword in POST call"
            assert "json" not in kwargs, "json= should NOT be present for form-encoded requests"

    def test_get_ignores_json_content_type(self):
        """GET requests should use params= regardless of Content-Type header."""
        session = _make_mock_session()
        tool = TimingCompareTool(session=session)

        tool.use(json.dumps({
            "url": "http://target.local/search",
            "method": "GET",
            "params1": {"q": "a"},
            "params2": {"q": "b"},
            "headers": {"Content-Type": "application/json"},
        }))

        # GET uses session.get, not session.post
        assert session.get.call_count == 2
        assert session.post.call_count == 0

        for c in session.get.call_args_list:
            _, kwargs = c
            assert "params" in kwargs, "GET requests must use params="
