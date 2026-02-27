"""
Tests for HTTP tools (HttpFetchTool and FormSubmitTool).

Covers:
- HttpFetchTool: GET, HEAD, POST, PUT, PATCH, DELETE, JSON body, error handling
- FormSubmitTool: form-encoded POST, JSON POST, Content-Type detection
- JSON API interaction patterns common in CTF challenges
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

from ctf_solver.tools.http_tools import HttpFetchTool, FormSubmitTool


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def mock_session():
    """Create a mock requests.Session."""
    session = Mock()
    session.cookies = Mock()
    session.cookies.items.return_value = []
    session.headers = {}
    return session


@pytest.fixture
def mock_response():
    """Create a factory for mock HTTP responses."""
    def _make(text="", status_code=200, headers=None, url="http://test.local/"):
        resp = Mock()
        resp.text = text
        resp.status_code = status_code
        resp.headers = headers or {"Content-Type": "text/html"}
        resp.url = url
        return resp
    return _make


# ==============================================================================
# HttpFetchTool Tests
# ==============================================================================


class TestHttpFetchTool:
    """Tests for HttpFetchTool."""

    def test_basic_get(self, mock_session, mock_response):
        """Test basic GET request."""
        resp = mock_response(text="Hello World", url="http://test.local/")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "[HttpFetchTool] Method: GET" in result
        assert "Status: 200" in result
        assert "Hello World" in result
        mock_session.get.assert_called_once()

    def test_head_request(self, mock_session, mock_response):
        """Test HEAD request returns no body."""
        resp = mock_response(url="http://test.local/")
        mock_session.head.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/", "method": "HEAD"}))

        assert "Method: HEAD" in result
        assert "[No body for HEAD request]" in result
        mock_session.head.assert_called_once()

    def test_post_without_body(self, mock_session, mock_response):
        """Test POST request without a body."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
        }))

        assert "Method: POST" in result
        assert "Status: 200" in result
        mock_session.post.assert_called_once()

    def test_post_with_json_body(self, mock_session, mock_response):
        """Test POST request with JSON body — the key fix for CTF challenges."""
        resp = mock_response(
            text='{"message": "Flag: FLAG{test}"}',
            url="http://test.local/check",
        )
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/check",
            "method": "POST",
            "body": {"status": ["open", "open", "open", "open"]},
        }))

        assert "Method: POST" in result
        assert "FLAG{test}" in result
        # Verify json= was used (not data=)
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"status": ["open", "open", "open", "open"]}

    def test_put_with_json_body(self, mock_session, mock_response):
        """Test PUT request with JSON body."""
        resp = mock_response(text='{"updated": true}', url="http://test.local/api/1")
        mock_session.put.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/api/1",
            "method": "PUT",
            "body": {"name": "updated"},
        }))

        assert "Method: PUT" in result
        mock_session.put.assert_called_once()
        call_kwargs = mock_session.put.call_args
        assert call_kwargs.kwargs.get("json") == {"name": "updated"}

    def test_patch_with_json_body(self, mock_session, mock_response):
        """Test PATCH request with JSON body."""
        resp = mock_response(text='{"patched": true}', url="http://test.local/api/1")
        mock_session.patch.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/api/1",
            "method": "PATCH",
            "body": {"field": "value"},
        }))

        assert "Method: PATCH" in result
        mock_session.patch.assert_called_once()

    def test_delete_request(self, mock_session, mock_response):
        """Test DELETE request."""
        resp = mock_response(text='{"deleted": true}', url="http://test.local/api/1")
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/api/1",
            "method": "DELETE",
        }))

        assert "Method: DELETE" in result
        mock_session.delete.assert_called_once()

    def test_invalid_method(self, mock_session):
        """Test that invalid methods are rejected."""
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/",
            "method": "TRACE",
        }))

        assert "Error" in result
        assert "method" in result.lower()

    def test_missing_url(self, mock_session):
        """Test error when URL is missing."""
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"method": "GET"}))

        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_json_input(self, mock_session):
        """Test error on invalid JSON input."""
        tool = HttpFetchTool(session=mock_session)
        result = tool.use("not json")

        assert "Error" in result

    def test_custom_headers(self, mock_session, mock_response):
        """Test passing custom headers."""
        resp = mock_response(text="ok", url="http://test.local/")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/",
            "headers": {"Authorization": "Bearer token123"},
        }))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["headers"]["Authorization"] == "Bearer token123"

    def test_query_params(self, mock_session, mock_response):
        """Test passing query parameters."""
        resp = mock_response(text="ok", url="http://test.local/?id=1")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/",
            "params": {"id": "1"},
        }))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["params"] == {"id": "1"}

    def test_body_truncation(self, mock_session, mock_response):
        """Test response body is truncated to max_body."""
        long_text = "A" * 10000
        resp = mock_response(text=long_text, url="http://test.local/")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/",
            "max_body": 100,
        }))

        assert "truncated" in result.lower()
        # Body should be truncated, not the full 10000 chars
        assert len(result) < 10000

    def test_connection_error(self, mock_session):
        """Test handling of connection errors."""
        mock_session.get.side_effect = ConnectionError("Connection refused")

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "Error" in result
        assert "Connection refused" in result

    def test_post_with_params_and_body(self, mock_session, mock_response):
        """Test POST with both query params and JSON body."""
        resp = mock_response(text="ok", url="http://test.local/api?v=2")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
            "params": {"v": "2"},
            "body": {"data": "test"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["params"] == {"v": "2"}
        assert call_kwargs.kwargs["json"] == {"data": "test"}

    def test_default_session_created(self):
        """Test that a default session is created when none provided."""
        tool = HttpFetchTool()
        assert tool.session is not None

    def test_name_and_description(self):
        """Test tool has correct name and description."""
        tool = HttpFetchTool()
        assert tool.name == "http_fetch"
        assert "POST" in tool.description
        assert "body" in tool.description


# ==============================================================================
# FormSubmitTool Tests
# ==============================================================================


class TestFormSubmitTool:
    """Tests for FormSubmitTool."""

    def test_basic_form_post(self, mock_session, mock_response):
        """Test basic form-encoded POST."""
        resp = mock_response(text="Welcome!", url="http://test.local/login")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/login",
            "method": "POST",
            "data": {"username": "admin", "password": "test"},
        }))

        assert "Method: POST" in result
        assert "Welcome!" in result
        # Should use data= (form-encoded) by default
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"username": "admin", "password": "test"}

    def test_json_post_with_content_type(self, mock_session, mock_response):
        """Test JSON POST when Content-Type is application/json."""
        resp = mock_response(
            text='{"message": "Access Granted! Flag: FLAG{json_win}"}',
            url="http://test.local/check",
        )
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/check",
            "method": "POST",
            "data": {"status": ["open", "open", "open", "open"]},
            "headers": {"Content-Type": "application/json"},
        }))

        assert "FLAG{json_win}" in result
        # Verify json= was used instead of data=
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"status": ["open", "open", "open", "open"]}
        assert "data" not in call_kwargs.kwargs or call_kwargs.kwargs.get("data") is None

    def test_json_post_case_insensitive_header(self, mock_session, mock_response):
        """Test JSON detection is case-insensitive for Content-Type header key."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
            "data": {"key": "value"},
            "headers": {"content-type": "application/json"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"key": "value"}

    def test_json_post_charset_in_content_type(self, mock_session, mock_response):
        """Test JSON detection works with charset parameter in Content-Type."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
            "data": {"key": "value"},
            "headers": {"Content-Type": "application/json; charset=utf-8"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"key": "value"}

    def test_form_encoded_without_json_header(self, mock_session, mock_response):
        """Test form-encoded POST when Content-Type is not JSON."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/form",
            "method": "POST",
            "data": {"field": "value"},
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}

    def test_form_encoded_no_headers(self, mock_session, mock_response):
        """Test form-encoded POST when no headers provided (default behavior)."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/form",
            "method": "POST",
            "data": {"field": "value"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}

    def test_get_with_params(self, mock_session, mock_response):
        """Test GET request sends data as query params."""
        resp = mock_response(text="results", url="http://test.local/search?q=test")
        mock_session.get.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/search",
            "method": "GET",
            "data": {"q": "test"},
        }))

        assert "Method: GET" in result
        mock_session.get.assert_called_once()

    def test_missing_url(self, mock_session):
        """Test error when URL is missing."""
        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({"method": "POST"}))

        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_method(self, mock_session):
        """Test error when method is missing."""
        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_method(self, mock_session):
        """Test error for invalid method."""
        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/",
            "method": "PUT",
        }))

        assert "Error" in result
        assert "GET" in result and "POST" in result

    def test_invalid_json_input(self, mock_session):
        """Test error on invalid JSON input."""
        tool = FormSubmitTool(session=mock_session)
        result = tool.use("not json")

        assert "Error" in result

    def test_connection_error(self, mock_session):
        """Test handling of connection errors."""
        mock_session.post.side_effect = ConnectionError("Connection refused")

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/",
            "method": "POST",
        }))

        assert "Error" in result

    def test_response_truncation(self, mock_session, mock_response):
        """Test response body truncation."""
        resp = mock_response(text="A" * 10000, url="http://test.local/")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/",
            "method": "POST",
            "max_body": 50,
        }))

        assert "truncated" in result.lower()

    def test_name_and_description(self):
        """Test tool has correct name and description."""
        tool = FormSubmitTool()
        assert tool.name == "form_submit"
        assert "JSON" in tool.description


# ==============================================================================
# JSON API Integration Pattern Tests
# ==============================================================================


class TestJsonApiPatterns:
    """Test common JSON API patterns that appear in CTF challenges."""

    def test_combination_lock_pattern(self, mock_session, mock_response):
        """Test the exact pattern from the Javashop CTF challenge."""
        resp = mock_response(
            text='{"message": "Access Granted! Flag: picoCTF{combination_cracked}"}',
            url="http://test.local/check-combination",
        )
        mock_session.post.return_value = resp

        # Using HttpFetchTool with POST + body (recommended approach)
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/check-combination",
            "method": "POST",
            "body": {"status": ["open", "open", "open", "open"]},
        }))

        assert "picoCTF{combination_cracked}" in result
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["json"] == {"status": ["open", "open", "open", "open"]}

    def test_api_auth_pattern(self, mock_session, mock_response):
        """Test API authentication with JSON body."""
        resp = mock_response(
            text='{"token": "abc123", "flag": "FLAG{api_auth}"}',
            url="http://test.local/api/login",
        )
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.local/api/login",
            "method": "POST",
            "body": {"username": "admin", "password": "secret"},
        }))

        assert "FLAG{api_auth}" in result

    def test_json_body_with_nested_objects(self, mock_session, mock_response):
        """Test sending nested JSON objects."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
            "body": {
                "user": {"name": "admin", "role": "superuser"},
                "action": "elevate",
            },
        }))

        call_kwargs = mock_session.post.call_args
        body = call_kwargs.kwargs["json"]
        assert body["user"]["role"] == "superuser"

    def test_json_body_with_array(self, mock_session, mock_response):
        """Test sending JSON array as body value."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({
            "url": "http://test.local/api",
            "method": "POST",
            "body": {"ids": [1, 2, 3], "action": "delete"},
        }))

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["json"]["ids"] == [1, 2, 3]


# ==============================================================================
# Self-Reflection Format Mismatch Detection Tests
# ==============================================================================


class TestFormatMismatchDetection:
    """Test that self-reflection detects tool-level format mismatches."""

    def test_detect_repeated_400_errors(self):
        """Test detection of repeated 400 errors to the same endpoint."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
        ]

        engine = ReflectionEngine(tracker)
        recent = tracker.tool_call_log[-10:]
        result = engine._detect_format_mismatch(recent)

        assert result is not None
        assert "TOOL FORMAT ISSUE" in result
        assert "http_fetch" in result
        assert "JSON" in result or "json" in result

    def test_no_detection_for_different_endpoints(self):
        """Test no false positive when 400s are on different endpoints."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api1\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api2\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api3\nBad Request"},
        ]

        engine = ReflectionEngine(tracker)
        recent = tracker.tool_call_log[-10:]
        result = engine._detect_format_mismatch(recent)

        assert result is None

    def test_no_detection_for_non_format_errors(self):
        """Test no false positive for 200/404 responses."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 200\nURL: http://test.local/api\nOK"},
            {"tool": "form_submit", "output": "Status: 404\nURL: http://test.local/api\nNot Found"},
            {"tool": "form_submit", "output": "Status: 200\nURL: http://test.local/api\nOK"},
        ]

        engine = ReflectionEngine(tracker)
        recent = tracker.tool_call_log[-10:]
        result = engine._detect_format_mismatch(recent)

        assert result is None

    def test_detect_415_unsupported_media_type(self):
        """Test detection of 415 Unsupported Media Type errors."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 415\nURL: http://test.local/api\nUnsupported"},
            {"tool": "form_submit", "output": "Status: 415\nURL: http://test.local/api\nUnsupported"},
            {"tool": "form_submit", "output": "Status: 415\nURL: http://test.local/api\nUnsupported"},
        ]

        engine = ReflectionEngine(tracker)
        recent = tracker.tool_call_log[-10:]
        result = engine._detect_format_mismatch(recent)

        assert result is not None
        assert "TOOL FORMAT ISSUE" in result

    def test_format_warning_in_full_reflection(self):
        """Test format warning appears in generate_reflection output."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
        ]

        engine = ReflectionEngine(tracker)
        result = engine.generate_reflection("form_submit", '{"url": "http://test.local/api"}', 3)

        assert "[SELF-REFLECTION]" in result
        assert "TOOL FORMAT ISSUE" in result
        assert "http_fetch" in result

    def test_fewer_than_threshold_no_detection(self):
        """Test no detection with fewer than 3 format errors."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
            {"tool": "form_submit", "output": "Status: 400\nURL: http://test.local/api\nBad Request"},
        ]

        engine = ReflectionEngine(tracker)
        recent = tracker.tool_call_log[-10:]
        result = engine._detect_format_mismatch(recent)

        assert result is None


# ==============================================================================
# Prompt Tests
# ==============================================================================


class TestPromptUpdates:
    """Test that prompt templates reflect new capabilities."""

    def test_system_prompt_mentions_json_post(self):
        """Test system prompt mentions JSON POST capability."""
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "POST" in DEFAULT_SYSTEM_PROMPT
        assert "body" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_mentions_form_submit_json_fallback(self):
        """Test system prompt guides agent to use http_fetch for JSON."""
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "400/415" in DEFAULT_SYSTEM_PROMPT or "http_fetch" in DEFAULT_SYSTEM_PROMPT

    def test_json_api_example_exists(self):
        """Test JSON API few-shot example is defined."""
        from ctf_solver.prompts.templates import JSON_API_EXAMPLE
        assert JSON_API_EXAMPLE is not None
        # Should contain the key pattern: POST + body + JSON
        example_text = JSON_API_EXAMPLE.text
        assert "POST" in example_text
        assert "body" in example_text

    def test_json_api_example_in_module(self):
        """Test JSON API example is exported from prompts module."""
        from ctf_solver.prompts import JSON_API_EXAMPLE
        assert JSON_API_EXAMPLE is not None
