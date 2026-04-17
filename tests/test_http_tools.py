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
    """Create a factory for mock HTTP responses.

    Each response mock includes:
    - text, status_code, headers, url (basic response fields)
    - history=[] (redirect chain, empty by default)
    - content (bytes version of text)
    - raw.headers.items() returning [] (for Set-Cookie extraction)
    """

    def _make(text="", status_code=200, headers=None, url="http://test.local/"):
        resp = Mock()
        resp.text = text
        resp.status_code = status_code
        resp.headers = headers or {"Content-Type": "text/html"}
        resp.url = url
        resp.history = []
        resp.content = text.encode("utf-8") if isinstance(text, str) else text
        # Provide a raw.headers mock so Set-Cookie extraction doesn't blow up
        raw_headers_mock = Mock()
        raw_headers_mock.items.return_value = []
        resp.raw = Mock()
        resp.raw.headers = raw_headers_mock
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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                }
            )
        )

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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/check",
                    "method": "POST",
                    "body": {"status": ["open", "open", "open", "open"]},
                }
            )
        )

        assert "Method: POST" in result
        assert "FLAG{test}" in result
        # Verify json= was used (not data=)
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {
            "status": ["open", "open", "open", "open"]
        }

    def test_put_with_json_body(self, mock_session, mock_response):
        """Test PUT request with JSON body."""
        resp = mock_response(text='{"updated": true}', url="http://test.local/api/1")
        mock_session.put.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/1",
                    "method": "PUT",
                    "body": {"name": "updated"},
                }
            )
        )

        assert "Method: PUT" in result
        mock_session.put.assert_called_once()
        call_kwargs = mock_session.put.call_args
        assert call_kwargs.kwargs.get("json") == {"name": "updated"}

    def test_patch_with_json_body(self, mock_session, mock_response):
        """Test PATCH request with JSON body."""
        resp = mock_response(text='{"patched": true}', url="http://test.local/api/1")
        mock_session.patch.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/1",
                    "method": "PATCH",
                    "body": {"field": "value"},
                }
            )
        )

        assert "Method: PATCH" in result
        mock_session.patch.assert_called_once()

    def test_delete_request(self, mock_session, mock_response):
        """Test DELETE request."""
        resp = mock_response(text='{"deleted": true}', url="http://test.local/api/1")
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/1",
                    "method": "DELETE",
                }
            )
        )

        assert "Method: DELETE" in result
        mock_session.delete.assert_called_once()

    def test_invalid_method(self, mock_session):
        """Test that invalid methods are rejected."""
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "method": "TRACE",
                }
            )
        )

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
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "headers": {"Authorization": "Bearer token123"},
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["headers"]["Authorization"] == "Bearer token123"

    def test_query_params(self, mock_session, mock_response):
        """Test passing query parameters."""
        resp = mock_response(text="ok", url="http://test.local/?id=1")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "params": {"id": "1"},
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["params"] == {"id": "1"}

    def test_body_truncation(self, mock_session, mock_response):
        """Test response body is truncated to max_body."""
        long_text = "A" * 10000
        resp = mock_response(text=long_text, url="http://test.local/")
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "max_body": 100,
                }
            )
        )

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
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "params": {"v": "2"},
                    "body": {"data": "test"},
                }
            )
        )

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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/login",
                    "method": "POST",
                    "data": {"username": "admin", "password": "test"},
                }
            )
        )

        assert "Method: POST" in result
        assert "Welcome!" in result
        # Should use data= (form-encoded) by default
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {
            "username": "admin",
            "password": "test",
        }

    def test_json_post_with_content_type(self, mock_session, mock_response):
        """Test JSON POST when Content-Type is application/json."""
        resp = mock_response(
            text='{"message": "Access Granted! Flag: FLAG{json_win}"}',
            url="http://test.local/check",
        )
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/check",
                    "method": "POST",
                    "data": {"status": ["open", "open", "open", "open"]},
                    "headers": {"Content-Type": "application/json"},
                }
            )
        )

        assert "FLAG{json_win}" in result
        # Verify json= was used instead of data=
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {
            "status": ["open", "open", "open", "open"]
        }
        assert (
            "data" not in call_kwargs.kwargs or call_kwargs.kwargs.get("data") is None
        )

    def test_json_post_case_insensitive_header(self, mock_session, mock_response):
        """Test JSON detection is case-insensitive for Content-Type header key."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "data": {"key": "value"},
                    "headers": {"content-type": "application/json"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"key": "value"}

    def test_json_post_charset_in_content_type(self, mock_session, mock_response):
        """Test JSON detection works with charset parameter in Content-Type."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "data": {"key": "value"},
                    "headers": {"Content-Type": "application/json; charset=utf-8"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("json") == {"key": "value"}

    def test_form_encoded_without_json_header(self, mock_session, mock_response):
        """Test form-encoded POST when Content-Type is not JSON."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/form",
                    "method": "POST",
                    "data": {"field": "value"},
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}

    def test_form_encoded_no_headers(self, mock_session, mock_response):
        """Test form-encoded POST when no headers provided (default behavior)."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/form",
                    "method": "POST",
                    "data": {"field": "value"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}

    def test_get_with_params(self, mock_session, mock_response):
        """Test GET request sends data as query params."""
        resp = mock_response(text="results", url="http://test.local/search?q=test")
        mock_session.get.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/search",
                    "method": "GET",
                    "data": {"q": "test"},
                }
            )
        )

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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "method": "PUT",
                }
            )
        )

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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "method": "POST",
                }
            )
        )

        assert "Error" in result

    def test_response_truncation(self, mock_session, mock_response):
        """Test response body truncation."""
        resp = mock_response(text="A" * 10000, url="http://test.local/")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "method": "POST",
                    "max_body": 50,
                }
            )
        )

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
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/check-combination",
                    "method": "POST",
                    "body": {"status": ["open", "open", "open", "open"]},
                }
            )
        )

        assert "picoCTF{combination_cracked}" in result
        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["json"] == {
            "status": ["open", "open", "open", "open"]
        }

    def test_api_auth_pattern(self, mock_session, mock_response):
        """Test API authentication with JSON body."""
        resp = mock_response(
            text='{"token": "abc123", "flag": "FLAG{api_auth}"}',
            url="http://test.local/api/login",
        )
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/login",
                    "method": "POST",
                    "body": {"username": "admin", "password": "secret"},
                }
            )
        )

        assert "FLAG{api_auth}" in result

    def test_json_body_with_nested_objects(self, mock_session, mock_response):
        """Test sending nested JSON objects."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "body": {
                        "user": {"name": "admin", "role": "superuser"},
                        "action": "elevate",
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        body = call_kwargs.kwargs["json"]
        assert body["user"]["role"] == "superuser"

    def test_json_body_with_array(self, mock_session, mock_response):
        """Test sending JSON array as body value."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "body": {"ids": [1, 2, 3], "action": "delete"},
                }
            )
        )

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
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
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
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api1\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api2\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api3\nBad Request",
            },
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
            {
                "tool": "form_submit",
                "output": "Status: 200\nURL: http://test.local/api\nOK",
            },
            {
                "tool": "form_submit",
                "output": "Status: 404\nURL: http://test.local/api\nNot Found",
            },
            {
                "tool": "form_submit",
                "output": "Status: 200\nURL: http://test.local/api\nOK",
            },
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
            {
                "tool": "form_submit",
                "output": "Status: 415\nURL: http://test.local/api\nUnsupported",
            },
            {
                "tool": "form_submit",
                "output": "Status: 415\nURL: http://test.local/api\nUnsupported",
            },
            {
                "tool": "form_submit",
                "output": "Status: 415\nURL: http://test.local/api\nUnsupported",
            },
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
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
        ]

        engine = ReflectionEngine(tracker)
        result = engine.generate_reflection(
            "form_submit", '{"url": "http://test.local/api"}', 3
        )

        assert "[SELF-REFLECTION]" in result
        assert "TOOL FORMAT ISSUE" in result
        assert "http_fetch" in result

    def test_fewer_than_threshold_no_detection(self):
        """Test no detection with fewer than 3 format errors."""
        from ctf_solver.tools.logging_wrapper import ReflectionEngine

        tracker = Mock()
        tracker.tool_call_log = [
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
            {
                "tool": "form_submit",
                "output": "Status: 400\nURL: http://test.local/api\nBad Request",
            },
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

        assert (
            "400/415" in DEFAULT_SYSTEM_PROMPT or "http_fetch" in DEFAULT_SYSTEM_PROMPT
        )

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


# ==============================================================================
# HttpFetchTool Enhancement Tests
# ==============================================================================


class TestHttpFetchToolEnhancements:
    """Tests for new HttpFetchTool features: follow_redirects, timeout, raw_body,
    auth, binary response detection, Set-Cookie extraction, redirect chain display,
    and DELETE with body."""

    # ------------------------------------------------------------------
    # follow_redirects parameter
    # ------------------------------------------------------------------

    def test_follow_redirects_default_true(self, mock_session, mock_response):
        """Test that follow_redirects defaults to True (allow_redirects=True)."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({"url": "http://test.local/"}))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["allow_redirects"] is True

    def test_follow_redirects_false(self, mock_session, mock_response):
        """Test that follow_redirects=False passes allow_redirects=False."""
        resp = mock_response(text="Moved", status_code=302, url="http://test.local/")
        resp.headers["Location"] = "http://test.local/new"
        resp.history = []
        resp.content = b"Moved"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "follow_redirects": False,
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["allow_redirects"] is False
        assert "302" in result

    def test_follow_redirects_false_for_post(self, mock_session, mock_response):
        """Test follow_redirects=False works for POST requests too."""
        resp = mock_response(text="", status_code=303, url="http://test.local/api")
        resp.headers["Location"] = "http://test.local/result"
        resp.history = []
        resp.content = b""
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "follow_redirects": False,
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["allow_redirects"] is False

    # ------------------------------------------------------------------
    # timeout parameter
    # ------------------------------------------------------------------

    def test_timeout_default_10(self, mock_session, mock_response):
        """Test that timeout defaults to 10 seconds."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({"url": "http://test.local/"}))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["timeout"] == 10

    def test_timeout_custom_value(self, mock_session, mock_response):
        """Test passing a custom timeout value."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({"url": "http://test.local/", "timeout": 30}))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["timeout"] == 30

    def test_timeout_custom_for_post(self, mock_session, mock_response):
        """Test custom timeout is forwarded for POST requests."""
        resp = mock_response(text="ok", url="http://test.local/api")
        resp.history = []
        resp.content = b"ok"
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "timeout": 60,
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["timeout"] == 60

    def test_timeout_invalid_falls_back_to_10(self, mock_session, mock_response):
        """Test that invalid timeout value falls back to 10."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({"url": "http://test.local/", "timeout": "not-a-number"}))

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["timeout"] == 10

    # ------------------------------------------------------------------
    # raw_body parameter
    # ------------------------------------------------------------------

    def test_raw_body_post_sends_data(self, mock_session, mock_response):
        """Test raw_body sends string via data= kwarg for POST."""
        resp = mock_response(text="<result>ok</result>", url="http://test.local/soap")
        resp.history = []
        resp.content = b"<result>ok</result>"
        mock_session.post.return_value = resp

        xml_payload = '<?xml version="1.0"?><request><action>test</action></request>'
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/soap",
                    "method": "POST",
                    "raw_body": xml_payload,
                    "headers": {"Content-Type": "text/xml"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["data"] == xml_payload
        assert "json" not in call_kwargs.kwargs
        assert "ok" in result

    def test_raw_body_put_sends_data(self, mock_session, mock_response):
        """Test raw_body works with PUT method."""
        resp = mock_response(text="updated", url="http://test.local/api")
        resp.history = []
        resp.content = b"updated"
        mock_session.put.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "PUT",
                    "raw_body": "raw-text-body",
                }
            )
        )

        call_kwargs = mock_session.put.call_args
        assert call_kwargs.kwargs["data"] == "raw-text-body"

    def test_raw_body_mutually_exclusive_with_body(self, mock_session):
        """Test that providing both body and raw_body returns an error."""
        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "body": {"key": "value"},
                    "raw_body": "raw text",
                }
            )
        )

        assert "Error" in result
        assert "mutually exclusive" in result

    def test_raw_body_delete(self, mock_session, mock_response):
        """Test raw_body works with DELETE method."""
        resp = mock_response(text="deleted", url="http://test.local/api/1")
        resp.history = []
        resp.content = b"deleted"
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/1",
                    "method": "DELETE",
                    "raw_body": "<delete id='1'/>",
                }
            )
        )

        call_kwargs = mock_session.delete.call_args
        assert call_kwargs.kwargs["data"] == "<delete id='1'/>"

    # ------------------------------------------------------------------
    # auth parameter (HTTP Basic Auth)
    # ------------------------------------------------------------------

    def test_auth_basic_get(self, mock_session, mock_response):
        """Test auth parameter sends HTTP Basic Auth tuple for GET."""
        resp = mock_response(text="Authenticated", url="http://test.local/secure")
        resp.history = []
        resp.content = b"Authenticated"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/secure",
                    "auth": ["admin", "secret123"],
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["auth"] == ("admin", "secret123")
        assert "Authenticated" in result

    def test_auth_basic_post(self, mock_session, mock_response):
        """Test auth parameter works for POST requests."""
        resp = mock_response(text="ok", url="http://test.local/api")
        resp.history = []
        resp.content = b"ok"
        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "auth": ["user", "pass"],
                    "body": {"action": "do"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["auth"] == ("user", "pass")
        assert call_kwargs.kwargs["json"] == {"action": "do"}

    def test_no_auth_omits_auth_kwarg(self, mock_session, mock_response):
        """Test that omitting auth does not include auth in kwargs."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(json.dumps({"url": "http://test.local/"}))

        call_kwargs = mock_session.get.call_args
        assert "auth" not in call_kwargs.kwargs

    def test_auth_invalid_list_ignored(self, mock_session, mock_response):
        """Test that invalid auth (wrong length) is ignored."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "auth": ["only-username"],
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert "auth" not in call_kwargs.kwargs

    def test_auth_values_converted_to_strings(self, mock_session, mock_response):
        """Test that auth values are converted to strings (handles numeric input)."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/",
                    "auth": [123, 456],
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["auth"] == ("123", "456")

    # ------------------------------------------------------------------
    # Binary response detection
    # ------------------------------------------------------------------

    def _make_binary_response(self, mock_response, content_type, content_bytes):
        """Helper: create a mock response with binary content and Content-Type."""
        resp = mock_response(text="", url="http://test.local/file")
        resp.headers = {"Content-Type": content_type}
        resp.content = content_bytes
        return resp

    def test_binary_octet_stream(self, mock_session, mock_response):
        """Test binary detection for application/octet-stream."""
        binary_data = bytes(range(256)) * 4  # 1024 bytes
        resp = self._make_binary_response(
            mock_response, "application/octet-stream", binary_data
        )
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result
        assert "1024 bytes" in result
        assert "Hex preview" in result
        assert "truncated" in result  # 1024 > 512 so should show truncated

    def test_binary_image_png(self, mock_session, mock_response):
        """Test binary detection for image/png."""
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        resp = self._make_binary_response(mock_response, "image/png", png_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result
        assert "Hex preview" in result

    def test_binary_audio_mpeg(self, mock_session, mock_response):
        """Test binary detection for audio/mpeg."""
        audio_data = b"\xff\xfb\x90\x00" + b"\x00" * 50
        resp = self._make_binary_response(mock_response, "audio/mpeg", audio_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result

    def test_binary_video_mp4(self, mock_session, mock_response):
        """Test binary detection for video/mp4."""
        video_data = b"\x00\x00\x00\x1c" + b"ftyp" + b"\x00" * 50
        resp = self._make_binary_response(mock_response, "video/mp4", video_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result

    def test_binary_pdf(self, mock_session, mock_response):
        """Test binary detection for application/pdf."""
        pdf_data = b"%PDF-1.4 " + b"\x00" * 100
        resp = self._make_binary_response(mock_response, "application/pdf", pdf_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result

    def test_binary_zip(self, mock_session, mock_response):
        """Test binary detection for application/zip."""
        zip_data = b"PK\x03\x04" + b"\x00" * 100
        resp = self._make_binary_response(mock_response, "application/zip", zip_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result

    def test_binary_gzip(self, mock_session, mock_response):
        """Test binary detection for application/gzip."""
        gzip_data = b"\x1f\x8b\x08" + b"\x00" * 100
        resp = self._make_binary_response(mock_response, "application/gzip", gzip_data)
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result

    def test_binary_hex_preview_first_512_bytes(self, mock_session, mock_response):
        """Test hex preview shows exactly the first 512 bytes."""
        binary_data = bytes(range(256)) * 4  # 1024 bytes total
        resp = self._make_binary_response(
            mock_response, "application/octet-stream", binary_data
        )
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        expected_hex = binary_data[:512].hex()
        assert expected_hex in result

    def test_binary_small_no_truncation_marker(self, mock_session, mock_response):
        """Test binary response <= 512 bytes does not show ...[truncated]... marker."""
        small_binary = b"\x00\x01\x02\x03"  # 4 bytes
        resp = self._make_binary_response(
            mock_response, "application/octet-stream", small_binary
        )
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/file"}))

        assert "[Binary response" in result
        assert "4 bytes" in result
        assert "...[truncated]..." not in result

    def test_non_binary_content_type_returns_text(self, mock_session, mock_response):
        """Test that text/html content is NOT treated as binary."""
        resp = mock_response(text="<html>Hello</html>", url="http://test.local/")
        resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        resp.content = b"<html>Hello</html>"
        resp.history = []
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "[Binary response" not in result
        assert "Hello" in result

    # ------------------------------------------------------------------
    # Set-Cookie header extraction
    # ------------------------------------------------------------------

    def test_set_cookie_extraction_from_response(self, mock_session, mock_response):
        """Test Set-Cookie headers are extracted and displayed."""
        resp = mock_response(text="ok", url="http://test.local/login")
        resp.history = []
        resp.content = b"ok"
        # Mock the headers as a dict-like with items() returning Set-Cookie
        resp.headers = {
            "Content-Type": "text/html",
            "Set-Cookie": "session=abc123; Path=/; HttpOnly",
        }

        mock_session.post.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/login",
                    "method": "POST",
                    "body": {"user": "admin"},
                }
            )
        )

        assert "[SET-COOKIE HEADERS]" in result
        assert "session=abc123" in result

    def test_no_set_cookie_section_when_absent(self, mock_session, mock_response):
        """Test no Set-Cookie section when no cookies in response."""
        resp = mock_response(text="ok", url="http://test.local/")
        resp.history = []
        resp.content = b"ok"
        resp.headers = {"Content-Type": "text/html"}
        # Ensure no raw attribute that would confuse the code
        if hasattr(resp, "raw"):
            del resp.raw
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "[SET-COOKIE HEADERS]" not in result

    # ------------------------------------------------------------------
    # Redirect chain display
    # ------------------------------------------------------------------

    @staticmethod
    def _make_redirect_mock(status_code, url, location, extra_headers=None):
        """Helper: create a mock redirect response with proper raw.headers."""
        r = Mock()
        r.status_code = status_code
        r.url = url
        hdrs = {"Location": location, "Content-Type": "text/html"}
        if extra_headers:
            hdrs.update(extra_headers)
        r.headers = hdrs
        raw_headers = Mock()
        raw_headers.items.return_value = []
        r.raw = Mock()
        r.raw.headers = raw_headers
        return r

    def test_redirect_chain_display(self, mock_session, mock_response):
        """Test redirect chain is shown when response has history."""
        redirect1 = self._make_redirect_mock(
            301, "http://test.local/old", "http://test.local/new"
        )
        redirect2 = self._make_redirect_mock(
            302, "http://test.local/new", "http://test.local/final"
        )

        final_resp = mock_response(text="Final page", url="http://test.local/final")
        final_resp.history = [redirect1, redirect2]

        mock_session.get.return_value = final_resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/old"}))

        assert "Redirect chain:" in result
        assert "301" in result
        assert "http://test.local/old" in result
        assert "302" in result
        assert "http://test.local/new" in result
        assert "Final page" in result

    def test_no_redirect_chain_when_no_history(self, mock_session, mock_response):
        """Test no redirect chain section when response has no history."""
        resp = mock_response(text="Direct hit", url="http://test.local/")
        resp.history = []
        resp.content = b"Direct hit"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/"}))

        assert "Redirect chain:" not in result

    def test_single_redirect_in_chain(self, mock_session, mock_response):
        """Test redirect chain with a single hop."""
        redirect = self._make_redirect_mock(
            302, "http://test.local/start", "http://test.local/end"
        )

        final_resp = mock_response(text="End", url="http://test.local/end")
        final_resp.history = [redirect]

        mock_session.get.return_value = final_resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(json.dumps({"url": "http://test.local/start"}))

        assert "Redirect chain:" in result
        assert "302" in result
        assert "http://test.local/start" in result
        assert "http://test.local/end" in result

    # ------------------------------------------------------------------
    # DELETE method with body
    # ------------------------------------------------------------------

    def test_delete_with_json_body(self, mock_session, mock_response):
        """Test DELETE request with a JSON body."""
        resp = mock_response(
            text='{"deleted": true}', url="http://test.local/api/item/5"
        )
        resp.history = []
        resp.content = b'{"deleted": true}'
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/item/5",
                    "method": "DELETE",
                    "body": {"confirm": True, "reason": "cleanup"},
                }
            )
        )

        assert "Method: DELETE" in result
        call_kwargs = mock_session.delete.call_args
        assert call_kwargs.kwargs["json"] == {"confirm": True, "reason": "cleanup"}

    def test_delete_without_body(self, mock_session, mock_response):
        """Test DELETE request without body still works (no json= or data= kwarg)."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api/item/5")
        resp.history = []
        resp.content = b'{"ok": true}'
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/item/5",
                    "method": "DELETE",
                }
            )
        )

        assert "Method: DELETE" in result
        call_kwargs = mock_session.delete.call_args
        assert "json" not in call_kwargs.kwargs
        assert "data" not in call_kwargs.kwargs

    def test_delete_with_raw_body(self, mock_session, mock_response):
        """Test DELETE request with raw_body parameter."""
        resp = mock_response(text="gone", url="http://test.local/api/item")
        resp.history = []
        resp.content = b"gone"
        mock_session.delete.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api/item",
                    "method": "DELETE",
                    "raw_body": "<delete><id>42</id></delete>",
                }
            )
        )

        call_kwargs = mock_session.delete.call_args
        assert call_kwargs.kwargs["data"] == "<delete><id>42</id></delete>"

    # ------------------------------------------------------------------
    # Combined features
    # ------------------------------------------------------------------

    def test_combined_auth_timeout_redirect(self, mock_session, mock_response):
        """Test auth + custom timeout + follow_redirects together."""
        resp = mock_response(text="secure content", url="http://test.local/secure")
        resp.history = []
        resp.content = b"secure content"
        mock_session.get.return_value = resp

        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/secure",
                    "auth": ["admin", "pass"],
                    "timeout": 25,
                    "follow_redirects": False,
                }
            )
        )

        call_kwargs = mock_session.get.call_args
        assert call_kwargs.kwargs["auth"] == ("admin", "pass")
        assert call_kwargs.kwargs["timeout"] == 25
        assert call_kwargs.kwargs["allow_redirects"] is False

    def test_post_raw_body_with_auth_and_timeout(self, mock_session, mock_response):
        """Test POST with raw_body, auth, and custom timeout."""
        resp = mock_response(text="response", url="http://test.local/soap")
        resp.history = []
        resp.content = b"response"
        mock_session.post.return_value = resp

        xml = "<Envelope><Body>test</Body></Envelope>"
        tool = HttpFetchTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/soap",
                    "method": "POST",
                    "raw_body": xml,
                    "auth": ["svc", "key"],
                    "timeout": 45,
                    "headers": {"Content-Type": "text/xml; charset=utf-8"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["data"] == xml
        assert call_kwargs.kwargs["auth"] == ("svc", "key")
        assert call_kwargs.kwargs["timeout"] == 45

    def test_redirect_chain_with_set_cookies(self, mock_session, mock_response):
        """Test redirect chain and Set-Cookie are both shown."""
        redirect = self._make_redirect_mock(
            302,
            "http://test.local/login",
            "http://test.local/dashboard",
            extra_headers={"Set-Cookie": "token=xyz; Path=/"},
        )

        final_resp = mock_response(text="Dashboard", url="http://test.local/dashboard")
        final_resp.history = [redirect]
        final_resp.headers = {
            "Content-Type": "text/html",
            "Set-Cookie": "pref=dark; Path=/",
        }

        mock_session.post.return_value = final_resp

        tool = HttpFetchTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/login",
                    "method": "POST",
                    "body": {"user": "admin", "pass": "secret"},
                }
            )
        )

        assert "Redirect chain:" in result
        assert "302" in result
        # At minimum the final response's Set-Cookie should appear
        assert "[SET-COOKIE HEADERS]" in result


# ==============================================================================
# FormSubmitTool Enhancement Tests
# ==============================================================================


class TestFormSubmitToolEnhancements:
    """Tests for new FormSubmitTool features: multipart parameter and files parameter."""

    # ------------------------------------------------------------------
    # multipart parameter (no files)
    # ------------------------------------------------------------------

    def test_multipart_true_no_files_sends_multipart(self, mock_session, mock_response):
        """Test multipart=True without files uses files={k: (None, v)} trick."""
        resp = mock_response(text="Uploaded", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "data": {"name": "test", "value": "123"},
                    "multipart": True,
                }
            )
        )

        assert "Uploaded" in result
        call_kwargs = mock_session.post.call_args
        # Should use files= kwarg with (None, value) tuples
        files_sent = call_kwargs.kwargs.get("files")
        assert files_sent is not None
        assert files_sent["name"] == (None, "test")
        assert files_sent["value"] == (None, "123")
        # Should NOT use data= directly for the form fields
        assert (
            call_kwargs.kwargs.get("data") is None or "data" not in call_kwargs.kwargs
        )

    def test_multipart_false_sends_form_encoded(self, mock_session, mock_response):
        """Test multipart=False (default) uses regular form-encoded data."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/form",
                    "method": "POST",
                    "data": {"field": "value"},
                    "multipart": False,
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}
        assert (
            "files" not in call_kwargs.kwargs or call_kwargs.kwargs.get("files") is None
        )

    def test_multipart_default_false(self, mock_session, mock_response):
        """Test multipart defaults to False when omitted."""
        resp = mock_response(text="ok", url="http://test.local/form")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/form",
                    "method": "POST",
                    "data": {"field": "value"},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs.get("data") == {"field": "value"}

    # ------------------------------------------------------------------
    # files parameter
    # ------------------------------------------------------------------

    def test_files_single_file_upload(self, mock_session, mock_response):
        """Test file upload with a single file field."""
        resp = mock_response(text="File received", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "data": {"description": "my file"},
                    "files": {
                        "file": {
                            "filename": "test.txt",
                            "content": "Hello, World!",
                            "content_type": "text/plain",
                        },
                    },
                }
            )
        )

        assert "File received" in result
        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs.get("files")
        assert files_sent is not None
        assert "file" in files_sent
        fname, fcontent, fct = files_sent["file"]
        assert fname == "test.txt"
        assert fcontent == b"Hello, World!"
        assert fct == "text/plain"
        # data should also be sent alongside files
        assert call_kwargs.kwargs.get("data") == {"description": "my file"}

    def test_files_multiple_fields(self, mock_session, mock_response):
        """Test file upload with multiple file fields."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "files": {
                        "avatar": {
                            "filename": "photo.jpg",
                            "content": "JFIF-data",
                            "content_type": "image/jpeg",
                        },
                        "resume": {
                            "filename": "resume.pdf",
                            "content": "PDF-data",
                            "content_type": "application/pdf",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        assert "avatar" in files_sent
        assert "resume" in files_sent
        assert files_sent["avatar"][0] == "photo.jpg"
        assert files_sent["avatar"][2] == "image/jpeg"
        assert files_sent["resume"][0] == "resume.pdf"
        assert files_sent["resume"][2] == "application/pdf"

    def test_files_default_content_type(self, mock_session, mock_response):
        """Test file upload defaults content_type to application/octet-stream."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "files": {
                        "binary": {
                            "filename": "data.bin",
                            "content": "some bytes",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        _, _, ct = files_sent["binary"]
        assert ct == "application/octet-stream"

    def test_files_default_filename(self, mock_session, mock_response):
        """Test file upload defaults filename to 'file' when omitted."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "files": {
                        "attachment": {
                            "content": "payload data",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        fname, _, _ = files_sent["attachment"]
        assert fname == "file"

    def test_files_string_shorthand(self, mock_session, mock_response):
        """Test file upload with string value shorthand (instead of dict)."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "files": {
                        "payload": "raw file content here",
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        fname, fcontent, fct = files_sent["payload"]
        assert fname == "payload"  # field name used as filename
        assert fcontent == b"raw file content here"
        assert fct == "application/octet-stream"

    def test_files_content_encoded_to_bytes(self, mock_session, mock_response):
        """Test that file content strings are encoded to bytes (UTF-8)."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        unicode_content = "Hello \u00e9\u00e0\u00fc"
        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "files": {
                        "file": {
                            "filename": "unicode.txt",
                            "content": unicode_content,
                            "content_type": "text/plain; charset=utf-8",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        _, fcontent, _ = files_sent["file"]
        assert isinstance(fcontent, bytes)
        assert fcontent == unicode_content.encode("utf-8")

    def test_files_with_data_fields(self, mock_session, mock_response):
        """Test files and regular form data are sent together."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "data": {"title": "My Upload", "category": "ctf"},
                    "files": {
                        "file": {
                            "filename": "exploit.py",
                            "content": "import os; os.system('id')",
                            "content_type": "text/x-python",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        assert call_kwargs.kwargs["data"] == {"title": "My Upload", "category": "ctf"}
        assert "file" in call_kwargs.kwargs["files"]

    def test_files_takes_precedence_over_multipart(self, mock_session, mock_response):
        """Test that when files are present, files_dict is used (not the multipart trick)."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "data": {"extra": "field"},
                    "multipart": True,
                    "files": {
                        "doc": {
                            "filename": "doc.pdf",
                            "content": "pdf-bytes",
                            "content_type": "application/pdf",
                        },
                    },
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        # files_dict should contain actual file tuples, not (None, v) trick
        assert files_sent["doc"][0] == "doc.pdf"
        assert files_sent["doc"][1] == b"pdf-bytes"
        # data should also be sent for the form fields
        assert call_kwargs.kwargs["data"] == {"extra": "field"}

    def test_multipart_json_content_type_takes_precedence(
        self, mock_session, mock_response
    ):
        """Test that application/json Content-Type takes precedence over multipart flag."""
        resp = mock_response(text='{"ok": true}', url="http://test.local/api")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/api",
                    "method": "POST",
                    "data": {"key": "value"},
                    "headers": {"Content-Type": "application/json"},
                    "multipart": True,
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        # JSON should win over multipart
        assert call_kwargs.kwargs.get("json") == {"key": "value"}

    def test_empty_files_dict_triggers_multipart_trick(
        self, mock_session, mock_response
    ):
        """Test that empty files={} with multipart=True uses the (None, v) trick."""
        resp = mock_response(text="ok", url="http://test.local/upload")
        mock_session.post.return_value = resp

        tool = FormSubmitTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.local/upload",
                    "method": "POST",
                    "data": {"field1": "val1"},
                    "multipart": True,
                    "files": {},
                }
            )
        )

        call_kwargs = mock_session.post.call_args
        files_sent = call_kwargs.kwargs["files"]
        # Empty files_dict means the code falls through to the multipart trick
        assert files_sent["field1"] == (None, "val1")
