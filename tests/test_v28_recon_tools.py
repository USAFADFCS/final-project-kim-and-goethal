"""
Tests for v2.8.0 recon meta-tools: SecurityHeaderAnalyzerTool and DeepReconTool.

SecurityHeaderAnalyzerTool analyzes HTTP response headers for security
misconfigurations, server/tech leaks, debug headers, CORS, cookie flags,
and CTF-relevant hints.

DeepReconTool orchestrates 6 sub-tools (http_fetch, html_inspector,
javascript_source, robots_txt, cookie_inspector, security_header_analyzer)
in a single call to save 4-5 ReAct cycles.
"""

import json
from unittest.mock import MagicMock

import requests

from ctf_solver.tools.recon_tools import DeepReconTool, SecurityHeaderAnalyzerTool

# ── Helpers ─────────────────────────────────────────────────────────────


def _mock_response(
    status_code: int = 200,
    headers: dict = None,
    text: str = "",
    set_cookies: list = None,
) -> MagicMock:
    """Build a mock requests.Response with the given attributes."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode()

    h = requests.structures.CaseInsensitiveDict(headers or {})
    resp.headers = h

    # Mock raw headers for cookie parsing
    raw = MagicMock()
    if set_cookies:
        raw.headers = MagicMock()
        raw.headers.getlist = MagicMock(return_value=set_cookies)
    else:
        raw.headers = MagicMock()
        raw.headers.getlist = MagicMock(return_value=[])
    resp.raw = raw

    return resp


def _make_session(response: MagicMock) -> MagicMock:
    """Create a mock session that returns the given response for GET."""
    session = MagicMock(spec=requests.Session)
    session.get = MagicMock(return_value=response)
    return session


# ═══════════════════════════════════════════════════════════════════════
# SecurityHeaderAnalyzerTool tests
# ═══════════════════════════════════════════════════════════════════════


class TestSecurityHeaderAnalyzerFAIR:
    """FAIR interface compliance."""

    def test_name_attribute(self):
        tool = SecurityHeaderAnalyzerTool()
        assert tool.name == "security_header_analyzer"

    def test_description_attribute(self):
        tool = SecurityHeaderAnalyzerTool()
        assert "security" in tool.description.lower()
        assert "header" in tool.description.lower()


class TestSecurityHeaderAnalyzerErrors:
    """Input validation and error handling."""

    def test_empty_url_returns_error(self):
        tool = SecurityHeaderAnalyzerTool()
        result = tool.use(json.dumps({"url": ""}))
        assert "Error" in result
        assert "'url' is required" in result

    def test_no_input_returns_error(self):
        tool = SecurityHeaderAnalyzerTool()
        result = tool.use("{}")
        assert "Error" in result

    def test_malformed_json_returns_error(self):
        tool = SecurityHeaderAnalyzerTool()
        result = tool.use("not json")
        assert "Error" in result
        assert "JSON" in result

    def test_network_error_returns_error(self):
        session = MagicMock(spec=requests.Session)
        session.get = MagicMock(
            side_effect=requests.exceptions.ConnectionError("refused")
        )
        tool = SecurityHeaderAnalyzerTool(session=session)
        result = tool.use(json.dumps({"url": "http://example.com"}))
        assert "Error" in result
        assert "example.com" in result


class TestSecurityHeaderAnalyzerMissing:
    """Missing security header detection."""

    def test_missing_all_security_headers(self):
        resp = _mock_response(headers={})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "MISSING SECURITY HEADERS" in result
        assert "Content-Security-Policy" in result
        assert "X-Frame-Options" in result
        assert "X-Content-Type-Options" in result

    def test_all_security_headers_present(self):
        resp = _mock_response(
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            }
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        # Should not have the MISSING section (or it should be empty)
        assert "MISSING SECURITY HEADERS" not in result


class TestSecurityHeaderAnalyzerLeaks:
    """Server/technology leak detection."""

    def test_server_version_leak(self):
        resp = _mock_response(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "TECHNOLOGY LEAKS" in result
        assert "Apache/2.4.41" in result

    def test_x_powered_by_leak(self):
        resp = _mock_response(headers={"X-Powered-By": "PHP/7.4.3"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "PHP/7.4.3" in result


class TestSecurityHeaderAnalyzerDebug:
    """Debug/custom header detection."""

    def test_debug_header_detected(self):
        resp = _mock_response(headers={"X-Debug-Token": "abc123"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "DEBUG" in result
        assert "X-Debug-Token" in result
        assert "abc123" in result

    def test_custom_header_with_flag_keyword(self):
        resp = _mock_response(headers={"X-Flag-Hint": "look_deeper"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "X-Flag-Hint" in result


class TestSecurityHeaderAnalyzerCORS:
    """CORS configuration analysis."""

    def test_cors_wildcard_origin(self):
        resp = _mock_response(headers={"Access-Control-Allow-Origin": "*"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "CORS" in result
        assert "overly permissive" in result

    def test_cors_credentials_with_wildcard(self):
        resp = _mock_response(
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "credentials" in result.lower()


class TestSecurityHeaderAnalyzerCookies:
    """Cookie security flag analysis."""

    def test_cookie_missing_httponly(self):
        resp = _mock_response(
            headers={"Set-Cookie": "session=abc123; Path=/"},
            set_cookies=["session=abc123; Path=/"],
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "COOKIE" in result
        assert "HttpOnly" in result

    def test_cookie_interesting_name_role(self):
        resp = _mock_response(
            headers={"Set-Cookie": "role=user; Path=/"},
            set_cookies=["role=user; Path=/"],
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "role" in result.lower()
        assert "user" in result


class TestSecurityHeaderAnalyzerHints:
    """CTF hint generation."""

    def test_php_detection_triggers_hint(self):
        resp = _mock_response(headers={"X-Powered-By": "PHP/7.4"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "CTF HINTS" in result
        assert "PHP" in result

    def test_no_csp_triggers_xss_hint(self):
        resp = _mock_response(headers={})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "XSS" in result

    def test_werkzeug_console_hint(self):
        resp = _mock_response(headers={"Server": "Werkzeug/2.0.1 Python/3.9"})
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "/console" in result

    def test_flask_detection_hint(self):
        resp = _mock_response(
            headers={"Server": "Werkzeug/2.0.1", "X-Powered-By": "Flask"}
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "Jinja2" in result or "Flask" in result

    def test_cookie_access_control_hint(self):
        resp = _mock_response(
            headers={"Set-Cookie": "admin=false; Path=/"},
            set_cookies=["admin=false; Path=/"],
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "cookie_set" in result or "Access-control cookie" in result

    def test_all_headers_listed_raw(self):
        resp = _mock_response(
            headers={
                "X-Custom": "value1",
                "Server": "test-server",
            }
        )
        session = _make_session(resp)
        tool = SecurityHeaderAnalyzerTool(session=session)

        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "ALL RESPONSE HEADERS" in result
        assert "X-Custom: value1" in result


# ═══════════════════════════════════════════════════════════════════════
# DeepReconTool tests
# ═══════════════════════════════════════════════════════════════════════


class TestDeepReconFAIR:
    """FAIR interface compliance."""

    def test_name_attribute(self):
        tool = DeepReconTool()
        assert tool.name == "deep_recon"

    def test_description_attribute(self):
        tool = DeepReconTool()
        assert "reconnaissance" in tool.description.lower()
        assert "url" in tool.description.lower()


class TestDeepReconErrors:
    """Input validation."""

    def test_empty_url_returns_error(self):
        tool = DeepReconTool()
        result = tool.use(json.dumps({"url": ""}))
        assert "Error" in result

    def test_no_input_returns_error(self):
        tool = DeepReconTool()
        result = tool.use("{}")
        assert "Error" in result

    def test_malformed_json_returns_error(self):
        tool = DeepReconTool()
        result = tool.use("not json")
        assert "Error" in result


class TestDeepReconSections:
    """Verify output structure and sub-tool orchestration."""

    def _make_tool_with_mocks(self):
        """Create a DeepReconTool with all sub-tools mocked."""
        tool = DeepReconTool()
        tool._http_tool = MagicMock()
        tool._http_tool.use = MagicMock(
            return_value="[HttpFetchTool] Status: 200\nBody: <html>hello</html>"
        )
        tool._html_tool = MagicMock()
        tool._html_tool.use = MagicMock(
            return_value="[HtmlInspectorTool] FORMS: 1 login form"
        )
        tool._js_tool = MagicMock()
        tool._js_tool.use = MagicMock(
            return_value="[JavaScriptSourceTool] INLINE SCRIPT: var x = 1;"
        )
        tool._robots_tool = MagicMock()
        tool._robots_tool.use = MagicMock(
            return_value="[RobotsTxtTool] Disallow: /admin"
        )
        tool._cookie_tool = MagicMock()
        tool._cookie_tool.use = MagicMock(
            return_value="[CookieInspectorTool] session=abc123"
        )
        tool._header_tool = MagicMock()
        tool._header_tool.use = MagicMock(
            return_value="[SecurityHeaderAnalyzerTool] CTF HINTS: PHP detected"
        )
        return tool

    def test_full_recon_all_sections(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "SECTION 1: HTTP RESPONSE" in result
        assert "SECTION 2: HTML STRUCTURE" in result
        assert "SECTION 3: JAVASCRIPT ANALYSIS" in result
        assert "SECTION 4: ROBOTS.TXT" in result
        assert "SECTION 5: COOKIES" in result
        assert "SECTION 6: SECURITY HEADERS" in result
        assert "RECON SUMMARY" in result

    def test_sub_tool_outputs_included(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(json.dumps({"url": "http://example.com"}))

        assert "[HttpFetchTool]" in result
        assert "[HtmlInspectorTool]" in result
        assert "[JavaScriptSourceTool]" in result
        assert "[RobotsTxtTool]" in result
        assert "[CookieInspectorTool]" in result
        assert "[SecurityHeaderAnalyzerTool]" in result

    def test_summary_captures_findings(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(json.dumps({"url": "http://example.com"}))

        # HTML has FORMS → finding
        assert "Forms detected" in result
        # JS has INLINE SCRIPT → finding
        assert "JavaScript code found" in result
        # Robots has Disallow → finding
        assert "disallowed paths" in result
        # Cookies have = → finding
        assert "Cookies set" in result
        # Headers have CTF HINTS → finding
        assert "CTF hints" in result

    def test_skip_robots(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(
            json.dumps({"url": "http://example.com", "skip": ["robots_txt"]})
        )

        assert "SECTION 4: ROBOTS.TXT" not in result
        # Other sections still present
        assert "SECTION 1: HTTP RESPONSE" in result
        assert "SECTION 2: HTML STRUCTURE" in result

    def test_skip_multiple(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(
            json.dumps(
                {
                    "url": "http://example.com",
                    "skip": ["javascript_source", "robots_txt", "security_headers"],
                }
            )
        )

        assert "SECTION 3: JAVASCRIPT" not in result
        assert "SECTION 4: ROBOTS" not in result
        assert "SECTION 6: SECURITY" not in result
        # Remaining sections present
        assert "SECTION 1: HTTP RESPONSE" in result
        assert "SECTION 5: COOKIES" in result

    def test_base_url_derived_from_url(self):
        tool = self._make_tool_with_mocks()
        tool.use(json.dumps({"url": "http://example.com/some/path"}))

        # robots_txt should receive base_url = http://example.com
        robots_call = tool._robots_tool.use.call_args[0][0]
        robots_data = json.loads(robots_call)
        assert robots_data["base_url"] == "http://example.com"

    def test_base_url_explicit(self):
        tool = self._make_tool_with_mocks()
        tool.use(
            json.dumps(
                {
                    "url": "http://example.com/path",
                    "base_url": "http://custom-base.com",
                }
            )
        )

        robots_call = tool._robots_tool.use.call_args[0][0]
        robots_data = json.loads(robots_call)
        assert robots_data["base_url"] == "http://custom-base.com"

    def test_sub_tool_failure_does_not_abort(self):
        tool = self._make_tool_with_mocks()
        # Make html_inspector raise an exception
        tool._html_tool.use = MagicMock(side_effect=Exception("parse error"))

        result = tool.use(json.dumps({"url": "http://example.com"}))

        # html section should show error but other sections still present
        assert "[Error]" in result
        assert "parse error" in result
        assert "SECTION 1: HTTP RESPONSE" in result
        assert "SECTION 3: JAVASCRIPT" in result
        assert "SECTION 5: COOKIES" in result

    def test_max_body_forwarded(self):
        tool = self._make_tool_with_mocks()
        tool.use(json.dumps({"url": "http://example.com", "max_body": 8000}))

        http_call = tool._http_tool.use.call_args[0][0]
        http_data = json.loads(http_call)
        assert http_data["max_body"] == 8000

    def test_target_url_in_header(self):
        tool = self._make_tool_with_mocks()
        result = tool.use(json.dumps({"url": "http://example.com/challenge"}))

        assert "Target: http://example.com/challenge" in result

    def test_shared_session_passed_to_sub_tools(self):
        """All sub-tools should share the same session."""
        session = MagicMock(spec=requests.Session)
        tool = DeepReconTool(session=session)

        assert tool._http_tool.session is session
        assert tool._html_tool.session is session
        assert tool._js_tool.session is session
        assert tool._robots_tool.session is session
        assert tool._cookie_tool.session is session
        assert tool._header_tool.session is session
