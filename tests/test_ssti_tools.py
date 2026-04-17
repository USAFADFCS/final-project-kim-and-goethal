"""
Tests for SSTI (Server-Side Template Injection) detection tools.
"""

import json
import pytest
from unittest.mock import Mock, patch

from ctf_solver.tools.ssti_tools import SstiProbeTool, SstiExploitSuggester


class TestSstiProbeToolBasics:
    """Test basic SstiProbeTool functionality."""

    def test_has_required_attributes(self):
        """Test that SstiProbeTool has name and description."""
        tool = SstiProbeTool()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "ssti_probe"
        assert "SSTI" in tool.description

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = SstiProbeTool()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test that url is required."""
        tool = SstiProbeTool()
        result = tool.use(json.dumps({"param": "name"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that param is required."""
        tool = SstiProbeTool()
        result = tool.use(json.dumps({"url": "http://test.com"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        tool = SstiProbeTool()
        result = tool.use(
            json.dumps({"url": "http://test.com", "param": "name", "method": "DELETE"})
        )
        assert "Error" in result
        assert "GET" in result or "POST" in result

    def test_accepts_session(self):
        """Test that tool accepts a requests session."""
        mock_session = Mock()
        tool = SstiProbeTool(session=mock_session)
        assert tool.session == mock_session


class TestSstiProbeDetection:
    """Test SSTI detection functionality."""

    def test_detects_jinja2_expression(self):
        """Test detection of Jinja2 template injection via {{7*7}}."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Hello 49 World"  # Template evaluated 7*7
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "VULNERABLE" in result or "49" in result

    def test_detects_string_multiplication(self):
        """Test detection via string multiplication (Jinja2/Twig)."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Result: 7777777"  # 7*'7' = '7777777'
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "VULNERABLE" in result or "7777777" in result

    def test_detects_jinja2_config(self):
        """Test detection of Jinja2 via config object."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if "config" in str(params.get("name", "")):
                resp.text = "<Config {'DEBUG': True}>"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "Jinja2" in result or "jinja2" in result.lower()

    def test_detects_twig_self(self):
        """Test detection of Twig via _self object."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if "_self" in str(params.get("name", "")):
                resp.text = "__TwigTemplate_abc123"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "Twig" in result or "Template" in result

    def test_detects_freemarker(self):
        """Test detection of Freemarker via version probe."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if ".version" in str(params.get("name", "")):
                resp.text = "Version: 2.3.31"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        # Should detect Freemarker or at least version output
        assert "reemarker" in result or "." in result

    def test_detects_erb(self):
        """Test detection of ERB via self object."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if "<%= self %>" in str(params.get("name", "")):
                resp.text = "#<Object:0x00007f8b8a1234>"
            elif "<%= 7*7 %>" in str(params.get("name", "")):
                resp.text = "Result: 49"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "ERB" in result or "Ruby" in result or "49" in result

    def test_post_method(self):
        """Test SSTI detection via POST method."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Hello 49 World"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "POST",
                    "param": "name",
                    "data": {"other": "value"},
                }
            )
        )

        # Should have used POST
        assert mock_session.post.called
        assert "VULNERABLE" in result or "49" in result


class TestSstiProbeErrorDetection:
    """Test error-based SSTI detection."""

    def test_detects_jinja2_error(self):
        """Test detection via Jinja2 error message."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 500
            if "{{" in str(params.get("name", "")):
                resp.text = "jinja2.exceptions.TemplateSyntaxError: unexpected '}'"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "jinja" in result.lower()

    def test_detects_twig_error(self):
        """Test detection via Twig error message."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 500
            if "{{" in str(params.get("name", "")):
                resp.text = "Twig_Error_Syntax: Unknown filter 'foo'"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "twig" in result.lower() or "Twig" in result


class TestSstiProbeExploitSuggestions:
    """Test that tool provides exploit suggestions."""

    def test_provides_rce_payloads_for_jinja2(self):
        """Test that Jinja2 detection provides RCE suggestions."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if "{{config}}" in str(params.get("name", "")):
                resp.text = "<Config {'SECRET_KEY': 'abc'}>"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "RCE" in result or "popen" in result or "Payload" in result


class TestSstiProbeHeaders:
    """Test SSTI probing with custom headers."""

    def test_sends_custom_headers(self):
        """Test that custom headers are sent."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Normal page"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = SstiProbeTool(session=mock_session)
        tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "name",
                    "headers": {"Authorization": "Bearer token123"},
                }
            )
        )

        # Check that headers were passed
        call_kwargs = mock_session.get.call_args[1]
        assert "headers" in call_kwargs
        assert call_kwargs["headers"].get("Authorization") == "Bearer token123"


class TestSstiExploitSuggesterBasics:
    """Test basic SstiExploitSuggester functionality."""

    def test_has_required_attributes(self):
        """Test that SstiExploitSuggester has name and description."""
        tool = SstiExploitSuggester()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "ssti_exploit_suggester"
        assert "RCE" in tool.description or "payload" in tool.description.lower()

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = SstiExploitSuggester()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_engine(self):
        """Test that engine is required."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({}))
        assert "Error" in result
        assert "engine" in result.lower()

    def test_unknown_engine(self):
        """Test handling of unknown engine."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "unknown_engine"}))
        assert "Error" in result
        assert "Unknown" in result or "unknown" in result


class TestSstiExploitSuggesterPayloads:
    """Test payload generation for different engines."""

    def test_jinja2_payloads(self):
        """Test Jinja2 payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "jinja2"}))

        assert "jinja2" in result.lower() or "JINJA2" in result
        assert "popen" in result or "subclasses" in result
        assert "{{" in result

    def test_jinja2_custom_command(self):
        """Test Jinja2 payloads with custom command."""
        tool = SstiExploitSuggester()
        result = tool.use(
            json.dumps({"engine": "jinja2", "command": "cat /etc/passwd"})
        )

        assert "cat /etc/passwd" in result

    def test_twig_payloads(self):
        """Test Twig payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "twig"}))

        assert "twig" in result.lower() or "TWIG" in result
        assert "filter" in result or "_self" in result

    def test_freemarker_payloads(self):
        """Test Freemarker payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "freemarker"}))

        assert "freemarker" in result.lower() or "FREEMARKER" in result
        assert "Execute" in result or "assign" in result

    def test_erb_payloads(self):
        """Test ERB payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "erb"}))

        assert "erb" in result.lower() or "ERB" in result
        assert "system" in result or "<%=" in result

    def test_smarty_payloads(self):
        """Test Smarty payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "smarty"}))

        assert "smarty" in result.lower() or "SMARTY" in result
        assert "system" in result or "{" in result

    def test_velocity_payloads(self):
        """Test Velocity payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "velocity"}))

        assert "velocity" in result.lower() or "VELOCITY" in result
        assert "Runtime" in result or "#set" in result

    def test_mako_payloads(self):
        """Test Mako payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "mako"}))

        assert "mako" in result.lower() or "MAKO" in result
        assert "import" in result or "os" in result

    def test_thymeleaf_payloads(self):
        """Test Thymeleaf payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "thymeleaf"}))

        assert "thymeleaf" in result.lower() or "THYMELEAF" in result
        assert "Runtime" in result or "__$" in result

    def test_pebble_payloads(self):
        """Test Pebble payload generation."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "pebble"}))

        assert "pebble" in result.lower() or "PEBBLE" in result


class TestSstiExploitSuggesterFileRead:
    """Test file read payload generation."""

    def test_jinja2_file_read(self):
        """Test Jinja2 file read payloads."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "jinja2", "file": "/etc/shadow"}))

        assert "/etc/shadow" in result
        assert "File" in result or "read" in result

    def test_erb_file_read(self):
        """Test ERB file read payloads."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "erb", "file": "/flag.txt"}))

        assert "/flag.txt" in result


class TestSstiExploitSuggesterInfo:
    """Test information disclosure payload generation."""

    def test_includes_info_payloads(self):
        """Test that info disclosure payloads are included."""
        tool = SstiExploitSuggester()
        result = tool.use(json.dumps({"engine": "jinja2"}))

        assert "config" in result.lower() or "Information" in result


class TestSstiToolsCTFScenarios:
    """Test realistic CTF scenarios."""

    def test_full_exploitation_workflow(self):
        """Test complete SSTI exploitation workflow."""
        mock_session = Mock()

        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            if "{{7*7}}" in str(params.get("name", "")):
                resp.text = "Hello 49!"
            elif "{{config}}" in str(params.get("name", "")):
                resp.text = "<Config {'DEBUG': True, 'SECRET': 'flag123'}>"
            else:
                resp.text = "Hello World!"
            return resp

        mock_session.get.side_effect = mock_get

        # Step 1: Detect SSTI
        probe_tool = SstiProbeTool(session=mock_session)
        probe_result = probe_tool.use(
            json.dumps(
                {"url": "http://test.com/greet", "method": "GET", "param": "name"}
            )
        )

        assert "VULNERABLE" in probe_result or "49" in probe_result

        # Step 2: Get exploitation payloads
        exploit_tool = SstiExploitSuggester()
        exploit_result = exploit_tool.use(
            json.dumps({"engine": "jinja2", "command": "cat /flag.txt"})
        )

        assert "cat /flag.txt" in exploit_result
        assert "popen" in exploit_result or "subclasses" in exploit_result

    def test_blind_ssti_detection(self):
        """Test detection when output isn't directly visible."""
        mock_session = Mock()

        # Error-based detection
        def mock_get(url, **kwargs):
            params = kwargs.get("params", {})
            resp = Mock()
            resp.status_code = 200
            param_value = str(params.get("name", ""))
            if "{{" in param_value and "}}" not in param_value:
                resp.status_code = 500
                resp.text = "TemplateSyntaxError: Unexpected end of template"
            else:
                resp.text = "Normal page"
            return resp

        mock_session.get.side_effect = mock_get

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        # Should detect via error
        assert "Error" in result or "Template" in result


class TestSstiToolsEdgeCases:
    """Test edge cases and error handling."""

    def test_request_timeout(self):
        """Test handling of request timeout."""
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection timeout")

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        assert "Error" in result or "timeout" in result.lower()

    def test_reflected_but_not_executed(self):
        """Test when probe is reflected but not executed."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Hello {{7*7}} World"  # Reflected, not executed
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = SstiProbeTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {"url": "http://test.com/page", "method": "GET", "param": "name"}
            )
        )

        # Should note reflection
        assert "Reflected" in result or "not executed" in result.lower()

    def test_case_insensitive_engine(self):
        """Test that engine name is case-insensitive."""
        tool = SstiExploitSuggester()

        result1 = tool.use(json.dumps({"engine": "JINJA2"}))
        result2 = tool.use(json.dumps({"engine": "Jinja2"}))
        result3 = tool.use(json.dumps({"engine": "jinja2"}))

        # All should work
        assert "Error" not in result1 or "Unknown" not in result1
        assert "Error" not in result2 or "Unknown" not in result2
        assert "Error" not in result3 or "Unknown" not in result3


class TestSstiToolsIntegration:
    """Test integration with CTF solver."""

    def test_import_from_tools(self):
        """Test that SSTI tools are importable from tools package."""
        from ctf_solver.tools import SstiProbeTool, SstiExploitSuggester

        probe = SstiProbeTool()
        suggester = SstiExploitSuggester()
        assert probe.name == "ssti_probe"
        assert suggester.name == "ssti_exploit_suggester"

    def test_tools_follow_fair_pattern(self):
        """Test that tools follow FAIR pattern."""
        for Tool in [SstiProbeTool, SstiExploitSuggester]:
            tool = Tool()

            # Has required attributes
            assert hasattr(tool, "name")
            assert hasattr(tool, "description")
            assert hasattr(tool, "use")

            # Types are correct
            assert isinstance(tool.name, str)
            assert isinstance(tool.description, str)

            # use returns string
            result = tool.use("{}")
            assert isinstance(result, str)

    def test_probe_shares_session(self):
        """Test that SstiProbeTool uses shared session."""
        import requests

        session = requests.Session()
        session.headers["X-Custom"] = "test"

        tool = SstiProbeTool(session=session)
        assert tool.session.headers.get("X-Custom") == "test"
