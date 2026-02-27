"""
Tests for v2 system prompt updates and failure_analyzer tool mappings.

Validates that:
- DEFAULT_SYSTEM_PROMPT contains references to all new v2 capabilities
  (redirect control, multipart, raw_body, cookie delete, JWT confusion,
   kid injection, double_url_encode, xor, JSON probe tools, file uploads)
- DEFAULT_ROLE_DEFINITION mentions JSON/multipart support
- _TOOL_TO_CATEGORY maps all new/renamed tools and does not contain stale names
"""

import pytest

from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT, DEFAULT_ROLE_DEFINITION
from ctf_solver.failure_analyzer import _TOOL_TO_CATEGORY, _CATEGORY_LABELS


# -----------------------------------------------------------------------
# System prompt content tests
# -----------------------------------------------------------------------

class TestSystemPromptUpdates:
    """Verify DEFAULT_SYSTEM_PROMPT mentions all v2 capability keywords."""

    def test_prompt_mentions_redirect_control(self):
        assert "follow_redirects" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_multipart(self):
        assert "multipart" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_raw_body(self):
        assert "raw_body" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_cookie_delete(self):
        assert "delete" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_jwt_confusion(self):
        assert "confusion_rs256_hs256" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_kid_inject(self):
        assert "kid_inject" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_double_url_encode(self):
        assert "double_url_encode" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_xor(self):
        assert "xor" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_json_probe_tools(self):
        assert "Content-Type: application/json" in DEFAULT_SYSTEM_PROMPT

    def test_prompt_mentions_file_uploads(self):
        # The prompt should mention file upload with multipart/files parameters
        prompt_lower = DEFAULT_SYSTEM_PROMPT.lower()
        assert "file upload" in prompt_lower or "file uploads" in prompt_lower
        assert "multipart" in DEFAULT_SYSTEM_PROMPT
        assert "files" in DEFAULT_SYSTEM_PROMPT


# -----------------------------------------------------------------------
# Role definition tests
# -----------------------------------------------------------------------

class TestRoleDefinitionUpdates:
    """Verify DEFAULT_ROLE_DEFINITION mentions JSON/multipart."""

    def test_role_mentions_json_multipart(self):
        assert "JSON/multipart" in DEFAULT_ROLE_DEFINITION


# -----------------------------------------------------------------------
# Failure analyzer tool mapping tests
# -----------------------------------------------------------------------

class TestFailureAnalyzerToolMappings:
    """Verify _TOOL_TO_CATEGORY includes all expected tool names."""

    def test_javascript_source_mapped(self):
        assert "javascript_source" in _TOOL_TO_CATEGORY

    def test_timing_compare_mapped(self):
        assert "timing_compare" in _TOOL_TO_CATEGORY

    def test_generic_tools_not_in_category_map(self):
        """Generic tools should NOT be in _TOOL_TO_CATEGORY to avoid biasing inference."""
        generic_tools = ["http_fetch", "form_submit", "regex_search",
                         "response_search", "encoding", "hash_identifier"]
        for tool in generic_tools:
            assert tool not in _TOOL_TO_CATEGORY, (
                f"Generic tool '{tool}' should not be in _TOOL_TO_CATEGORY"
            )

    def test_all_category_specific_tools_have_categories(self):
        """Every category-specific tool name must appear in _TOOL_TO_CATEGORY."""
        expected_tools = [
            # Recon (category-specific, not generic)
            "html_inspector",
            "javascript_source",
            "cookie_inspector",
            "cookie_set",
            "robots_txt",
            "timing_compare",
            "response_diff",
            "attack_planner",
            # SQL injection
            "sqli_probe",
            "sqli_column_counter",
            "blind_sqli_boolean",
            "blind_sqli_time",
            "sqli_data_dumper",
            "sql_pattern_hint",
            # XPath
            "xpath_probe",
            "xpath_blind_boolean",
            "xpath_payload_generator",
            # Command injection
            "cmdi_probe",
            "cmdi_payload_generator",
            # File inclusion
            "lfi_probe",
            "lfi_payload_generator",
            # NoSQL
            "nosql_probe",
            "nosql_payload_generator",
            # SSRF
            "ssrf_probe",
            "ssrf_payload_generator",
            # Crypto
            "crypto_probe",
            "crypto_analyzer",
            "crypto_payload_generator",
            # Deserialization
            "deserialization_probe",
            "deserialization_payload_generator",
            # SSTI
            "ssti_probe",
            "ssti_exploit_suggester",
            # File upload
            "file_upload",
            "upload_location_finder",
            # XXE
            "xxe_probe",
            "xxe_payload_generator",
            "xxe_doctype_builder",
            # JWT
            "jwt_tool",
            # Filter bypass
            "filter_enumerator",
            "payload_mutator",
        ]
        missing = [t for t in expected_tools if t not in _TOOL_TO_CATEGORY]
        assert missing == [], f"Tools missing from _TOOL_TO_CATEGORY: {missing}"

    def test_old_js_source_not_in_mapping(self):
        """The old 'js_source' name was renamed to 'javascript_source'."""
        assert "js_source" not in _TOOL_TO_CATEGORY
