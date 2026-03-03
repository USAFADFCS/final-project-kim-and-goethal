"""
Tests for CTFAgent guards and parser robustness.

Covers:
- _extract_json_object: balanced-brace JSON extraction from mixed text
- _robust_parse: parser monkey-patch (markdown stripping, JSON extraction, format error)
- _has_unexploited_findings: exploitable-finding detection
- _only_recon_so_far: recon-only tool usage detection
- _build_guard_message: escalating continuation messages
- Progress check injection
- Dynamic retry cap based on step budget
"""

import json
import re
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from ctf_solver.agent import (
    _extract_json_object,
    _EXPLOITABLE_KEYWORDS,
    _RECON_TOOLS,
    CTFAgent,
)
from ctf_solver.prompts.templates import COOKIE_BYPASS_EXAMPLE


# ==============================================================================
# _extract_json_object — balanced-brace JSON extraction
# ==============================================================================


class TestExtractJsonObject:
    """Tests for _extract_json_object helper."""

    def test_pure_json(self):
        text = '{"thought": "hello", "action": {"tool":"x", "tool_input": "y"}}'
        assert _extract_json_object(text) == text

    def test_json_with_leading_text(self):
        text = 'Sure, here is my response:\n{"thought": "test", "action": {}}'
        result = _extract_json_object(text)
        assert result is not None
        assert json.loads(result)["thought"] == "test"

    def test_json_with_trailing_text(self):
        text = '{"thought": "test", "action": {}}\nI chose this because...'
        result = _extract_json_object(text)
        assert result is not None
        assert json.loads(result)["thought"] == "test"

    def test_json_with_both_surrounding_text(self):
        text = 'Analysis:\n{"a": 1, "b": {"c": 2}}\nDone.'
        result = _extract_json_object(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["a"] == 1
        assert parsed["b"]["c"] == 2

    def test_no_json_returns_none(self):
        assert _extract_json_object("No JSON here at all") is None

    def test_empty_string(self):
        assert _extract_json_object("") is None

    def test_nested_braces(self):
        text = '{"outer": {"inner": {"deep": true}}}'
        result = _extract_json_object(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["outer"]["inner"]["deep"] is True

    def test_string_with_braces(self):
        """Braces inside JSON strings should not confuse the parser."""
        text = '{"msg": "hello {world}", "val": 42}'
        result = _extract_json_object(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["msg"] == "hello {world}"

    def test_escaped_quotes(self):
        text = r'{"msg": "he said \"hi\"", "n": 1}'
        result = _extract_json_object(text)
        assert result is not None

    def test_invalid_json_braces(self):
        """Balanced braces but invalid JSON content returns None."""
        text = "{not: valid, json: here}"
        assert _extract_json_object(text) is None

    def test_multiple_json_objects_returns_first(self):
        text = '{"a": 1} {"b": 2}'
        result = _extract_json_object(text)
        assert result is not None
        assert json.loads(result) == {"a": 1}


# ==============================================================================
# _EXPLOITABLE_KEYWORDS — regex pattern matching
# ==============================================================================


class TestExploitableKeywords:
    """Tests for the exploitable-finding keyword regex."""

    def test_password_keyword(self):
        assert _EXPLOITABLE_KEYWORDS.search("I found the password in JavaScript")

    def test_credential_keyword(self):
        assert _EXPLOITABLE_KEYWORDS.search("The credential was hardcoded")

    def test_token_keyword(self):
        assert _EXPLOITABLE_KEYWORDS.search("The token prefix is cur8-")

    def test_api_key_keyword(self):
        assert _EXPLOITABLE_KEYWORDS.search("Found an API key in the source")

    def test_found_in_js(self):
        assert _EXPLOITABLE_KEYWORDS.search("found the secret in JavaScript")

    def test_injection_detected(self):
        assert _EXPLOITABLE_KEYWORDS.search("SQL injection detected in the login")

    def test_no_match_generic(self):
        assert not _EXPLOITABLE_KEYWORDS.search("The page returned a 200 status code")

    def test_no_match_flag(self):
        assert not _EXPLOITABLE_KEYWORDS.search("FLAG{test_flag_123}")

    def test_protected_page(self):
        assert _EXPLOITABLE_KEYWORDS.search("found a protected page at /admin")


# ==============================================================================
# _RECON_TOOLS — tool categorization
# ==============================================================================


class TestReconTools:
    """Tests for the recon tools set."""

    def test_http_fetch_is_recon(self):
        assert "http_fetch" in _RECON_TOOLS

    def test_javascript_source_is_recon(self):
        assert "javascript_source" in _RECON_TOOLS

    def test_sqli_probe_is_not_recon(self):
        assert "sqli_probe" not in _RECON_TOOLS

    def test_form_submit_is_not_recon(self):
        assert "form_submit" not in _RECON_TOOLS

    def test_cookie_set_is_not_recon(self):
        assert "cookie_set" not in _RECON_TOOLS


# ==============================================================================
# CTFAgent — guard methods
# ==============================================================================


class TestCTFAgentGuards:
    """Tests for CTFAgent guard methods (without full agent construction)."""

    def _make_agent(self, **kwargs):
        """Create a minimal CTFAgent with mocked dependencies."""
        mock_llm = MagicMock()
        mock_planner = MagicMock()
        mock_planner._parse_json_response = MagicMock()
        mock_executor = MagicMock()
        mock_memory = MagicMock()
        mock_memory.get_history.return_value = []

        return CTFAgent(
            llm=mock_llm,
            planner=mock_planner,
            tool_executor=mock_executor,
            memory=mock_memory,
            max_steps=20,
            log_callback=lambda msg: None,
            **kwargs,
        )

    def test_has_unexploited_findings_with_password(self):
        agent = self._make_agent()
        assert agent._has_unexploited_findings("I found the password 'admin123'")

    def test_has_unexploited_findings_with_token(self):
        agent = self._make_agent()
        assert agent._has_unexploited_findings("The token prefix is cur8-")

    def test_has_unexploited_findings_without_keywords(self):
        agent = self._make_agent()
        assert not agent._has_unexploited_findings("The page returned 200 OK")

    def test_only_recon_with_recon_tools(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = [
            {"tool":"http_fetch"},
            {"tool":"javascript_source"},
            {"tool":"robots_txt"},
        ]
        assert agent._only_recon_so_far()

    def test_only_recon_false_with_exploit_tools(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = [
            {"tool":"http_fetch"},
            {"tool":"sqli_probe"},
        ]
        assert not agent._only_recon_so_far()

    def test_only_recon_false_with_no_tools(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = []
        assert not agent._only_recon_so_far()

    def test_build_guard_message_attempt_1(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = [{"tool":"http_fetch"}]
        msg = agent._build_guard_message(1, "I found the password")
        assert "Finding information is NOT the same" in msg
        assert "http_fetch" in msg

    def test_build_guard_message_attempt_2_with_findings(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = [{"tool":"javascript_source"}]
        msg = agent._build_guard_message(2, "I found the password in JavaScript")
        assert "URGENT" in msg
        assert "EXPLOIT" in msg

    def test_build_guard_message_attempt_2_without_findings(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = [{"tool":"sqli_probe"}]
        msg = agent._build_guard_message(2, "I could not find any vulnerabilities")
        assert "COMPLETELY different approach" in msg

    def test_build_guard_message_attempt_3(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.tool_call_log = []
        msg = agent._build_guard_message(3, "Giving up")
        assert "FINAL WARNING" in msg
        assert "concrete exploitation action" in msg

    def test_has_flag_with_tracker(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = ["FLAG{test}"]
        assert agent._has_flag()

    def test_has_flag_in_text(self):
        agent = self._make_agent()
        assert agent._has_flag("The flag is FLAG{hello_world}")

    def test_has_flag_no_match(self):
        agent = self._make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        assert not agent._has_flag("no flag here")


# ==============================================================================
# Parser monkey-patch tests
# ==============================================================================


class TestParserMonkeyPatch:
    """Tests for the robust parser monkey-patch."""

    def _make_agent(self):
        """Create agent with a parser mock that matches fairlib's real behavior."""
        from fairlib.core.message import FinalAnswer, Thought, Action

        mock_llm = MagicMock()
        mock_planner = MagicMock()
        mock_executor = MagicMock()
        mock_memory = MagicMock()
        mock_memory.get_history.return_value = []

        # Replicates fairlib's _parse_json_response including its fallback
        # behavior of treating non-JSON as FinalAnswer
        def real_parse(text):
            try:
                data = json.loads(text.strip())
                thought_text = data.get("thought")
                action_data = data.get("action")
                if not thought_text or not action_data:
                    raise KeyError("Missing thought or action")
                tool_name = action_data.get("tool_name")
                tool_input = action_data.get("tool_input")
                if not tool_name or tool_input is None:
                    raise KeyError("Missing tool_name or tool_input")
                if tool_name == "final_answer":
                    return FinalAnswer(text=str(tool_input))
                return Thought(text=str(thought_text)), Action(
                    tool_name=str(tool_name), tool_input=tool_input
                )
            except json.JSONDecodeError:
                # This is the critical fairlib fallback that we're patching around
                return FinalAnswer(text=text)
            except (KeyError, TypeError):
                return FinalAnswer(text=text)

        mock_planner._parse_json_response = real_parse

        agent = CTFAgent(
            llm=mock_llm,
            planner=mock_planner,
            tool_executor=mock_executor,
            memory=mock_memory,
            max_steps=20,
            log_callback=lambda msg: None,
        )
        return agent

    def test_valid_json_passes_through(self):
        from fairlib.core.message import Thought, Action

        agent = self._make_agent()
        text = json.dumps({
            "thought": "test",
            "action": {"tool_name": "http_fetch", "tool_input": "{}"},
        })
        result = agent.planner._parse_json_response(text)
        thought, action = result
        assert thought.text == "test"
        assert action.tool_name == "http_fetch"

    def test_markdown_fenced_json(self):
        from fairlib.core.message import Thought, Action

        agent = self._make_agent()
        text = '```json\n{"thought": "test", "action": {"tool_name": "http_fetch", "tool_input": "{}"}}\n```'
        result = agent.planner._parse_json_response(text)
        thought, action = result
        assert thought.text == "test"
        assert action.tool_name == "http_fetch"

    def test_json_with_leading_text_is_extracted(self):
        from fairlib.core.message import Thought, Action

        agent = self._make_agent()
        text = 'Sure, here is my analysis:\n{"thought": "found it", "action": {"tool_name": "http_fetch", "tool_input": "{}"}}'
        result = agent.planner._parse_json_response(text)
        thought, action = result
        assert thought.text == "found it"
        assert action.tool_name == "http_fetch"

    def test_non_json_triggers_format_error(self):
        """Non-JSON response should return a format-error action, not FinalAnswer."""
        from fairlib.core.message import FinalAnswer, Thought, Action

        agent = self._make_agent()
        text = "I found the password in JavaScript. Let me try logging in now."
        result = agent.planner._parse_json_response(text)

        # Should NOT be a FinalAnswer (the critical fix)
        assert not isinstance(result, FinalAnswer)

        # Should be a thought + action for format recovery
        thought, action = result
        assert "FORMAT RECOVERY" in thought.text
        assert action.tool_name == "__format_error__"

    def test_format_error_count_increments(self):
        agent = self._make_agent()
        text = "Not JSON at all"

        agent.planner._parse_json_response(text)
        assert agent._format_error_count == 1

        agent.planner._parse_json_response(text)
        assert agent._format_error_count == 2

    def test_format_error_fallback_after_3(self):
        """After 3 format errors, falls back to original parser (FinalAnswer)."""
        from fairlib.core.message import FinalAnswer

        agent = self._make_agent()
        agent._format_error_count = 3  # Already had 3 errors

        text = "Not JSON at all"
        result = agent.planner._parse_json_response(text)
        # Now it should fall back to original parser's FinalAnswer behavior
        assert isinstance(result, FinalAnswer)

    def test_final_answer_tool_still_works(self):
        from fairlib.core.message import FinalAnswer

        agent = self._make_agent()
        text = json.dumps({
            "thought": "Found the flag",
            "action": {"tool_name": "final_answer", "tool_input": "FLAG{test}"},
        })
        result = agent.planner._parse_json_response(text)
        assert isinstance(result, FinalAnswer)
        assert result.text == "FLAG{test}"


# ==============================================================================
# Prompt template tests
# ==============================================================================


class TestPromptEnhancements:
    """Tests for the enhanced prompt templates."""

    def test_system_prompt_has_information_vs_solution(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "INFORMATION vs. SOLUTION" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_exploitation_protocol(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "EXPLOITATION FOLLOW-THROUGH PROTOCOL" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_checklist(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "BEFORE calling final_answer, verify" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_negative_format_examples(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "INCORRECT formats" in DEFAULT_SYSTEM_PROMPT

    def test_js_example_shows_full_chain(self):
        """JS example should show: find cred → use cred → access page → flag."""
        from ctf_solver.prompts.templates import JS_ANALYSIS_EXAMPLE
        example_text = JS_ANALYSIS_EXAMPLE.text
        # Should include login POST
        assert "api/login" in example_text or "/api/login" in example_text
        # Should include visiting dashboard
        assert "dashboard" in example_text
        # Should have a flag at the end
        assert "FLAG{" in example_text
        # Should NOT just report the password as final answer
        assert "The correct password is" not in example_text

    def test_cookie_bypass_example_exists(self):
        assert COOKIE_BYPASS_EXAMPLE is not None
        assert "cur8-" in COOKIE_BYPASS_EXAMPLE.text
        assert "FLAG{" in COOKIE_BYPASS_EXAMPLE.text

    def test_cookie_bypass_example_shows_exploitation(self):
        """Cookie example should show full chain: find prefix → POST → visit → flag."""
        text = COOKIE_BYPASS_EXAMPLE.text
        assert "api/login" in text
        assert "exhibit" in text
        assert "final_answer" in text

    def test_initial_message_has_exploitation_warning(self):
        from ctf_solver.prompts.templates import get_initial_message
        msg = get_initial_message(challenge_url="http://test.com")
        assert "Finding information is NOT the same" in msg

    def test_system_prompt_common_chains(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT
        assert "Credential found in JS" in DEFAULT_SYSTEM_PROMPT
        assert "Token prefix/format found" in DEFAULT_SYSTEM_PROMPT
        assert "Cookie controls access" in DEFAULT_SYSTEM_PROMPT
