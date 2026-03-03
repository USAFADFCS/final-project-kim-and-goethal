"""
Tests for v1.8.0 efficiency improvements.

Covers:
- HttpFetchTool pre-truncation flag scanning
- FormSubmitTool pre-truncation flag scanning
- SqliProbeTool baseline flag filtering
- LoggingToolWrapper flag recording in tracker
- Query expander paywall/client-side terms
- Reranker HIGH_VALUE_TERMS additions
- Prompt template updates (truncation, paywall)
"""

import json
import re
from unittest.mock import MagicMock, patch

import pytest
import requests

from ctf_solver.tools.http_tools import (
    HttpFetchTool,
    FormSubmitTool,
    _scan_for_flags,
    _FLAG_SCAN_RE,
)
from ctf_solver.tools.sqli_tools import SqliProbeTool
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper
from ctf_solver.rag.query_expander import QueryExpander
from ctf_solver.rag.reranker import SimpleReranker


# ==============================================================================
# _scan_for_flags — flag detection helper
# ==============================================================================


class TestScanForFlags:
    """Tests for the _scan_for_flags helper function."""

    def test_flag_beyond_truncation(self):
        # Realistic HTML: flag is in a <p> tag beyond truncation
        text = (
            "<html>"
            + "<p>Lorem ipsum.</p>\n" * 250
            + "<p>CTF{hidden_flag_here}</p></html>"
        )
        result = _scan_for_flags(text, 4000)
        assert "CTF{hidden_flag_here}" in result

    def test_flag_before_truncation_not_returned(self):
        text = "<html><p>CTF{visible_flag}</p>" + "<p>text</p>\n" * 300 + "</html>"
        result = _scan_for_flags(text, 4000)
        assert result == []

    def test_no_flags(self):
        text = "<html>" + "<p>No flags here.</p>\n" * 500 + "</html>"
        result = _scan_for_flags(text, 4000)
        assert result == []

    def test_multiple_flags_beyond_truncation(self):
        # "<p>text</p>\n" = 12 chars, need > 4000/12 ≈ 334 reps
        text = (
            "<html>"
            + "<p>text</p>\n" * 350
            + "<p>FLAG{first}</p><p>CTF{second}</p></html>"
        )
        assert len(text) > 4000  # sanity check
        result = _scan_for_flags(text, 4000)
        assert "FLAG{first}" in result
        assert "CTF{second}" in result

    def test_deduplication(self):
        text = (
            "<html>" + "<p>text</p>\n" * 350 + "<p>CTF{dup}</p><p>CTF{dup}</p></html>"
        )
        result = _scan_for_flags(text, 4000)
        assert result.count("CTF{dup}") == 1

    def test_various_flag_formats(self):
        text = "<html>" + "<p>text</p>\n" * 350 + "<p>picoCTF{pico_flag}</p></html>"
        result = _scan_for_flags(text, 4000)
        assert "picoCTF{pico_flag}" in result

    def test_flag_at_exact_truncation_boundary(self):
        # Flag starts right at truncation point
        text = "<p>" + "x" * 3993 + "</p> CTF{boundary}"
        result = _scan_for_flags(text, 4000)
        assert "CTF{boundary}" in result


class TestFlagScanRegex:
    """Tests for the _FLAG_SCAN_RE pattern."""

    def test_ctf_format(self):
        assert _FLAG_SCAN_RE.search("CTF{test_flag}")

    def test_flag_format(self):
        assert _FLAG_SCAN_RE.search("FLAG{test_flag}")

    def test_picoctf_format(self):
        assert _FLAG_SCAN_RE.search("picoCTF{test_flag}")

    def test_htb_format(self):
        assert _FLAG_SCAN_RE.search("HTB{test_flag}")

    def test_custom_prefix(self):
        assert _FLAG_SCAN_RE.search("MetaCTF{custom_flag}")

    def test_no_match_plain_text(self):
        assert not _FLAG_SCAN_RE.search("This is just plain text")


# ==============================================================================
# HttpFetchTool — pre-truncation flag scanning
# ==============================================================================


class TestHttpFetchToolFlagScan:
    """Tests for HttpFetchTool pre-truncation flag scanning."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = HttpFetchTool(session=self.session)

    def _mock_response(self, text, status=200):
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.content = text.encode("utf-8")
        mock_resp.url = "http://example.com/test"
        mock_resp.status_code = status
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.history = []
        mock_resp.raw = MagicMock()
        mock_resp.raw.headers = MagicMock()
        mock_resp.raw.headers.items.return_value = []
        return mock_resp

    def test_flag_beyond_truncation_is_reported(self):
        html = "<html>" + "A" * 5000 + "<p>CTF{hidden_paywall_flag}</p></html>"
        mock_resp = self._mock_response(html)
        with patch.object(self.session, "get", return_value=mock_resp):
            result = self.tool.use(json.dumps({"url": "http://example.com/test"}))
        assert "[FLAG PATTERN DETECTED beyond truncation point]" in result
        assert "CTF{hidden_paywall_flag}" in result

    def test_flag_within_truncation_no_extra_section(self):
        html = "<html><p>CTF{visible_flag}</p>" + "A" * 100 + "</html>"
        mock_resp = self._mock_response(html)
        with patch.object(self.session, "get", return_value=mock_resp):
            result = self.tool.use(json.dumps({"url": "http://example.com/test"}))
        assert "[FLAG PATTERN DETECTED beyond truncation point]" not in result
        assert "CTF{visible_flag}" in result

    def test_no_flag_no_extra_section(self):
        html = "<html>" + "A" * 5000 + "</html>"
        mock_resp = self._mock_response(html)
        with patch.object(self.session, "get", return_value=mock_resp):
            result = self.tool.use(json.dumps({"url": "http://example.com/test"}))
        assert "[FLAG PATTERN DETECTED" not in result

    def test_max_body_zero_no_truncation(self):
        html = "<html>" + "A" * 5000 + "CTF{full_body_flag}</html>"
        mock_resp = self._mock_response(html)
        with patch.object(self.session, "get", return_value=mock_resp):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/test",
                        "max_body": 0,
                    }
                )
            )
        # With max_body=0, full body is returned, no truncation notice needed
        assert "CTF{full_body_flag}" in result
        assert "[FLAG PATTERN DETECTED" not in result


# ==============================================================================
# FormSubmitTool — pre-truncation flag scanning
# ==============================================================================


class TestFormSubmitToolFlagScan:
    """Tests for FormSubmitTool pre-truncation flag scanning."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = FormSubmitTool(session=self.session)

    def _mock_response(self, text, status=200):
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.url = "http://example.com/form"
        mock_resp.status_code = status
        mock_resp.headers = {"Content-Type": "text/html"}
        return mock_resp

    def test_flag_beyond_truncation_is_reported(self):
        html = "<html>" + "A" * 5000 + "<p>FLAG{form_hidden}</p></html>"
        mock_resp = self._mock_response(html)
        with patch.object(self.session, "post", return_value=mock_resp):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/form",
                        "method": "POST",
                        "data": {"key": "val"},
                    }
                )
            )
        assert "[FLAG PATTERN DETECTED beyond truncation point]" in result
        assert "FLAG{form_hidden}" in result


# ==============================================================================
# SqliProbeTool — baseline flag filtering
# ==============================================================================


class TestSqliBaselineFiltering:
    """Tests for SqliProbeTool baseline flag filtering."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = SqliProbeTool(session=self.session)

    def _mock_response(self, text, status=200):
        mock_resp = MagicMock()
        mock_resp.text = text
        mock_resp.status_code = status
        return mock_resp

    def test_flag_in_baseline_not_reported_as_injection(self):
        """Flag already in baseline should not be reported as 'found via injection'."""
        html_with_flag = "<html><p>CTF{static_flag}</p></html>"
        mock_resp = self._mock_response(html_with_flag)
        with patch.object(self.session, "get", return_value=mock_resp):
            with patch.object(self.session, "post", return_value=mock_resp):
                result = self.tool.use(
                    json.dumps(
                        {
                            "url": "http://example.com/page",
                            "method": "GET",
                            "param": "q",
                            "payload_set": "custom",
                            "custom_payloads": ["' OR '1'='1"],
                        }
                    )
                )
        assert "FLAGS FOUND (via injection)" not in result
        assert "already present in the baseline response" in result

    def test_new_flag_from_injection_is_reported(self):
        """A flag that only appears after injection should be reported."""
        baseline_html = "<html><p>No flag here</p></html>"
        injected_html = "<html><p>FLAG{injected_flag}</p></html>"
        baseline_resp = self._mock_response(baseline_html)
        injected_resp = self._mock_response(injected_html)

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return injected_resp

        with patch.object(self.session, "get", side_effect=side_effect):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/page",
                        "method": "GET",
                        "param": "q",
                        "payload_set": "custom",
                        "custom_payloads": ["' UNION SELECT flag FROM flags --"],
                    }
                )
            )
        assert "FLAGS FOUND (via injection)" in result
        assert "FLAG{injected_flag}" in result

    def test_baseline_flag_note_includes_flag(self):
        """Baseline note should mention the flag found."""
        html_with_flag = "<html>CTF{in_baseline}</html>"
        mock_resp = self._mock_response(html_with_flag)
        with patch.object(self.session, "get", return_value=mock_resp):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/page",
                        "method": "GET",
                        "param": "q",
                        "payload_set": "custom",
                        "custom_payloads": ["test"],
                    }
                )
            )
        assert "CTF{in_baseline}" in result
        assert "already present in the baseline" in result


# ==============================================================================
# LoggingToolWrapper — flag recording in tracker
# ==============================================================================


class TestLoggingWrapperFlagRecording:
    """Tests for LoggingToolWrapper recording flags in tracker."""

    def test_flags_recorded_in_tracker(self):
        tracker = MagicMock()
        tracker.candidate_flags_found = []
        tracker.record_tool_call = MagicMock()
        tracker.record_detailed_tool_call = MagicMock()

        inner = MagicMock()
        inner.name = "test_tool"
        inner.description = "test"
        inner.use.return_value = "Result: CTF{found_by_tool}"

        wrapper = LoggingToolWrapper(
            inner,
            flag_regex=r"CTF\{[^}]+\}",
            log_callback=lambda m: None,
            tracker=tracker,
        )
        wrapper.use("{}")
        assert "CTF{found_by_tool}" in tracker.candidate_flags_found

    def test_duplicate_flags_not_recorded_twice(self):
        tracker = MagicMock()
        tracker.candidate_flags_found = ["CTF{already_found}"]
        tracker.record_tool_call = MagicMock()
        tracker.record_detailed_tool_call = MagicMock()

        inner = MagicMock()
        inner.name = "test_tool"
        inner.description = "test"
        inner.use.return_value = "Result: CTF{already_found}"

        wrapper = LoggingToolWrapper(
            inner,
            flag_regex=r"CTF\{[^}]+\}",
            log_callback=lambda m: None,
            tracker=tracker,
        )
        wrapper.use("{}")
        assert tracker.candidate_flags_found.count("CTF{already_found}") == 1

    def test_no_tracker_no_error(self):
        inner = MagicMock()
        inner.name = "test_tool"
        inner.description = "test"
        inner.use.return_value = "Result: CTF{flag}"

        wrapper = LoggingToolWrapper(
            inner,
            flag_regex=r"CTF\{[^}]+\}",
            log_callback=lambda m: None,
            tracker=None,
        )
        # Should not raise
        wrapper.use("{}")


# ==============================================================================
# QueryExpander — paywall/client-side terms
# ==============================================================================


class TestQueryExpanderPaywall:
    """Tests for query expander paywall/client-side term additions."""

    def setup_method(self):
        self.expander = QueryExpander()

    def test_paywall_has_expansions(self):
        terms = self.expander.get_expansion_terms("paywall")
        assert len(terms) > 0
        assert any("client-side" in t or "bypass" in t for t in terms)

    def test_paywall_query_expanded(self):
        expanded = self.expander.expand_query("paywall bypass techniques")
        assert len(expanded) > len("paywall bypass techniques")

    def test_client_side_has_expansions(self):
        terms = self.expander.get_expansion_terms("client-side")
        assert len(terms) > 0

    def test_dom_has_expansions(self):
        terms = self.expander.get_expansion_terms("dom")
        assert len(terms) > 0

    def test_access_control_has_expansions(self):
        terms = self.expander.get_expansion_terms("access control")
        assert len(terms) > 0

    def test_overlay_has_expansions(self):
        terms = self.expander.get_expansion_terms("overlay")
        assert len(terms) > 0


# ==============================================================================
# Reranker — HIGH_VALUE_TERMS additions
# ==============================================================================


class TestRerankerNewTerms:
    """Tests for reranker HIGH_VALUE_TERMS additions."""

    def test_paywall_in_high_value(self):
        assert "paywall" in SimpleReranker.HIGH_VALUE_TERMS

    def test_client_side_in_high_value(self):
        assert "client-side" in SimpleReranker.HIGH_VALUE_TERMS

    def test_dom_in_high_value(self):
        assert "dom" in SimpleReranker.HIGH_VALUE_TERMS

    def test_access_control_in_high_value(self):
        assert "access control" in SimpleReranker.HIGH_VALUE_TERMS

    def test_authorization_in_high_value(self):
        assert "authorization" in SimpleReranker.HIGH_VALUE_TERMS

    def test_overlay_in_high_value(self):
        assert "overlay" in SimpleReranker.HIGH_VALUE_TERMS

    def test_paywall_doc_gets_boost(self):
        """Document mentioning paywall should score higher than one without."""
        reranker = SimpleReranker()

        class FakeDoc:
            def __init__(self, content):
                self.page_content = content

        paywall_doc = FakeDoc(
            "This covers paywall bypass and client-side DOM access control techniques"
        )
        sqli_doc = FakeDoc("SQL injection union select error based exploitation")

        paywall_score, _ = reranker.score_document("paywall bypass", paywall_doc)
        sqli_score, _ = reranker.score_document("paywall bypass", sqli_doc)
        assert paywall_score > sqli_score


# ==============================================================================
# Prompt template tests
# ==============================================================================


class TestPromptUpdates:
    """Tests for prompt template efficiency updates."""

    def test_system_prompt_has_truncation_warning(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "truncated" in DEFAULT_SYSTEM_PROMPT.lower()
        assert "max_body" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_paywall_guidance(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "paywall" in DEFAULT_SYSTEM_PROMPT.lower()

    def test_system_prompt_paywall_chain(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "Paywall/overlay blocking content" in DEFAULT_SYSTEM_PROMPT

    def test_initial_message_has_truncation_warning(self):
        from ctf_solver.prompts.templates import get_initial_message

        msg = get_initial_message(challenge_url="http://test.com")
        assert "TRUNCATION" in msg or "truncat" in msg.lower()

    def test_initial_message_has_paywall_note(self):
        from ctf_solver.prompts.templates import get_initial_message

        msg = get_initial_message(challenge_url="http://test.com")
        assert "PAYWALL" in msg or "paywall" in msg.lower()

    def test_recon_priority_includes_paywall_step(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert (
            "subscription wall" in DEFAULT_SYSTEM_PROMPT
            or "paywall" in DEFAULT_SYSTEM_PROMPT.lower()
        )
