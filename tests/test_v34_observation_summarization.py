"""
Tests for Phase 2 of the agent-reliability plan — observation
summarization (``summarize_for_llm``).

The helper strips <style>/<script> bodies, collapses runs of identical
lines, truncates to a cap, and guarantees flag-regex matches survive.

Test layout:
  TestSummarizeForLlm       — the helper in isolation (13 cases)
  TestHttpFetchSummarization — HttpFetchTool call-site integration
  TestDeepReconSummarization — DeepReconTool call-site integration
  TestRagChunkCap           — SafeKnowledgeQueryTool chunk cap

The ``TestSummarizeForLlm`` cases are the correctness contract; if any
of them regresses, downstream tools will silently misbehave.
"""

import re
from unittest.mock import MagicMock, Mock, patch

import pytest

from ctf_solver.tools.core import summarize_for_llm

# ---------------------------------------------------------------------------
# TestSummarizeForLlm — helper in isolation
# ---------------------------------------------------------------------------


class TestSummarizeForLlm:
    def test_strips_style_block(self):
        html = (
            "<html><head><style>body{color:red; background:"
            + "x" * 500
            + "}</style></head><body>Hello</body></html>"
        )
        out = summarize_for_llm(html, max_chars=1000)
        assert "<style>" not in out
        assert "color:red" not in out
        assert "[style:" in out
        assert "Hello" in out  # body preserved

    def test_strips_script_block(self):
        html = "<body><script>var x = 'secret code';</script>Visible</body>"
        out = summarize_for_llm(html, max_chars=1000)
        assert "<script>" not in out
        assert "secret code" not in out
        assert "[script:" in out
        assert "Visible" in out

    def test_preserves_script_src_in_placeholder(self):
        """External script URLs are valuable recon targets — keep them
        visible in the placeholder even though the body is stripped."""
        html = '<script src="https://example.com/app.js">' + "x" * 300 + "</script>"
        out = summarize_for_llm(html, max_chars=1000)
        assert "https://example.com/app.js" in out
        assert 'src="https://example.com/app.js"' in out
        # Original body content is gone.
        assert "xxxx" not in out

    def test_preserves_html_comments(self):
        """CTF challenges frequently hide hints in HTML comments —
        the helper must never strip them."""
        html = (
            "<!-- SECRET: the admin password is hunter2 -->"
            "<style>body{color:red}</style>"
            "<body>Page content</body>"
        )
        out = summarize_for_llm(html, max_chars=1000)
        assert "SECRET: the admin password is hunter2" in out
        assert "<!--" in out

    def test_preserves_form_and_inputs(self):
        html = (
            "<style>input{border:1px}</style>"
            '<form action="/login" method="POST">'
            '<input name="username" type="text"/>'
            '<input name="password" type="password"/>'
            "</form>"
        )
        out = summarize_for_llm(html, max_chars=1000)
        assert '<form action="/login"' in out
        assert 'name="username"' in out
        assert 'name="password"' in out
        assert "[style:" in out

    def test_collapses_three_identical_lines(self):
        text = "alpha\nalpha\nalpha\nbeta"
        out = summarize_for_llm(text, max_chars=1000)
        lines = out.split("\n")
        # First occurrence kept, then a marker, then 'beta'.
        assert lines[0] == "alpha"
        assert "2 more identical lines" in lines[1]
        assert "beta" in out

    def test_does_not_collapse_two_repeats(self):
        """Two repeats stay — only runs of 3+ collapse."""
        text = "alpha\nalpha\nbeta"
        out = summarize_for_llm(text, max_chars=1000)
        assert out.count("alpha") == 2
        assert "identical lines" not in out

    def test_truncates_at_max_chars(self):
        text = "a" * 5000
        out = summarize_for_llm(text, max_chars=100)
        assert len(out) <= 100
        assert out.endswith("[... truncated]")

    def test_idempotent_simple(self):
        """Applying twice equals applying once. Guards against double-
        summarization at the DeepRecon → HttpFetch boundary."""
        html = (
            "<style>body{color:red}</style>"
            "<script>var a=1;</script>"
            "<p>visible</p>\n"
            "dup\ndup\ndup\n"
            "tail"
        )
        once = summarize_for_llm(html, max_chars=500)
        twice = summarize_for_llm(once, max_chars=500)
        assert once == twice

    def test_idempotent_with_flag(self):
        html = "<style>body{color:red}</style>" "<p>MetaCTF{flag_here}</p>"
        flag_re = re.compile(r"MetaCTF\{[^}]+\}")
        once = summarize_for_llm(html, max_chars=500, flag_regex=flag_re)
        twice = summarize_for_llm(once, max_chars=500, flag_regex=flag_re)
        assert once == twice

    def test_flag_in_style_block_preserved(self):
        """HARD CONTRACT: a flag hidden inside a <style> block must
        still be visible after summarization. Without this guarantee
        the agent's flag-detection silently loses flags."""
        html = (
            "<style>/* MetaCTF{flag_hidden_in_css} */ "
            "body{color:red}</style>"
            "<body>normal content</body>"
        )
        out = summarize_for_llm(html, max_chars=500, flag_regex=r"MetaCTF\{[^}]+\}")
        assert "MetaCTF{flag_hidden_in_css}" in out
        assert "[Flag pattern matches preserved" in out

    def test_flag_in_script_block_preserved(self):
        html = (
            '<script>const flag = "MetaCTF{js_flag_value}";</script>' "<p>content</p>"
        )
        out = summarize_for_llm(html, max_chars=500, flag_regex=r"MetaCTF\{[^}]+\}")
        assert "MetaCTF{js_flag_value}" in out
        assert "[Flag pattern matches preserved" in out

    def test_flag_in_visible_text_not_duplicated(self):
        """When the flag is in the visible body (not stripped) it must
        stay intact and the preservation-append should NOT fire."""
        html = "<p>Here is the flag: MetaCTF{visible_flag}</p>"
        out = summarize_for_llm(html, max_chars=500, flag_regex=r"MetaCTF\{[^}]+\}")
        assert "MetaCTF{visible_flag}" in out
        assert "[Flag pattern matches preserved" not in out

    def test_invalid_flag_regex_degrades_silently(self):
        """Bad regex should not crash — it just disables preservation."""
        html = "<style>body{color:red}</style><p>hello</p>"
        # Intentionally invalid regex (unbalanced paren)
        out = summarize_for_llm(html, max_chars=500, flag_regex=r"(unterminated")
        assert "hello" in out
        assert "[style:" in out

    def test_empty_input_returns_empty(self):
        assert summarize_for_llm("", max_chars=1000) == ""
        assert summarize_for_llm("", max_chars=1000, flag_regex=r".*") == ""

    def test_unclosed_style_tag_not_stripped(self):
        """Regex requires closing </style> — unclosed tags pass through
        untouched. This is safe default behaviour."""
        html = "<style>body{color:red}<p>oops</p>"
        out = summarize_for_llm(html, max_chars=500)
        # No stripping happened because there's no </style>
        assert "<style>" in out
        assert "color:red" in out

    def test_accepts_compiled_pattern(self):
        pat = re.compile(r"FLAG\{[^}]+\}")
        html = "<style>FLAG{secret}</style><p>body</p>"
        out = summarize_for_llm(html, max_chars=500, flag_regex=pat)
        assert "FLAG{secret}" in out

    def test_accepts_none_flag_regex(self):
        html = "<style>MetaCTF{hidden}</style><p>body</p>"
        out = summarize_for_llm(html, max_chars=500, flag_regex=None)
        # No flag scan performed — the flag-in-style is lost. That's
        # the documented behaviour when flag_regex is None (callers
        # like the RAG tool opt out deliberately).
        assert "MetaCTF{hidden}" not in out


# ---------------------------------------------------------------------------
# TestHttpFetchSummarization — HttpFetchTool call-site integration
# ---------------------------------------------------------------------------
#
# The helper is wired into ``HttpFetchTool.use()`` after body truncation.
# These tests use the same mock-session pattern as tests/test_http_tools.py
# but only exercise the paths that matter for summarization.


@pytest.fixture
def http_mock_session():
    session = Mock()
    session.cookies = Mock()
    session.cookies.items.return_value = []
    session.headers = {}
    return session


def _build_mock_response(
    text: str, *, status_code: int = 200, url: str = "http://test.local/"
):
    resp = Mock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = {"Content-Type": "text/html"}
    resp.url = url
    resp.history = []
    resp.content = text.encode("utf-8")
    raw_headers_mock = Mock()
    raw_headers_mock.items.return_value = []
    resp.raw = Mock()
    resp.raw.headers = raw_headers_mock
    return resp


class TestHttpFetchSummarization:
    def test_css_heavy_page_shrinks_meaningfully(self, http_mock_session):
        """A page dominated by CSS (but small enough that the whole
        <style>...</style> fits under max_body=4000) should lose the
        CSS in the body preview. Confirms the helper is actually
        wired into HttpFetchTool and not bypassed on the text-branch.

        Note on scope: if a <style> block is larger than max_body, the
        truncation happens before summarize_for_llm sees the data and
        the closing </style> is gone, so the regex correctly skips
        stripping. Flag safety for that case is carried by
        HttpFetchTool's separate _scan_for_flags pass on the full
        pre-truncation text, not by this helper."""
        import json as _json

        from ctf_solver.tools.http_tools import HttpFetchTool

        # ~2.8 KB of CSS — realistic for an ornate challenge page, and
        # small enough that the whole <style> block fits under the
        # default 4000-char max_body truncation.
        big_css = "body { " + "color:red; background:blue; " * 100 + " }"
        html = f"<html><head><style>{big_css}</style></head><body>Actual content here.</body></html>"
        http_mock_session.get.return_value = _build_mock_response(html)

        tool = HttpFetchTool(session=http_mock_session)
        result = tool.use(_json.dumps({"url": "http://test.local/"}))

        # CSS rule text is stripped; placeholder + body content preserved.
        assert "color:red; background:blue;" not in result
        assert "[style:" in result
        assert "Actual content here." in result

    def test_flag_hidden_in_style_block_still_surfaces(self, http_mock_session):
        """HARD CONTRACT end-to-end: a flag hiding inside <style> must
        reach the caller. HttpFetchTool has two flag-preservation
        mechanisms — _scan_for_flags (beyond truncation) and
        summarize_for_llm's append (within truncation). This test
        exercises the latter."""
        import json as _json

        from ctf_solver.tools.http_tools import HttpFetchTool

        html = (
            "<html><head><style>/* MetaCTF{css_hidden_flag} */ "
            "body{color:red}</style></head><body>content</body></html>"
        )
        http_mock_session.get.return_value = _build_mock_response(html)

        tool = HttpFetchTool(session=http_mock_session)
        result = tool.use(_json.dumps({"url": "http://test.local/"}))

        assert "MetaCTF{css_hidden_flag}" in result

    def test_max_body_zero_disables_summarization(self, http_mock_session):
        """``max_body: 0`` means 'give me everything verbatim' — the
        caller is explicitly asking for raw content (e.g. a re-fetch
        to find a flag beyond a prior truncation). Summarization must
        NOT fire on that path."""
        import json as _json

        from ctf_solver.tools.http_tools import HttpFetchTool

        html = "<style>body{color:red}</style><p>raw</p>"
        http_mock_session.get.return_value = _build_mock_response(html)

        tool = HttpFetchTool(session=http_mock_session)
        result = tool.use(_json.dumps({"url": "http://test.local/", "max_body": 0}))

        # Raw CSS content survives because summarization was skipped.
        assert "color:red" in result
        assert "[style:" not in result


# ---------------------------------------------------------------------------
# TestDeepReconSummarization — DeepReconTool call-site integration
# ---------------------------------------------------------------------------


class TestDeepReconSummarization:
    def test_summarize_called_with_4000_cap(self):
        """Verify DeepReconTool wires the second-pass summarize with
        max_chars=4000 (lowered from 6000 in v3.10 P3b — the live
        gemma4:26b run on Crystal Peak showed 6 KB recon obs filled the
        16k context before exploitation; bottom-of-section content is
        already promoted to ``findings`` when relevant) and the correct
        flag regex. Monkeypatch the imported symbol in recon_tools so
        we can assert on call args without exercising the full HTTP
        stack."""
        from ctf_solver.tools import recon_tools
        from ctf_solver.tools.recon_tools import DeepReconTool

        captured = {}

        def spy_summarize(text, *, max_chars, flag_regex):
            captured["max_chars"] = max_chars
            captured["flag_regex"] = flag_regex
            captured["in_len"] = len(text)
            # Return the input unchanged so the rest of the flow is
            # structurally identical to the real path.
            return text

        with patch.object(recon_tools, "summarize_for_llm", side_effect=spy_summarize):
            # Mock every sub-tool to return a small fixed string so the
            # combined result is deterministic.
            tool = DeepReconTool(session=Mock())
            for sub in (
                "_http_tool",
                "_html_tool",
                "_js_tool",
                "_robots_tool",
                "_cookie_tool",
                "_header_tool",
            ):
                getattr(tool, sub).use = Mock(return_value="fake section output")

            import json as _json

            tool.use(_json.dumps({"url": "http://test.local/"}))

        assert captured["max_chars"] == 4000
        # The flag regex threaded through should be the shared _FLAG_SCAN_RE
        # compiled pattern from http_tools — instance equality is fine.
        from ctf_solver.tools.http_tools import _FLAG_SCAN_RE

        assert captured["flag_regex"] is _FLAG_SCAN_RE

    def test_combined_output_stays_under_cap_with_real_summarizer(self):
        """End-to-end with the real summarize_for_llm: even when the
        sub-tools return bloated fake output, the final DeepRecon
        result must be ≤ 4000 chars (plus a small truncation marker
        allowance) — v3.10 P3b lowered the cap from 6000 to 4000."""
        from ctf_solver.tools.recon_tools import DeepReconTool

        tool = DeepReconTool(session=Mock())
        # Each fake section is 2000 chars of repeated-line bloat.
        bloat = "bloat line that repeats a lot\n" * 100
        for sub in (
            "_http_tool",
            "_html_tool",
            "_js_tool",
            "_robots_tool",
            "_cookie_tool",
            "_header_tool",
        ):
            getattr(tool, sub).use = Mock(return_value=bloat)

        import json as _json

        result = tool.use(_json.dumps({"url": "http://test.local/"}))

        # Summarizer caps at 4000; an outer defensive truncator at 8000
        # never fires. Real cap hit here is summarizer's 4000.
        assert len(result) <= 4100  # tiny slack for the "[... truncated]" marker

    def test_idempotent_under_repeated_calls(self):
        """Running DeepReconTool twice on the same deterministic inputs
        produces the same output. This matters because the agent's tool
        cache keys on (tool_name, tool_input) — non-idempotent output
        would manifest as phantom changes across runs."""
        from ctf_solver.tools.recon_tools import DeepReconTool

        def make_tool():
            t = DeepReconTool(session=Mock())
            for sub in (
                "_http_tool",
                "_html_tool",
                "_js_tool",
                "_robots_tool",
                "_cookie_tool",
                "_header_tool",
            ):
                getattr(t, sub).use = Mock(return_value="deterministic output")
            return t

        import json as _json

        a = make_tool().use(_json.dumps({"url": "http://test.local/"}))
        b = make_tool().use(_json.dumps({"url": "http://test.local/"}))
        assert a == b


# ---------------------------------------------------------------------------
# TestRagChunkCap — SafeKnowledgeQueryTool per-chunk 400-char cap
# ---------------------------------------------------------------------------


def _rag_doc(content: str, source: str = "x.md") -> MagicMock:
    d = MagicMock()
    d.page_content = content
    d.metadata = {"source_file": source}
    return d


class TestRagChunkCap:
    def test_large_chunk_is_capped(self):
        """A 1000-char chunk → capped by summarize_for_llm(max_chars=400)."""
        from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool

        long_content = "A" * 1000
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = [_rag_doc(long_content, "big.md")]

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("q")

        # The [Result 1] header is <80 chars; the content after the
        # header must be capped. Total after header + cap + truncation
        # marker should be well under 600.
        assert "[... truncated]" in output
        # And no way the full 1000-char content survived verbatim.
        assert "A" * 500 not in output

    def test_small_chunk_is_not_modified(self):
        """A 200-char chunk (under the 400 cap) should pass through
        unchanged — no truncation marker, no content loss."""
        from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool

        short_content = "Short relevant paragraph about SQL injection."
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = [_rag_doc(short_content, "small.md")]

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("q")
        assert short_content in output
        assert "[... truncated]" not in output

    def test_cap_does_not_break_dedup(self):
        """Phase 1b dedup + Phase 2 cap compose cleanly: duplicates
        still collapse to one, and that one gets the 400-char cap."""
        from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool

        long_dup = "B" * 1500
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = [
            _rag_doc(long_dup, "dup.md") for _ in range(5)
        ]

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("q")
        # Exactly one [Result N] header (dedup worked).
        assert output.count("[Result 1]") == 1
        assert "[Result 2]" not in output
        # And that single chunk was capped (Phase 2 worked).
        assert "[... truncated]" in output
