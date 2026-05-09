"""v3.3 Phase 3b — parse_json_input auto-repair + context-aware error hints.

Targets two kinds of ``tool_input must be JSON`` failure observed in the
2026-04-23 Gemma4-26B batch (recentTestRun.txt):

1. Unambiguously repairable malformations (bare URLs, Python call
   syntax) — verified by exercising the new ``url_field`` and
   ``allow_python_call_syntax`` kwargs.
2. Ambiguous malformations (unescaped quotes in ``raw_body`` XML,
   literal newlines, truncated JSON) — verified by checking the new
   actionable ``→ Hint:`` line appended to the error message.

Also includes a replay bank of real malformed inputs pulled straight
from recentTestRun.txt plus a prompt smoke-check ensuring the new
XXE_RAW_BODY_EXAMPLE is exported and renders with ``\\"``-escaped
inner quotes.
"""

from __future__ import annotations

from ctf_solver.prompts import XXE_RAW_BODY_EXAMPLE
from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.http_tools import HttpFetchTool


class TestParseJsonInputAutoRepair:
    """Deterministic repairs — only when the caller opts in."""

    def test_bare_url_wrapped_when_url_field_set(self):
        data, err = parse_json_input(
            "http://example.com/api/v1/user/1",
            "HttpFetchTool",
            url_field="url",
        )
        assert err is None
        assert data == {"url": "http://example.com/api/v1/user/1"}

    def test_bare_url_ignored_when_url_field_none(self):
        # Back-compat: no url_field → bare URL still fails JSON parse.
        data, err = parse_json_input(
            "http://example.com/api/v1/user/1",
            "HttpFetchTool",
        )
        assert data is None
        assert err is not None
        assert "tool_input must be JSON" in err

    def test_https_url_wrapped(self):
        data, err = parse_json_input(
            "https://cyberlabhost.com/abc/",
            "HttpFetchTool",
            url_field="url",
        )
        assert err is None
        assert data == {"url": "https://cyberlabhost.com/abc/"}

    def test_url_with_whitespace_not_auto_wrapped(self):
        # Ambiguous — could be "URL + extra data", safest to fail.
        data, err = parse_json_input(
            "http://example.com/ extra stuff",
            "HttpFetchTool",
            url_field="url",
        )
        assert data is None
        assert err is not None

    def test_url_that_looks_like_json_still_parses_as_json(self):
        # If the input contains '{', JSON parse wins — we don't wrap.
        data, err = parse_json_input(
            '{"url": "http://example.com"}',
            "HttpFetchTool",
            url_field="url",
        )
        assert err is None
        assert data == {"url": "http://example.com"}

    def test_python_call_syntax_parsed_when_opted_in(self):
        data, err = parse_json_input(
            "http_fetch(url='http://localhost:8080/api/v1/user/1')",
            "http_fetch",
            allow_python_call_syntax=True,
        )
        assert err is None
        assert data == {"url": "http://localhost:8080/api/v1/user/1"}

    def test_python_call_syntax_rejected_when_default(self):
        data, err = parse_json_input(
            "http_fetch(url='http://localhost:8080/api/v1/user/1')",
            "http_fetch",
        )
        assert data is None
        assert err is not None

    def test_python_call_wrong_tool_name_falls_through(self):
        # Only accept calls whose leading ident matches tool_name exactly.
        data, err = parse_json_input(
            "something_else(url='http://x')",
            "http_fetch",
            allow_python_call_syntax=True,
        )
        assert data is None
        assert err is not None

    def test_malformed_python_call_falls_through_to_error(self):
        # Not parseable as literal — fall through to JSON error path.
        data, err = parse_json_input(
            "http_fetch(url=undefined_name)",
            "http_fetch",
            allow_python_call_syntax=True,
        )
        assert data is None
        assert err is not None


class TestParseJsonInputErrorHints:
    """JSON decode failures now carry a one-line actionable hint."""

    def test_bare_string_triggers_not_json_hint(self):
        data, err = parse_json_input("hello world", "HttpFetchTool")
        assert data is None
        assert err is not None
        assert "→ Hint:" in err
        assert "not JSON" in err

    def test_unescaped_quotes_in_raw_body_triggers_escape_hint(self):
        # Real sample from recentTestRun.txt run 6 (dot_matrix_destruction).
        payload = (
            '{"url": "http://target/api/search", "raw_body": '
            '"<?xml version="1.0"?><root/>"}'
        )
        data, err = parse_json_input(payload, "HttpFetchTool")
        assert data is None
        assert err is not None
        assert "→ Hint:" in err
        assert "raw_body" in err
        assert '\\"' in err

    def test_literal_newline_triggers_control_char_hint(self):
        payload = '{"raw_body": "line1\nline2"}'
        data, err = parse_json_input(payload, "HttpFetchTool")
        assert data is None
        assert err is not None
        assert "→ Hint:" in err
        assert "\\n" in err

    def test_unterminated_string_triggers_truncation_hint(self):
        payload = '{"url": "http://example.com'
        data, err = parse_json_input(payload, "HttpFetchTool")
        assert data is None
        assert err is not None
        assert "→ Hint:" in err
        assert "truncated" in err.lower() or "closing quote" in err.lower()

    def test_unknown_error_falls_through_without_hint(self):
        # JSON array isn't a decode error — it's a "not an object" error,
        # which doesn't go through the hint classifier at all.
        data, err = parse_json_input("[1, 2, 3]", "HttpFetchTool")
        assert data is None
        assert err is not None
        assert "→ Hint:" not in err

    def test_hint_appended_preserving_original_error_prefix(self):
        # Back-compat: log scrapers that match the mechanical prefix
        # must still work.
        data, err = parse_json_input("not json at all", "HttpFetchTool")
        assert data is None
        assert err is not None
        assert err.startswith(
            "[HttpFetchTool] Error: tool_input must be JSON. Decoding failed with:"
        )


class TestReplayRealFailures:
    """Replay each distinct failure category from recentTestRun.txt."""

    def test_run6_xxe_quote_failure_gets_escape_hint(self):
        # Condensed sample of the XXE payload shape that failed 13× in run 6.
        raw = (
            '{"url": "http://70.249.212.221/api/search_printers", '
            '"raw_body": "<?xml version="1.0"?><root/>"}'
        )
        data, err = parse_json_input(raw, "HttpFetchTool")
        assert data is None
        assert err is not None
        # Hint must mention raw_body AND show the correct escape form.
        assert "raw_body" in err
        assert '\\"' in err

    def test_run7_python_call_syntax_gets_wrapped(self):
        raw = "http_fetch(url='http://localhost:8080/api/v1/user/1')"
        # Without opt-in, it fails.
        _d, err_default = parse_json_input(raw, "http_fetch")
        assert err_default is not None
        # With opt-in, it repairs.
        data, err = parse_json_input(raw, "http_fetch", allow_python_call_syntax=True)
        assert err is None
        assert data == {"url": "http://localhost:8080/api/v1/user/1"}

    def test_run6_bare_url_gets_wrapped(self):
        # 4 of 5 "D" bare-URL errors were in run 6.
        raw = "http://70.249.212.221/api/search?printer_name=test"
        data, err = parse_json_input(raw, "HttpFetchTool", url_field="url")
        assert err is None
        assert data == {"url": raw}


class TestHttpFetchWithBareUrl:
    """Integration: HttpFetchTool accepts a bare URL via the opt-in."""

    def test_http_fetch_rejects_bare_url_without_opt_in_at_tool_level(self):
        # Sanity: direct helper WITHOUT url_field still rejects.
        data, err = parse_json_input("http://example.com/", "HttpFetchTool")
        assert data is None
        assert err is not None

    def test_http_fetch_tool_wraps_bare_url_before_network_call(self):
        # With Phase 3b wiring, HttpFetchTool.use passes url_field="url".
        # We don't actually hit the network — we only check that the
        # bare URL produces a different code path than "error" (i.e. it
        # tries to fetch, which will fail with a connection error, not
        # a tool_input-must-be-JSON error).
        tool = HttpFetchTool()
        result = tool.use("http://definitely-not-a-real-host-12345.invalid/")
        assert "tool_input must be JSON" not in result
        # Either a connection-level error or a 4xx/5xx — both are fine.
        # The key is that parse_json_input no longer rejected the input.
        assert "[HttpFetchTool]" in result


class TestPromptXxeExample:
    """The Phase 3b prompt example must render with escaped inner quotes."""

    def test_xxe_example_exported(self):
        assert XXE_RAW_BODY_EXAMPLE is not None

    def test_xxe_example_contains_escaped_quotes_in_raw_body(self):
        # The Example's text body must include the escaped form so the
        # LLM sees the right pattern in its few-shot context.
        text = getattr(
            XXE_RAW_BODY_EXAMPLE,
            "text",
            getattr(XXE_RAW_BODY_EXAMPLE, "content", str(XXE_RAW_BODY_EXAMPLE)),
        )
        assert "raw_body" in text
        assert '\\"1.0\\"' in text
        assert "file:///flag.txt" in text
