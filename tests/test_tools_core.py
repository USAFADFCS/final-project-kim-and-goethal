"""Tests for ``ctf_solver.tools.core`` (Batch D #6).

Shared helper for tool JSON input parsing.  ``http_tools`` is the first
adopter — other tools can migrate incrementally without breaking tests as
long as the error string stays byte-identical to the dominant format.
"""

from ctf_solver.tools.core import parse_json_input


class TestParseJsonInput:
    def test_valid_json_object(self):
        data, err = parse_json_input('{"url": "http://x", "timeout": 5}', "Foo")
        assert err is None
        assert data == {"url": "http://x", "timeout": 5}

    def test_empty_string_returns_empty_dict_no_error(self):
        data, err = parse_json_input("", "Foo")
        assert err is None
        assert data == {}

    def test_none_like_whitespace_returns_empty_dict_no_error(self):
        data, err = parse_json_input("   ", "Foo")
        assert err is None
        assert data == {}

    def test_invalid_json_returns_error_with_tool_name(self):
        data, err = parse_json_input("{not json", "BarTool")
        assert data is None
        assert err is not None
        assert err.startswith("[BarTool] Error: tool_input must be JSON.")
        assert "Decoding failed with:" in err

    def test_non_object_json_returns_error(self):
        # A JSON array parses but tools always expect an object.
        data, err = parse_json_input("[1, 2, 3]", "QuxTool")
        assert data is None
        assert err is not None
        assert "[QuxTool] Error" in err
        assert "JSON object" in err

    def test_error_format_matches_pre_migration_string(self):
        """http_tools.py relied on an exact error string format; the helper
        must preserve it so migrating tools doesn't break their own tests."""
        _data, err = parse_json_input("garbage", "HttpFetchTool")
        # Pre-migration format was:
        # "[HttpFetchTool] Error: tool_input must be JSON. Decoding failed with: <exc>"
        assert err is not None
        assert err.startswith(
            "[HttpFetchTool] Error: tool_input must be JSON. " "Decoding failed with:"
        )
