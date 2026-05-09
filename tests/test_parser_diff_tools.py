"""
Tests for parser differential tools (ParserDifferentialProbeTool).

Covers:
- Tool name/description
- Error handling for invalid JSON, missing URL
- HPP payload table existence
- Test dispatching (mocked HTTP)
- Output format
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ctf_solver.tools.parser_diff_tools import ParserDifferentialProbeTool


class TestParserDifferentialProbeTool:
    """Tests for ParserDifferentialProbeTool."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = ParserDifferentialProbeTool(session=self.session)

    # -- identity -----------------------------------------------------------

    def test_tool_name(self):
        assert self.tool.name == "parser_differential_probe"

    def test_tool_description_mentions_parser(self):
        assert "parser" in self.tool.description.lower()

    # -- error handling -----------------------------------------------------

    def test_invalid_json(self):
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "tool_input must be JSON" in result

    def test_missing_url(self):
        result = self.tool.use(json.dumps({"param": "q"}))
        assert "Error" in result
        assert "'url'" in result

    def test_url_must_be_string(self):
        result = self.tool.use(json.dumps({"url": 42}))
        assert "Error" in result

    def test_empty_input(self):
        result = self.tool.use("")
        assert "Error" in result

    # -- payload tables exist -----------------------------------------------

    def test_hpp_payloads_exist(self):
        assert len(ParserDifferentialProbeTool.HPP_PAYLOADS) >= 4

    def test_content_type_payloads_exist(self):
        assert len(ParserDifferentialProbeTool.CONTENT_TYPE_PAYLOADS) >= 3

    def test_url_parsing_payloads_exist(self):
        assert len(ParserDifferentialProbeTool.URL_PARSING_PAYLOADS) >= 5

    # -- test dispatching ---------------------------------------------------

    def test_default_runs_all_tests(self):
        """Without tests param, all test categories are run."""
        with (
            patch.object(self.tool, "_test_duplicate_params", return_value=[]) as m1,
            patch.object(self.tool, "_test_content_type", return_value=[]) as m2,
            patch.object(self.tool, "_test_url_parsing", return_value=[]) as m3,
            patch.object(self.tool, "_test_encoding_diff", return_value=[]) as m4,
        ):
            self.tool.use(json.dumps({"url": "http://example.com/api"}))
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()

    def test_selective_test(self):
        """Only the specified test runs."""
        with (
            patch.object(self.tool, "_test_duplicate_params", return_value=[]) as m1,
            patch.object(self.tool, "_test_content_type", return_value=[]) as m2,
        ):
            self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/api",
                        "tests": ["duplicate_params"],
                    }
                )
            )
            m1.assert_called_once()
            m2.assert_not_called()

    # -- output format ------------------------------------------------------

    def test_output_header(self):
        with patch.object(self.tool, "_test_duplicate_params", return_value=[]):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/api",
                        "tests": ["duplicate_params"],
                    }
                )
            )
            assert "ParserDifferentialProbeTool" in result

    def test_no_session_creates_default(self):
        tool = ParserDifferentialProbeTool()
        assert tool.session is not None

    def test_method_default_is_get(self):
        """Default method should be GET."""
        with patch.object(self.tool, "_test_duplicate_params", return_value=[]) as mock:
            self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/api",
                        "tests": ["duplicate_params"],
                    }
                )
            )
            # Check method passed to _test_duplicate_params
            args = mock.call_args
            assert args[0][2] == "GET" or args[1].get("method") == "GET"
