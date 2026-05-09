"""
Tests for OAuth/OIDC tools (OAuthProbeTool, OAuthPayloadGenerator).

Covers:
- OAuthProbeTool: name/description, error handling, redirect_uri/state/scope
  test dispatching (with mocked HTTP)
- OAuthPayloadGenerator: all 5 operations, error handling, output content
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ctf_solver.tools.oauth_tools import OAuthProbeTool, OAuthPayloadGenerator

# ==============================================================================
# OAuthProbeTool Tests
# ==============================================================================


class TestOAuthProbeTool:
    """Tests for OAuthProbeTool."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = OAuthProbeTool(session=self.session)

    def test_tool_name(self):
        assert self.tool.name == "oauth_probe"

    def test_tool_description_mentions_oauth(self):
        assert "OAuth" in self.tool.description

    def test_invalid_json_returns_error(self):
        result = self.tool.use("not json{{{")
        assert "Error" in result
        assert "tool_input must be JSON" in result

    def test_missing_url_returns_error(self):
        result = self.tool.use(json.dumps({"client_id": "test"}))
        assert "Error" in result
        assert "'url'" in result

    def test_empty_input_returns_error(self):
        result = self.tool.use("")
        assert "Error" in result

    def test_url_must_be_string(self):
        result = self.tool.use(json.dumps({"url": 123}))
        assert "Error" in result

    def test_default_tests_all(self):
        """Without tests param, all 4 tests are run."""
        with (
            patch.object(self.tool, "_test_redirect_uri", return_value=[]) as m1,
            patch.object(self.tool, "_test_state_param", return_value=[]) as m2,
            patch.object(self.tool, "_test_scope_escalation", return_value=[]) as m3,
            patch.object(self.tool, "_test_open_redirect", return_value=[]) as m4,
        ):
            self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/auth",
                        "redirect_uri": "http://example.com/cb",
                    }
                )
            )
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()

    def test_selective_tests(self):
        """Only specified tests run."""
        with (
            patch.object(self.tool, "_test_redirect_uri", return_value=[]) as m1,
            patch.object(self.tool, "_test_state_param", return_value=[]) as m2,
        ):
            self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/auth",
                        "redirect_uri": "http://example.com/cb",
                        "tests": ["redirect_uri"],
                    }
                )
            )
            m1.assert_called_once()
            m2.assert_not_called()

    def test_redirect_uri_manipulation_payloads_exist(self):
        """Tool has redirect manipulation payloads."""
        assert len(OAuthProbeTool.REDIRECT_MANIPULATIONS) >= 5

    def test_scope_escalation_payloads_exist(self):
        """Tool has scope escalation payloads."""
        assert len(OAuthProbeTool.SCOPE_ESCALATIONS) >= 3

    def test_output_format(self):
        """Output contains header and summary."""
        with patch.object(self.tool, "_test_redirect_uri", return_value=[]):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://example.com/auth",
                        "tests": ["redirect_uri"],
                    }
                )
            )
            assert "OAuthProbeTool" in result

    def test_flag_extraction(self):
        """_extract_flags finds CTF flag patterns."""
        flags = self.tool._extract_flags("body contains FLAG{test_flag} here")
        assert "FLAG{test_flag}" in flags

    def test_flag_extraction_empty(self):
        flags = self.tool._extract_flags("no flags here")
        assert flags == []

    def test_no_session_creates_default(self):
        tool = OAuthProbeTool()
        assert tool.session is not None


# ==============================================================================
# OAuthPayloadGenerator Tests
# ==============================================================================


class TestOAuthPayloadGenerator:
    """Tests for OAuthPayloadGenerator."""

    def setup_method(self):
        self.tool = OAuthPayloadGenerator()

    def test_tool_name(self):
        assert self.tool.name == "oauth_payload_generator"

    def test_invalid_json(self):
        result = self.tool.use("{bad json")
        assert "Error" in result

    def test_missing_operation(self):
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_unknown_operation(self):
        result = self.tool.use(json.dumps({"operation": "nonexistent"}))
        assert "Error" in result
        assert "Unknown operation" in result

    def test_redirect_uri_bypass(self):
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "redirect_uri_bypass",
                    "redirect_uri": "https://example.com/callback",
                }
            )
        )
        assert "Redirect URI" in result
        assert "evil" in result.lower()

    def test_token_theft(self):
        result = self.tool.use(json.dumps({"operation": "token_theft"}))
        assert "Token" in result

    def test_scope_escalation(self):
        result = self.tool.use(json.dumps({"operation": "scope_escalation"}))
        assert "Scope" in result
        assert "admin" in result

    def test_pkce_bypass(self):
        result = self.tool.use(json.dumps({"operation": "pkce_bypass"}))
        assert "PKCE" in result

    def test_discovery(self):
        result = self.tool.use(json.dumps({"operation": "discovery"}))
        assert "well-known" in result.lower() or "openid" in result.lower()

    def test_all_operations_valid(self):
        """All declared operations produce non-empty output."""
        for op in OAuthPayloadGenerator.VALID_OPERATIONS:
            result = self.tool.use(json.dumps({"operation": op}))
            assert "Error" not in result, f"Operation {op} returned error"
            assert len(result) > 50, f"Operation {op} output too short"
