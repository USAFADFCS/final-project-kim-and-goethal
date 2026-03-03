"""
Tests for WebSocket tools (WebSocketProbeTool).

Covers:
- Tool name/description
- Error handling for invalid JSON, missing URL, unknown operation
- Injection payload table existence
- Operation dispatch (mocked websocket-client)
- Graceful fallback when websocket-client not installed
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from ctf_solver.tools.websocket_tools import WebSocketProbeTool


class TestWebSocketProbeTool:
    """Tests for WebSocketProbeTool."""

    def setup_method(self):
        self.tool = WebSocketProbeTool()

    # -- identity -----------------------------------------------------------

    def test_tool_name(self):
        assert self.tool.name == "websocket_probe"

    def test_tool_description_mentions_websocket(self):
        assert "WebSocket" in self.tool.description

    # -- error handling -----------------------------------------------------

    def test_invalid_json(self):
        result = self.tool.use("{bad")
        assert "Error" in result
        assert "Invalid JSON" in result

    def test_missing_url(self):
        result = self.tool.use(json.dumps({"operation": "connect"}))
        assert "Error" in result
        assert "'url'" in result

    def test_url_must_be_string(self):
        result = self.tool.use(json.dumps({"url": 123}))
        assert "Error" in result

    def test_unknown_operation(self):
        result = self.tool.use(json.dumps({
            "url": "ws://example.com/ws",
            "operation": "hack",
        }))
        assert "Error" in result
        assert "Unknown operation" in result

    def test_empty_input(self):
        result = self.tool.use("")
        assert "Error" in result

    # -- payload tables -----------------------------------------------------

    def test_injection_payloads_exist(self):
        assert len(WebSocketProbeTool.INJECTION_PAYLOADS) >= 5

    def test_injection_payloads_cover_types(self):
        types = {p["type"] for p in WebSocketProbeTool.INJECTION_PAYLOADS}
        assert "xss" in types
        assert "sqli" in types
        assert "ssti" in types

    def test_valid_operations_set(self):
        assert "connect" in WebSocketProbeTool.VALID_OPERATIONS
        assert "cswsh" in WebSocketProbeTool.VALID_OPERATIONS
        assert "enumerate" in WebSocketProbeTool.VALID_OPERATIONS
        assert "injection" in WebSocketProbeTool.VALID_OPERATIONS

    # -- flag extraction ----------------------------------------------------

    def test_flag_extraction(self):
        flags = self.tool._extract_flags("found FLAG{ws_vuln} in response")
        assert "FLAG{ws_vuln}" in flags

    def test_flag_extraction_empty(self):
        flags = self.tool._extract_flags("nothing here")
        assert flags == []

    # -- default operation --------------------------------------------------

    def test_default_operation_is_connect(self):
        """When no operation specified, defaults to connect."""
        with patch.object(self.tool, "_operation_connect", return_value="ok") as mock:
            self.tool.use(json.dumps({"url": "ws://example.com/ws"}))
            mock.assert_called_once()

    # -- no websocket lib ---------------------------------------------------

    def test_ws_connect_without_library(self):
        """Graceful error when websocket-client not installed."""
        with patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", False):
            result = self.tool._ws_connect_send(
                "ws://example.com/ws", None, None, None, 5
            )
            assert "error" in result
            assert "not installed" in result["error"]
