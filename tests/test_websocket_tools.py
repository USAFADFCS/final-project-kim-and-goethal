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
        assert "tool_input must be JSON" in result

    def test_missing_url(self):
        result = self.tool.use(json.dumps({"operation": "connect"}))
        assert "Error" in result
        assert "'url'" in result

    def test_url_must_be_string(self):
        result = self.tool.use(json.dumps({"url": 123}))
        assert "Error" in result

    def test_unknown_operation(self):
        result = self.tool.use(
            json.dumps(
                {
                    "url": "ws://example.com/ws",
                    "operation": "hack",
                }
            )
        )
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
        assert "session" in WebSocketProbeTool.VALID_OPERATIONS

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

    # -- session operation (multi-frame, one persistent connection) -------

    def _mock_ws_factory(self, recv_results):
        """Build a fake ws_lib object whose create_connection returns a
        Mock socket. recv_results is a list of either strings (returned) or
        Exceptions (raised)."""
        recv_iter = iter(recv_results)

        def _recv():
            item = next(recv_iter)
            if isinstance(item, Exception):
                raise item
            return item

        fake_ws = MagicMock()
        fake_ws.recv.side_effect = _recv
        fake_ws.send.return_value = None
        fake_ws.settimeout.return_value = None
        fake_ws.close.return_value = None

        fake_lib = MagicMock()
        fake_lib.create_connection.return_value = fake_ws
        return fake_lib, fake_ws

    def test_session_opens_one_connection_for_all_messages(self):
        import websocket as real_ws

        # Socket.IO-shaped transcript: handshake → register → login.
        recv_results = [
            '0{"sid":"ABC","pingInterval":25000}',
            real_ws.WebSocketTimeoutException(),  # drain end after msg 1
            '42["action_response",{"success":false}]',
            real_ws.WebSocketTimeoutException(),  # drain end after msg 2
            '42["action_response",{"redirect":"/admin"}]',
            real_ws.WebSocketTimeoutException(),  # drain end after msg 3
            real_ws.WebSocketTimeoutException(),  # final drain exits
        ]
        fake_lib, fake_ws = self._mock_ws_factory(recv_results)

        with (
            patch("ctf_solver.tools.websocket_tools.ws_lib", fake_lib),
            patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", True),
        ):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "ws://target/socket.io/?EIO=4&transport=websocket",
                        "operation": "session",
                        "messages": [
                            "40",
                            '42["register",{"u":"x"}]',
                            '42["login",{"u":"x"}]',
                        ],
                    }
                )
            )

        # Exactly one connection must be opened.
        assert fake_lib.create_connection.call_count == 1
        # All three sends must have happened on that one socket.
        assert fake_ws.send.call_count == 3
        # Transcript must contain both directions.
        assert "[TX] 40" in result
        assert '[TX] 42["register"' in result
        assert "[RX]" in result
        assert "action_response" in result
        # Socket closed exactly once.
        assert fake_ws.close.call_count == 1

    def test_session_surfaces_flag_in_transcript(self):
        recv_results = ["greeting FLAG{ws_session_leak}"]
        fake_lib, _ = self._mock_ws_factory(recv_results)
        # After the one frame, recv should raise to end the loop.
        import websocket as real_ws

        extended = ["greeting FLAG{ws_session_leak}"] + [
            real_ws.WebSocketTimeoutException()
        ] * 20
        fake_lib, _ = self._mock_ws_factory(extended)

        with (
            patch("ctf_solver.tools.websocket_tools.ws_lib", fake_lib),
            patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", True),
        ):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "ws://target/",
                        "operation": "session",
                        "messages": ["ping"],
                    }
                )
            )
        assert "FLAGS FOUND" in result
        assert "FLAG{ws_session_leak}" in result

    def test_session_requires_messages(self):
        with patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", True):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "ws://target/",
                        "operation": "session",
                        "messages": [],
                    }
                )
            )
        assert "Error" in result
        assert "messages" in result.lower()

    def test_session_library_missing_returns_error(self):
        with patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", False):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "ws://target/",
                        "operation": "session",
                        "messages": ["ping"],
                    }
                )
            )
        # Top-level message from use() handles the lib-missing case.
        assert "not installed" in result

    def test_session_rejects_non_numeric_timeouts(self):
        with patch("ctf_solver.tools.websocket_tools.HAS_WEBSOCKET", True):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "ws://target/",
                        "operation": "session",
                        "messages": ["ping"],
                        "read_timeout": "not a number",
                    }
                )
            )
        assert "Error" in result
        assert "numeric" in result
