"""
WebSocket testing tools for CTF solving.

Provides WebSocket connect/send/receive and CSWSH (Cross-Site WebSocket
Hijacking) detection capabilities.

Appeared in: RWCTF 2023 ChatUWU, m0leCon 2023 goldinospizza2.
"""

import re
from typing import Any, Dict, List, Optional

from ctf_solver.tools.core import parse_json_input

# Optional websocket-client dependency
try:
    import websocket as ws_lib  # type: ignore

    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False


class WebSocketProbeTool:
    """
    WebSocketProbeTool: test WebSocket endpoints for vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "ws://target.com/ws",
          "operation": "connect",
          "message": "hello",
          "headers": {},
          "origin": "http://evil.com",
          "messages": ["msg1", "msg2"],
          "timeout": 5
        }

    Operations:
      - connect: Connect and optionally send/receive messages
      - cswsh: Test for Cross-Site WebSocket Hijacking (origin validation)
      - enumerate: Send multiple messages and collect responses
      - injection: Test for injection via WebSocket messages
    """

    name: str = "websocket_probe"
    description: str = (
        "Test WebSocket endpoints for vulnerabilities. Input must be JSON with "
        "'url' (WebSocket URL, ws:// or wss://), 'operation' (connect, cswsh, "
        "enumerate, injection). For connect: optional 'message' to send, 'headers'. "
        "For cswsh: optional 'origin' (evil origin to test). For enumerate: "
        "'messages' (list of messages to send, each on its OWN fresh "
        "connection). For session: 'messages' (list sent on a SINGLE "
        "persistent connection — required for multi-frame protocols like "
        "Socket.IO where a handshake frame must precede event frames), "
        "optional 'read_timeout' (per-message drain, default 2.0s), "
        "'final_read_timeout' (end-of-session drain, default 5.0s), "
        "'max_frames_per_read' (cap on frames per recv loop, default 5). "
        "For injection: tests common injection payloads via WebSocket. "
        "Optional 'timeout' (default 5). Requires websocket-client library."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "ws:// or wss:// URL"},
            "operation": {
                "type": "string",
                "enum": ["connect", "cswsh", "enumerate", "injection", "session"],
            },
            "message": {"type": "string"},
            "messages": {"type": "array"},
            "headers": {"type": "object"},
            "origin": {"type": "string"},
            "timeout": {"type": "number", "default": 5},
            "read_timeout": {"type": "number", "default": 2.0},
            "final_read_timeout": {"type": "number", "default": 5.0},
            "max_frames_per_read": {"type": "integer", "default": 5},
        },
        "required": ["url", "operation"],
        "additionalProperties": False,
    }
    samples = [
        {"url": "ws://example.com/ws", "operation": "connect", "message": "hello"},
        {"url": "ws://example.com/ws", "operation": "cswsh", "origin": "http://evil"},
        {
            "url": "ws://example.com/ws",
            "operation": "enumerate",
            "messages": ["ping", "list"],
        },
    ]

    VALID_OPERATIONS = {"connect", "cswsh", "enumerate", "injection", "session"}

    # Common injection payloads for WebSocket messages
    INJECTION_PAYLOADS: List[Dict[str, str]] = [
        {"payload": "<script>alert(1)</script>", "type": "xss"},
        {"payload": "' OR 1=1 --", "type": "sqli"},
        {"payload": '{"$gt": ""}', "type": "nosql"},
        {"payload": "{{7*7}}", "type": "ssti"},
        {"payload": "../../../etc/passwd", "type": "lfi"},
        {"payload": "; id", "type": "cmdi"},
        {"payload": '{"__proto__": {"admin": true}}', "type": "prototype_pollution"},
    ]

    FLAG_PATTERNS: List[str] = [
        r"(picoCTF\{[^}]+\})",
        r"(HTB\{[^}]+\})",
        r"(THM\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
    ]

    def _extract_flags(self, text: str) -> List[str]:
        flags = []
        for pattern in self.FLAG_PATTERNS:
            for m in re.finditer(pattern, text):
                if m.group(1) not in flags:
                    flags.append(m.group(1))
        return flags

    def _ws_connect_send(
        self,
        url: str,
        message: Optional[str],
        headers: Optional[Dict[str, str]],
        origin: Optional[str],
        timeout: int,
    ) -> Dict[str, Any]:
        """Connect to WebSocket, optionally send a message, receive response."""
        if not HAS_WEBSOCKET:
            return {
                "error": "websocket-client library not installed. pip install websocket-client"
            }

        result: Dict[str, Any] = {
            "connected": False,
            "sent": None,
            "received": [],
            "error": None,
        }

        try:
            header_list = []
            if headers:
                for k, v in headers.items():
                    header_list.append(f"{k}: {v}")

            ws = ws_lib.create_connection(
                url,
                header=header_list or None,
                origin=origin,
                timeout=timeout,
            )
            result["connected"] = True

            if message is not None:
                ws.send(message)
                result["sent"] = message

                # Try to receive response(s)
                try:
                    ws.settimeout(timeout)
                    response = ws.recv()
                    result["received"].append(response)

                    # Try for additional messages (non-blocking)
                    ws.settimeout(1)
                    for _ in range(5):
                        try:
                            extra = ws.recv()
                            result["received"].append(extra)
                        except Exception:
                            break
                except Exception:
                    pass

            ws.close()
        except Exception as exc:
            result["error"] = str(exc)

        return result

    def _operation_connect(
        self, url: str, message: Optional[str], headers: Dict, timeout: int
    ) -> str:
        """Simple connect and send/receive."""
        result = self._ws_connect_send(url, message, headers, None, timeout)

        lines = ["--- Connect Result ---"]
        lines.append(f"  Connected: {result['connected']}")
        if result["sent"]:
            lines.append(f"  Sent: {result['sent']}")
        if result["received"]:
            for i, msg in enumerate(result["received"]):
                preview = str(msg)[:500]
                lines.append(f"  Response {i}: {preview}")
        if result["error"]:
            lines.append(f"  Error: {result['error']}")

        # Check for flags
        all_text = " ".join(str(r) for r in result["received"])
        flags = self._extract_flags(all_text)
        if flags:
            lines.append("  !!! FLAGS FOUND !!!")
            for f in flags:
                lines.append(f"    {f}")

        return "\n".join(lines)

    def _operation_cswsh(
        self, url: str, headers: Dict, timeout: int, origin: Optional[str]
    ) -> str:
        """Test Cross-Site WebSocket Hijacking."""
        lines = ["--- CSWSH Test ---"]

        evil_origins = [
            origin or "http://evil.com",
            "http://localhost",
            "null",
            "",
        ]

        for test_origin in evil_origins:
            result = self._ws_connect_send(url, "ping", headers, test_origin, timeout)
            status = "CONNECTED" if result["connected"] else "REJECTED"
            lines.append(f"  Origin '{test_origin}': {status}")
            if result["connected"] and result["received"]:
                lines.append(f"    Response: {str(result['received'][0])[:200]}")
            if result["error"] and not result["connected"]:
                lines.append(f"    Error: {result['error'][:100]}")

        lines.append("")
        connected_count = sum(
            1
            for o in evil_origins
            if self._ws_connect_send(url, None, headers, o, timeout)["connected"]
        )
        if connected_count > 0:
            lines.append(
                "  [!] CSWSH LIKELY: WebSocket accepts connections from arbitrary origins!"
            )
        else:
            lines.append("  [-] Origin validation appears to be enforced.")

        return "\n".join(lines)

    def _operation_enumerate(
        self, url: str, messages: List[str], headers: Dict, timeout: int
    ) -> str:
        """Send multiple messages and collect responses."""
        lines = ["--- Enumerate Results ---"]

        for msg in messages[:20]:  # Cap at 20
            result = self._ws_connect_send(url, msg, headers, None, timeout)
            lines.append(f"  Message: {msg[:100]}")
            if result["received"]:
                for r in result["received"]:
                    lines.append(f"    Response: {str(r)[:300]}")
            elif result["error"]:
                lines.append(f"    Error: {result['error'][:100]}")
            else:
                lines.append("    (no response)")
            lines.append("")

        return "\n".join(lines)

    def _operation_session(
        self,
        url: str,
        messages: List[str],
        headers: Dict,
        timeout: int,
        read_timeout: float,
        final_read_timeout: float,
        max_frames_per_read: int,
    ) -> str:
        """Open ONE websocket, send each message on it, drain between and
        after. Unlike ``enumerate`` (which opens a fresh connection per
        message), this preserves server-side session state — required for
        protocols like Socket.IO where a namespace-connect frame (``40``)
        must precede event frames (``42[...]``) on the same socket.

        Transcript format:
            [TX] <sent frame>
            [RX] <received frame>  (one line per frame)
            (timeout)               (when drain hits the per-message budget)
        """
        lines = ["--- Session Transcript ---"]

        if not messages:
            lines.append("  Error: 'messages' is required for session operation.")
            return "\n".join(lines)

        if not HAS_WEBSOCKET:
            lines.append(
                "  Error: websocket-client library not installed. "
                "Install with: pip install websocket-client"
            )
            return "\n".join(lines)

        header_list = [f"{k}: {v}" for k, v in (headers or {}).items()]

        ws = None
        all_rx: List[str] = []
        try:
            ws = ws_lib.create_connection(
                url,
                header=header_list or None,
                timeout=timeout,
            )
            lines.append(f"  [connected] {url}")

            # Capped to keep output/token footprint bounded.
            for msg in messages[:20]:
                ws.send(msg)
                lines.append(f"  [TX] {str(msg)[:300]}")

                ws.settimeout(read_timeout)
                for _ in range(max_frames_per_read):
                    try:
                        frame = ws.recv()
                    except Exception:
                        lines.append("  [timeout]")
                        break
                    all_rx.append(str(frame))
                    lines.append(f"  [RX] {str(frame)[:300]}")

            # Final drain — catch late broadcasts (e.g. Socket.IO server-side
            # 'action_response' frames that arrive after the last send).
            ws.settimeout(final_read_timeout)
            for _ in range(max_frames_per_read * 2):
                try:
                    frame = ws.recv()
                except Exception:
                    break
                all_rx.append(str(frame))
                lines.append(f"  [RX-drain] {str(frame)[:300]}")
        except Exception as exc:
            lines.append(f"  Error: {exc}")
        finally:
            if ws is not None:
                try:
                    ws.close()
                except Exception:
                    pass

        # Flag scan across all received frames.
        combined = " ".join(all_rx)
        flags = self._extract_flags(combined)
        if flags:
            lines.append("")
            lines.append("  !!! FLAGS FOUND !!!")
            for f in flags:
                lines.append(f"    {f}")

        return "\n".join(lines)

    def _operation_injection(self, url: str, headers: Dict, timeout: int) -> str:
        """Test injection payloads via WebSocket."""
        lines = ["--- Injection Test ---"]

        for payload_info in self.INJECTION_PAYLOADS:
            payload = payload_info["payload"]
            inj_type = payload_info["type"]

            result = self._ws_connect_send(url, payload, headers, None, timeout)
            resp_text = " ".join(str(r) for r in result["received"])

            interesting = False
            reasons = []

            if "error" in resp_text.lower() or "exception" in resp_text.lower():
                interesting = True
                reasons.append("Error in response")

            flags = self._extract_flags(resp_text)
            if flags:
                interesting = True
                reasons.append(f"FLAG: {', '.join(flags)}")

            if inj_type == "xss" and "alert" in resp_text:
                interesting = True
                reasons.append("XSS reflected")
            if inj_type == "ssti" and "49" in resp_text:
                interesting = True
                reasons.append("SSTI evaluated")

            if interesting:
                lines.append(f"  [!] {inj_type}: {payload}")
                lines.append(f"      Reasons: {', '.join(reasons)}")
                if result["received"]:
                    lines.append(f"      Response: {resp_text[:200]}")
                lines.append("")

        if not any("[!]" in line for line in lines):
            lines.append("  No injection vulnerabilities detected via WebSocket.")

        return "\n".join(lines)

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "WebSocketProbeTool")
        if err:
            return err
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[WebSocketProbeTool] Error: 'url' (string) is required."

        operation = (data.get("operation") or "connect").lower()
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[WebSocketProbeTool] Error: Unknown operation '{operation}'. "
                f"Valid: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        message = data.get("message")
        headers = data.get("headers") or {}
        origin = data.get("origin")
        messages = data.get("messages") or []
        timeout = data.get("timeout", 5)

        lines = [
            "[WebSocketProbeTool] WebSocket Probe Results",
            "=" * 50,
            f"URL: {url}",
            f"Operation: {operation}",
            "",
        ]

        if not HAS_WEBSOCKET:
            lines.append(
                "ERROR: websocket-client library not installed. "
                "Install with: pip install websocket-client"
            )
            return "\n".join(lines)

        if operation == "connect":
            lines.append(self._operation_connect(url, message, headers, timeout))
        elif operation == "cswsh":
            lines.append(self._operation_cswsh(url, headers, timeout, origin))
        elif operation == "enumerate":
            lines.append(self._operation_enumerate(url, messages, headers, timeout))
        elif operation == "injection":
            lines.append(self._operation_injection(url, headers, timeout))
        elif operation == "session":
            read_timeout = data.get("read_timeout", 2.0)
            final_read_timeout = data.get("final_read_timeout", 5.0)
            max_frames_per_read = data.get("max_frames_per_read", 5)
            try:
                read_timeout = float(read_timeout)
                final_read_timeout = float(final_read_timeout)
                max_frames_per_read = int(max_frames_per_read)
            except (TypeError, ValueError):
                return (
                    "[WebSocketProbeTool] Error: 'read_timeout', "
                    "'final_read_timeout', 'max_frames_per_read' must be "
                    "numeric."
                )
            lines.append(
                self._operation_session(
                    url,
                    messages,
                    headers,
                    timeout,
                    read_timeout,
                    final_read_timeout,
                    max_frames_per_read,
                )
            )

        return "\n".join(lines)
