"""
Race condition tools for CTF solving.

Provides concurrent request capabilities to exploit race conditions
(e.g., double-spend, TOCTOU vulnerabilities), including the single-packet
race attack technique from PortSwigger's "Smashing the state machine"
(Black Hat USA 2023).
"""

import json
import socket
import ssl
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


class RaceConditionTool:
    """
    RaceConditionTool: send concurrent requests to exploit race conditions.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/transfer",
          "method": "POST",
          "data": {"amount": "100", "to": "user2"},
          "body": "{\"amount\": 100}",
          "headers": {},
          "cookies": {},
          "concurrency": 10,
          "repeat": 1,
          "timeout": 15
        }

    Behavior:
      - Fires `concurrency` identical requests simultaneously using
        ThreadPoolExecutor to exploit race conditions.
      - Each thread uses its own requests.Session (with cookies copied from
        the shared session) to avoid thread-safety issues.
      - `data` sends form-encoded POST data; `body` sends a raw JSON body.
        They are mutually exclusive.
      - `repeat` controls how many rounds of concurrent requests to fire
        (max 5). Useful for increasing the chance of triggering the race.
      - Analyzes results: groups by status code and response length, detects
        anomalies where most responses match but some differ, and flags
        indicators of successful race exploitation (e.g., multiple success
        responses for a single-use operation).
      - Concurrency is capped at 50 and repeat at 5 to prevent abuse.
    """

    name: str = "race_condition"
    description: str = (
        "Send concurrent HTTP requests to exploit race conditions (e.g., "
        "double-spend, TOCTOU). Input must be JSON with keys: 'url' (required), "
        "'method' (optional: 'GET' or 'POST', default 'POST'), 'data' (optional "
        "dict of form data), 'body' (optional raw JSON body string, mutually "
        "exclusive with 'data'), 'headers' (optional dict), 'cookies' (optional "
        "dict), 'concurrency' (optional int, default 10, max 50), 'repeat' "
        "(optional int, number of rounds, default 1, max 5), 'timeout' (optional "
        "int, default 15), 'mode' (optional: 'thread' or 'single_packet', default "
        "'thread'). 'single_packet' mode uses the PortSwigger last-byte sync "
        "technique for sub-1ms synchronization. Returns per-request results "
        "and race condition analysis."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _build_thread_session(self, extra_cookies: Optional[Dict[str, str]] = None) -> requests.Session:
        """Create a per-thread session with cookies copied from the main session."""
        thread_session = requests.Session()
        thread_session.cookies.update(self.session.cookies)
        if extra_cookies:
            thread_session.cookies.update(extra_cookies)
        return thread_session

    def _send_request(
        self,
        index: int,
        url: str,
        method: str,
        data: Optional[Dict[str, Any]],
        body: Optional[str],
        headers: Dict[str, str],
        extra_cookies: Optional[Dict[str, str]],
        timeout: int,
    ) -> Dict[str, Any]:
        """Send a single request and return a result dict."""
        thread_session = self._build_thread_session(extra_cookies)
        start = time.time()
        try:
            kwargs: Dict[str, Any] = {
                "headers": headers,
                "timeout": timeout,
            }
            if method == "POST":
                if body is not None:
                    # Raw JSON body
                    kwargs["data"] = body
                    # Ensure Content-Type is set for raw JSON
                    if "Content-Type" not in headers and "content-type" not in headers:
                        kwargs["headers"] = {**headers, "Content-Type": "application/json"}
                elif data is not None:
                    kwargs["data"] = data
                resp = thread_session.post(url, **kwargs)
            else:
                if data is not None:
                    kwargs["params"] = data
                resp = thread_session.get(url, **kwargs)

            elapsed_ms = (time.time() - start) * 1000
            body_text = resp.text or ""
            return {
                "index": index,
                "status": resp.status_code,
                "length": len(body_text),
                "body": body_text,
                "body_preview": body_text[:200],
                "elapsed_ms": round(elapsed_ms, 1),
                "error": None,
            }
        except Exception as exc:
            elapsed_ms = (time.time() - start) * 1000
            return {
                "index": index,
                "status": None,
                "length": 0,
                "body": "",
                "body_preview": "",
                "elapsed_ms": round(elapsed_ms, 1),
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Single-packet race attack (PortSwigger "Smashing the state machine")
    # ------------------------------------------------------------------

    def _build_raw_http_request(
        self,
        host: str,
        port: int,
        path: str,
        method: str,
        data: Optional[Dict[str, Any]],
        body: Optional[str],
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]],
    ) -> bytes:
        """Build a raw HTTP/1.1 request as bytes."""
        # Build body
        body_bytes = b""
        content_type = ""
        if body is not None:
            body_bytes = body.encode("utf-8")
            content_type = "application/json"
        elif data is not None and method == "POST":
            from urllib.parse import urlencode
            body_bytes = urlencode(data).encode("utf-8")
            content_type = "application/x-www-form-urlencoded"

        # Build headers
        req_headers: Dict[str, str] = {
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "Connection": "keep-alive",
        }
        if content_type and "Content-Type" not in headers:
            req_headers["Content-Type"] = content_type
        if body_bytes:
            req_headers["Content-Length"] = str(len(body_bytes))

        # Add session cookies
        cookie_parts = []
        for k, v in (self.session.cookies.get_dict() or {}).items():
            cookie_parts.append(f"{k}={v}")
        if cookies:
            for k, v in cookies.items():
                cookie_parts.append(f"{k}={v}")
        if cookie_parts:
            req_headers["Cookie"] = "; ".join(cookie_parts)

        req_headers.update(headers)

        # Build request line + headers
        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in req_headers.items():
            lines.append(f"{k}: {v}")
        request_str = "\r\n".join(lines) + "\r\n\r\n"
        return request_str.encode("utf-8") + body_bytes

    def _single_packet_attack(
        self,
        url: str,
        method: str,
        data: Optional[Dict[str, Any]],
        body: Optional[str],
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]],
        concurrency: int,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """
        Single-packet race attack using the last-byte synchronization technique.

        Strategy:
        1. Open N TCP connections to the target
        2. Send all but the last byte of each HTTP request
        3. Simultaneously send the final byte on all connections
        4. Read all responses

        This achieves sub-1ms synchronization across all requests.
        """
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        use_ssl = parsed.scheme == "https"

        # Build the full HTTP request
        raw_request = self._build_raw_http_request(
            host, port, path, method, data, body, headers, cookies
        )

        # Split into prefix (all but last byte) and suffix (last byte)
        prefix = raw_request[:-1]
        suffix = raw_request[-1:]

        results: List[Dict[str, Any]] = []

        # Step 1: Open all connections and send the prefix
        connections: List[Optional[socket.socket]] = []
        for i in range(concurrency):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))

                if use_ssl:
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                # Send all but the last byte
                sock.sendall(prefix)
                connections.append(sock)
            except Exception as exc:
                connections.append(None)
                results.append({
                    "index": i + 1,
                    "status": None,
                    "length": 0,
                    "body": "",
                    "body_preview": "",
                    "elapsed_ms": 0,
                    "error": f"Connection failed: {exc}",
                })

        # Step 2: Send the last byte simultaneously on all connections
        start = time.time()
        for sock in connections:
            if sock is not None:
                try:
                    sock.sendall(suffix)
                except Exception:
                    pass

        # Step 3: Read all responses
        for i, sock in enumerate(connections):
            if sock is None:
                continue
            try:
                # Read response
                response_data = b""
                sock.settimeout(timeout)
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        # Stop after reading headers + some body
                        if len(response_data) > 16384:
                            break
                    except (socket.timeout, ssl.SSLError):
                        break

                elapsed_ms = (time.time() - start) * 1000
                response_text = response_data.decode("utf-8", errors="replace")

                # Parse status code from raw response
                status = None
                body_text = response_text
                if response_text.startswith("HTTP/"):
                    first_line = response_text.split("\r\n", 1)[0]
                    parts = first_line.split(" ", 2)
                    if len(parts) >= 2:
                        try:
                            status = int(parts[1])
                        except ValueError:
                            pass
                    # Extract body after double CRLF
                    body_sep = response_text.find("\r\n\r\n")
                    if body_sep >= 0:
                        body_text = response_text[body_sep + 4:]

                results.append({
                    "index": i + 1,
                    "status": status,
                    "length": len(body_text),
                    "body": body_text,
                    "body_preview": body_text[:200],
                    "elapsed_ms": round(elapsed_ms, 1),
                    "error": None,
                })
            except Exception as exc:
                elapsed_ms = (time.time() - start) * 1000
                results.append({
                    "index": i + 1,
                    "status": None,
                    "length": 0,
                    "body": "",
                    "body_preview": "",
                    "elapsed_ms": round(elapsed_ms, 1),
                    "error": str(exc),
                })
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        results.sort(key=lambda r: r["index"])
        return results

    def _analyze_results(self, results: List[Dict[str, Any]]) -> List[str]:
        """Analyze a list of request results and return analysis lines."""
        lines: List[str] = []

        # Filter out errors for analysis
        valid = [r for r in results if r["error"] is None]
        errors = [r for r in results if r["error"] is not None]

        if not valid:
            lines.append("[!] All requests failed. No analysis possible.")
            return lines

        # Status code distribution
        status_counts: Counter = Counter(r["status"] for r in valid)
        lines.append(f"Status code distribution: {dict(status_counts)}")

        # Response length distribution (group within 10-byte buckets)
        raw_lengths = [r["length"] for r in valid]
        length_counts: Counter = Counter(raw_lengths)
        lines.append(f"Response length distribution: {dict(length_counts)}")

        # Unique response bodies
        unique_bodies: Dict[str, int] = {}
        for r in valid:
            body = r["body"]
            unique_bodies[body] = unique_bodies.get(body, 0) + 1
        lines.append(f"Unique response bodies: {len(unique_bodies)}")

        # Detect anomalies
        race_indicators: List[str] = []

        # 1. Multiple different bodies for identical requests
        if len(unique_bodies) > 1:
            race_indicators.append(
                "RACE CONDITION LIKELY: Multiple different response bodies for identical requests"
            )

        # 2. Status code inconsistencies
        if len(status_counts) > 1:
            race_indicators.append(
                f"Status code inconsistency: got {len(status_counts)} different status codes "
                f"({', '.join(str(s) for s in sorted(status_counts.keys()))})"
            )

        # 3. Check for multiple "success" responses (possible double-spend)
        success_keywords = ["success", "transferred", "completed", "approved", "done", "ok"]
        success_count = 0
        for r in valid:
            body_lower = r["body"].lower()
            if r["status"] == 200 and any(kw in body_lower for kw in success_keywords):
                success_count += 1
        if success_count > 1:
            race_indicators.append(
                f"Possible double-spend: {success_count} requests returned success-like responses"
            )

        # 4. Response length anomalies (majority same length, some different)
        if len(length_counts) > 1:
            most_common_len, most_common_count = length_counts.most_common(1)[0]
            outlier_count = len(valid) - most_common_count
            if outlier_count > 0 and most_common_count > outlier_count:
                race_indicators.append(
                    f"Response length anomaly: {most_common_count} responses had length "
                    f"{most_common_len}, but {outlier_count} differed"
                )

        if race_indicators:
            for indicator in race_indicators:
                lines.append(f"[!] {indicator}")
        else:
            lines.append("[ ] No obvious race condition indicators detected.")
            lines.append("    All responses appear identical. Try increasing concurrency or check")
            lines.append("    if the endpoint is actually vulnerable to race conditions.")

        if errors:
            lines.append(f"[*] {len(errors)} request(s) failed with errors.")

        return lines

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[RaceConditionTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[RaceConditionTool] Error: 'url' (string) is required in the input JSON."

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[RaceConditionTool] Error: 'method' must be 'GET' or 'POST'."

        form_data = data.get("data")
        body = data.get("body")
        headers = data.get("headers") or {}
        cookies = data.get("cookies") or {}
        concurrency = data.get("concurrency", 10)
        repeat = data.get("repeat", 1)
        timeout = data.get("timeout", 15)
        mode = (data.get("mode") or "thread").lower()

        # Validate mutual exclusivity
        if form_data is not None and body is not None:
            return "[RaceConditionTool] Error: 'data' and 'body' are mutually exclusive."

        if not isinstance(headers, dict):
            return "[RaceConditionTool] Error: 'headers' must be a JSON object (dict)."
        if not isinstance(cookies, dict):
            return "[RaceConditionTool] Error: 'cookies' must be a JSON object (dict)."

        # Cap concurrency and repeat to prevent abuse
        try:
            concurrency = int(concurrency)
        except (ValueError, TypeError):
            concurrency = 10
        concurrency = max(1, min(concurrency, 50))

        try:
            repeat = int(repeat)
        except (ValueError, TypeError):
            repeat = 1
        repeat = max(1, min(repeat, 5))

        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 15

        if mode not in ("thread", "single_packet"):
            mode = "thread"

        # Build output header
        output_lines = [
            "[RaceConditionTool] Concurrent Request Results",
            "=" * 50,
            f"URL: {url}",
            f"Method: {method}",
            f"Mode: {mode}",
            f"Concurrency: {concurrency}",
            f"Rounds: {repeat}",
            "",
        ]

        all_round_results: List[List[Dict[str, Any]]] = []

        for round_num in range(1, repeat + 1):
            output_lines.append(f"=== Round {round_num} Results ===")

            results: List[Dict[str, Any]] = []

            if mode == "single_packet":
                # Single-packet race attack (last-byte synchronization)
                results = self._single_packet_attack(
                    url, method, form_data, body, headers,
                    cookies if cookies else None, concurrency, timeout,
                )
            else:
                # Standard ThreadPoolExecutor approach
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    futures = [
                        executor.submit(
                            self._send_request,
                            i + 1,
                            url,
                            method,
                            form_data,
                            body,
                            headers,
                            cookies if cookies else None,
                            timeout,
                        )
                        for i in range(concurrency)
                    ]
                    for future in as_completed(futures):
                        try:
                            results.append(future.result())
                        except Exception as exc:
                            results.append({
                                "index": -1,
                                "status": None,
                                "length": 0,
                                "body": "",
                                "body_preview": "",
                                "elapsed_ms": 0,
                                "error": str(exc),
                            })

            # Sort results by index for consistent display
            results.sort(key=lambda r: r["index"])
            all_round_results.append(results)

            # Display per-request results
            for r in results:
                if r["error"]:
                    output_lines.append(
                        f"Request {r['index']:>2}: ERROR ({r['elapsed_ms']:.0f}ms) - {r['error']}"
                    )
                else:
                    preview = r["body_preview"]
                    # Escape newlines in preview for readability
                    preview = preview.replace("\n", "\\n").replace("\r", "\\r")
                    output_lines.append(
                        f"Request {r['index']:>2}: {r['status']} "
                        f"({r['length']} bytes, {r['elapsed_ms']:.0f}ms) - "
                        f"\"{preview}{'...' if len(r['body']) > 200 else ''}\""
                    )

            output_lines.append("")

        # Analysis section
        output_lines.append("=== Analysis ===")

        # Analyze all rounds combined
        all_results: List[Dict[str, Any]] = []
        for round_results in all_round_results:
            all_results.extend(round_results)

        analysis_lines = self._analyze_results(all_results)
        output_lines.extend(analysis_lines)

        # Per-round analysis if multiple rounds
        if repeat > 1:
            output_lines.append("")
            output_lines.append("=== Per-Round Analysis ===")
            for round_num, round_results in enumerate(all_round_results, 1):
                output_lines.append(f"--- Round {round_num} ---")
                round_analysis = self._analyze_results(round_results)
                output_lines.extend(round_analysis)
                output_lines.append("")

        # Unique response bodies section
        output_lines.append("")
        output_lines.append("=== Full Response Bodies (unique only) ===")

        valid_results = [r for r in all_results if r["error"] is None]
        unique_bodies: Dict[str, int] = {}
        for r in valid_results:
            b = r["body"]
            unique_bodies[b] = unique_bodies.get(b, 0) + 1

        # Sort by frequency (most common first)
        sorted_bodies = sorted(unique_bodies.items(), key=lambda x: -x[1])
        for idx, (body_text, count) in enumerate(sorted_bodies, 1):
            # Truncate very long bodies
            max_display = 500
            display_body = body_text[:max_display]
            if len(body_text) > max_display:
                display_body += f"\n  ...[truncated, full length: {len(body_text)} chars]..."
            output_lines.append(f"[Body {idx}] (seen {count} times):")
            output_lines.append(f"  {display_body}")
            output_lines.append("")

        return "\n".join(output_lines)
