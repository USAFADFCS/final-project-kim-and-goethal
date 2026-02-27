"""
Race condition tools for CTF solving.

Provides concurrent request capabilities to exploit race conditions
(e.g., double-spend, TOCTOU vulnerabilities).
"""

import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

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
        "int, default 15). Returns per-request status/length/timing/body, plus "
        "analysis of status code distribution, response length distribution, "
        "unique response bodies, and race condition indicators."
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

        # Build output header
        output_lines = [
            "[RaceConditionTool] Concurrent Request Results",
            "=" * 50,
            f"URL: {url}",
            f"Method: {method}",
            f"Concurrency: {concurrency}",
            f"Rounds: {repeat}",
            "",
        ]

        all_round_results: List[List[Dict[str, Any]]] = []

        for round_num in range(1, repeat + 1):
            output_lines.append(f"=== Round {round_num} Results ===")

            # Fire all requests concurrently
            results: List[Dict[str, Any]] = []
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
