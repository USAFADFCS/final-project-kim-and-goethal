"""
Response comparison and diff tools for CTF solving.

Provides utilities for comparing HTTP responses to detect vulnerabilities.
"""

import json
import time
from typing import List, Optional, Tuple

import requests


class ResponseDiffTool:
    """
    ResponseDiffTool: compare two HTTP responses to identify differences.

    Useful for detecting:
    - Boolean-based SQL injection (same structure, different content)
    - Error-based detection (one response has errors)
    - Information leakage (extra content in one response)

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "response1": "<full response text>",
          "response2": "<full response text>",
          "mode": "summary"  # optional: "summary", "detailed", "length_only"
        }
    """

    name: str = "response_diff"
    description: str = (
        "Compare two HTTP responses to identify differences. Input must be JSON with keys: "
        "'response1' (first response text), 'response2' (second response text), and optionally "
        "'mode' ('summary', 'detailed', or 'length_only', default 'summary'). "
        "Returns length differences, content changes, and heuristics for SQLi/error detection. "
        "Use this tool to compare responses from different inputs to detect vulnerabilities."
    )

    # Keywords that suggest error-based differences
    ERROR_KEYWORDS = [
        "error",
        "exception",
        "syntax",
        "sql",
        "mysql",
        "sqlite",
        "postgresql",
        "warning",
        "fatal",
        "undefined",
        "null",
        "failed",
        "invalid",
        "denied",
        "forbidden",
        "unauthorized",
    ]

    # Keywords that suggest successful auth/access
    SUCCESS_KEYWORDS = [
        "welcome",
        "dashboard",
        "admin",
        "logged in",
        "success",
        "flag",
        "authenticated",
        "authorized",
        "session",
        "token",
    ]

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[ResponseDiffTool] Error: tool_input must be JSON: {exc}"

        response1 = data.get("response1", "")
        response2 = data.get("response2", "")
        mode = data.get("mode", "summary").lower()

        if not isinstance(response1, str) or not isinstance(response2, str):
            return (
                "[ResponseDiffTool] Error: 'response1' and 'response2' must be strings."
            )

        if mode not in ("summary", "detailed", "length_only"):
            mode = "summary"

        # Calculate basic metrics
        len1, len2 = len(response1), len(response2)
        len_diff = abs(len1 - len2)
        len_diff_pct = (len_diff / max(len1, len2) * 100) if max(len1, len2) > 0 else 0

        lines1 = response1.splitlines()
        lines2 = response2.splitlines()
        line_diff = abs(len(lines1) - len(lines2))

        # Check for error keywords in each response
        errors1 = self._find_keywords(response1, self.ERROR_KEYWORDS)
        errors2 = self._find_keywords(response2, self.ERROR_KEYWORDS)

        # Check for success keywords
        success1 = self._find_keywords(response1, self.SUCCESS_KEYWORDS)
        success2 = self._find_keywords(response2, self.SUCCESS_KEYWORDS)

        # Heuristics
        likely_boolean_sqli = (
            len_diff_pct > 5
            and len_diff_pct < 50
            and len(errors1) == len(errors2)  # Same error state
            and len1 > 100
            and len2 > 100  # Both have substantial content
        )

        likely_error_based = (len(errors1) > 0) != (
            len(errors2) > 0
        )  # Error in one but not other

        likely_auth_diff = (len(success1) > 0) != (
            len(success2) > 0
        )  # Success in one but not other

        # Build output based on mode
        output_lines = ["[ResponseDiffTool] Comparison Results", ""]

        # Basic metrics (always included)
        output_lines.append("=== LENGTH ANALYSIS ===")
        output_lines.append(f"Response 1: {len1} bytes, {len(lines1)} lines")
        output_lines.append(f"Response 2: {len2} bytes, {len(lines2)} lines")
        output_lines.append(
            f"Difference: {len_diff} bytes ({len_diff_pct:.1f}%), {line_diff} lines"
        )
        output_lines.append("")

        if mode == "length_only":
            return "\n".join(output_lines)

        # Keyword analysis
        output_lines.append("=== KEYWORD ANALYSIS ===")
        output_lines.append(
            f"Error keywords in response 1: {errors1 if errors1 else 'None'}"
        )
        output_lines.append(
            f"Error keywords in response 2: {errors2 if errors2 else 'None'}"
        )
        output_lines.append(
            f"Success keywords in response 1: {success1 if success1 else 'None'}"
        )
        output_lines.append(
            f"Success keywords in response 2: {success2 if success2 else 'None'}"
        )
        output_lines.append("")

        # Heuristics
        output_lines.append("=== VULNERABILITY HEURISTICS ===")
        if likely_boolean_sqli:
            output_lines.append(
                "[!] LIKELY BOOLEAN-BASED SQLI: Responses differ in content but similar structure"
            )
        if likely_error_based:
            output_lines.append(
                "[!] LIKELY ERROR-BASED DETECTION: One response has errors, other doesn't"
            )
        if likely_auth_diff:
            output_lines.append(
                "[!] LIKELY AUTH DIFFERENCE: One response shows success indicators"
            )
        if not (likely_boolean_sqli or likely_error_based or likely_auth_diff):
            output_lines.append("No obvious vulnerability patterns detected")
        output_lines.append("")

        if mode == "detailed":
            # Show actual content differences
            output_lines.append("=== CONTENT DIFFERENCES ===")
            diff_lines = self._get_diff_lines(lines1, lines2, max_diffs=10)
            if diff_lines:
                output_lines.extend(diff_lines)
            else:
                output_lines.append("Responses are identical")

        return "\n".join(output_lines)

    def _find_keywords(self, text: str, keywords: List[str]) -> List[str]:
        """Find which keywords appear in the text."""
        text_lower = text.lower()
        return [kw for kw in keywords if kw in text_lower]

    def _get_diff_lines(
        self, lines1: List[str], lines2: List[str], max_diffs: int = 10
    ) -> List[str]:
        """Get a simple diff showing changed lines."""
        output = []
        diff_count = 0

        # Simple line-by-line comparison
        max_lines = max(len(lines1), len(lines2))
        for i in range(min(max_lines, 100)):  # Limit to first 100 lines
            line1 = lines1[i] if i < len(lines1) else ""
            line2 = lines2[i] if i < len(lines2) else ""

            if line1 != line2:
                if diff_count < max_diffs:
                    output.append(f"Line {i+1}:")
                    output.append(
                        f"  - R1: {line1[:100]}{'...' if len(line1) > 100 else ''}"
                    )
                    output.append(
                        f"  - R2: {line2[:100]}{'...' if len(line2) > 100 else ''}"
                    )
                diff_count += 1

        if diff_count > max_diffs:
            output.append(f"... and {diff_count - max_diffs} more differences")

        return output


class TimingCompareTool:
    """
    TimingCompareTool: compare response times for two requests.

    Useful for detecting time-based blind SQL injection.

    Expected JSON tool_input format:

        {
          "url": "http://example.com/search",
          "method": "GET",
          "params1": {"q": "test"},
          "params2": {"q": "test' AND SLEEP(5)--"},
          "headers": {"Content-Type": "application/json"},
          "threshold": 3.0,
          "timeout": 15
        }
    """

    name: str = "timing_compare"
    description: str = (
        "Compare response times for two requests to detect time-based vulnerabilities. "
        "Input must be JSON with keys: 'url' (target URL), 'method' ('GET' or 'POST'), "
        "'params1' (first request parameters), 'params2' (second request parameters), "
        "optional 'headers' (dict of headers — set Content-Type: application/json to "
        "send JSON body instead of form-encoded), optional 'threshold' (time difference "
        "in seconds to flag, default 3.0), optional 'timeout' (request timeout, default 15). "
        "Use this tool to detect time-based blind SQL injection."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[TimingCompareTool] Error: tool_input must be JSON: {exc}"

        url = data.get("url")
        method = data.get("method", "GET").upper()
        params1 = data.get("params1", {})
        params2 = data.get("params2", {})
        headers = data.get("headers", {})
        threshold = data.get("threshold", 3.0)
        timeout = data.get("timeout", 15)

        if not url:
            return "[TimingCompareTool] Error: 'url' is required."

        if method not in ("GET", "POST"):
            return "[TimingCompareTool] Error: 'method' must be 'GET' or 'POST'."

        try:
            threshold = float(threshold)
            timeout = int(timeout)
        except (ValueError, TypeError):
            threshold = 3.0
            timeout = 15

        # Time first request
        time1, status1, error1 = self._timed_request(
            url, method, params1, headers, timeout
        )

        # Time second request
        time2, status2, error2 = self._timed_request(
            url, method, params2, headers, timeout
        )

        # Analyze results
        output_lines = ["[TimingCompareTool] Timing Comparison Results", ""]

        output_lines.append("=== REQUEST 1 ===")
        output_lines.append(f"Params: {json.dumps(params1)[:100]}")
        if error1:
            output_lines.append(f"Error: {error1}")
        else:
            output_lines.append(f"Status: {status1}")
            output_lines.append(f"Time: {time1:.3f} seconds")

        output_lines.append("")
        output_lines.append("=== REQUEST 2 ===")
        output_lines.append(f"Params: {json.dumps(params2)[:100]}")
        if error2:
            output_lines.append(f"Error: {error2}")
        else:
            output_lines.append(f"Status: {status2}")
            output_lines.append(f"Time: {time2:.3f} seconds")

        output_lines.append("")
        output_lines.append("=== ANALYSIS ===")

        if error1 or error2:
            output_lines.append("One or both requests failed - cannot compare timing")
        else:
            time_diff = abs(time2 - time1)
            output_lines.append(f"Time difference: {time_diff:.3f} seconds")
            output_lines.append(f"Threshold: {threshold} seconds")

            if time_diff >= threshold:
                output_lines.append("")
                output_lines.append("[!] SIGNIFICANT TIME DIFFERENCE DETECTED")
                output_lines.append(
                    "[!] This may indicate TIME-BASED BLIND SQL INJECTION"
                )
                if time2 > time1:
                    output_lines.append(
                        f"[!] Request 2 was {time_diff:.1f}s slower - params2 may contain working payload"
                    )
                else:
                    output_lines.append(
                        f"[!] Request 1 was {time_diff:.1f}s slower - params1 may contain working payload"
                    )
            else:
                output_lines.append("No significant timing difference detected")

        return "\n".join(output_lines)

    def _timed_request(
        self, url: str, method: str, params: dict, headers: dict, timeout: int
    ) -> Tuple[float, Optional[int], Optional[str]]:
        """
        Make a timed request.
        Returns: (elapsed_time, status_code, error_message)
        """
        try:
            start = time.time()
            if method == "GET":
                resp = self.session.get(
                    url, params=params, headers=headers, timeout=timeout
                )
            else:
                # Detect JSON content type
                content_type = ""
                for k, v in headers.items():
                    if k.lower() == "content-type":
                        content_type = v.lower()
                        break
                if "application/json" in content_type:
                    resp = self.session.post(
                        url, json=params, headers=headers, timeout=timeout
                    )
                else:
                    resp = self.session.post(
                        url, data=params, headers=headers, timeout=timeout
                    )
            elapsed = time.time() - start
            return elapsed, resp.status_code, None
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            return elapsed, None, f"Timeout after {timeout}s"
        except Exception as e:
            return 0.0, None, str(e)


class ResponseFingerprinter:
    """
    ResponseFingerprinter: create a fingerprint of a response for quick comparison.

    Useful for quickly identifying if responses are "same" or "different" without
    storing full response text.
    """

    name: str = "response_fingerprint"
    description: str = (
        "Create a fingerprint of an HTTP response for quick comparison. "
        "Input must be JSON with key 'response' (response text). "
        "Returns a fingerprint object with length, line count, keyword presence, "
        "and content hash. Use this to quickly categorize responses."
    )

    ERROR_KEYWORDS = ["error", "exception", "sql", "warning", "failed", "invalid"]
    SUCCESS_KEYWORDS = ["welcome", "success", "flag", "admin", "dashboard"]

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[ResponseFingerprinter] Error: tool_input must be JSON: {exc}"

        response = data.get("response", "")
        if not isinstance(response, str):
            return "[ResponseFingerprinter] Error: 'response' must be a string."

        import hashlib

        # Create fingerprint
        lines = response.splitlines()
        text_lower = response.lower()

        fingerprint = {
            "length": len(response),
            "lines": len(lines),
            "hash_md5": hashlib.md5(response.encode()).hexdigest()[:16],
            "has_errors": any(kw in text_lower for kw in self.ERROR_KEYWORDS),
            "has_success": any(kw in text_lower for kw in self.SUCCESS_KEYWORDS),
            "content_type_hint": self._guess_content_type(response),
        }

        output_lines = [
            "[ResponseFingerprinter] Response Fingerprint",
            "",
            f"Length: {fingerprint['length']} bytes",
            f"Lines: {fingerprint['lines']}",
            f"Hash (MD5 prefix): {fingerprint['hash_md5']}",
            f"Contains error keywords: {fingerprint['has_errors']}",
            f"Contains success keywords: {fingerprint['has_success']}",
            f"Content type hint: {fingerprint['content_type_hint']}",
        ]

        return "\n".join(output_lines)

    def _guess_content_type(self, response: str) -> str:
        """Guess the content type based on response content."""
        stripped = response.strip()
        if stripped.startswith("<!DOCTYPE") or stripped.startswith("<html"):
            return "HTML"
        elif stripped.startswith("{") or stripped.startswith("["):
            return "JSON"
        elif stripped.startswith("<?xml"):
            return "XML"
        elif "<" in stripped and ">" in stripped:
            return "HTML/XML"
        else:
            return "Text/Unknown"
