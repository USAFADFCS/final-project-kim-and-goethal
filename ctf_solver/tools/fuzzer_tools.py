"""
Fuzzer tools for CTF solving.

Provides parameter fuzzing / request repeater capabilities similar to Burp Intruder's Sniper mode.
"""

import json
import re
import time
from collections import Counter
from typing import Dict, List, Optional

import requests


class RequestRepeaterTool:
    """
    RequestRepeaterTool: Send a templated request with variable substitution.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "method": "POST",
          "param": "password",
          "wordlist": "common_passwords",
          "values": ["admin", "test", "123456"],
          "data": {"username": "admin"},
          "body_template": null,
          "headers": {},
          "match_status": null,
          "match_regex": null,
          "filter_status": null,
          "filter_length": null,
          "max_requests": 200,
          "timeout": 10
        }

    Modes:
      - param mode: inject each value into the specified parameter in data/query params.
      - body_template mode: replace the marker in the raw body with each value.

    Built-in wordlists: common_passwords, common_usernames, common_pins, sqli_auth_bypass.
    """

    name: str = "request_repeater"
    description: str = (
        "Send a templated request with variable substitution for parameter fuzzing "
        "(similar to Burp Intruder Sniper mode). Input must be JSON with keys: "
        "'url' (required), 'param' (required, parameter name to fuzz), "
        "'method' (optional, GET or POST, default GET), "
        "'wordlist' (optional, built-in wordlist: 'common_passwords', 'common_usernames', "
        "'common_pins', 'sqli_auth_bypass'), 'values' (optional, custom list of values "
        "to test, max 200), 'data' (optional dict, other form fields), "
        "'body_template' (optional string with FUZZ marker for raw body mode), "
        "'headers' (optional dict), 'match_status' (optional int, only show this status), "
        "'match_regex' (optional string, only show responses matching regex), "
        "'filter_status' (optional int, hide this status), "
        "'filter_length' (optional int, hide responses with this exact length), "
        "'max_requests' (optional int, default/cap 200), 'timeout' (optional int, default 10). "
        "Returns a table of results with status codes, lengths, timing, and anomaly detection."
    )

    FUZZ_MARKER: str = "\u00a7FUZZ\u00a7"

    COMMON_PASSWORDS: List[str] = [
        "admin", "password", "123456", "password123", "admin123",
        "letmein", "welcome", "monkey", "dragon", "master",
        "qwerty", "login", "pass", "test", "guest",
        "root", "toor", "changeme", "secret", "1234",
        "12345", "123456789", "password1", "iloveyou", "sunshine",
        "princess", "football", "charlie", "shadow", "michael",
        "654321", "111111",
    ]

    COMMON_USERNAMES: List[str] = [
        "admin", "administrator", "root", "user", "test",
        "guest", "info", "webmaster", "sysadmin", "backup",
        "operator", "manager", "support", "demo", "ftp",
        "oracle", "postgres", "mysql",
    ]

    SQLI_AUTH_BYPASS: List[str] = [
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "\" OR 1=1--",
        "' OR 1=1#",
        "') OR 1=1--",
        "' OR 'a'='a",
        "\" OR \"a\"=\"a",
        "') OR ('a'='a",
        "admin' #",
        "1' OR '1'='1' --",
        "' UNION SELECT 1,1--",
        "' OR ''='",
    ]

    MAX_REQUESTS_CAP: int = 200

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _get_wordlist(self, wordlist_name: str) -> List[str]:
        """Return the values for a built-in wordlist name."""
        if wordlist_name == "common_passwords":
            return list(self.COMMON_PASSWORDS)
        elif wordlist_name == "common_usernames":
            return list(self.COMMON_USERNAMES)
        elif wordlist_name == "common_pins":
            return [f"{i:04d}" for i in range(10000)]
        elif wordlist_name == "sqli_auth_bypass":
            return list(self.SQLI_AUTH_BYPASS)
        else:
            return []

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[RequestRepeaterTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        # --- Validate required fields ---
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[RequestRepeaterTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[RequestRepeaterTool] Error: 'param' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[RequestRepeaterTool] Error: 'method' must be 'GET' or 'POST'."

        # --- Optional fields ---
        wordlist_name = data.get("wordlist")
        custom_values = data.get("values")
        form_data = data.get("data") or {}
        body_template = data.get("body_template")
        headers = data.get("headers") or {}
        match_status = data.get("match_status")
        match_regex = data.get("match_regex")
        filter_status = data.get("filter_status")
        filter_length = data.get("filter_length")
        max_requests = data.get("max_requests", self.MAX_REQUESTS_CAP)
        timeout = data.get("timeout", 10)

        if not isinstance(form_data, dict):
            return "[RequestRepeaterTool] Error: 'data' must be a JSON object (dict)."
        if not isinstance(headers, dict):
            return "[RequestRepeaterTool] Error: 'headers' must be a JSON object (dict)."

        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 10

        try:
            max_requests = int(max_requests)
        except (ValueError, TypeError):
            max_requests = self.MAX_REQUESTS_CAP
        max_requests = min(max_requests, self.MAX_REQUESTS_CAP)

        # --- Build values list ---
        values: List[str] = []
        if custom_values and isinstance(custom_values, list):
            values = [str(v) for v in custom_values]
        elif wordlist_name and isinstance(wordlist_name, str):
            values = self._get_wordlist(wordlist_name)
            if not values:
                return (
                    f"[RequestRepeaterTool] Error: Unknown wordlist '{wordlist_name}'. "
                    f"Available: common_passwords, common_usernames, common_pins, sqli_auth_bypass."
                )
        else:
            return (
                "[RequestRepeaterTool] Error: Either 'values' (list) or 'wordlist' "
                "(string) must be provided."
            )

        if not values:
            return "[RequestRepeaterTool] Error: No values to test."

        # Cap values at max_requests
        values = values[:max_requests]

        # --- Determine body_template mode ---
        use_body_template = body_template is not None and isinstance(body_template, str)

        # --- Compile match_regex if provided ---
        compiled_match_regex = None
        if match_regex:
            try:
                compiled_match_regex = re.compile(match_regex, re.IGNORECASE)
            except re.error as exc:
                return f"[RequestRepeaterTool] Error: Invalid match_regex: {exc}"

        # --- Send requests and collect results ---
        results: List[Dict] = []

        for value in values:
            try:
                start_time = time.time()

                if use_body_template:
                    # Body template mode: replace marker with value
                    body = body_template.replace(self.FUZZ_MARKER, value)
                    if method == "GET":
                        resp = self.session.get(
                            url, data=body, headers=headers, timeout=timeout
                        )
                    else:
                        resp = self.session.post(
                            url, data=body, headers=headers, timeout=timeout
                        )
                else:
                    # Param mode: inject value into param
                    request_data = {**form_data, param: value}
                    if method == "GET":
                        resp = self.session.get(
                            url, params=request_data, headers=headers, timeout=timeout
                        )
                    else:
                        resp = self.session.post(
                            url, data=request_data, headers=headers, timeout=timeout
                        )

                elapsed_ms = int((time.time() - start_time) * 1000)
                resp_text = resp.text or ""
                resp_length = len(resp_text)
                body_preview = resp_text[:100].replace("\n", " ").replace("\r", "")
                if len(resp_text) > 100:
                    body_preview += "..."

                results.append({
                    "value": value,
                    "status": resp.status_code,
                    "length": resp_length,
                    "time_ms": elapsed_ms,
                    "preview": body_preview,
                    "error": None,
                })
            except requests.exceptions.Timeout:
                results.append({
                    "value": value,
                    "status": 0,
                    "length": 0,
                    "time_ms": timeout * 1000,
                    "preview": "(timeout)",
                    "error": "timeout",
                })
            except Exception as exc:
                results.append({
                    "value": value,
                    "status": 0,
                    "length": 0,
                    "time_ms": 0,
                    "preview": f"(error: {exc})",
                    "error": str(exc),
                })

        # --- Apply match/filter criteria ---
        filtered_results: List[Dict] = []
        for r in results:
            # Apply match_status: only include responses with this status
            if match_status is not None:
                try:
                    if r["status"] != int(match_status):
                        continue
                except (ValueError, TypeError):
                    pass

            # Apply match_regex: only include responses matching this regex
            if compiled_match_regex is not None:
                if not compiled_match_regex.search(r["preview"]):
                    continue

            # Apply filter_status: exclude responses with this status
            if filter_status is not None:
                try:
                    if r["status"] == int(filter_status):
                        continue
                except (ValueError, TypeError):
                    pass

            # Apply filter_length: exclude responses with this exact length
            if filter_length is not None:
                try:
                    if r["length"] == int(filter_length):
                        continue
                except (ValueError, TypeError):
                    pass

            filtered_results.append(r)

        # --- Detect anomalies ---
        # Find the majority status code and length among all (unfiltered) results
        status_counts: Counter = Counter()
        length_counts: Counter = Counter()
        all_times: List[int] = []

        for r in results:
            if r["error"] is None:
                status_counts[r["status"]] += 1
                length_counts[r["length"]] += 1
                all_times.append(r["time_ms"])

        majority_status = status_counts.most_common(1)[0][0] if status_counts else None
        majority_length = length_counts.most_common(1)[0][0] if length_counts else None
        avg_time = int(sum(all_times) / len(all_times)) if all_times else 0

        anomalies: List[str] = []
        for r in results:
            if r["error"] is not None:
                anomalies.append(
                    f'[!] "{r["value"]}" caused an error: {r["error"]}'
                )
                continue
            if majority_status is not None and r["status"] != majority_status:
                anomalies.append(
                    f'[!] "{r["value"]}" returned different status '
                    f'({r["status"]} vs {majority_status} majority)'
                )
            if majority_length is not None and r["length"] != majority_length:
                length_diff = abs(r["length"] - majority_length)
                # Only flag if the difference is significant (>10% or >50 bytes)
                if length_diff > max(50, majority_length * 0.1):
                    anomalies.append(
                        f'[!] "{r["value"]}" returned different length '
                        f'({r["length"]} vs {majority_length} majority, diff: {length_diff})'
                    )
            if avg_time > 0 and r["time_ms"] > avg_time * 3:
                anomalies.append(
                    f'[!] "{r["value"]}" had slow response '
                    f'({r["time_ms"]}ms vs {avg_time}ms average)'
                )

        # --- Build output ---
        mode_str = "body_template" if use_body_template else "param"
        output_lines = [
            f"[RequestRepeaterTool] Parameter Fuzzing Results",
            "=" * 50,
            f"URL: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Mode: {mode_str}",
            f"Values tested: {len(results)}",
        ]

        # Note if filtering was applied
        if len(filtered_results) != len(results):
            output_lines.append(
                f"Results shown: {len(filtered_results)} (filtered from {len(results)})"
            )

        output_lines.append("")
        output_lines.append("=== Results ===")
        output_lines.append(
            f"{'Value':<20} {'Status':>6}  {'Length':>6}  {'Time(ms)':>8}  Response Preview"
        )
        output_lines.append("-" * 80)

        for r in filtered_results:
            value_display = r["value"][:20]
            if r["error"]:
                output_lines.append(
                    f"{value_display:<20} {'ERR':>6}  {r['length']:>6}  {r['time_ms']:>8}  {r['preview']}"
                )
            else:
                output_lines.append(
                    f"{value_display:<20} {r['status']:>6}  {r['length']:>6}  {r['time_ms']:>8}  {r['preview']}"
                )

        # Anomalies section
        if anomalies:
            output_lines.append("")
            output_lines.append("=== Anomalies ===")
            for a in anomalies:
                output_lines.append(a)

        # Statistics section
        output_lines.append("")
        output_lines.append("=== Statistics ===")
        output_lines.append(f"Total requests: {len(results)}")
        if status_counts:
            status_dict = dict(status_counts.most_common())
            output_lines.append(f"Status codes: {status_dict}")
        if all_times:
            min_length = min(r["length"] for r in results if r["error"] is None)
            max_length = max(r["length"] for r in results if r["error"] is None)
            output_lines.append(f"Response length range: {min_length} - {max_length} bytes")
            output_lines.append(f"Average response time: {avg_time}ms")

        error_count = sum(1 for r in results if r["error"] is not None)
        if error_count:
            output_lines.append(f"Errors: {error_count}")

        return "\n".join(output_lines)
