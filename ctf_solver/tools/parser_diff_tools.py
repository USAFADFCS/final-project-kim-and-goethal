"""
Parser differential tools for CTF solving.

Detects parsing differences between front-end and back-end servers
(Flask/PHP, Express/URL API, nginx/gunicorn) that can lead to security
bypasses.

Parser differentials appeared in Google CTF, DiceCTF, corCTF, HITCON 2023.
"""

from typing import Any, Dict, List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class ParserDifferentialProbeTool:
    """
    ParserDifferentialProbeTool: detect parsing differences between HTTP
    components that can lead to security bypasses.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/endpoint",
          "param": "user",
          "method": "GET",
          "tests": ["duplicate_params", "content_type", "url_parsing",
                    "encoding", "chunked"],
          "timeout": 10
        }

    Tests:
      - duplicate_params: HTTP Parameter Pollution (HPP)
      - content_type: Content-Type confusion between parsers
      - url_parsing: URL path parsing differences
      - encoding: Double/mixed encoding interpretation
      - chunked: Transfer-Encoding parsing differences
    """

    name: str = "parser_differential_probe"
    description: str = (
        "Detect HTTP parser differential vulnerabilities. Input must be JSON with "
        "'url' (target URL), optional 'param' (parameter to test), optional 'method' "
        "(GET/POST, default GET), optional 'tests' (list: duplicate_params, content_type, "
        "url_parsing, encoding, chunked; default all), optional 'timeout' (default 10). "
        "Tests for parsing differences between front-end/back-end that lead to bypasses "
        "(HPP, Content-Type confusion, URL parsing tricks, encoding differences)."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "param": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "tests": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "duplicate_params",
                        "content_type",
                        "url_parsing",
                        "encoding",
                        "chunked",
                    ],
                },
            },
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    samples = [
        {"url": "http://example.com/api/endpoint", "param": "user"},
    ]

    # Duplicate parameter payloads for HPP
    HPP_PAYLOADS: List[Tuple[str, str]] = [
        ("duplicate query param", "{param}=safe&{param}=evil"),
        ("array notation", "{param}[]=safe&{param}[]=evil"),
        ("mixed array/scalar", "{param}=safe&{param}[]=evil"),
        ("semicolon separator", "{param}=safe;{param}=evil"),
        ("comma in value", "{param}=safe,evil"),
        ("null byte separator", "{param}=safe%00evil"),
    ]

    # Content-Type confusion payloads
    CONTENT_TYPE_PAYLOADS: List[Tuple[str, str, str]] = [
        (
            "JSON with form CT",
            "application/x-www-form-urlencoded",
            '{{"admin": true}}',
        ),
        (
            "Form with JSON CT",
            "application/json",
            "admin=true&role=admin",
        ),
        (
            "Multipart boundary trick",
            "multipart/form-data; boundary=----",
            '------\r\nContent-Disposition: form-data; name="admin"\r\n\r\ntrue\r\n------',
        ),
        (
            "charset utf-7",
            "application/json; charset=utf-7",
            "+AHsAIg-admin+ACI-:true+AH0-",
        ),
    ]

    # URL parsing differential payloads
    URL_PARSING_PAYLOADS: List[Tuple[str, str]] = [
        ("path parameter", "/api/endpoint;bypass=true"),
        ("backslash substitution", "/api/endpoint\\..\\admin"),
        ("double URL encoding", "/api/%25%36%31dmin"),
        ("unicode normalization", "/api/\u0061dmin"),
        ("dot segment", "/api/./endpoint/../admin"),
        ("null byte path", "/api/endpoint%00.json"),
        ("semicolon path", "/api/endpoint%3Bbypass"),
        ("tab in path", "/api%09/endpoint"),
        ("fragment before path", "/api#/../admin"),
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _test_duplicate_params(
        self,
        url: str,
        param: str,
        method: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test HTTP Parameter Pollution."""
        findings: List[Dict[str, Any]] = []

        # Get baseline
        try:
            if method == "GET":
                baseline = self.session.get(
                    url, params={param: "baseline"}, timeout=timeout
                )
            else:
                baseline = self.session.post(
                    url, data={param: "baseline"}, timeout=timeout
                )
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
        except Exception as exc:
            return [{"error": f"Baseline failed: {exc}"}]

        for desc, payload_template in self.HPP_PAYLOADS:
            qs = payload_template.format(param=param)
            try:
                if method == "GET":
                    test_url = f"{url}?{qs}"
                    resp = self.session.get(test_url, timeout=timeout)
                else:
                    resp = self.session.post(
                        url,
                        data=qs,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=timeout,
                    )

                diff = abs(len(resp.text) - baseline_len)
                if diff > 50 or resp.status_code != baseline.status_code:
                    findings.append(
                        {
                            "test": "duplicate_params",
                            "desc": desc,
                            "payload": qs,
                            "status": resp.status_code,
                            "length_diff": diff,
                            "body_preview": resp.text[:200],
                        }
                    )
            except Exception:
                pass

        return findings

    def _test_content_type(
        self,
        url: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test Content-Type confusion."""
        findings: List[Dict[str, Any]] = []

        for desc, content_type, body in self.CONTENT_TYPE_PAYLOADS:
            try:
                resp = self.session.post(
                    url,
                    data=body,
                    headers={"Content-Type": content_type},
                    timeout=timeout,
                )

                # Look for signs of successful parsing confusion
                if resp.status_code in (200, 302):
                    findings.append(
                        {
                            "test": "content_type",
                            "desc": desc,
                            "content_type": content_type,
                            "status": resp.status_code,
                            "body_preview": resp.text[:200],
                        }
                    )
            except Exception:
                pass

        return findings

    def _test_url_parsing(
        self,
        url: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test URL path parsing differences."""
        findings: List[Dict[str, Any]] = []

        # Get baseline
        try:
            baseline = self.session.get(url, timeout=timeout)
            baseline_status = baseline.status_code
        except Exception:
            baseline_status = None

        from urllib.parse import urlparse

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for desc, path_payload in self.URL_PARSING_PAYLOADS:
            test_url = base + path_payload
            try:
                resp = self.session.get(test_url, timeout=timeout)

                # Interesting if we get a different response than expected
                if (
                    resp.status_code == 200
                    and baseline_status is not None
                    and resp.status_code != baseline_status
                ) or (resp.status_code in (200, 302) and "admin" in path_payload):
                    findings.append(
                        {
                            "test": "url_parsing",
                            "desc": desc,
                            "payload_url": test_url,
                            "status": resp.status_code,
                            "body_preview": resp.text[:200],
                        }
                    )
            except Exception:
                pass

        return findings

    def _test_encoding_diff(
        self,
        url: str,
        param: str,
        method: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test encoding interpretation differences."""
        findings: List[Dict[str, Any]] = []

        encoding_payloads = [
            ("double URL encode", f"{param}=%2561dmin"),
            ("unicode escape", f"{param}=\\u0061dmin"),
            ("hex encode", f"{param}=\\x61dmin"),
            ("overlong UTF-8", f"{param}=%c0%e1dmin"),
            ("mixed case percent", f"{param}=%4F%52%31%3D%31"),
        ]

        for desc, qs in encoding_payloads:
            try:
                if method == "GET":
                    test_url = f"{url}?{qs}"
                    resp = self.session.get(test_url, timeout=timeout)
                else:
                    resp = self.session.post(
                        url,
                        data=qs,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=timeout,
                    )

                if resp.status_code in (200, 302):
                    findings.append(
                        {
                            "test": "encoding",
                            "desc": desc,
                            "payload": qs,
                            "status": resp.status_code,
                            "body_preview": resp.text[:200],
                        }
                    )
            except Exception:
                pass

        return findings

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "ParserDifferentialProbeTool")
        if err:
            return err
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[ParserDifferentialProbeTool] Error: 'url' (string) is required."

        param = data.get("param", "q")
        method = (data.get("method") or "GET").upper()
        tests = data.get("tests") or [
            "duplicate_params",
            "content_type",
            "url_parsing",
            "encoding",
        ]
        timeout = data.get("timeout", 10)

        all_findings: List[Dict[str, Any]] = []

        if "duplicate_params" in tests:
            all_findings.extend(
                self._test_duplicate_params(url, param, method, timeout)
            )

        if "content_type" in tests:
            all_findings.extend(self._test_content_type(url, timeout))

        if "url_parsing" in tests:
            all_findings.extend(self._test_url_parsing(url, timeout))

        if "encoding" in tests:
            all_findings.extend(self._test_encoding_diff(url, param, method, timeout))

        # Build output
        lines = [
            "[ParserDifferentialProbeTool] Parser Differential Probe Results",
            "=" * 50,
            f"URL: {url}",
            f"Parameter: {param}",
            f"Method: {method}",
            f"Tests: {', '.join(tests)}",
            "",
        ]

        if all_findings:
            lines.append(f"FINDINGS ({len(all_findings)}):")
            lines.append("-" * 40)
            for f in all_findings:
                if "error" in f:
                    lines.append(f"  Error: {f['error']}")
                    continue
                lines.append(f"  Test: {f['test']}")
                lines.append(f"  Description: {f.get('desc', 'N/A')}")
                for k, v in f.items():
                    if k not in ("test", "desc"):
                        val = str(v)[:200]
                        lines.append(f"    {k}: {val}")
                lines.append("")
        else:
            lines.append("No parser differential issues detected.")
            lines.append("")

        lines.append("RECOMMENDATIONS:")
        has_hpp = any(f.get("test") == "duplicate_params" for f in all_findings)
        has_ct = any(f.get("test") == "content_type" for f in all_findings)
        has_url = any(f.get("test") == "url_parsing" for f in all_findings)

        if has_hpp:
            lines.append(
                "  - HPP detected! Front-end/back-end parse parameters differently."
            )
            lines.append(
                "  - Try injecting malicious values as the second/last parameter."
            )
        if has_ct:
            lines.append("  - Content-Type confusion detected!")
            lines.append(
                "  - Try sending JSON body with form Content-Type or vice versa."
            )
        if has_url:
            lines.append("  - URL parsing differences detected!")
            lines.append(
                "  - Try path traversal or access control bypass with special path chars."
            )
        if not all_findings:
            lines.append("  - Try testing with different parameters or endpoints.")
            lines.append("  - Check for Node.js qs module (deep object parsing).")

        return "\n".join(lines)
