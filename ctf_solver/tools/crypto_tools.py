"""
Cryptographic attack tools for CTF solving.

Provides utilities for detecting and exploiting cryptographic weaknesses
in CTF challenges, including padding oracle, ECB mode, token analysis,
encoding detection, XOR analysis, and attack methodology generation.
"""

import base64
import binascii
import json
import string
from collections import Counter
from typing import Dict, List, Optional

import requests


class CryptoProbeTool:
    """
    CryptoProbeTool: detect cryptographic weaknesses in web applications.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/decrypt",
          "param": "token",
          "method": "GET",
          "data": {},
          "crypto_type": "padding_oracle",
          "ciphertext": "aabbccdd...",
          "block_size": 16,
          "num_samples": 5,
          "timeout": 10
        }

    Supported crypto_type values:
      - padding_oracle: Test for padding oracle vulnerability
      - ecb_detect: Detect ECB mode encryption
      - token_analysis: Analyze token generation for weaknesses
    """

    name: str = "crypto_probe"
    description: str = (
        "Test for cryptographic weaknesses in web applications. Input must be JSON with "
        "'url', 'param' (parameter name), and 'crypto_type' (padding_oracle, ecb_detect, "
        "token_analysis). For padding_oracle, provide 'ciphertext' (hex or base64). "
        "For ecb_detect, sends crafted plaintext to detect ECB mode. "
        "For token_analysis, collects multiple tokens to analyze patterns. "
        "Optionally provide 'method' (GET/POST), 'data', 'block_size', 'num_samples', 'timeout'."
    )

    CRYPTO_TYPES = {"padding_oracle", "ecb_detect", "token_analysis"}

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[CryptoProbeTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        url = data.get("url", "").strip()
        param = data.get("param", "").strip()
        method = data.get("method", "GET").upper()
        extra_data = data.get("data", {})
        crypto_type = data.get("crypto_type", "").strip().lower()
        ciphertext = data.get("ciphertext", "")
        block_size = data.get("block_size", 16)
        num_samples = data.get("num_samples", 5)
        timeout = data.get("timeout", 10)

        if not url:
            return "[CryptoProbeTool] Error: 'url' is required."
        if not param:
            return "[CryptoProbeTool] Error: 'param' is required."
        if not crypto_type:
            return "[CryptoProbeTool] Error: 'crypto_type' is required."
        if crypto_type not in self.CRYPTO_TYPES:
            return (
                f"[CryptoProbeTool] Error: Unknown crypto_type '{crypto_type}'. "
                f"Valid types: {', '.join(sorted(self.CRYPTO_TYPES))}"
            )

        try:
            # Get baseline response first
            baseline_resp = self._make_request(
                url, method, param, "BASELINE_TEST_VALUE", extra_data, timeout
            )
            baseline_status = baseline_resp.status_code
            baseline_text = baseline_resp.text

            if crypto_type == "padding_oracle":
                return self._test_padding_oracle(
                    url, method, param, extra_data, ciphertext, block_size, timeout
                )
            elif crypto_type == "ecb_detect":
                return self._test_ecb_detect(
                    url, method, param, extra_data, block_size, timeout
                )
            elif crypto_type == "token_analysis":
                return self._test_token_analysis(
                    url, method, param, extra_data, num_samples, timeout
                )
            else:
                return f"[CryptoProbeTool] Error: crypto_type '{crypto_type}' not implemented."
        except requests.RequestException as e:
            return f"[CryptoProbeTool] Error: Request failed: {e}"
        except Exception as e:
            return f"[CryptoProbeTool] Error: {e}"

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        value: str,
        extra_data: dict,
        timeout: int,
    ) -> requests.Response:
        """Make an HTTP request with the given parameter value."""
        if method == "GET":
            params = {param: value, **extra_data}
            return self.session.get(url, params=params, timeout=timeout)
        else:
            form_data = {param: value, **extra_data}
            return self.session.post(url, data=form_data, timeout=timeout)

    def _normalize_ciphertext(self, ciphertext: str) -> bytes:
        """Normalize ciphertext from hex or base64 to raw bytes."""
        ciphertext = ciphertext.strip()

        # Try hex first
        try:
            cleaned = ciphertext.replace(" ", "").replace(":", "")
            if (
                all(c in "0123456789abcdefABCDEF" for c in cleaned)
                and len(cleaned) % 2 == 0
            ):
                return bytes.fromhex(cleaned)
        except (ValueError, binascii.Error):
            pass

        # Try base64
        try:
            padded = (
                ciphertext + "=" * (4 - len(ciphertext) % 4)
                if len(ciphertext) % 4 != 0
                else ciphertext
            )
            return base64.b64decode(padded)
        except Exception:
            pass

        return ciphertext.encode("utf-8")

    def _test_padding_oracle(
        self,
        url: str,
        method: str,
        param: str,
        extra_data: dict,
        ciphertext: str,
        block_size: int,
        timeout: int,
    ) -> str:
        """Test for padding oracle vulnerability."""
        results = ["[CryptoProbeTool] Padding Oracle Test"]
        results.append("=" * 50)

        if not ciphertext:
            results.append(
                "[!] Error: 'ciphertext' is required for padding_oracle test."
            )
            return "\n".join(results)

        ct_bytes = self._normalize_ciphertext(ciphertext)
        results.append(f"Ciphertext length: {len(ct_bytes)} bytes")
        results.append(f"Block size: {block_size} bytes")
        results.append(f"Number of blocks: {len(ct_bytes) // block_size}")
        results.append("")

        if len(ct_bytes) < block_size * 2:
            results.append(
                "[!] Ciphertext too short for padding oracle test (need at least 2 blocks)."
            )
            return "\n".join(results)

        # Modify the last byte of the second-to-last block through several values
        # to detect differential responses indicating a padding oracle
        response_groups: Dict[str, List[int]] = {}
        test_count = min(256, 256)  # Test all 256 byte values

        results.append(
            f"Testing {test_count} byte modifications on penultimate block..."
        )
        results.append("")

        ct_array = bytearray(ct_bytes)
        # Position: last byte of the penultimate block
        target_pos = len(ct_array) - block_size - 1

        for byte_val in range(test_count):
            modified = bytearray(ct_array)
            modified[target_pos] = byte_val

            # Encode modified ciphertext back to the original format
            modified_hex = modified.hex()

            try:
                resp = self._make_request(
                    url, method, param, modified_hex, extra_data, timeout
                )
                # Create a response signature from status code and response length range
                sig = f"{resp.status_code}:{len(resp.text) // 100}"
                if sig not in response_groups:
                    response_groups[sig] = []
                response_groups[sig].append(byte_val)
            except Exception:
                continue

        # Analyze response groups
        num_groups = len(response_groups)
        results.append(f"Response groups found: {num_groups}")
        results.append("")

        for sig, byte_values in sorted(response_groups.items()):
            status, length_bucket = sig.split(":")
            results.append(
                f"  Group [status={status}, ~length={int(length_bucket) * 100}]: "
                f"{len(byte_values)} responses"
            )

        results.append("")

        if num_groups == 2:
            results.append("[!] PADDING ORACLE DETECTED!")
            results.append("")
            results.append("Two distinct response groups found, indicating the server")
            results.append("differentiates between valid and invalid padding.")
            results.append("")

            # Identify which group is likely valid padding
            sorted_groups = sorted(response_groups.items(), key=lambda x: len(x[1]))
            minority_sig = sorted_groups[0][0]
            majority_sig = sorted_groups[1][0]
            results.append(
                f"Valid padding pattern: {minority_sig} ({len(sorted_groups[0][1])} responses)"
            )
            results.append(
                f"Invalid padding pattern: {majority_sig} ({len(sorted_groups[1][1])} responses)"
            )
            results.append("")
            results.append("=== Next Steps ===")
            results.append(
                "1. Use the padding oracle to decrypt the ciphertext byte-by-byte"
            )
            results.append(
                "2. Use crypto_payload_generator with operation 'padding_oracle' for methodology"
            )
        elif num_groups == 1:
            results.append("[-] No padding oracle detected.")
            results.append(
                "All responses identical - server does not differentiate padding errors."
            )
        else:
            results.append(f"[*] Inconclusive: {num_groups} response groups found.")
            results.append(
                "Multiple response patterns may indicate other vulnerabilities."
            )

        return "\n".join(results)

    def _test_ecb_detect(
        self,
        url: str,
        method: str,
        param: str,
        extra_data: dict,
        block_size: int,
        timeout: int,
    ) -> str:
        """Detect ECB mode encryption."""
        results = ["[CryptoProbeTool] ECB Mode Detection"]
        results.append("=" * 50)
        results.append(f"Block size: {block_size} bytes")
        results.append("")

        # Send repeated plaintext blocks
        repeated_char = "A" * block_size * 4
        results.append(
            f"Sending repeated plaintext: {'A' * 16}... ({len(repeated_char)} chars)"
        )

        try:
            resp = self._make_request(
                url, method, param, repeated_char, extra_data, timeout
            )
            resp_text = resp.text.strip()
        except Exception as e:
            results.append(f"[!] Request failed: {e}")
            return "\n".join(results)

        # Try to extract ciphertext from response (look for hex or base64)
        ciphertext_hex = self._extract_ciphertext(resp_text)

        if not ciphertext_hex:
            results.append("[!] Could not extract ciphertext from response.")
            results.append(f"Response preview: {resp_text[:200]}")
            return "\n".join(results)

        results.append(f"Extracted ciphertext: {ciphertext_hex[:64]}...")
        results.append("")

        # Check for repeated blocks
        ct_bytes = bytes.fromhex(ciphertext_hex) if ciphertext_hex else b""
        blocks = [
            ct_bytes[i : i + block_size]
            for i in range(0, len(ct_bytes) - block_size + 1, block_size)
        ]

        block_counts = Counter(blocks)
        repeated_blocks = {b.hex(): c for b, c in block_counts.items() if c > 1}

        if repeated_blocks:
            results.append("[!] ECB MODE DETECTED!")
            results.append("")
            results.append("Repeated ciphertext blocks found:")
            for block_hex, count in repeated_blocks.items():
                results.append(f"  Block {block_hex}: appears {count} times")
            results.append("")
            results.append("ECB mode encrypts identical plaintext blocks to identical")
            results.append("ciphertext blocks, enabling cut-and-paste attacks.")
            results.append("")
            results.append("=== Next Steps ===")
            results.append(
                "1. Use crypto_payload_generator with operation 'ecb_attack' for methodology"
            )
            results.append(
                "2. Try block-aligned input to control encryption boundaries"
            )
        else:
            results.append("[-] No repeated blocks detected.")
            results.append(
                "Encryption may use CBC, CTR, or another mode with diffusion."
            )

        # Also test with two different inputs to compare
        results.append("")
        results.append("=== Additional Analysis ===")
        try:
            resp2 = self._make_request(
                url, method, param, "B" * block_size * 4, extra_data, timeout
            )
            ct2_hex = self._extract_ciphertext(resp2.text.strip())
            if ct2_hex and ciphertext_hex:
                # Compare block-by-block
                ct1_bytes = bytes.fromhex(ciphertext_hex)
                ct2_bytes = bytes.fromhex(ct2_hex)
                matching = 0
                total = min(len(ct1_bytes), len(ct2_bytes)) // block_size
                for i in range(total):
                    b1 = ct1_bytes[i * block_size : (i + 1) * block_size]
                    b2 = ct2_bytes[i * block_size : (i + 1) * block_size]
                    if b1 == b2:
                        matching += 1
                results.append(
                    f"Block comparison (AAAA vs BBBB): {matching}/{total} blocks match"
                )
                if matching > 0:
                    results.append(
                        "[*] Some blocks match between different inputs - possible ECB with prefix"
                    )
                else:
                    results.append("[*] No blocks match between different inputs")
        except Exception as e:
            results.append(f"[!] Comparison test failed: {e}")

        return "\n".join(results)

    def _extract_ciphertext(self, text: str) -> str:
        """Try to extract hex ciphertext from response text."""
        import re

        # Look for long hex strings
        hex_matches = re.findall(r"[0-9a-fA-F]{16,}", text)
        if hex_matches:
            # Return the longest hex string found
            return max(hex_matches, key=len).lower()

        # Try to decode the entire response as hex
        cleaned = text.strip().replace(" ", "").replace("\n", "")
        if all(c in "0123456789abcdefABCDEF" for c in cleaned) and len(cleaned) >= 16:
            return cleaned.lower()

        # Try base64 decode to hex
        try:
            padded = (
                cleaned + "=" * (4 - len(cleaned) % 4)
                if len(cleaned) % 4 != 0
                else cleaned
            )
            decoded = base64.b64decode(padded)
            return decoded.hex()
        except Exception:
            pass

        return ""

    def _test_token_analysis(
        self,
        url: str,
        method: str,
        param: str,
        extra_data: dict,
        num_samples: int,
        timeout: int,
    ) -> str:
        """Analyze token generation for weaknesses."""
        results = ["[CryptoProbeTool] Token Analysis"]
        results.append("=" * 50)
        results.append(f"Collecting {num_samples} token samples...")
        results.append("")

        tokens = []
        for i in range(num_samples):
            try:
                resp = self._make_request(
                    url, method, param, f"test_user_{i}", extra_data, timeout
                )
                # Look for tokens in response (common locations)
                token = self._extract_token(resp)
                if token:
                    tokens.append(token)
            except Exception as e:
                results.append(f"[!] Sample {i + 1} failed: {e}")

        if not tokens:
            results.append("[!] No tokens could be extracted from responses.")
            return "\n".join(results)

        results.append(f"Collected {len(tokens)} tokens:")
        for i, token in enumerate(tokens):
            results.append(
                f"  [{i + 1}] {token[:64]}{'...' if len(token) > 64 else ''}"
            )
        results.append("")

        weaknesses = []

        # Check length consistency
        lengths = [len(t) for t in tokens]
        if len(set(lengths)) == 1:
            results.append(f"[*] Token length: consistent ({lengths[0]} chars)")
        else:
            results.append(
                f"[*] Token lengths: variable ({min(lengths)}-{max(lengths)} chars)"
            )
            weaknesses.append(
                "Variable token length may indicate predictable structure"
            )

        # Check for sequential patterns
        if len(tokens) >= 2:
            sequential = self._check_sequential(tokens)
            if sequential:
                weaknesses.append("Sequential/incrementing pattern detected")
                results.append("[!] Sequential pattern detected in tokens!")

        # Check for base64-decodable structure
        for i, token in enumerate(tokens):
            try:
                padded = (
                    token + "=" * (4 - len(token) % 4) if len(token) % 4 != 0 else token
                )
                decoded = base64.b64decode(padded)
                # Check if decoded content has structure
                try:
                    parsed = json.loads(decoded)
                    results.append(
                        f"  Token {i + 1}: base64-encoded JSON: {json.dumps(parsed)[:100]}"
                    )
                    weaknesses.append(
                        "Tokens contain base64-encoded JSON (potentially forgeable)"
                    )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            except Exception:
                pass

        # Check entropy
        for i, token in enumerate(tokens):
            entropy = self._calculate_entropy(token)
            results.append(f"  Token {i + 1} entropy: {entropy:.2f} bits/char")
            if entropy < 3.0:
                weaknesses.append(
                    f"Low entropy in token {i + 1} ({entropy:.2f} bits/char)"
                )

        # Check for timestamp components
        import time

        current_ts = str(int(time.time()))
        for i, token in enumerate(tokens):
            if current_ts[:6] in token:
                weaknesses.append(f"Token {i + 1} may contain Unix timestamp component")
                results.append(
                    f"  Token {i + 1}: possible timestamp component detected"
                )

        results.append("")
        results.append("=== Analysis Summary ===")
        if weaknesses:
            results.append("[!] Potential weaknesses found:")
            for w in weaknesses:
                results.append(f"  - {w}")
        else:
            results.append("[-] No obvious weaknesses detected in token generation.")

        return "\n".join(results)

    def _extract_token(self, response: requests.Response) -> str:
        """Extract a token from the response (cookies, headers, body)."""
        # Check Set-Cookie header
        for cookie in response.cookies:
            if any(
                name in cookie.name.lower()
                for name in ["token", "session", "auth", "jwt"]
            ):
                return cookie.value

        # Check response headers
        for header_name in ["X-Token", "X-Auth-Token", "Authorization"]:
            if header_name in response.headers:
                return response.headers[header_name]

        # Check response body for token-like values
        import re

        body = response.text
        # Look for quoted token values
        token_patterns = [
            r'"token"\s*:\s*"([^"]+)"',
            r'"access_token"\s*:\s*"([^"]+)"',
            r'"session"\s*:\s*"([^"]+)"',
            r'"auth"\s*:\s*"([^"]+)"',
        ]
        for pattern in token_patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)

        # Fall back to the full response text if short enough
        if len(body.strip()) < 256:
            return body.strip()

        return ""

    def _check_sequential(self, tokens: List[str]) -> bool:
        """Check if tokens appear sequential/incrementing."""
        # Try numeric comparison
        try:
            nums = [int(t) for t in tokens]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if len(set(diffs)) == 1:
                return True
        except (ValueError, TypeError):
            pass

        # Check if hex values are sequential
        try:
            hex_nums = [int(t, 16) for t in tokens]
            diffs = [hex_nums[i + 1] - hex_nums[i] for i in range(len(hex_nums) - 1)]
            if len(set(diffs)) == 1 and diffs[0] > 0:
                return True
        except (ValueError, TypeError):
            pass

        # Check common substring with incrementing suffix
        if len(tokens) >= 2:
            # Find common prefix
            prefix_len = 0
            min_len = min(len(t) for t in tokens)
            for i in range(min_len):
                if len(set(t[i] for t in tokens)) == 1:
                    prefix_len = i + 1
                else:
                    break

            if prefix_len > 0:
                suffixes = [t[prefix_len:] for t in tokens]
                try:
                    suffix_nums = [int(s) for s in suffixes if s]
                    if suffix_nums and len(suffix_nums) >= 2:
                        diffs = [
                            suffix_nums[i + 1] - suffix_nums[i]
                            for i in range(len(suffix_nums) - 1)
                        ]
                        if len(set(diffs)) == 1:
                            return True
                except (ValueError, TypeError):
                    pass

        return False

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math

        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


class CryptoAnalyzerTool:
    """
    CryptoAnalyzerTool: analyze cryptographic data without network access.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "identify_encoding",
          "text": "SGVsbG8gV29ybGQ=",
          "ciphertext": "aabbccdd...",
          "key": "secretkey",
          "keys": ["key1", "key2"],
          "block_size": 16
        }

    Supported operations:
      - identify_encoding: Detect encoding type of given text
      - detect_cipher_mode: Analyze ciphertext for ECB vs CBC
      - analyze_key: Check key(s) for weaknesses
      - xor_analysis: Try single-byte XOR decryption
      - frequency_analysis: Character frequency analysis
    """

    name: str = "crypto_analyzer"
    description: str = (
        "Analyze cryptographic data offline (no network access). Input must be JSON with "
        "'operation' (identify_encoding, detect_cipher_mode, analyze_key, xor_analysis, "
        "frequency_analysis). For identify_encoding, provide 'text'. For detect_cipher_mode, "
        "provide 'ciphertext' (hex). For analyze_key, provide 'key' or 'keys'. "
        "For xor_analysis, provide 'ciphertext' (hex). For frequency_analysis, provide 'text'. "
        "Optionally provide 'block_size' for cipher mode detection."
    )

    OPERATIONS = {
        "identify_encoding",
        "detect_cipher_mode",
        "analyze_key",
        "xor_analysis",
        "frequency_analysis",
    }

    # Common weak keys
    WEAK_KEYS = [
        b"\x00" * 16,
        b"\x00" * 24,
        b"\x00" * 32,
        bytes(range(16)),
        bytes(range(24)),
        bytes(range(32)),
        b"0000000000000000",
        b"1234567890123456",
        b"AAAAAAAAAAAAAAAA",
    ]

    # English letter frequencies (approximate)
    ENGLISH_FREQ = {
        "a": 8.167,
        "b": 1.492,
        "c": 2.782,
        "d": 4.253,
        "e": 12.702,
        "f": 2.228,
        "g": 2.015,
        "h": 6.094,
        "i": 6.966,
        "j": 0.153,
        "k": 0.772,
        "l": 4.025,
        "m": 2.406,
        "n": 6.749,
        "o": 7.507,
        "p": 1.929,
        "q": 0.095,
        "r": 5.987,
        "s": 6.327,
        "t": 9.056,
        "u": 2.758,
        "v": 0.978,
        "w": 2.360,
        "x": 0.150,
        "y": 1.974,
        "z": 0.074,
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[CryptoAnalyzerTool] Error: tool_input must be JSON. Decoding failed with: {exc}"

        operation = data.get("operation", "").strip().lower()
        if not operation:
            return "[CryptoAnalyzerTool] Error: 'operation' is required."

        if operation not in self.OPERATIONS:
            return (
                f"[CryptoAnalyzerTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(sorted(self.OPERATIONS))}"
            )

        try:
            if operation == "identify_encoding":
                return self._identify_encoding(data)
            elif operation == "detect_cipher_mode":
                return self._detect_cipher_mode(data)
            elif operation == "analyze_key":
                return self._analyze_key(data)
            elif operation == "xor_analysis":
                return self._xor_analysis(data)
            elif operation == "frequency_analysis":
                return self._frequency_analysis(data)
            else:
                return f"[CryptoAnalyzerTool] Error: Operation '{operation}' not implemented."
        except Exception as exc:
            return f"[CryptoAnalyzerTool] Error performing '{operation}': {exc}"

    def _identify_encoding(self, data: dict) -> str:
        """Detect the encoding type of given text."""
        text = data.get("text", "")
        if not text:
            return (
                "[CryptoAnalyzerTool] Error: 'text' is required for identify_encoding."
            )

        results = ["[CryptoAnalyzerTool] Encoding Identification"]
        results.append("=" * 50)
        results.append(f"Input: {text[:80]}{'...' if len(text) > 80 else ''}")
        results.append(f"Length: {len(text)} chars")
        results.append("")

        detected = []

        # Check hex encoding
        cleaned_hex = text.strip().replace(" ", "").replace(":", "").replace("0x", "")
        if (
            all(c in "0123456789abcdefABCDEF" for c in cleaned_hex)
            and len(cleaned_hex) >= 2
            and len(cleaned_hex) % 2 == 0
        ):
            try:
                decoded = bytes.fromhex(cleaned_hex)
                preview = decoded[:20]
                detected.append(("hex", f"Decoded ({len(decoded)} bytes): {preview!r}"))
            except (ValueError, binascii.Error):
                pass

        # Check base64 encoding
        b64_chars = set(string.ascii_letters + string.digits + "+/=")
        cleaned_b64 = text.strip().replace("\n", "").replace("\r", "")
        if len(cleaned_b64) >= 4 and all(c in b64_chars for c in cleaned_b64):
            try:
                padded = cleaned_b64
                if len(cleaned_b64) % 4 != 0:
                    padded = cleaned_b64 + "=" * (4 - len(cleaned_b64) % 4)
                decoded = base64.b64decode(padded)
                # Check if it decodes to valid text
                try:
                    decoded_text = decoded.decode("utf-8")
                    detected.append(("base64", f"Decoded: {decoded_text[:50]}"))
                except UnicodeDecodeError:
                    detected.append(
                        (
                            "base64",
                            f"Decoded (binary, {len(decoded)} bytes): {decoded[:20].hex()}",
                        )
                    )
            except Exception:
                pass

        # Check base32 encoding
        b32_chars = set(string.ascii_uppercase + "234567=")
        cleaned_b32 = text.strip().upper().replace("\n", "").replace("\r", "")
        if len(cleaned_b32) >= 8 and all(c in b32_chars for c in cleaned_b32):
            try:
                padded_b32 = cleaned_b32
                if len(cleaned_b32) % 8 != 0:
                    padded_b32 = cleaned_b32 + "=" * (8 - len(cleaned_b32) % 8)
                decoded = base64.b32decode(padded_b32)
                try:
                    decoded_text = decoded.decode("utf-8")
                    detected.append(("base32", f"Decoded: {decoded_text[:50]}"))
                except UnicodeDecodeError:
                    detected.append(
                        (
                            "base32",
                            f"Decoded (binary, {len(decoded)} bytes): {decoded[:20].hex()}",
                        )
                    )
            except Exception:
                pass

        # Check URL encoding
        if "%" in text:
            import urllib.parse

            decoded_url = urllib.parse.unquote(text)
            if decoded_url != text:
                detected.append(("url_encoding", f"Decoded: {decoded_url[:50]}"))

        # Summary
        if detected:
            results.append("Detected encodings:")
            for enc_type, detail in detected:
                results.append(f"  [{enc_type}] {detail}")
        else:
            results.append("[-] Could not identify encoding.")
            results.append(
                "Text may be plaintext, encrypted, or use an unusual encoding."
            )

        return "\n".join(results)

    def _detect_cipher_mode(self, data: dict) -> str:
        """Detect cipher mode from ciphertext analysis."""
        ciphertext = data.get("ciphertext", "")
        if not ciphertext:
            return "[CryptoAnalyzerTool] Error: 'ciphertext' (hex) is required for detect_cipher_mode."

        results = ["[CryptoAnalyzerTool] Cipher Mode Detection"]
        results.append("=" * 50)

        # Clean and convert hex ciphertext
        cleaned = ciphertext.strip().replace(" ", "").replace(":", "")
        try:
            ct_bytes = bytes.fromhex(cleaned)
        except (ValueError, binascii.Error):
            return "[CryptoAnalyzerTool] Error: 'ciphertext' must be valid hex."

        results.append(f"Ciphertext length: {len(ct_bytes)} bytes")
        results.append("")

        # Try block sizes
        block_sizes = data.get("block_size", None)
        if block_sizes:
            sizes_to_try = [block_sizes]
        else:
            sizes_to_try = [8, 16]

        for bs in sizes_to_try:
            results.append(f"--- Block size: {bs} bytes ---")

            if len(ct_bytes) % bs != 0:
                results.append(f"[*] Ciphertext not aligned to {bs}-byte blocks")
                continue

            num_blocks = len(ct_bytes) // bs
            blocks = [ct_bytes[i * bs : (i + 1) * bs] for i in range(num_blocks)]

            results.append(f"Number of blocks: {num_blocks}")

            # Check for repeated blocks (ECB indicator)
            block_counts = Counter(blocks)
            repeated = {b.hex(): c for b, c in block_counts.items() if c > 1}

            if repeated:
                results.append("[!] REPEATED BLOCKS DETECTED - likely ECB mode!")
                for block_hex, count in repeated.items():
                    results.append(f"  Block {block_hex}: appears {count} times")
            else:
                results.append("[*] No repeated blocks (consistent with CBC/CTR/GCM)")

            # Check block alignment
            if len(ct_bytes) % bs == 0:
                results.append(f"[*] Ciphertext aligns to {bs}-byte boundary")
            results.append("")

        # Overall assessment
        results.append("=== Assessment ===")
        any_repeated = False
        for bs in sizes_to_try:
            if len(ct_bytes) % bs == 0:
                num_blocks = len(ct_bytes) // bs
                blocks = [ct_bytes[i * bs : (i + 1) * bs] for i in range(num_blocks)]
                if len(blocks) != len(set(blocks)):
                    any_repeated = True

        if any_repeated:
            results.append(
                "[!] ECB mode likely - repeated plaintext blocks produce repeated ciphertext blocks"
            )
            results.append("Consider using ECB cut-and-paste attack")
        else:
            results.append("[-] No ECB indicators found")
            results.append(
                "Cipher likely uses CBC, CTR, GCM, or another mode with diffusion"
            )

        return "\n".join(results)

    def _analyze_key(self, data: dict) -> str:
        """Analyze cryptographic key(s) for weaknesses."""
        key = data.get("key", "")
        keys = data.get("keys", [])

        if not key and not keys:
            return "[CryptoAnalyzerTool] Error: 'key' or 'keys' is required for analyze_key."

        if key and not keys:
            keys = [key]

        results = ["[CryptoAnalyzerTool] Key Analysis"]
        results.append("=" * 50)

        for i, k in enumerate(keys):
            results.append(
                f"\n--- Key {i + 1}: {k[:32]}{'...' if len(k) > 32 else ''} ---"
            )

            key_bytes = k.encode("utf-8") if isinstance(k, str) else k
            weaknesses = []

            # Check length
            key_len = len(key_bytes)
            results.append(f"Length: {key_len} bytes ({key_len * 8} bits)")

            if key_len < 8:
                weaknesses.append("Key is very short (< 8 bytes) - easily brute-forced")
            elif key_len < 16:
                weaknesses.append("Key is short (< 16 bytes / 128 bits)")

            # Check for all zeros
            if all(b == 0 for b in key_bytes):
                weaknesses.append("CRITICAL: Key is all zeros!")

            # Check for sequential bytes
            if key_bytes == bytes(range(len(key_bytes))):
                weaknesses.append("CRITICAL: Key is sequential bytes (0, 1, 2, ...)")

            # Check for repeating single byte
            if len(set(key_bytes)) == 1 and len(key_bytes) > 1:
                weaknesses.append(
                    f"CRITICAL: Key is single repeated byte (0x{key_bytes[0]:02x})"
                )

            # Check if ASCII-only
            if all(32 <= b <= 126 for b in key_bytes):
                weaknesses.append("Key is ASCII-only (reduced keyspace)")

            # Check against known weak keys
            for weak_key in self.WEAK_KEYS:
                if key_bytes == weak_key:
                    weaknesses.append("CRITICAL: Matches known weak key pattern")
                    break

            # Check for common password patterns
            k_lower = k.lower() if isinstance(k, str) else ""
            common_patterns = [
                "password",
                "secret",
                "admin",
                "123456",
                "key",
                "test",
                "default",
                "changeme",
                "qwerty",
                "abc123",
            ]
            for pattern in common_patterns:
                if pattern in k_lower:
                    weaknesses.append(f"Contains common password pattern: '{pattern}'")
                    break

            if weaknesses:
                results.append("[!] Weaknesses found:")
                for w in weaknesses:
                    results.append(f"  - {w}")
            else:
                results.append("[+] No obvious weaknesses detected")

        return "\n".join(results)

    def _xor_analysis(self, data: dict) -> str:
        """Try single-byte XOR decryption and score by English frequency."""
        ciphertext = data.get("ciphertext", "")
        if not ciphertext:
            return "[CryptoAnalyzerTool] Error: 'ciphertext' (hex) is required for xor_analysis."

        results = ["[CryptoAnalyzerTool] Single-Byte XOR Analysis"]
        results.append("=" * 50)

        # Convert hex to bytes
        cleaned = ciphertext.strip().replace(" ", "").replace(":", "")
        try:
            ct_bytes = bytes.fromhex(cleaned)
        except (ValueError, binascii.Error):
            return "[CryptoAnalyzerTool] Error: 'ciphertext' must be valid hex."

        results.append(f"Ciphertext length: {len(ct_bytes)} bytes")
        results.append("")

        # Try all 256 single-byte XOR keys
        candidates = []
        for key_byte in range(256):
            decrypted = bytes([b ^ key_byte for b in ct_bytes])

            # Score by English character frequency
            score = self._score_english(decrypted)
            try:
                decoded_text = decrypted.decode("ascii", errors="replace")
            except Exception:
                decoded_text = decrypted.hex()

            candidates.append((key_byte, score, decoded_text))

        # Sort by score (higher is more English-like)
        candidates.sort(key=lambda x: x[1], reverse=True)

        # Return top 5
        results.append("Top 5 candidates (by English frequency score):")
        results.append("")
        for rank, (key_byte, score, text) in enumerate(candidates[:5], 1):
            results.append(
                f"  #{rank}: Key=0x{key_byte:02x} ({key_byte}) | Score={score:.2f}"
            )
            results.append(f"       Text: {text[:80]}{'...' if len(text) > 80 else ''}")
            results.append("")

        return "\n".join(results)

    def _score_english(self, data: bytes) -> float:
        """Score how English-like a byte string is."""
        score = 0.0
        for byte in data:
            char = chr(byte).lower()
            if char in self.ENGLISH_FREQ:
                score += self.ENGLISH_FREQ[char]
            elif byte == 32:  # space
                score += 13.0  # Space is very common in English
            elif 32 <= byte <= 126:
                score += 0.5  # Other printable ASCII
            else:
                score -= 5.0  # Non-printable penalty
        return score

    def _frequency_analysis(self, data: dict) -> str:
        """Perform character frequency analysis on text."""
        text = data.get("text", "")
        if not text:
            return (
                "[CryptoAnalyzerTool] Error: 'text' is required for frequency_analysis."
            )

        results = ["[CryptoAnalyzerTool] Frequency Analysis"]
        results.append("=" * 50)
        results.append(f"Text length: {len(text)} characters")
        results.append("")

        # Count frequencies
        freq = Counter(text.lower())
        total = sum(freq.values())
        letter_freq = {c: count for c, count in freq.items() if c.isalpha()}
        total_letters = sum(letter_freq.values())

        if total_letters == 0:
            results.append("[-] No alphabetic characters found in text.")
            return "\n".join(results)

        # Calculate observed frequencies (percentage)
        observed = {}
        for char, count in sorted(letter_freq.items(), key=lambda x: -x[1]):
            pct = (count / total_letters) * 100
            observed[char] = pct
            bar = "#" * int(pct * 2)
            results.append(f"  {char}: {pct:5.2f}% ({count:4d}) {bar}")

        results.append("")

        # Calculate chi-squared against English
        chi_squared = 0.0
        for char in "abcdefghijklmnopqrstuvwxyz":
            expected = self.ENGLISH_FREQ.get(char, 0.0)
            observed_pct = observed.get(char, 0.0)
            if expected > 0:
                chi_squared += ((observed_pct - expected) ** 2) / expected

        results.append(f"Chi-squared vs English: {chi_squared:.2f}")
        results.append("")

        # Assess cipher type
        results.append("=== Assessment ===")
        if chi_squared < 30:
            results.append("[*] Frequency distribution close to English")
            results.append(
                "Likely: plaintext, simple substitution (partially solved), or transposition cipher"
            )
        elif chi_squared < 100:
            results.append("[*] Moderate deviation from English frequencies")
            results.append("Likely: simple substitution cipher (monoalphabetic)")
        else:
            results.append("[*] Significant deviation from English frequencies")
            results.append(
                "Likely: polyalphabetic cipher (Vigenere), or not English text"
            )

        # Most common letter analysis
        if observed:
            most_common = max(observed, key=observed.get)
            results.append(
                f"\nMost frequent letter: '{most_common}' ({observed[most_common]:.2f}%)"
            )
            results.append("In English, 'e' is most frequent at ~12.7%")
            if most_common != "e":
                shift = (ord(most_common) - ord("e")) % 26
                results.append(
                    f"If Caesar cipher, possible shift: {shift} ('{most_common}' -> 'e')"
                )

        return "\n".join(results)


class CryptoPayloadGenerator:
    """
    CryptoPayloadGenerator: generate attack methodology for cryptographic vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "padding_oracle"
        }

    Supported operations:
      - padding_oracle: Step-by-step padding oracle attack methodology
      - ecb_attack: ECB cut-and-paste attack methodology
      - bit_flip: CBC bit-flipping attack methodology
      - hash_extension: Hash length extension attack methodology
    """

    name: str = "crypto_payload_generator"
    description: str = (
        "Generate attack methodology and pseudocode for cryptographic vulnerabilities. "
        "Input must be JSON with 'operation' (padding_oracle, ecb_attack, bit_flip, "
        "hash_extension). Returns step-by-step methodology, explanation of the attack, "
        "and Python pseudocode templates for exploitation."
    )

    OPERATIONS = {"padding_oracle", "ecb_attack", "bit_flip", "hash_extension"}

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[CryptoPayloadGenerator] Error: tool_input must be JSON. Decoding failed with: {exc}"

        operation = data.get("operation", "").strip().lower()
        if not operation:
            return "[CryptoPayloadGenerator] Error: 'operation' is required."

        if operation not in self.OPERATIONS:
            return (
                f"[CryptoPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(sorted(self.OPERATIONS))}"
            )

        if operation == "padding_oracle":
            return self._padding_oracle_methodology()
        elif operation == "ecb_attack":
            return self._ecb_attack_methodology()
        elif operation == "bit_flip":
            return self._bit_flip_methodology()
        elif operation == "hash_extension":
            return self._hash_extension_methodology()
        else:
            return f"[CryptoPayloadGenerator] Error: Operation '{operation}' not implemented."

    def _padding_oracle_methodology(self) -> str:
        """Generate padding oracle attack methodology."""
        return """[CryptoPayloadGenerator] Padding Oracle Attack Methodology
==================================================

=== Overview ===
A padding oracle attack exploits a server that reveals whether CBC-mode
decrypted ciphertext has valid PKCS#7 padding. By manipulating ciphertext
bytes and observing the server's response, you can decrypt the entire
message without knowing the key.

=== How It Works ===

1. CBC Decryption: P[i] = D(C[i]) XOR C[i-1]
   - D(C[i]) is the raw block cipher decryption (the "intermediate value")
   - C[i-1] is the previous ciphertext block (or IV for the first block)

2. PKCS#7 Padding: The last block is padded so its last N bytes are all N
   - Valid: ...\\x01, ...\\x02\\x02, ...\\x03\\x03\\x03, etc.
   - The oracle tells us if padding is valid after our modification

3. To find intermediate byte I[n] (last byte of intermediate value):
   - Modify C'[i-1][n] through all 256 values
   - When padding is valid (\\x01), we know: C'[i-1][n] XOR I[n] = 0x01
   - Therefore: I[n] = C'[i-1][n] XOR 0x01
   - Original plaintext: P[n] = I[n] XOR C[i-1][n] (original byte)

4. For subsequent bytes, set known bytes to produce target padding value
   and iterate through the unknown byte.

=== Block Structure ===
For a 16-byte block size:
  Ciphertext: [  IV/C0  ][   C1   ][   C2   ]...[   Cn   ]
  Plaintext:  [   P1    ][   P2   ]...[   Pn   ]

=== Python Pseudocode ===

```python
import requests

BLOCK_SIZE = 16

def padding_oracle(ciphertext_hex):
    \"\"\"Returns True if server accepts the padding.\"\"\"
    resp = requests.get(URL, params={PARAM: ciphertext_hex})
    # Adapt this condition to your oracle:
    return resp.status_code == 200  # or check response body

def decrypt_block(prev_block, target_block):
    \"\"\"Decrypt a single block using the padding oracle.\"\"\"
    intermediate = [0] * BLOCK_SIZE
    plaintext = [0] * BLOCK_SIZE

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos

        # Set already-known bytes to produce correct padding
        crafted = bytearray(BLOCK_SIZE)
        for k in range(byte_pos + 1, BLOCK_SIZE):
            crafted[k] = intermediate[k] ^ padding_value

        # Brute-force the target byte
        for guess in range(256):
            crafted[byte_pos] = guess
            test_ct = crafted.hex() + target_block.hex()
            if padding_oracle(test_ct):
                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                break

    return bytes(plaintext)

# Decrypt all blocks
ct = bytes.fromhex(CIPHERTEXT_HEX)
blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
plaintext = b""
for i in range(1, len(blocks)):
    plaintext += decrypt_block(blocks[i-1], blocks[i])
print(f"Decrypted: {plaintext}")
```

=== Tips ===
- The oracle response may be: different HTTP status codes, different error
  messages, different response lengths, or timing differences
- Some oracles are inverted (error = valid padding)
- You may need to URL-encode or base64-encode the modified ciphertext
- Rate limiting may require delays between requests"""

    def _ecb_attack_methodology(self) -> str:
        """Generate ECB cut-and-paste attack methodology."""
        return """[CryptoPayloadGenerator] ECB Cut-and-Paste Attack Methodology
==================================================

=== Overview ===
ECB (Electronic Codebook) mode encrypts each block independently with the
same key. Identical plaintext blocks produce identical ciphertext blocks.
This allows an attacker to rearrange, duplicate, or remove blocks to
manipulate the decrypted plaintext.

=== How It Works ===

1. Block alignment: Input is split into fixed-size blocks (typically 16 bytes)
2. Each block is encrypted independently: C[i] = E(P[i], K)
3. By controlling input, you can:
   - Align sensitive values to block boundaries
   - Craft blocks with desired content
   - Rearrange ciphertext blocks to change decrypted output

=== Attack Steps ===

1. **Determine block size**: Send increasing input until ciphertext length jumps
   - block_size = jump_point - previous_length

2. **Confirm ECB mode**: Send repeated input (e.g., 'A' * 48)
   - Look for repeated ciphertext blocks

3. **Map block boundaries**: Determine where your input falls in blocks
   - Send inputs of varying length and observe ciphertext changes

4. **Craft attack input**: Align your target value to a block boundary
   - Example: If format is "email=X&role=user"
   - Craft email so "admin" starts at a block boundary
   - Then cut that block and paste it where "user" would be

=== Python Pseudocode ===

```python
BLOCK_SIZE = 16

def encrypt(plaintext):
    \"\"\"Send plaintext to the encryption oracle.\"\"\"
    resp = requests.get(URL, params={PARAM: plaintext})
    return resp.text  # hex ciphertext

def split_blocks(ciphertext_hex):
    ct = bytes.fromhex(ciphertext_hex)
    return [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

# Step 1: Find block size
prev_len = len(encrypt("A"))
for i in range(2, 64):
    curr_len = len(encrypt("A" * i))
    if curr_len > prev_len:
        block_size = (curr_len - prev_len) // 2  # hex chars
        break
    prev_len = curr_len

# Step 2: Craft aligned blocks
# If server encrypts: "prefix" + input + "suffix"
# Calculate padding needed to align target to block boundary
prefix_padding = "A" * (BLOCK_SIZE - len("prefix") % BLOCK_SIZE)
target_value = "admin" + chr(11) * 11  # PKCS#7 pad to fill block

# Step 3: Get the target block
attack_input = prefix_padding + target_value
ct_blocks = split_blocks(encrypt(attack_input))
admin_block = ct_blocks[ADMIN_BLOCK_INDEX]

# Step 4: Build final ciphertext
normal_ct = split_blocks(encrypt("normal_input"))
# Replace the role block with the admin block
final_ct = normal_ct[:ROLE_BLOCK] + [admin_block]
print(f"Attack ciphertext: {b''.join(final_ct).hex()}")
```

=== Tips ===
- Draw out the block layout on paper to visualize boundaries
- Use padding characters to push values to exact positions
- The prefix/suffix added by the server affects block alignment
- If you can register users, the email field is often controllable"""

    def _bit_flip_methodology(self) -> str:
        """Generate CBC bit-flipping attack methodology."""
        return """[CryptoPayloadGenerator] CBC Bit-Flipping Attack Methodology
==================================================

=== Overview ===
In CBC mode, modifying byte N in ciphertext block C[i-1] will flip the
corresponding byte N in the DECRYPTED plaintext block P[i]. This is
because: P[i] = D(C[i]) XOR C[i-1]. The attacker controls C[i-1],
and thus controls the XOR applied to the intermediate decryption output.

=== The Key Formula ===

To change plaintext byte P[i][n] from value A to value B:
  C[i-1][n] = C[i-1][n] XOR A XOR B

This works because:
  New P[i][n] = D(C[i])[n] XOR new_C[i-1][n]
             = D(C[i])[n] XOR (C[i-1][n] XOR A XOR B)
             = (D(C[i])[n] XOR C[i-1][n]) XOR A XOR B
             = A XOR A XOR B
             = B

Note: This CORRUPTS block P[i-1] (the block where you modify the ciphertext).

=== Attack Steps ===

1. Identify the target byte position in the plaintext
2. Determine which ciphertext block precedes the target block
3. Calculate the byte position within that ciphertext block
4. Apply the XOR modification: C[pos] ^= old_value ^ new_value

=== Python Pseudocode ===

```python
BLOCK_SIZE = 16

def bit_flip_attack(ciphertext_hex, target_block_idx, byte_offset,
                    old_value, new_value):
    \"\"\"
    Flip a byte in CBC ciphertext to change plaintext.

    Args:
        ciphertext_hex: Original ciphertext (hex)
        target_block_idx: Index of plaintext block to modify (1-based)
        byte_offset: Byte position within the block (0-15)
        old_value: Current plaintext byte value (int or char)
        new_value: Desired plaintext byte value (int or char)
    \"\"\"
    ct = bytearray(bytes.fromhex(ciphertext_hex))

    if isinstance(old_value, str):
        old_value = ord(old_value)
    if isinstance(new_value, str):
        new_value = ord(new_value)

    # Modify byte in the PREVIOUS ciphertext block
    modify_pos = (target_block_idx - 1) * BLOCK_SIZE + byte_offset
    ct[modify_pos] ^= old_value ^ new_value

    return ct.hex()

# Example: Change ";admin=0" to ";admin=1" in block 2
# Original plaintext block 2 contains "...;admin=0;..."
# Target: byte at offset 10 (the '0'), change to '1'
modified = bit_flip_attack(
    ciphertext_hex=ORIGINAL_CT,
    target_block_idx=2,
    byte_offset=10,
    old_value='0',
    new_value='1'
)
print(f"Modified ciphertext: {modified}")

# For multiple byte changes:
def multi_flip(ciphertext_hex, changes):
    \"\"\"Apply multiple bit flips.
    changes: list of (target_block, offset, old_val, new_val)\"\"\"
    ct = bytearray(bytes.fromhex(ciphertext_hex))
    for block, offset, old_v, new_v in changes:
        pos = (block - 1) * BLOCK_SIZE + offset
        old_byte = ord(old_v) if isinstance(old_v, str) else old_v
        new_byte = ord(new_v) if isinstance(new_v, str) else new_v
        ct[pos] ^= old_byte ^ new_byte
    return ct.hex()
```

=== Tips ===
- Modifying C[i-1] corrupts P[i-1] but correctly flips P[i]
- If the corrupted block is checked (e.g., for valid format), you need
  to work around this or find a block that isn't validated
- Common targets: changing "0" to "1" for boolean flags, changing "user"
  to "admin" (multi-byte flip)
- For the first plaintext block, modify the IV instead of C[0]
- URL-encode or re-encode the modified ciphertext as needed"""

    def _hash_extension_methodology(self) -> str:
        """Generate hash length extension attack methodology."""
        return """[CryptoPayloadGenerator] Hash Length Extension Attack Methodology
==================================================

=== Overview ===
Hash length extension attacks exploit Merkle-Damgard hash functions
(MD5, SHA-1, SHA-256, SHA-512) when used as MAC with a secret prefix:
  MAC = H(secret || message)

An attacker who knows H(secret || message) and len(secret) can compute
H(secret || message || padding || extension) WITHOUT knowing the secret.

=== When Applicable ===
- Hash function is MD5, SHA-1, SHA-256, or SHA-512 (Merkle-Damgard)
- MAC format is: H(secret + message), NOT H(secret + H(message)) or HMAC
- You know the MAC value (hash output)
- You know or can guess the secret length
- You can append data to the message

=== NOT Vulnerable ===
- HMAC (H(K XOR opad || H(K XOR ipad || message)))
- SHA-3 / Keccak (sponge construction)
- BLAKE2, Poly1305
- H(message + secret) format

=== How It Works ===

1. The hash function processes data in blocks and maintains internal state
2. The hash output IS the internal state after processing all blocks
3. By setting the hash function's state to the known MAC value, you can
   continue hashing as if the secret prefix was already processed
4. You must account for the padding that the original hash added

=== Attack Steps ===

1. Obtain: MAC = H(secret || original_message)
2. Know or guess: length of the secret
3. Calculate: the padding that would be applied after (secret || original_message)
4. Compute: new_MAC = H(secret || original_message || padding || your_extension)
   - This is done by initializing hash state to MAC and hashing the extension
5. Send: original_message || padding || your_extension with new_MAC

=== Tools ===

**HashPump** (recommended):
```bash
# Install
git clone https://github.com/bwall/HashPump && cd HashPump && make

# Usage
hashpump -s <original_mac> -d <original_data> -a <data_to_append> -k <secret_length>

# Example
hashpump -s 6d5f807e23db210bc254a28be2d6759a0f5f5d99 \\
         -d "count=10&lat=37.351&user_id=1&long=-119.827&waession_id=session1" \\
         -a "&waession_id=2&admin=true" \\
         -k 14
```

**Python (with hashpumpy)**:
```python
import hashpumpy

# hashpumpy.hashpump(original_hash, original_data, data_to_add, key_length)
new_hash, new_data = hashpumpy.hashpump(
    "6d5f807e23db210bc254a28be2d6759a0f5f5d99",
    "original_message",
    "&admin=true",
    secret_length  # Try lengths 8-32 if unknown
)

# new_data contains: original_message + padding + "&admin=true"
# new_hash is the valid MAC for new_data with the unknown secret
```

=== Bruteforcing Secret Length ===
```python
import hashpumpy

for secret_len in range(1, 50):
    new_hash, new_data = hashpumpy.hashpump(
        original_mac,
        original_data,
        append_data,
        secret_len
    )
    # Send new_data with new_hash and check if accepted
    resp = requests.get(url, params={"data": new_data, "mac": new_hash})
    if "success" in resp.text.lower():
        print(f"Secret length: {secret_len}")
        break
```

=== Tips ===
- If you don't know the secret length, try values from 1 to 50
- The padding bytes in the middle of the extended message are binary
  (null bytes, length encoding) - URL-encode them
- SHA-256 is most commonly seen in CTFs using this vulnerability
- Look for APIs that verify MAC = H(secret + user_data)
- Common in cookie/session signing where the server uses H(secret + cookie_data)"""
