"""
Encoding and decoding tools for CTF solving.

Provides utilities for common encoding schemes encountered in CTF challenges.
"""

import base64
import html
import json
import urllib.parse
from typing import Optional


class EncodingTool:
    """
    EncodingTool: encode/decode text using various schemes common in CTF challenges.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "text": "some text to encode or decode",
          "operation": "base64_encode"
        }

    Supported operations:
      - base64_encode / base64_decode
      - url_encode / url_decode
      - hex_encode / hex_decode
      - html_entity_encode / html_entity_decode
      - rot13
      - binary_to_ascii / ascii_to_binary
      - jwt_decode (decode without verification)
      - unicode_normalize
      - reverse_string
    """

    name: str = "encoding"
    description: str = (
        "Encode or decode text using various schemes. Input must be JSON with keys: "
        "'text' (string to process), 'operation' (one of: base64_encode, base64_decode, "
        "base32_encode, base32_decode, url_encode, url_decode, double_url_encode, "
        "hex_encode, hex_decode, html_entity_encode, html_entity_decode, rot13, "
        "binary_to_ascii, ascii_to_binary, jwt_decode, unicode_normalize, unicode_escape, "
        "unicode_unescape, reverse_string, xor, octal_encode, octal_decode), and "
        "optionally 'key' (for xor operation, hex string like 'deadbeef'). "
        "Use this tool to decode cookies, parameters, obfuscated strings, or encode payloads."
    )

    # Valid operations
    OPERATIONS = {
        "base64_encode",
        "base64_decode",
        "base32_encode",
        "base32_decode",
        "url_encode",
        "url_decode",
        "double_url_encode",
        "hex_encode",
        "hex_decode",
        "html_entity_encode",
        "html_entity_decode",
        "rot13",
        "binary_to_ascii",
        "ascii_to_binary",
        "jwt_decode",
        "unicode_normalize",
        "unicode_escape",
        "unicode_unescape",
        "reverse_string",
        "xor",
        "octal_encode",
        "octal_decode",
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[EncodingTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        operation = data.get("operation")
        key = data.get("key")

        if not isinstance(text, str):
            return "[EncodingTool] Error: 'text' must be a string."
        if not isinstance(operation, str):
            return "[EncodingTool] Error: 'operation' must be a string."

        operation = operation.lower().strip()
        if operation not in self.OPERATIONS:
            return (
                f"[EncodingTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(sorted(self.OPERATIONS))}"
            )

        try:
            result = self._perform_operation(text, operation, key=key)
            return f"[EncodingTool] Operation: {operation}\nInput: {text[:100]}{'...' if len(text) > 100 else ''}\nResult: {result}"
        except Exception as exc:
            return f"[EncodingTool] Error performing '{operation}': {exc}"

    def _perform_operation(
        self, text: str, operation: str, *, key: Optional[str] = None
    ) -> str:
        """Perform the specified encoding/decoding operation."""

        if operation == "base64_encode":
            return base64.b64encode(text.encode("utf-8")).decode("ascii")

        elif operation == "base64_decode":
            # Handle missing padding
            padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 != 0 else text
            try:
                return base64.b64decode(padded).decode("utf-8")
            except UnicodeDecodeError:
                # Return hex representation for binary data
                decoded_bytes = base64.b64decode(padded)
                return f"[Binary data, hex representation]: {decoded_bytes.hex()}"

        elif operation == "base32_encode":
            return base64.b32encode(text.encode("utf-8")).decode("ascii")

        elif operation == "base32_decode":
            # Handle missing padding
            padded = text + "=" * ((8 - len(text) % 8) % 8)
            try:
                return base64.b32decode(padded.upper()).decode("utf-8")
            except UnicodeDecodeError:
                decoded_bytes = base64.b32decode(padded.upper())
                return f"[Binary data, hex representation]: {decoded_bytes.hex()}"

        elif operation == "url_encode":
            return urllib.parse.quote(text, safe="")

        elif operation == "url_decode":
            return urllib.parse.unquote(text)

        elif operation == "double_url_encode":
            first = urllib.parse.quote(text, safe="")
            return urllib.parse.quote(first, safe="")

        elif operation == "hex_encode":
            return text.encode("utf-8").hex()

        elif operation == "hex_decode":
            # Remove common prefixes and clean up
            cleaned = text.lower().replace("0x", "").replace(" ", "").replace(":", "")
            try:
                return bytes.fromhex(cleaned).decode("utf-8")
            except UnicodeDecodeError:
                decoded_bytes = bytes.fromhex(cleaned)
                return f"[Binary data, raw bytes]: {decoded_bytes!r}"

        elif operation == "html_entity_encode":
            return html.escape(text)

        elif operation == "html_entity_decode":
            return html.unescape(text)

        elif operation == "rot13":
            return self._rot13(text)

        elif operation == "binary_to_ascii":
            # Expects space-separated binary strings like "01001000 01101001"
            binary_values = text.split()
            chars = []
            for bv in binary_values:
                bv_clean = bv.strip()
                if bv_clean:
                    try:
                        chars.append(chr(int(bv_clean, 2)))
                    except ValueError:
                        chars.append(f"[invalid:{bv_clean}]")
            return "".join(chars)

        elif operation == "ascii_to_binary":
            return " ".join(format(ord(c), "08b") for c in text)

        elif operation == "jwt_decode":
            return self._jwt_decode(text)

        elif operation == "unicode_normalize":
            import unicodedata

            return unicodedata.normalize("NFKC", text)

        elif operation == "unicode_escape":
            # Convert each non-ASCII char (and optionally ASCII) to \uXXXX form
            return "".join(
                f"\\u{ord(c):04x}" if ord(c) > 127 or not c.isalnum() else c
                for c in text
            )

        elif operation == "unicode_unescape":
            # Decode \uXXXX escape sequences
            try:
                return text.encode("utf-8").decode("unicode_escape")
            except Exception:
                # Fallback: use raw_unicode_escape for broader compat
                try:
                    return text.encode("utf-8").decode("raw_unicode_escape")
                except Exception:
                    return text

        elif operation == "reverse_string":
            return text[::-1]

        elif operation == "xor":
            if not key:
                return "[XOR requires 'key' parameter (hex string, e.g. 'deadbeef')]"
            try:
                key_bytes = bytes.fromhex(key)
            except ValueError:
                # Treat key as raw string
                key_bytes = key.encode("utf-8")
            if not key_bytes:
                return "[EncodingTool] Error: XOR key cannot be empty."
            text_bytes = text.encode("utf-8")
            result_bytes = bytes(
                b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes)
            )
            try:
                return result_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return f"[Binary result, hex]: {result_bytes.hex()}"

        elif operation == "octal_encode":
            return " ".join(f"\\{ord(c):03o}" for c in text)

        elif operation == "octal_decode":
            # Parse octal sequences like \101\102\103 or space-separated 101 102 103
            import re

            # Try \NNN format first
            octal_matches = re.findall(r"\\(\d{1,3})", text)
            if octal_matches:
                return "".join(chr(int(o, 8)) for o in octal_matches)
            # Try space-separated
            parts = text.split()
            chars = []
            for p in parts:
                p = p.strip().lstrip("\\")
                if p:
                    try:
                        chars.append(chr(int(p, 8)))
                    except ValueError:
                        chars.append(f"[invalid:{p}]")
            return "".join(chars)

        else:
            return f"[Operation '{operation}' not implemented]"

    def _rot13(self, text: str) -> str:
        """Apply ROT13 cipher."""
        result = []
        for char in text:
            if "a" <= char <= "z":
                result.append(chr((ord(char) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= char <= "Z":
                result.append(chr((ord(char) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(char)
        return "".join(result)

    def _jwt_decode(self, token: str) -> str:
        """
        Decode a JWT token without verification.
        Returns the header and payload as readable JSON.
        """
        parts = token.split(".")
        if len(parts) < 2:
            return f"[Invalid JWT format - expected at least 2 parts, got {len(parts)}]"

        def decode_part(part: str) -> str:
            # Add padding if needed
            padded = part + "=" * (4 - len(part) % 4) if len(part) % 4 != 0 else part
            # JWT uses URL-safe base64
            try:
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
                # Try to pretty-print as JSON
                try:
                    parsed = json.loads(decoded)
                    return json.dumps(parsed, indent=2)
                except json.JSONDecodeError:
                    return decoded
            except Exception as e:
                return f"[Decode error: {e}]"

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        result = f"=== JWT HEADER ===\n{header}\n\n=== JWT PAYLOAD ===\n{payload}"

        if len(parts) >= 3:
            sig = parts[2]
            result += f"\n\n=== SIGNATURE ===\n[Present, {len(sig)} chars]"
            if not sig or sig in ["", "."]:
                result += (
                    "\n[WARNING: Empty signature - possible alg:none vulnerability!]"
                )

        return result


class HashIdentifierTool:
    """
    HashIdentifierTool: identify the type of a hash based on its format.

    This tool does NOT crack hashes - it only identifies the likely algorithm.
    """

    name: str = "hash_identifier"
    description: str = (
        "Identify the likely hash algorithm based on hash format. Input must be JSON with "
        "'hash' (the hash string to identify). Returns possible hash types. Does NOT crack "
        "hashes - only identifies the algorithm. Use this to understand what type of hash "
        "you're dealing with."
    )

    # Hash patterns: (length, regex_pattern, possible_types)
    HASH_PATTERNS = [
        (32, "^[a-fA-F0-9]{32}$", ["MD5", "NTLM", "MD4"]),
        (40, "^[a-fA-F0-9]{40}$", ["SHA-1", "MySQL5.x"]),
        (64, "^[a-fA-F0-9]{64}$", ["SHA-256", "SHA3-256"]),
        (96, "^[a-fA-F0-9]{96}$", ["SHA-384", "SHA3-384"]),
        (128, "^[a-fA-F0-9]{128}$", ["SHA-512", "SHA3-512", "Whirlpool"]),
        (60, r"^\$2[ayb]\$.{56}$", ["bcrypt"]),
        (34, r"^\$1\$.{31}$", ["MD5crypt"]),
        (34, r"^\$5\$.{43,}$", ["SHA-256crypt"]),
        (34, r"^\$6\$.{86,}$", ["SHA-512crypt"]),
    ]

    def use(self, tool_input: str) -> str:
        import re

        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[HashIdentifierTool] Error: tool_input must be JSON: {exc}"

        hash_value = data.get("hash", "").strip()
        if not hash_value:
            return "[HashIdentifierTool] Error: 'hash' is required."

        matches = []
        hash_len = len(hash_value)

        for expected_len, pattern, types in self.HASH_PATTERNS:
            if re.match(pattern, hash_value):
                matches.extend(types)

        # Check for special formats
        if hash_value.startswith("$"):
            if hash_value.startswith("$2"):
                matches.append("bcrypt (confirmed)")
            elif hash_value.startswith("$1$"):
                matches.append("MD5crypt (confirmed)")
            elif hash_value.startswith("$5$"):
                matches.append("SHA-256crypt (confirmed)")
            elif hash_value.startswith("$6$"):
                matches.append("SHA-512crypt (confirmed)")
            elif hash_value.startswith("$argon2"):
                matches.append("Argon2 (confirmed)")

        if not matches:
            return (
                f"[HashIdentifierTool] Unknown hash format\n"
                f"Hash: {hash_value}\n"
                f"Length: {hash_len} characters\n"
                f"Could not determine hash type."
            )

        unique_matches = list(dict.fromkeys(matches))  # Preserve order, remove dupes
        return (
            f"[HashIdentifierTool] Hash Analysis\n"
            f"Hash: {hash_value}\n"
            f"Length: {hash_len} characters\n"
            f"Possible types: {', '.join(unique_matches)}"
        )
