"""
Encoding and decoding tools for CTF solving.

Provides utilities for common encoding schemes encountered in CTF challenges.
"""

import base64
import binascii
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

    name: str = "encoding_tool"
    description: str = (
        "Encode or decode text using various schemes. Input must be JSON with keys: "
        "'text' (string to process) and 'operation' (one of: base64_encode, base64_decode, "
        "url_encode, url_decode, hex_encode, hex_decode, html_entity_encode, html_entity_decode, "
        "rot13, binary_to_ascii, ascii_to_binary, jwt_decode, unicode_normalize, reverse_string). "
        "Use this tool to decode cookies, parameters, obfuscated strings, or encode payloads."
    )

    # Valid operations
    OPERATIONS = {
        "base64_encode",
        "base64_decode",
        "url_encode",
        "url_decode",
        "hex_encode",
        "hex_decode",
        "html_entity_encode",
        "html_entity_decode",
        "rot13",
        "binary_to_ascii",
        "ascii_to_binary",
        "jwt_decode",
        "unicode_normalize",
        "reverse_string",
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
            result = self._perform_operation(text, operation)
            return f"[EncodingTool] Operation: {operation}\nInput: {text[:100]}{'...' if len(text) > 100 else ''}\nResult: {result}"
        except Exception as exc:
            return f"[EncodingTool] Error performing '{operation}': {exc}"

    def _perform_operation(self, text: str, operation: str) -> str:
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

        elif operation == "url_encode":
            return urllib.parse.quote(text, safe="")

        elif operation == "url_decode":
            return urllib.parse.unquote(text)

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

        elif operation == "reverse_string":
            return text[::-1]

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
                result += "\n[WARNING: Empty signature - possible alg:none vulnerability!]"

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
