"""
Tests for encoding_tools.py
"""

import json
import pytest
from ctf_solver.tools.encoding_tools import EncodingTool, HashIdentifierTool


class TestEncodingTool:
    """Tests for the EncodingTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = EncodingTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_text(self):
        """Test handling of missing text parameter."""
        result = self.tool.use(json.dumps({"operation": "base64_encode"}))
        assert "Error" in result
        assert "'text'" in result

    def test_missing_operation(self):
        """Test handling of missing operation parameter."""
        result = self.tool.use(json.dumps({"text": "hello"}))
        assert "Error" in result
        assert "'operation'" in result

    def test_invalid_operation(self):
        """Test handling of invalid operation."""
        result = self.tool.use(json.dumps({"text": "hello", "operation": "invalid_op"}))
        assert "Error" in result
        assert "Unknown operation" in result

    # === Base64 Tests ===

    def test_base64_encode(self):
        """Test base64 encoding."""
        result = self.tool.use(json.dumps({
            "text": "Hello, World!",
            "operation": "base64_encode"
        }))
        assert "SGVsbG8sIFdvcmxkIQ==" in result

    def test_base64_decode(self):
        """Test base64 decoding."""
        result = self.tool.use(json.dumps({
            "text": "SGVsbG8sIFdvcmxkIQ==",
            "operation": "base64_decode"
        }))
        assert "Hello, World!" in result

    def test_base64_decode_no_padding(self):
        """Test base64 decoding with missing padding."""
        # "Hello" without padding
        result = self.tool.use(json.dumps({
            "text": "SGVsbG8",
            "operation": "base64_decode"
        }))
        assert "Hello" in result

    def test_base64_decode_binary(self):
        """Test base64 decoding of binary data."""
        # Binary data that's not valid UTF-8
        import base64
        binary_b64 = base64.b64encode(bytes([0x00, 0x01, 0xFF, 0xFE])).decode()
        result = self.tool.use(json.dumps({
            "text": binary_b64,
            "operation": "base64_decode"
        }))
        assert "Binary data" in result or "hex" in result.lower()

    # === URL Encoding Tests ===

    def test_url_encode(self):
        """Test URL encoding."""
        result = self.tool.use(json.dumps({
            "text": "Hello World!",
            "operation": "url_encode"
        }))
        assert "Hello%20World%21" in result

    def test_url_decode(self):
        """Test URL decoding."""
        result = self.tool.use(json.dumps({
            "text": "Hello%20World%21",
            "operation": "url_decode"
        }))
        assert "Hello World!" in result

    def test_url_encode_special_chars(self):
        """Test URL encoding of special characters."""
        result = self.tool.use(json.dumps({
            "text": "<script>alert('xss')</script>",
            "operation": "url_encode"
        }))
        assert "%3C" in result  # <
        assert "%3E" in result  # >
        assert "%27" in result  # '

    # === Hex Encoding Tests ===

    def test_hex_encode(self):
        """Test hex encoding."""
        result = self.tool.use(json.dumps({
            "text": "Hello",
            "operation": "hex_encode"
        }))
        assert "48656c6c6f" in result

    def test_hex_decode(self):
        """Test hex decoding."""
        result = self.tool.use(json.dumps({
            "text": "48656c6c6f",
            "operation": "hex_decode"
        }))
        assert "Hello" in result

    def test_hex_decode_with_prefix(self):
        """Test hex decoding with 0x prefix."""
        result = self.tool.use(json.dumps({
            "text": "0x48656c6c6f",
            "operation": "hex_decode"
        }))
        assert "Hello" in result

    def test_hex_decode_with_spaces(self):
        """Test hex decoding with spaces."""
        result = self.tool.use(json.dumps({
            "text": "48 65 6c 6c 6f",
            "operation": "hex_decode"
        }))
        assert "Hello" in result

    # === HTML Entity Tests ===

    def test_html_entity_encode(self):
        """Test HTML entity encoding."""
        result = self.tool.use(json.dumps({
            "text": "<script>alert('xss')</script>",
            "operation": "html_entity_encode"
        }))
        assert "&lt;" in result
        assert "&gt;" in result

    def test_html_entity_decode(self):
        """Test HTML entity decoding."""
        result = self.tool.use(json.dumps({
            "text": "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
            "operation": "html_entity_decode"
        }))
        assert "<script>" in result

    # === ROT13 Tests ===

    def test_rot13(self):
        """Test ROT13 encoding."""
        result = self.tool.use(json.dumps({
            "text": "Hello",
            "operation": "rot13"
        }))
        assert "Uryyb" in result

    def test_rot13_roundtrip(self):
        """Test ROT13 is its own inverse."""
        original = "The quick brown fox"
        result1 = self.tool.use(json.dumps({
            "text": original,
            "operation": "rot13"
        }))
        # Extract the result
        encoded = result1.split("Result: ")[1].strip()
        result2 = self.tool.use(json.dumps({
            "text": encoded,
            "operation": "rot13"
        }))
        assert original in result2

    # === Binary/ASCII Tests ===

    def test_ascii_to_binary(self):
        """Test ASCII to binary conversion."""
        result = self.tool.use(json.dumps({
            "text": "Hi",
            "operation": "ascii_to_binary"
        }))
        assert "01001000" in result  # H
        assert "01101001" in result  # i

    def test_binary_to_ascii(self):
        """Test binary to ASCII conversion."""
        result = self.tool.use(json.dumps({
            "text": "01001000 01101001",
            "operation": "binary_to_ascii"
        }))
        assert "Hi" in result

    # === JWT Tests ===

    def test_jwt_decode_valid(self):
        """Test JWT decoding with a valid token."""
        # A sample JWT (HS256, payload: {"sub": "1234567890", "name": "John Doe", "iat": 1516239022})
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = self.tool.use(json.dumps({
            "text": token,
            "operation": "jwt_decode"
        }))
        assert "JWT HEADER" in result
        assert "JWT PAYLOAD" in result
        assert "HS256" in result
        assert "John Doe" in result
        assert "1234567890" in result

    def test_jwt_decode_alg_none(self):
        """Test JWT decoding with alg:none (should flag as potential vulnerability)."""
        # JWT with alg:none and empty signature
        token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0."
        result = self.tool.use(json.dumps({
            "text": token,
            "operation": "jwt_decode"
        }))
        assert "none" in result.lower()
        assert "admin" in result

    def test_jwt_decode_invalid(self):
        """Test JWT decoding with invalid token."""
        result = self.tool.use(json.dumps({
            "text": "not.a.valid.jwt",
            "operation": "jwt_decode"
        }))
        # Should still attempt to decode what it can
        assert "JWT" in result

    # === Unicode Normalize Tests ===

    def test_unicode_normalize(self):
        """Test Unicode normalization."""
        # Full-width characters should normalize to ASCII
        result = self.tool.use(json.dumps({
            "text": "ＨＥＬＬｏ",
            "operation": "unicode_normalize"
        }))
        assert "HELLo" in result

    # === Reverse String Tests ===

    def test_reverse_string(self):
        """Test string reversal."""
        result = self.tool.use(json.dumps({
            "text": "Hello World",
            "operation": "reverse_string"
        }))
        assert "dlroW olleH" in result


class TestEncodingToolNewOperations:
    """Tests for newly added EncodingTool operations (base32, double_url_encode,
    unicode_escape/unescape, xor, octal_encode/decode)."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = EncodingTool()

    # === Name Attribute Test ===

    def test_name_attribute_is_encoding(self):
        """Test that the tool name attribute is 'encoding'."""
        assert self.tool.name == "encoding"

    # === Base32 Encode Tests ===

    def test_base32_encode_simple(self):
        """Test base32 encoding of a simple string."""
        result = self.tool.use(json.dumps({
            "text": "Hello",
            "operation": "base32_encode"
        }))
        assert "JBSWY3DP" in result

    def test_base32_encode_with_padding(self):
        """Test base32 encoding produces correct padding."""
        result = self.tool.use(json.dumps({
            "text": "Hi",
            "operation": "base32_encode"
        }))
        # base64.b32encode(b"Hi") == b"JBUQ===="
        assert "JBUQ====" in result

    def test_base32_encode_empty_string(self):
        """Test base32 encoding of an empty string."""
        result = self.tool.use(json.dumps({
            "text": "",
            "operation": "base32_encode"
        }))
        assert "Result: " in result

    def test_base32_encode_result_format(self):
        """Test base32 encode output follows the expected format."""
        result = self.tool.use(json.dumps({
            "text": "test",
            "operation": "base32_encode"
        }))
        assert "[EncodingTool] Operation: base32_encode" in result
        assert "Input: test" in result
        assert "Result: " in result

    # === Base32 Decode Tests ===

    def test_base32_decode_simple(self):
        """Test base32 decoding of a simple string."""
        result = self.tool.use(json.dumps({
            "text": "JBSWY3DP",
            "operation": "base32_decode"
        }))
        assert "Hello" in result

    def test_base32_decode_with_padding(self):
        """Test base32 decoding with proper padding."""
        result = self.tool.use(json.dumps({
            "text": "JBUQ====",
            "operation": "base32_decode"
        }))
        assert "Hi" in result

    def test_base32_decode_missing_padding(self):
        """Test base32 decoding handles missing padding."""
        result = self.tool.use(json.dumps({
            "text": "JBSWY3DP",
            "operation": "base32_decode"
        }))
        assert "Hello" in result

    def test_base32_decode_auto_uppercase(self):
        """Test base32 decoding auto-uppercases lowercase input."""
        result = self.tool.use(json.dumps({
            "text": "jbswy3dp",
            "operation": "base32_decode"
        }))
        assert "Hello" in result

    def test_base32_decode_binary_returns_hex(self):
        """Test base32 decoding returns hex for binary (non-UTF-8) data."""
        import base64
        binary_data = bytes([0x00, 0x01, 0xFF, 0xFE])
        b32_encoded = base64.b32encode(binary_data).decode("ascii")
        result = self.tool.use(json.dumps({
            "text": b32_encoded,
            "operation": "base32_decode"
        }))
        assert "Binary data" in result or "hex" in result.lower()

    def test_base32_roundtrip(self):
        """Test base32 encode then decode roundtrip."""
        original = "CTF{base32_flag}"
        result1 = self.tool.use(json.dumps({
            "text": original,
            "operation": "base32_encode"
        }))
        encoded = result1.split("Result: ")[1].strip()
        result2 = self.tool.use(json.dumps({
            "text": encoded,
            "operation": "base32_decode"
        }))
        assert original in result2

    # === Double URL Encode Tests ===

    def test_double_url_encode_angle_bracket(self):
        """Test double URL encoding of '<' produces %253C."""
        result = self.tool.use(json.dumps({
            "text": "<",
            "operation": "double_url_encode"
        }))
        assert "%253C" in result

    def test_double_url_encode_space(self):
        """Test double URL encoding of space produces %2520."""
        result = self.tool.use(json.dumps({
            "text": " ",
            "operation": "double_url_encode"
        }))
        assert "%2520" in result

    def test_double_url_encode_xss_payload(self):
        """Test double URL encoding of an XSS payload."""
        result = self.tool.use(json.dumps({
            "text": "<script>alert(1)</script>",
            "operation": "double_url_encode"
        }))
        # < becomes %3C then %253C
        assert "%253C" in result
        # > becomes %3E then %253E
        assert "%253E" in result

    def test_double_url_encode_already_safe_chars(self):
        """Test double URL encoding of alphanumeric chars (they stay the same)."""
        result = self.tool.use(json.dumps({
            "text": "abc123",
            "operation": "double_url_encode"
        }))
        assert "abc123" in result

    def test_double_url_encode_result_format(self):
        """Test double URL encode output follows the expected format."""
        result = self.tool.use(json.dumps({
            "text": "test&value",
            "operation": "double_url_encode"
        }))
        assert "[EncodingTool] Operation: double_url_encode" in result

    # === Unicode Escape Tests ===

    def test_unicode_escape_non_ascii(self):
        """Test unicode_escape converts non-ASCII chars to \\uXXXX form."""
        result = self.tool.use(json.dumps({
            "text": "\u00e9",
            "operation": "unicode_escape"
        }))
        assert "\\u00e9" in result

    def test_unicode_escape_keeps_alphanums(self):
        """Test unicode_escape keeps alphanumeric characters as-is."""
        result = self.tool.use(json.dumps({
            "text": "abc123",
            "operation": "unicode_escape"
        }))
        assert "abc123" in result

    def test_unicode_escape_special_chars(self):
        """Test unicode_escape escapes punctuation and special chars."""
        result = self.tool.use(json.dumps({
            "text": "a<b>c",
            "operation": "unicode_escape"
        }))
        # < and > should be escaped, a b c should remain
        assert "a" in result
        assert "\\u003c" in result  # <
        assert "b" in result
        assert "\\u003e" in result  # >
        assert "c" in result

    def test_unicode_escape_emoji(self):
        """Test unicode_escape on an emoji character."""
        result = self.tool.use(json.dumps({
            "text": "\u2603",
            "operation": "unicode_escape"
        }))
        assert "\\u2603" in result

    # === Unicode Unescape Tests ===

    def test_unicode_unescape_basic(self):
        """Test unicode_unescape decodes \\uXXXX sequences."""
        result = self.tool.use(json.dumps({
            "text": "\\u0048\\u0065\\u006c\\u006c\\u006f",
            "operation": "unicode_unescape"
        }))
        assert "Hello" in result

    def test_unicode_unescape_non_ascii(self):
        """Test unicode_unescape decodes a non-ASCII escape sequence."""
        result = self.tool.use(json.dumps({
            "text": "caf\\u00e9",
            "operation": "unicode_unescape"
        }))
        assert "caf\u00e9" in result

    def test_unicode_escape_unescape_roundtrip(self):
        """Test unicode_escape then unicode_unescape roundtrip for non-ASCII."""
        original = "\u00e9\u00e8\u00ea"
        result1 = self.tool.use(json.dumps({
            "text": original,
            "operation": "unicode_escape"
        }))
        escaped = result1.split("Result: ")[1].strip()
        result2 = self.tool.use(json.dumps({
            "text": escaped,
            "operation": "unicode_unescape"
        }))
        assert original in result2

    # === XOR Tests ===

    def test_xor_basic(self):
        """Test XOR with a simple hex key."""
        # XOR 'A' (0x41) with key 0x20 -> 0x61 -> 'a'
        result = self.tool.use(json.dumps({
            "text": "A",
            "operation": "xor",
            "key": "20"
        }))
        assert "a" in result

    def test_xor_no_key_returns_error(self):
        """Test XOR without key returns an error message."""
        result = self.tool.use(json.dumps({
            "text": "hello",
            "operation": "xor"
        }))
        assert "key" in result.lower()

    def test_xor_repeating_key(self):
        """Test XOR with a repeating key."""
        # XOR "AB" (0x41,0x42) with key "ff" (0xff)
        # 0x41 ^ 0xff = 0xbe, 0x42 ^ 0xff = 0xbd -> non-UTF-8 -> hex output
        result = self.tool.use(json.dumps({
            "text": "AB",
            "operation": "xor",
            "key": "ff"
        }))
        assert "bebd" in result.lower()

    def test_xor_binary_result_returns_hex(self):
        """Test XOR producing non-UTF-8 binary returns hex representation."""
        result = self.tool.use(json.dumps({
            "text": "Hello",
            "operation": "xor",
            "key": "ff"
        }))
        assert "hex" in result.lower() or "Binary" in result

    def test_xor_with_multi_byte_key(self):
        """Test XOR with a multi-byte hex key (key cycles)."""
        # XOR "AAAA" with key "0102" -> 0x41^0x01=0x40, 0x41^0x02=0x43, repeat
        result = self.tool.use(json.dumps({
            "text": "AAAA",
            "operation": "xor",
            "key": "0102"
        }))
        assert "@C@C" in result

    def test_xor_roundtrip(self):
        """Test XOR is its own inverse with the same key."""
        original = "secret"
        key = "ab"
        result1 = self.tool.use(json.dumps({
            "text": original,
            "operation": "xor",
            "key": key
        }))
        xored = result1.split("Result: ")[1].strip()
        # If result was hex, we need to decode it differently
        # For this test, use a key that produces valid UTF-8
        # XOR "Hi" with key "01" -> 0x48^0x01=0x49='I', 0x69^0x01=0x68='h'
        result1 = self.tool.use(json.dumps({
            "text": "Hi",
            "operation": "xor",
            "key": "01"
        }))
        intermediate = result1.split("Result: ")[1].strip()
        result2 = self.tool.use(json.dumps({
            "text": intermediate,
            "operation": "xor",
            "key": "01"
        }))
        assert "Hi" in result2

    # === Octal Encode Tests ===

    def test_octal_encode_simple(self):
        """Test octal encoding of a simple string."""
        result = self.tool.use(json.dumps({
            "text": "A",
            "operation": "octal_encode"
        }))
        # ord('A') == 65 == 0o101 -> \101
        assert "\\101" in result

    def test_octal_encode_hello(self):
        """Test octal encoding of 'Hello'."""
        result = self.tool.use(json.dumps({
            "text": "Hello",
            "operation": "octal_encode"
        }))
        # H=110, e=145, l=154, l=154, o=157
        assert "\\110" in result
        assert "\\145" in result
        assert "\\154" in result
        assert "\\157" in result

    def test_octal_encode_space_separated(self):
        """Test octal encode values are space-separated."""
        result = self.tool.use(json.dumps({
            "text": "AB",
            "operation": "octal_encode"
        }))
        encoded = result.split("Result: ")[1].strip()
        assert " " in encoded

    def test_octal_encode_result_format(self):
        """Test octal encode output follows the expected format."""
        result = self.tool.use(json.dumps({
            "text": "X",
            "operation": "octal_encode"
        }))
        assert "[EncodingTool] Operation: octal_encode" in result

    # === Octal Decode Tests ===

    def test_octal_decode_backslash_format(self):
        """Test octal decoding of \\NNN format."""
        result = self.tool.use(json.dumps({
            "text": "\\110\\145\\154\\154\\157",
            "operation": "octal_decode"
        }))
        assert "Hello" in result

    def test_octal_decode_space_separated(self):
        """Test octal decoding of space-separated octal values."""
        result = self.tool.use(json.dumps({
            "text": "110 145 154 154 157",
            "operation": "octal_decode"
        }))
        assert "Hello" in result

    def test_octal_encode_decode_roundtrip(self):
        """Test octal encode then decode roundtrip."""
        original = "flag{octal}"
        result1 = self.tool.use(json.dumps({
            "text": original,
            "operation": "octal_encode"
        }))
        encoded = result1.split("Result: ")[1].strip()
        result2 = self.tool.use(json.dumps({
            "text": encoded,
            "operation": "octal_decode"
        }))
        assert original in result2

    def test_octal_decode_single_char(self):
        """Test octal decoding of a single octal value."""
        result = self.tool.use(json.dumps({
            "text": "\\101",
            "operation": "octal_decode"
        }))
        assert "A" in result


class TestHashIdentifierTool:
    """Tests for the HashIdentifierTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = HashIdentifierTool()

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result

    def test_missing_hash(self):
        """Test handling of missing hash parameter."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result

    def test_md5_hash(self):
        """Test MD5 hash identification."""
        # MD5 hash of "hello"
        result = self.tool.use(json.dumps({
            "hash": "5d41402abc4b2a76b9719d911017c592"
        }))
        assert "MD5" in result

    def test_sha1_hash(self):
        """Test SHA-1 hash identification."""
        # SHA-1 hash of "hello"
        result = self.tool.use(json.dumps({
            "hash": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        }))
        assert "SHA-1" in result

    def test_sha256_hash(self):
        """Test SHA-256 hash identification."""
        # SHA-256 hash of "hello"
        result = self.tool.use(json.dumps({
            "hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        }))
        assert "SHA-256" in result

    def test_sha512_hash(self):
        """Test SHA-512 hash identification."""
        # SHA-512 hash (128 hex chars)
        sha512 = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        result = self.tool.use(json.dumps({
            "hash": sha512
        }))
        assert "SHA-512" in result

    def test_bcrypt_hash(self):
        """Test bcrypt hash identification."""
        # bcrypt hash
        bcrypt_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.UjxQ8FPw1Rn9u9gJEa"
        result = self.tool.use(json.dumps({
            "hash": bcrypt_hash
        }))
        assert "bcrypt" in result.lower()

    def test_unknown_hash(self):
        """Test handling of unknown hash format."""
        result = self.tool.use(json.dumps({
            "hash": "this_is_not_a_valid_hash_format_12345"
        }))
        assert "Unknown" in result or "not determine" in result


class TestEncodingToolCTFScenarios:
    """Test CTF-specific scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = EncodingTool()

    def test_ctf_flag_in_base64(self):
        """Test extracting a flag from base64."""
        import base64
        flag = "picoCTF{b4s3_64_3nc0d1ng}"
        encoded = base64.b64encode(flag.encode()).decode()
        result = self.tool.use(json.dumps({
            "text": encoded,
            "operation": "base64_decode"
        }))
        assert "picoCTF" in result
        assert "b4s3_64_3nc0d1ng" in result

    def test_ctf_nested_encoding(self):
        """Test handling nested encodings (common in CTFs)."""
        # Start with flag, URL encode, then base64
        import base64
        import urllib.parse
        flag = "FLAG{nested}"
        url_encoded = urllib.parse.quote(flag)
        b64_encoded = base64.b64encode(url_encoded.encode()).decode()

        # First decode base64
        result1 = self.tool.use(json.dumps({
            "text": b64_encoded,
            "operation": "base64_decode"
        }))
        # Extract the intermediate result
        intermediate = result1.split("Result: ")[1].strip()

        # Then URL decode
        result2 = self.tool.use(json.dumps({
            "text": intermediate,
            "operation": "url_decode"
        }))
        assert "FLAG{nested}" in result2

    def test_jwt_admin_claim(self):
        """Test detecting admin claims in JWT (common CTF pattern)."""
        # JWT with role: "admin"
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"user":"guest","role":"admin","iat":1234567890}').decode().rstrip("=")
        token = f"{header}.{payload}.fake_signature"

        result = self.tool.use(json.dumps({
            "text": token,
            "operation": "jwt_decode"
        }))
        assert "admin" in result
        assert "guest" in result
