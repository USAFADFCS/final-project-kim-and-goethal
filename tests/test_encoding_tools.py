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
