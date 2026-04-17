"""
Tests for cryptographic attack tools.
"""

import base64
import json
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.crypto_tools import (
    CryptoProbeTool,
    CryptoAnalyzerTool,
    CryptoPayloadGenerator,
)

# ---------------------------------------------------------------------------
# CryptoProbeTool tests
# ---------------------------------------------------------------------------


class TestCryptoProbeTool:
    """Tests for CryptoProbeTool."""

    def setup_method(self):
        self.mock_session = MagicMock()
        self.tool = CryptoProbeTool(session=self.mock_session)

    def test_missing_url(self):
        """Test that url is required."""
        result = self.tool.use(
            json.dumps({"param": "token", "crypto_type": "ecb_detect"})
        )
        assert "[CryptoProbeTool] Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that param is required."""
        result = self.tool.use(
            json.dumps({"url": "http://test.com", "crypto_type": "ecb_detect"})
        )
        assert "[CryptoProbeTool] Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON."""
        result = self.tool.use("not valid json{{{")
        assert "[CryptoProbeTool] Error" in result
        assert "JSON" in result

    def test_missing_crypto_type(self):
        """Test that crypto_type is required."""
        result = self.tool.use(json.dumps({"url": "http://test.com", "param": "token"}))
        assert "[CryptoProbeTool] Error" in result
        assert "crypto_type" in result.lower()

    def test_invalid_crypto_type(self):
        """Test handling of unknown crypto_type."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "param": "token",
                    "crypto_type": "nonexistent_type",
                }
            )
        )
        assert "[CryptoProbeTool] Error" in result
        assert "Unknown crypto_type" in result

    def test_padding_oracle_detected(self):
        """Test padding oracle detection with 2 distinct response patterns."""
        # Create a 32-byte (2-block) ciphertext in hex
        ciphertext = ("aa" * 16) + ("bb" * 16)

        call_count = {"n": 0}

        def mock_get(url, **kwargs):
            resp = MagicMock()
            params = kwargs.get("params", {})
            token_val = params.get("token", "")
            call_count["n"] += 1

            # Simulate baseline request
            if token_val == "BASELINE_TEST_VALUE":
                resp.status_code = 200
                resp.text = "OK"
                return resp

            # For padding oracle: most byte values return 500 (bad padding),
            # but a few return 200 (valid padding) -> 2 groups
            try:
                ct_bytes = bytes.fromhex(token_val)
                # The modified byte is at position 15 (last byte of first block)
                modified_byte = ct_bytes[15]
                # Only one value produces valid padding
                if modified_byte == 0x42:
                    resp.status_code = 200
                    resp.text = "OK - valid padding"
                else:
                    resp.status_code = 500
                    resp.text = "Error - invalid padding"
            except Exception:
                resp.status_code = 200
                resp.text = "OK"

            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/decrypt",
                    "param": "token",
                    "crypto_type": "padding_oracle",
                    "ciphertext": ciphertext,
                    "block_size": 16,
                }
            )
        )

        assert "PADDING ORACLE DETECTED" in result
        assert "2" in result  # 2 response groups

    def test_padding_oracle_not_detected(self):
        """Test padding oracle not detected when all responses are the same."""
        ciphertext = ("aa" * 16) + ("bb" * 16)

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "Always the same response"
            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/decrypt",
                    "param": "token",
                    "crypto_type": "padding_oracle",
                    "ciphertext": ciphertext,
                    "block_size": 16,
                }
            )
        )

        assert (
            "No padding oracle detected" in result
            or "Response groups found: 1" in result
        )

    def test_ecb_detect_repeated_blocks(self):
        """Test ECB detection when response contains repeated ciphertext blocks."""
        repeated_block = "aa" * 16
        response_ct = repeated_block * 4  # 4 identical blocks

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            params = kwargs.get("params", {})
            if params.get("token") == "BASELINE_TEST_VALUE":
                resp.text = "baseline"
            else:
                resp.text = response_ct
            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/encrypt",
                    "param": "token",
                    "crypto_type": "ecb_detect",
                    "block_size": 16,
                }
            )
        )

        assert "ECB MODE DETECTED" in result

    def test_ecb_detect_no_repetition(self):
        """Test ECB detection when no repeated blocks are found."""
        # All different blocks
        block1 = "aa" * 16
        block2 = "bb" * 16
        block3 = "cc" * 16
        block4 = "dd" * 16
        response_ct = block1 + block2 + block3 + block4

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            params = kwargs.get("params", {})
            if params.get("token") == "BASELINE_TEST_VALUE":
                resp.text = "baseline"
            else:
                resp.text = response_ct
            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/encrypt",
                    "param": "token",
                    "crypto_type": "ecb_detect",
                    "block_size": 16,
                }
            )
        )

        assert "No repeated blocks" in result or "ECB MODE DETECTED" not in result

    def test_token_analysis_sequential(self):
        """Test token analysis detects sequential/incrementing tokens."""
        counter = {"val": 1000}

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            counter["val"] += 1
            # Return a simple incrementing token in a JSON-like body
            resp.text = f'{{"token": "{counter["val"]}"}}'
            resp.cookies = MagicMock()
            resp.cookies.__iter__ = MagicMock(return_value=iter([]))
            resp.headers = {}
            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/login",
                    "param": "token",
                    "crypto_type": "token_analysis",
                    "num_samples": 5,
                }
            )
        )

        assert "Token Analysis" in result
        assert (
            "Sequential" in result or "sequential" in result or "incrementing" in result
        )

    def test_token_analysis_random(self):
        """Test token analysis with random-looking tokens."""
        import hashlib

        counter = {"val": 0}

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            counter["val"] += 1
            # Return a random-looking hash token
            token = hashlib.sha256(
                f"random_seed_{counter['val']}_{id(resp)}".encode()
            ).hexdigest()
            resp.text = f'{{"token": "{token}"}}'
            resp.cookies = MagicMock()
            resp.cookies.__iter__ = MagicMock(return_value=iter([]))
            resp.headers = {}
            return resp

        self.mock_session.get.side_effect = mock_get

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/login",
                    "param": "token",
                    "crypto_type": "token_analysis",
                    "num_samples": 5,
                }
            )
        )

        assert "Token Analysis" in result
        # Should not report sequential patterns for hash-based tokens
        assert "Sequential pattern detected" not in result

    def test_baseline_failure(self):
        """Test handling when baseline request fails."""
        self.mock_session.get.side_effect = Exception("Connection refused")

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/decrypt",
                    "param": "token",
                    "crypto_type": "padding_oracle",
                    "ciphertext": "aa" * 32,
                }
            )
        )

        assert "Error" in result


# ---------------------------------------------------------------------------
# CryptoAnalyzerTool tests
# ---------------------------------------------------------------------------


class TestCryptoAnalyzerTool:
    """Tests for CryptoAnalyzerTool."""

    def setup_method(self):
        self.tool = CryptoAnalyzerTool()

    def test_missing_operation(self):
        """Test that operation is required."""
        result = self.tool.use(json.dumps({"text": "hello"}))
        assert "[CryptoAnalyzerTool] Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of unknown operation."""
        result = self.tool.use(json.dumps({"operation": "nonexistent"}))
        assert "[CryptoAnalyzerTool] Error" in result
        assert "Unknown operation" in result

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("this is not json!!!")
        assert "[CryptoAnalyzerTool] Error" in result
        assert "JSON" in result

    def test_identify_base64(self):
        """Test identification of base64-encoded text."""
        # "Hello World" in base64
        text = base64.b64encode(b"Hello World").decode("ascii")
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "identify_encoding",
                    "text": text,
                }
            )
        )

        assert "base64" in result.lower()
        assert "Hello World" in result

    def test_identify_hex(self):
        """Test identification of hex-encoded text."""
        text = "48656c6c6f"  # "Hello" in hex
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "identify_encoding",
                    "text": text,
                }
            )
        )

        assert "hex" in result.lower()

    def test_identify_base32(self):
        """Test identification of base32-encoded text."""
        text = base64.b32encode(b"Hello World").decode("ascii")
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "identify_encoding",
                    "text": text,
                }
            )
        )

        assert "base32" in result.lower()

    def test_detect_ecb_mode(self):
        """Test ECB mode detection with repeated hex blocks."""
        # Create ciphertext with repeated blocks
        block = "aa" * 16
        ciphertext = block * 4  # 4 identical blocks

        result = self.tool.use(
            json.dumps(
                {
                    "operation": "detect_cipher_mode",
                    "ciphertext": ciphertext,
                }
            )
        )

        assert "ECB" in result
        assert "REPEATED" in result or "repeated" in result.lower()

    def test_detect_non_ecb(self):
        """Test cipher mode detection with no repeated blocks."""
        # All different blocks
        ciphertext = "".join(f"{i:02x}" * 16 for i in range(4))

        result = self.tool.use(
            json.dumps(
                {
                    "operation": "detect_cipher_mode",
                    "ciphertext": ciphertext,
                }
            )
        )

        assert "No ECB indicators" in result or "No repeated blocks" in result

    def test_xor_single_byte(self):
        """Test single-byte XOR analysis recovers correct key."""
        # Encrypt "Hello World test message" with key 0x42
        plaintext = b"Hello World test message"
        key_byte = 0x42
        ciphertext = bytes([b ^ key_byte for b in plaintext])

        result = self.tool.use(
            json.dumps(
                {
                    "operation": "xor_analysis",
                    "ciphertext": ciphertext.hex(),
                }
            )
        )

        # The correct key (0x42 = 66) should be in top candidates
        assert "0x42" in result or "66" in result
        assert "Hello World" in result

    def test_frequency_analysis_english(self):
        """Test frequency analysis on English text."""
        english_text = (
            "the quick brown fox jumps over the lazy dog and the cat sat on the mat "
            "while the rain in spain falls mainly on the plain"
        )
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "frequency_analysis",
                    "text": english_text,
                }
            )
        )

        assert "Frequency Analysis" in result
        assert "chi-squared" in result.lower() or "Chi-squared" in result

    def test_analyze_weak_key(self):
        """Test key analysis detects weak all-zero key."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze_key",
                    "key": "\x00" * 16,
                }
            )
        )

        assert "all zeros" in result.lower() or "CRITICAL" in result

    def test_analyze_strong_key(self):
        """Test key analysis on a reasonably strong key."""
        # 32-byte key with good variety
        strong_key = "aK9#mP2$xL5@nQ8&bR4!wJ7*yF3^hD6"
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze_key",
                    "key": strong_key,
                }
            )
        )

        # Strong key may still have "ASCII-only" noted; verify no critical weaknesses
        assert "Key Analysis" in result
        assert "all zeros" not in result.lower()
        assert "sequential" not in result.lower()


# ---------------------------------------------------------------------------
# CryptoPayloadGenerator tests
# ---------------------------------------------------------------------------


class TestCryptoPayloadGenerator:
    """Tests for CryptoPayloadGenerator."""

    def setup_method(self):
        self.tool = CryptoPayloadGenerator()

    def test_missing_operation(self):
        """Test that operation is required."""
        result = self.tool.use(json.dumps({}))
        assert "[CryptoPayloadGenerator] Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of unknown operation."""
        result = self.tool.use(json.dumps({"operation": "nonexistent_attack"}))
        assert "[CryptoPayloadGenerator] Error" in result
        assert "Unknown operation" in result

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("{bad json")
        assert "[CryptoPayloadGenerator] Error" in result
        assert "JSON" in result

    def test_padding_oracle_methodology(self):
        """Test padding oracle methodology generation."""
        result = self.tool.use(json.dumps({"operation": "padding_oracle"}))

        assert "Padding Oracle" in result
        assert "CBC" in result or "cbc" in result.lower()
        assert "intermediate" in result.lower()
        assert "XOR" in result or "xor" in result.lower()
        assert "def " in result  # Contains pseudocode

    def test_ecb_attack_methodology(self):
        """Test ECB attack methodology generation."""
        result = self.tool.use(json.dumps({"operation": "ecb_attack"}))

        assert "ECB" in result
        assert "cut-and-paste" in result.lower() or "block" in result.lower()
        assert "boundary" in result.lower() or "alignment" in result.lower()
        assert "def " in result  # Contains pseudocode

    def test_bit_flip_methodology(self):
        """Test CBC bit-flipping methodology generation."""
        result = self.tool.use(json.dumps({"operation": "bit_flip"}))

        assert (
            "Bit-Flip" in result
            or "bit_flip" in result.lower()
            or "bit flip" in result.lower()
        )
        assert "CBC" in result or "cbc" in result.lower()
        assert "XOR" in result or "xor" in result.lower()
        assert "C[i-1]" in result or "ciphertext" in result.lower()

    def test_hash_extension_methodology(self):
        """Test hash length extension methodology generation."""
        result = self.tool.use(json.dumps({"operation": "hash_extension"}))

        assert "Hash" in result or "hash" in result.lower()
        assert "extension" in result.lower()
        assert "MD5" in result or "SHA" in result
        assert "HashPump" in result or "hashpump" in result.lower()

    def test_all_operations_return_content(self):
        """Test that all operations return non-trivial content."""
        for operation in ["padding_oracle", "ecb_attack", "bit_flip", "hash_extension"]:
            result = self.tool.use(json.dumps({"operation": operation}))

            # Each methodology should return substantial content
            assert (
                len(result) > 200
            ), f"Operation '{operation}' returned too little content ({len(result)} chars)"
            assert (
                "Error" not in result
            ), f"Operation '{operation}' returned an error: {result[:100]}"
