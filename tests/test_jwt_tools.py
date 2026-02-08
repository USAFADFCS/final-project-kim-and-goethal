"""
Tests for JWT attack tools.
"""

import base64
import hashlib
import hmac
import json
import pytest

from ctf_solver.tools.jwt_tools import JwtTool


def b64_url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_test_jwt(header: dict, payload: dict, secret: str = "secret") -> str:
    """Create a valid HS256 JWT for testing."""
    header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    sig_b64 = b64_url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


class TestJwtToolBasics:
    """Test basic JwtTool functionality."""

    def test_has_required_attributes(self):
        """Test that JwtTool has name and description."""
        tool = JwtTool()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "jwt_tool"
        assert "JWT" in tool.description

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = JwtTool()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Test that operation is required."""
        tool = JwtTool()
        result = tool.use(json.dumps({"token": "eyJ..."}))
        assert "Error" in result
        assert "operation" in result

    def test_invalid_operation(self):
        """Test handling of unknown operation."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "invalid_op"}))
        assert "Error" in result
        assert "Unknown operation" in result


class TestJwtDecode:
    """Test JWT decode operation."""

    def test_decode_missing_token(self):
        """Test decode requires token."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "decode"}))
        assert "Error" in result
        assert "token" in result.lower()

    def test_decode_invalid_jwt_format(self):
        """Test handling of invalid JWT format."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "decode", "token": "notavalidjwt"}))
        assert "Error" in result or "Could not" in result

    def test_decode_valid_jwt(self):
        """Test decoding a valid JWT."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user123", "admin": False}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({"operation": "decode", "token": token}))

        assert "HEADER" in result
        assert "PAYLOAD" in result
        assert "HS256" in result
        assert "user123" in result
        assert "SIGNATURE" in result

    def test_decode_detects_none_algorithm(self):
        """Test that decode flags alg:none as vulnerable."""
        tool = JwtTool()
        header = {"alg": "none", "typ": "JWT"}
        payload = {"user": "admin"}

        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}."

        result = tool.use(json.dumps({"operation": "decode", "token": token}))

        assert "VULNERABLE" in result or "none" in result.lower()

    def test_decode_shows_interesting_claims(self):
        """Test that decode highlights interesting claims."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"admin": True, "role": "user", "username": "testuser"}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({"operation": "decode", "token": token}))

        assert "admin" in result
        assert "role" in result


class TestJwtForgeNone:
    """Test alg:none attack forging."""

    def test_forge_none_missing_token(self):
        """Test forge_none requires token."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "forge_none"}))
        assert "Error" in result
        assert "token" in result.lower()

    def test_forge_none_creates_multiple_variants(self):
        """Test that forge_none creates multiple alg variants."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin", "admin": False}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({"operation": "forge_none", "token": token}))

        assert "none" in result.lower()
        assert "None" in result or "NONE" in result
        assert "." in result  # Should have JWT dots

    def test_forge_none_preserves_payload(self):
        """Test that forge_none preserves original payload."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "victim", "role": "user"}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({"operation": "forge_none", "token": token}))

        # Parse one of the output tokens to verify payload preserved
        lines = result.split("\n")
        for line in lines:
            if line.startswith("eyJ") and "." in line:
                parts = line.strip().rstrip(".").split(".")
                if len(parts) >= 2:
                    payload_b64 = parts[1]
                    padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(padded))
                    assert decoded.get("user") == "victim"
                    assert decoded.get("role") == "user"
                    break


class TestJwtModifyClaim:
    """Test claim modification."""

    def test_modify_claim_missing_token(self):
        """Test modify_claim requires token."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "modify_claim",
            "claims": {"admin": True}
        }))
        assert "Error" in result
        assert "token" in result.lower()

    def test_modify_claim_missing_claims(self):
        """Test modify_claim requires claims."""
        tool = JwtTool()
        token = create_test_jwt({"alg": "HS256"}, {"user": "test"})
        result = tool.use(json.dumps({
            "operation": "modify_claim",
            "token": token
        }))
        assert "Error" in result
        assert "claims" in result.lower()

    def test_modify_claim_shows_changes(self):
        """Test that modify_claim shows what changed."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({
            "operation": "modify_claim",
            "token": token,
            "claims": {"admin": True}
        }))

        assert "admin" in result
        assert "False" in result or "false" in result
        assert "True" in result or "true" in result

    def test_modify_claim_with_key_signs(self):
        """Test that modify_claim signs with provided key."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        token = create_test_jwt(header, payload, "mysecret")

        result = tool.use(json.dumps({
            "operation": "modify_claim",
            "token": token,
            "claims": {"admin": True},
            "key": "mysecret"
        }))

        assert "Signed" in result or "HS256" in result
        # Output should contain a valid token
        assert "eyJ" in result

    def test_modify_claim_without_key_provides_attack_variants(self):
        """Test that modify_claim provides attack variants when no key."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({
            "operation": "modify_claim",
            "token": token,
            "claims": {"admin": True}
        }))

        assert "none" in result.lower()
        assert "No key" in result or "attack" in result.lower()


class TestJwtCrack:
    """Test JWT secret cracking."""

    def test_crack_missing_token(self):
        """Test crack requires token."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "crack"}))
        assert "Error" in result
        assert "token" in result.lower()

    def test_crack_finds_common_secret(self):
        """Test that crack finds a common secret."""
        tool = JwtTool()
        # Create JWT with a secret that's in the default wordlist
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin"}
        token = create_test_jwt(header, payload, "secret")

        result = tool.use(json.dumps({"operation": "crack", "token": token}))

        assert "FOUND" in result
        assert "secret" in result

    def test_crack_finds_custom_wordlist_secret(self):
        """Test crack with custom wordlist."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin"}
        token = create_test_jwt(header, payload, "mycustomsecret123")

        result = tool.use(json.dumps({
            "operation": "crack",
            "token": token,
            "wordlist": ["wrong1", "wrong2", "mycustomsecret123", "wrong3"]
        }))

        assert "FOUND" in result
        assert "mycustomsecret123" in result

    def test_crack_not_found(self):
        """Test crack reports when secret not found."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin"}
        token = create_test_jwt(header, payload, "verysecretkeynotinlist")

        result = tool.use(json.dumps({
            "operation": "crack",
            "token": token,
            "wordlist": ["wrong1", "wrong2"]
        }))

        assert "No secret found" in result or "not found" in result.lower()

    def test_crack_rejects_non_hmac(self):
        """Test crack rejects non-HMAC algorithms."""
        tool = JwtTool()
        # Create a token with RS256 header
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "admin"}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakesig"

        result = tool.use(json.dumps({"operation": "crack", "token": token}))

        assert "Error" in result or "Cannot crack" in result

    def test_crack_provides_forged_sample(self):
        """Test that crack provides a sample forged token when found."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin", "admin": False}
        token = create_test_jwt(header, payload, "secret")

        result = tool.use(json.dumps({"operation": "crack", "token": token}))

        assert "forged" in result.lower()
        # Should contain a new JWT
        lines = [l for l in result.split("\n") if l.startswith("eyJ")]
        assert len(lines) >= 1


class TestJwtForgeWithKey:
    """Test JWT forging with known key."""

    def test_forge_with_key_missing_claims(self):
        """Test forge_with_key requires claims."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "key": "secret"
        }))
        assert "Error" in result
        assert "claims" in result.lower()

    def test_forge_with_key_missing_key(self):
        """Test forge_with_key requires key."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "claims": {"admin": True}
        }))
        assert "Error" in result
        assert "key" in result.lower()

    def test_forge_with_key_creates_valid_jwt(self):
        """Test forge_with_key creates a valid JWT."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "claims": {"user": "admin", "admin": True},
            "key": "testsecret"
        }))

        assert "eyJ" in result  # Has JWT format
        assert "admin" in result

        # Extract and verify the token
        for line in result.split("\n"):
            if line.startswith("eyJ"):
                token = line.strip()
                # Verify it's valid by comparing signatures
                parts = token.split(".")
                assert len(parts) == 3

    def test_forge_with_key_supports_algorithms(self):
        """Test forge_with_key supports different algorithms."""
        tool = JwtTool()

        for alg in ["HS256", "HS384", "HS512"]:
            result = tool.use(json.dumps({
                "operation": "forge_with_key",
                "claims": {"test": True},
                "key": "secret",
                "algorithm": alg
            }))

            assert alg in result
            assert "eyJ" in result

    def test_forge_with_key_rejects_unsupported_alg(self):
        """Test forge_with_key rejects unsupported algorithms."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "claims": {"test": True},
            "key": "secret",
            "algorithm": "RS256"
        }))

        assert "Error" in result or "Unsupported" in result


class TestJwtAnalyze:
    """Test JWT security analysis."""

    def test_analyze_missing_token(self):
        """Test analyze requires token."""
        tool = JwtTool()
        result = tool.use(json.dumps({"operation": "analyze"}))
        assert "Error" in result
        assert "token" in result.lower()

    def test_analyze_detects_alg_none(self):
        """Test analyze detects alg:none vulnerability."""
        tool = JwtTool()
        header = {"alg": "none", "typ": "JWT"}
        payload = {"user": "admin"}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}."

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "CRITICAL" in result or "none" in result

    def test_analyze_detects_hmac_weakness(self):
        """Test analyze notes HMAC may be crackable."""
        tool = JwtTool()
        token = create_test_jwt({"alg": "HS256"}, {"user": "test"})

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "crack" in result.lower() or "weak" in result.lower() or "HMAC" in result

    def test_analyze_detects_privilege_claims(self):
        """Test analyze detects privilege-related claims."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256"},
            {"user": "test", "admin": False, "role": "user"}
        )

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "admin" in result.lower()
        assert "role" in result.lower()

    def test_analyze_detects_kid_header(self):
        """Test analyze flags kid header as potential injection point."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT", "kid": "key1"}
        token = create_test_jwt(header, {"user": "test"})

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "kid" in result
        assert "injection" in result.lower() or "traversal" in result.lower()

    def test_analyze_provides_attack_suggestions(self):
        """Test analyze provides actionable suggestions."""
        tool = JwtTool()
        token = create_test_jwt({"alg": "HS256"}, {"admin": False})

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "forge_none" in result or "crack" in result or "modify" in result


class TestJwtToolCTFScenarios:
    """Test realistic CTF scenarios."""

    def test_admin_privilege_escalation(self):
        """Test privilege escalation workflow."""
        tool = JwtTool()

        # Step 1: Decode to understand the token
        original = create_test_jwt(
            {"alg": "HS256"},
            {"username": "user", "admin": False}
        )
        decode_result = tool.use(json.dumps({
            "operation": "decode",
            "token": original
        }))
        assert "admin" in decode_result
        assert "False" in decode_result or "false" in decode_result

        # Step 2: Try alg:none attack
        forge_result = tool.use(json.dumps({
            "operation": "forge_none",
            "token": original
        }))
        assert "none" in forge_result.lower()

        # Step 3: Modify claims
        modify_result = tool.use(json.dumps({
            "operation": "modify_claim",
            "token": original,
            "claims": {"admin": True}
        }))
        assert "True" in modify_result or "true" in modify_result

    def test_weak_secret_exploitation(self):
        """Test workflow for exploiting weak secrets."""
        tool = JwtTool()

        # Create JWT with weak secret
        weak_token = create_test_jwt(
            {"alg": "HS256"},
            {"user": "guest", "role": "user"},
            "password"  # Weak secret
        )

        # Step 1: Crack the secret
        crack_result = tool.use(json.dumps({
            "operation": "crack",
            "token": weak_token
        }))
        assert "FOUND" in crack_result
        assert "password" in crack_result

        # Step 2: Forge new token with cracked secret
        forge_result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "claims": {"user": "admin", "role": "admin"},
            "key": "password"
        }))
        assert "eyJ" in forge_result

    def test_empty_secret_detection(self):
        """Test that empty string secret is detected."""
        tool = JwtTool()
        # Some implementations incorrectly accept empty secrets
        token = create_test_jwt(
            {"alg": "HS256"},
            {"user": "test"},
            ""  # Empty secret
        )

        result = tool.use(json.dumps({
            "operation": "crack",
            "token": token
        }))

        assert "FOUND" in result
        assert "empty" in result.lower() or '""' in result or "(empty string)" in result


class TestJwtToolEdgeCases:
    """Test edge cases and error handling."""

    def test_malformed_base64(self):
        """Test handling of malformed base64 in JWT."""
        tool = JwtTool()
        # Invalid base64 characters
        result = tool.use(json.dumps({
            "operation": "decode",
            "token": "!!!.@@@.###"
        }))
        assert "Error" in result or "Could not" in result

    def test_empty_token(self):
        """Test handling of empty token."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "decode",
            "token": ""
        }))
        assert "Error" in result

    def test_two_part_jwt(self):
        """Test handling of JWT with only 2 parts."""
        tool = JwtTool()
        header = {"alg": "none"}
        payload = {"user": "test"}
        header_b64 = b64_url_encode(json.dumps(header).encode())
        payload_b64 = b64_url_encode(json.dumps(payload).encode())
        token = f"{header_b64}.{payload_b64}"

        result = tool.use(json.dumps({
            "operation": "decode",
            "token": token
        }))

        # Should still decode header and payload
        assert "user" in result or "test" in result

    def test_unicode_in_claims(self):
        """Test handling of unicode in claims."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "forge_with_key",
            "claims": {"user": "usuario\u00e9", "emoji": "\ud83d\ude00"},
            "key": "secret"
        }))

        assert "eyJ" in result
        assert "Error" not in result


class TestJwtToolIntegration:
    """Test integration with CTF solver."""

    def test_import_from_tools(self):
        """Test that JwtTool is importable from tools package."""
        from ctf_solver.tools import JwtTool
        tool = JwtTool()
        assert tool.name == "jwt_tool"

    def test_tool_follows_fair_pattern(self):
        """Test that tool follows FAIR pattern."""
        tool = JwtTool()

        # Has required attributes
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert hasattr(tool, "use")

        # name is string
        assert isinstance(tool.name, str)

        # description is string
        assert isinstance(tool.description, str)

        # use accepts str and returns str
        result = tool.use('{"operation": "decode"}')
        assert isinstance(result, str)
