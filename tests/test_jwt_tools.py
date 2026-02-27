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


class TestJwtConfusionAttack:
    """Test RS256->HS256 algorithm confusion attack."""

    def test_confusion_missing_token_and_claims(self):
        """Test confusion attack requires token or claims."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "key": "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
        }))
        assert "Error" in result
        assert "token" in result.lower() or "claims" in result.lower()

    def test_confusion_missing_public_key_shows_locations(self):
        """Test confusion attack without public_key returns common key locations."""
        tool = JwtTool()
        # Create an RS256-looking token (just for parsing, signature is fake)
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakesig"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token
        }))

        assert "No public key" in result or "public key" in result.lower()
        assert "/.well-known/jwks.json" in result
        assert "/api" in result.lower() or "public-key" in result.lower()

    def test_confusion_creates_hs256_token(self):
        """Test confusion attack produces a token with HS256 header."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token,
            "key": public_key
        }))

        assert "Forged token" in result or "forged" in result.lower()
        assert "HS256" in result

        # Extract the forged token and verify header is HS256
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("eyJ") and "." in line:
                parts = line.split(".")
                assert len(parts) == 3
                padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                decoded_header = json.loads(base64.urlsafe_b64decode(padded))
                assert decoded_header["alg"] == "HS256"
                assert decoded_header["typ"] == "JWT"
                break
        else:
            pytest.fail("No forged JWT token found in output")

    def test_confusion_preserves_original_payload(self):
        """Test confusion attack preserves the original payload when no claims override."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "victim", "role": "user", "admin": False}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        public_key = "my-public-key-content"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token,
            "key": public_key
        }))

        # Extract forged token and verify payload
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("eyJ") and "." in line:
                parts = line.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded_payload = json.loads(base64.urlsafe_b64decode(padded))
                    assert decoded_payload["user"] == "victim"
                    assert decoded_payload["role"] == "user"
                    assert decoded_payload["admin"] is False
                    break
        else:
            pytest.fail("No forged JWT token found in output")

    def test_confusion_with_claims_override(self):
        """Test confusion attack overrides claims when provided."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "victim", "admin": False}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        public_key = "the-public-key"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token,
            "key": public_key,
            "claims": {"admin": True, "role": "admin"}
        }))

        # Extract forged token and verify claims were overridden
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("eyJ") and "." in line:
                parts = line.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded_payload = json.loads(base64.urlsafe_b64decode(padded))
                    assert decoded_payload["admin"] is True
                    assert decoded_payload["role"] == "admin"
                    # Original claim should still be present
                    assert decoded_payload["user"] == "victim"
                    break
        else:
            pytest.fail("No forged JWT token found in output")

    def test_confusion_signs_with_public_key(self):
        """Test that the forged token is signed using public_key as HMAC secret."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "admin"}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        public_key = "test-public-key-pem"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token,
            "key": public_key
        }))

        # Extract forged token
        forged_token = None
        for line in result.split("\n"):
            line = line.strip()
            if line.startswith("eyJ") and line.count(".") == 2:
                forged_token = line
                break

        assert forged_token is not None, "No forged JWT token found in output"

        # Manually compute expected signature
        parts = forged_token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(
            public_key.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        expected_sig_b64 = b64_url_encode(expected_sig)

        assert parts[2] == expected_sig_b64

    def test_confusion_with_claims_only_no_token(self):
        """Test confusion attack works with only claims (no token)."""
        tool = JwtTool()
        public_key = "my-rsa-public-key"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "claims": {"user": "admin", "admin": True},
            "key": public_key
        }))

        assert "eyJ" in result
        assert "Error" not in result or "Forged" in result

    def test_confusion_explains_attack(self):
        """Test confusion attack output includes explanation of the technique."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "test"}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakesig"

        result = tool.use(json.dumps({
            "operation": "confusion_rs256_hs256",
            "token": token,
            "key": "some-public-key"
        }))

        # Should explain the attack mechanism
        assert "RS256" in result or "asymmetric" in result.lower()
        assert "HS256" in result or "symmetric" in result.lower()
        assert "public key" in result.lower()


class TestJwtKidInjection:
    """Test kid header injection attack."""

    def test_kid_inject_missing_token_and_claims(self):
        """Test kid_inject requires token or claims."""
        tool = JwtTool()
        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "key": "secret"
        }))
        assert "Error" in result
        assert "token" in result.lower() or "claims" in result.lower()

    def test_kid_inject_generates_path_traversal_tokens(self):
        """Test kid_inject produces path traversal variants."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test", "admin": False}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        assert "../../../dev/null" in result
        assert "path_traversal" in result

    def test_kid_inject_generates_sqli_tokens(self):
        """Test kid_inject produces SQL injection variants."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        assert "UNION SELECT" in result
        assert "sqli" in result
        assert "OR '1'='1" in result

    def test_kid_inject_returns_multiple_tokens(self):
        """Test kid_inject returns multiple forged tokens."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        # Count JWT tokens in output (lines starting with eyJ or "Token: eyJ")
        jwt_lines = []
        for line in result.split("\n"):
            stripped = line.strip()
            if stripped.startswith("Token: eyJ"):
                jwt_str = stripped[len("Token: "):]
            elif stripped.startswith("eyJ"):
                jwt_str = stripped
            else:
                continue
            if jwt_str.count(".") == 2:
                jwt_lines.append(jwt_str)
        # Should have at least path traversal (3) + sqli (3) = 6 variants
        assert len(jwt_lines) >= 6

    def test_kid_inject_tokens_are_valid_jwts(self):
        """Test that each generated token is a properly formatted JWT."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        for line in result.split("\n"):
            line = line.strip()
            # Skip lines that just happen to mention a token inline
            if line.startswith("Token: eyJ"):
                jwt_str = line[len("Token: "):]
            elif line.startswith("eyJ") and line.count(".") == 2:
                jwt_str = line
            else:
                continue

            parts = jwt_str.split(".")
            assert len(parts) == 3, f"Token should have 3 parts: {jwt_str[:60]}"

            # Header should decode to valid JSON with alg and kid
            padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            decoded_header = json.loads(base64.urlsafe_b64decode(padded))
            assert "alg" in decoded_header
            assert "kid" in decoded_header

    def test_kid_inject_preserves_payload(self):
        """Test kid_inject preserves the original payload claims."""
        tool = JwtTool()
        original_payload = {"user": "victim", "role": "user", "admin": False}
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            original_payload
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        # Check that at least one forged token has the preserved payload
        found = False
        for line in result.split("\n"):
            line = line.strip()
            jwt_str = None
            if line.startswith("Token: eyJ"):
                jwt_str = line[len("Token: "):]
            elif line.startswith("eyJ") and line.count(".") == 2:
                jwt_str = line

            if jwt_str:
                parts = jwt_str.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(padded))
                    assert decoded.get("user") == "victim"
                    assert decoded.get("role") == "user"
                    assert decoded.get("admin") is False
                    found = True
                    break

        assert found, "Could not find a forged token with preserved payload"

    def test_kid_inject_all_tokens_use_hs256(self):
        """Test that all kid_inject variants use HS256 algorithm."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        for line in result.split("\n"):
            line = line.strip()
            jwt_str = None
            if line.startswith("Token: eyJ"):
                jwt_str = line[len("Token: "):]
            elif line.startswith("eyJ") and line.count(".") == 2:
                jwt_str = line

            if jwt_str:
                parts = jwt_str.split(".")
                padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                decoded_header = json.loads(base64.urlsafe_b64decode(padded))
                assert decoded_header["alg"] == "HS256", (
                    f"Expected HS256 but got {decoded_header['alg']}"
                )

    def test_kid_inject_dev_null_signed_with_empty_key(self):
        """Test that dev/null path traversal is signed with empty string key."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "anything"
        }))

        # Find the dev/null token and verify it's signed with empty key
        lines = result.split("\n")
        for i, line in enumerate(lines):
            if "../../../dev/null" in line:
                # Find the token line nearby
                for j in range(i, min(i + 5, len(lines))):
                    stripped = lines[j].strip()
                    jwt_str = None
                    if stripped.startswith("Token: eyJ"):
                        jwt_str = stripped[len("Token: "):]
                    elif stripped.startswith("eyJ") and stripped.count(".") == 2:
                        jwt_str = stripped

                    if jwt_str:
                        parts = jwt_str.split(".")
                        signing_input = f"{parts[0]}.{parts[1]}"
                        expected_sig = hmac.new(
                            b"", signing_input.encode(), hashlib.sha256
                        ).digest()
                        expected_sig_b64 = b64_url_encode(expected_sig)
                        assert parts[2] == expected_sig_b64, (
                            "dev/null token should be signed with empty string key"
                        )
                        return
        pytest.fail("Could not find dev/null path traversal token in output")

    def test_kid_inject_sqli_union_signed_with_secret(self):
        """Test UNION SELECT 'secret' variant is signed with 'secret' key."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "anything"
        }))

        # Find the UNION SELECT 'secret' token
        lines = result.split("\n")
        for i, line in enumerate(lines):
            if "UNION SELECT 'secret'" in line:
                for j in range(i, min(i + 5, len(lines))):
                    stripped = lines[j].strip()
                    jwt_str = None
                    if stripped.startswith("Token: eyJ"):
                        jwt_str = stripped[len("Token: "):]
                    elif stripped.startswith("eyJ") and stripped.count(".") == 2:
                        jwt_str = stripped

                    if jwt_str:
                        parts = jwt_str.split(".")
                        signing_input = f"{parts[0]}.{parts[1]}"
                        expected_sig = hmac.new(
                            b"secret", signing_input.encode(), hashlib.sha256
                        ).digest()
                        expected_sig_b64 = b64_url_encode(expected_sig)
                        assert parts[2] == expected_sig_b64, (
                            "UNION SELECT 'secret' token should be signed with 'secret'"
                        )
                        return
        pytest.fail("Could not find UNION SELECT 'secret' token in output")

    def test_kid_inject_custom_kid_value(self):
        """Test kid_inject includes custom kid_value when provided."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        custom_kid = "/etc/passwd"

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret",
            "kid_value": custom_kid
        }))

        assert custom_kid in result
        assert "custom" in result.lower()

    def test_kid_inject_with_claims_override(self):
        """Test kid_inject applies claims overrides to all tokens."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test", "admin": False}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret",
            "claims": {"admin": True}
        }))

        # Extract any forged token and check that claims override was applied
        for line in result.split("\n"):
            line = line.strip()
            jwt_str = None
            if line.startswith("Token: eyJ"):
                jwt_str = line[len("Token: "):]
            elif line.startswith("eyJ") and line.count(".") == 2:
                jwt_str = line

            if jwt_str:
                parts = jwt_str.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(padded))
                    assert decoded.get("admin") is True, (
                        "Claims override should set admin to True"
                    )
                    break
        else:
            pytest.fail("No forged token found to verify claims override")

    def test_kid_inject_includes_descriptions(self):
        """Test kid_inject output includes descriptions for each attack variant."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        # Should have descriptive labels for path traversal and sqli
        assert "path_traversal" in result or "Path traversal" in result or "traversal" in result.lower()
        assert "sqli" in result or "SQL" in result or "injection" in result.lower()

    def test_kid_inject_includes_tips(self):
        """Test kid_inject output includes attack tips."""
        tool = JwtTool()
        token = create_test_jwt(
            {"alg": "HS256", "typ": "JWT", "kid": "key1"},
            {"user": "test"}
        )

        result = tool.use(json.dumps({
            "operation": "kid_inject",
            "token": token,
            "key": "secret"
        }))

        assert "Tips" in result or "TIP" in result or "tip" in result.lower()


class TestJwtAnalyzeNewRecommendations:
    """Test that _analyze() recommends the new operations."""

    def test_analyze_recommends_confusion_for_rs256(self):
        """Test analyze recommends confusion_rs256_hs256 when algorithm is RS256."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "test", "admin": False}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "confusion_rs256_hs256" in result
        assert "algorithm confusion" in result.lower() or "Algorithm confusion" in result

    def test_analyze_recommends_kid_inject_when_kid_present(self):
        """Test analyze recommends kid_inject when kid is in header."""
        tool = JwtTool()
        header = {"alg": "HS256", "typ": "JWT", "kid": "key-id-123"}
        payload = {"user": "test"}
        token = create_test_jwt(header, payload)

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "kid_inject" in result
        assert "kid" in result

    def test_analyze_recommends_both_for_rs256_with_kid(self):
        """Test analyze recommends both attacks when RS256 token has kid."""
        tool = JwtTool()
        header = {"alg": "RS256", "typ": "JWT", "kid": "server-key-1"}
        payload = {"user": "test"}
        header_b64 = b64_url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64_url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{header_b64}.{payload_b64}.fakersasig"

        result = tool.use(json.dumps({"operation": "analyze", "token": token}))

        assert "confusion_rs256_hs256" in result
        assert "kid_inject" in result
