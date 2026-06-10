"""
Tests for session forgery tools (FlaskSessionForgeryTool, DomClobberingPayloadGenerator).

Covers:
- FlaskSessionForgeryTool: decode, forge, brute_secret, analyze operations
  including error handling for missing/invalid params and real cookie workflows
- DomClobberingPayloadGenerator: overwrite_var (1/2/3-level), form_hijack,
  reference operations and error handling
"""

import json
import base64
import pytest

from ctf_solver.tools.session_forgery_tools import (
    FlaskSessionForgeryTool,
    DomClobberingPayloadGenerator,
)

# ==============================================================================
# Helpers
# ==============================================================================


def _make_test_cookie(payload_dict: dict) -> str:
    """Build a minimal Flask-like cookie: base64(json).timestamp.signature."""
    payload_json = json.dumps(payload_dict, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    # Fake timestamp and signature parts (not cryptographically valid)
    return f"{payload_b64}.AAAA.BBBB"


# ==============================================================================
# FlaskSessionForgeryTool Tests
# ==============================================================================


class TestFlaskSessionForgeryTool:
    """Tests for the FlaskSessionForgeryTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = FlaskSessionForgeryTool()

    # -- name / description --------------------------------------------------

    def test_tool_name(self):
        """Verify tool name is 'flask_session_forge'."""
        assert self.tool.name == "flask_session_forge"

    def test_tool_description_exists(self):
        """Verify description is a non-empty string."""
        assert isinstance(self.tool.description, str)
        assert len(self.tool.description) > 0

    # -- error handling ------------------------------------------------------

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"cookie": "abc"}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "decode" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in result
        assert "explode" in result
        assert "decode" in result

    def test_empty_input(self):
        """Empty string input should request an operation."""
        result = self.tool.use("")
        assert "Error" in result
        assert "operation" in result.lower()

    # -- decode operation ----------------------------------------------------

    def test_decode_missing_cookie(self):
        """decode without 'cookie' should return an error."""
        result = self.tool.use(json.dumps({"operation": "decode"}))
        assert "Error" in result
        assert "cookie" in result.lower()

    def test_decode_valid_cookie(self):
        """decode a well-formed base64 JSON cookie should show payload."""
        cookie = _make_test_cookie({"admin": False, "username": "guest"})
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "decode",
                    "cookie": cookie,
                }
            )
        )
        assert "Decoded Payload" in result
        assert '"admin"' in result
        assert '"guest"' in result

    def test_decode_shows_interesting_fields(self):
        """decode should highlight admin/role/user fields as interesting."""
        cookie = _make_test_cookie({"admin": False, "role": "user", "uid": 42})
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "decode",
                    "cookie": cookie,
                }
            )
        )
        assert "Interesting Fields" in result
        assert "admin" in result
        assert "role" in result
        assert "uid" in result

    def test_decode_invalid_base64(self):
        """decode with a garbage cookie that cannot be decoded."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "decode",
                    "cookie": "!!!garbage!!!.xxx.yyy",
                }
            )
        )
        assert "Failed to decode" in result or "not be a Flask" in result

    def test_decode_zlib_compressed_real_cookie(self):
        """Regression for memory/window_mode_failure_analysis.md gap G1.

        Flask compressed-session cookies start with a literal ``.`` to
        signal zlib compression.  Previously ``cookie.split('.')`` yielded
        ``parts[0] == ''`` and the decode silently returned None.  Cookie
        captured from the MetaCTF Super Quick Logic Invitational run
        (2026-05-17).
        """
        cookie = (
            ".eJxljs1KxDAURl8lZD0j-Wman40vIbgQKcntzUywndTkdiHiu1vdjOD2HL7D"
            "98mhtzxRfcMbDxw0WrQx2QTai0GOg41jBi9RCA9OpNmkYdZRK6uzAzVqsBmM"
            "BWGSsUryE4e9NbzRNJecC-wLffAw3PHWalpw5cHLf3CKRLhu1HkQd_m-Y6dS"
            "f-49XyOx0hldkS2xXQ7BtlZWZDkC1cZqZkp6-3j8uMQV_wRfXk-8Q2342-4U"
            "G010LI-qEmo8C3OW7kmYIFSQ6sE7Kd3Av74BxE5cSw"
            ".agqdVA.pUAd3K83TIXb8gxNA5MvoWbtBL0"
        )
        payload = self.tool._decode_payload(cookie)
        assert payload is not None, "compressed cookie should decode"
        # Sanity check on the actual fields that were inside this session
        assert payload["current_problem"] == 91
        assert payload["csrf_token"].startswith("c3e7e7ab")

    def test_decode_zlib_via_use_operation(self):
        """Same fix via the public ``use(...)`` entry point."""
        cookie = (
            ".eJxljs1KxDAURl8lZD0j-Wman40vIbgQKcntzUywndTkdiHiu1vdjOD2HL7D"
            "98mhtzxRfcMbDxw0WrQx2QTai0GOg41jBi9RCA9OpNmkYdZRK6uzAzVqsBmM"
            "BWGSsUryE4e9NbzRNJecC-wLffAw3PHWalpw5cHLf3CKRLhu1HkQd_m-Y6dS"
            "f-49XyOx0hldkS2xXQ7BtlZWZDkC1cZqZkp6-3j8uMQV_wRfXk-8Q2342-4U"
            "G010LI-qEmo8C3OW7kmYIFSQ6sE7Kd3Av74BxE5cSw"
            ".agqdVA.pUAd3K83TIXb8gxNA5MvoWbtBL0"
        )
        result = self.tool.use(json.dumps({"operation": "decode", "cookie": cookie}))
        assert "Failed to decode" not in result
        assert "current_problem" in result

    # -- forge operation -----------------------------------------------------

    def test_forge_missing_data(self):
        """forge without 'data' should return an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "forge",
                    "secret": "mysecret",
                }
            )
        )
        assert "Error" in result
        assert "data" in result.lower()

    def test_forge_missing_secret(self):
        """forge without 'secret' should return an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "forge",
                    "data": {"admin": True},
                }
            )
        )
        assert "Error" in result
        assert "secret" in result.lower()

    def test_forge_produces_cookie(self):
        """forge with valid data and secret should produce a signed cookie."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "forge",
                    "data": {"admin": True, "username": "admin"},
                    "secret": "s3cr3t",
                }
            )
        )
        assert "Forged Cookie" in result
        # The forged cookie should have 3 dot-separated parts
        lines = result.split("\n")
        cookie_line = None
        for i, line in enumerate(lines):
            if "Forged Cookie" in line:
                # The next non-empty line after the header should be the cookie
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() and not lines[j].startswith("="):
                        cookie_line = lines[j].strip()
                        break
                break
        assert cookie_line is not None
        assert cookie_line.count(".") >= 2

    def test_forge_shows_usage_instructions(self):
        """forge should include curl and cookie_set usage examples."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "forge",
                    "data": {"admin": True},
                    "secret": "test",
                }
            )
        )
        assert "curl" in result.lower()
        assert "cookie_set" in result

    # -- brute_secret operation -----------------------------------------------

    def test_brute_secret_missing_cookie(self):
        """brute_secret without 'cookie' should return an error."""
        result = self.tool.use(json.dumps({"operation": "brute_secret"}))
        assert "Error" in result
        assert "cookie" in result.lower()

    def test_brute_secret_finds_known_secret(self):
        """brute_secret should find 'secret' when the cookie was signed with it."""
        # Forge a cookie with a known common secret
        tool = FlaskSessionForgeryTool()
        forged = tool._sign_payload({"admin": False}, "secret")

        result = tool.use(
            json.dumps(
                {
                    "operation": "brute_secret",
                    "cookie": forged,
                }
            )
        )
        assert "SECRET FOUND" in result
        assert "'secret'" in result

    def test_brute_secret_no_match(self):
        """brute_secret should report failure when secret is not in wordlist."""
        # Use a secret not in COMMON_SECRETS
        tool = FlaskSessionForgeryTool()
        forged = tool._sign_payload({"x": 1}, "xK9$very_unusual_key_2026!")

        result = tool.use(
            json.dumps(
                {
                    "operation": "brute_secret",
                    "cookie": forged,
                }
            )
        )
        assert "No matching secret found" in result

    def test_brute_secret_custom_wordlist(self):
        """brute_secret with a custom wordlist should try those secrets first."""
        tool = FlaskSessionForgeryTool()
        forged = tool._sign_payload({"role": "guest"}, "my_unique_key_12345")

        result = tool.use(
            json.dumps(
                {
                    "operation": "brute_secret",
                    "cookie": forged,
                    "wordlist": ["wrong1", "wrong2", "my_unique_key_12345"],
                }
            )
        )
        assert "SECRET FOUND" in result
        assert "my_unique_key_12345" in result

    # -- analyze operation ---------------------------------------------------

    def test_analyze_missing_cookie(self):
        """analyze without 'cookie' should return an error."""
        result = self.tool.use(json.dumps({"operation": "analyze"}))
        assert "Error" in result
        assert "cookie" in result.lower()

    def test_analyze_with_admin_false(self):
        """analyze should suggest setting admin=True when admin is False."""
        cookie = _make_test_cookie({"admin": False, "username": "guest"})
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze",
                    "cookie": cookie,
                }
            )
        )
        assert "Attack Vectors" in result
        assert "admin" in result
        assert "True" in result or "true" in result

    def test_analyze_with_role_field(self):
        """analyze should suggest role escalation when role field is present."""
        cookie = _make_test_cookie({"role": "user"})
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze",
                    "cookie": cookie,
                }
            )
        )
        assert "role" in result
        assert "admin" in result.lower()

    def test_analyze_no_escalation_fields(self):
        """analyze with no obvious escalation fields reports that."""
        cookie = _make_test_cookie({"theme": "dark", "lang": "en"})
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze",
                    "cookie": cookie,
                }
            )
        )
        assert "No obvious privilege escalation" in result

    def test_analyze_invalid_cookie(self):
        """analyze with a non-decodable cookie should explain other formats."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "analyze",
                    "cookie": "completely_invalid",
                }
            )
        )
        assert "Could not decode" in result
        assert "Express" in result or "Django" in result or "JWT" in result


class TestFlaskWordlistExpansion:
    """Gap E1: COMMON_SECRETS had 112 entries — MetaCTF run #14 (Microdosing,
    2026-04-17) brute-forced a Flask cookie and couldn't crack the secret
    because the real key was in flask-unsign's bundled list but not ours."""

    def test_common_secrets_covers_at_least_400_entries(self):
        """The expanded list must include flask-unsign top-200 entries
        plus CTF-flavored and framework defaults. Exact count may grow
        over time; 400 is the minimum we commit to."""
        assert len(FlaskSessionForgeryTool.COMMON_SECRETS) >= 400

    def test_common_secrets_has_no_duplicates(self):
        seen = set()
        for s in FlaskSessionForgeryTool.COMMON_SECRETS:
            assert s not in seen, f"duplicate secret: {s!r}"
            seen.add(s)

    def test_common_secrets_includes_framework_defaults(self):
        """Sanity check: 'changeme-in-production' is in flask-unsign's
        default list and is a classic CTF target."""
        assert "changeme-in-production" in FlaskSessionForgeryTool.COMMON_SECRETS

    def test_brute_finds_expanded_list_secret(self):
        """A secret that was NOT in the original 112-entry list but IS
        in the expanded 400+ list should now be crackable."""
        tool = FlaskSessionForgeryTool()
        # Use a framework default that was added in Gap E.
        forged = tool._sign_payload({"admin": False}, "changeme-in-production")
        result = tool.use(
            json.dumps(
                {
                    "operation": "brute_secret",
                    "cookie": forged,
                }
            )
        )
        assert "SECRET FOUND" in result
        assert "changeme-in-production" in result


class TestFlaskDebugEndpointProbe:
    """Gap E2: new debug_endpoint_probe operation. MetaCTF run #14 had no
    way to check /console (Werkzeug), /debug, /_debug_toolbar — these
    exposed endpoints can leak the secret or allow direct RCE."""

    def test_operation_registered(self):
        assert "debug_endpoint_probe" in FlaskSessionForgeryTool.VALID_OPERATIONS

    def test_requires_url(self):
        tool = FlaskSessionForgeryTool()
        result = tool.use(json.dumps({"operation": "debug_endpoint_probe"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_reports_open_endpoints(self):
        """When a probe returns non-404, the tool reports the status
        and first body snippet so the agent can follow up."""
        import unittest.mock as _mock

        tool = FlaskSessionForgeryTool()

        def _fake_head(url, *args, **kwargs):
            resp = _mock.Mock()
            if "/console" in url:
                resp.status_code = 200
                resp.text = "Werkzeug Interactive Debugger console"
            else:
                resp.status_code = 404
                resp.text = "Not Found"
            return resp

        with _mock.patch(
            "ctf_solver.tools.session_forgery_tools.requests.head",
            side_effect=_fake_head,
        ):
            result = tool.use(
                json.dumps(
                    {
                        "operation": "debug_endpoint_probe",
                        "url": "http://target.example/",
                    }
                )
            )

        assert "/console" in result
        assert "200" in result
        assert "Werkzeug" in result

    def test_reports_all_closed_when_all_404(self):
        import unittest.mock as _mock

        tool = FlaskSessionForgeryTool()

        def _fake_head(url, *args, **kwargs):
            resp = _mock.Mock()
            resp.status_code = 404
            resp.text = "Not Found"
            return resp

        with _mock.patch(
            "ctf_solver.tools.session_forgery_tools.requests.head",
            side_effect=_fake_head,
        ):
            result = tool.use(
                json.dumps(
                    {
                        "operation": "debug_endpoint_probe",
                        "url": "http://target.example/",
                    }
                )
            )

        assert "no debug endpoints" in result.lower()


# ==============================================================================
# DomClobberingPayloadGenerator Tests
# ==============================================================================


class TestDomClobberingPayloadGenerator:
    """Tests for the DomClobberingPayloadGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = DomClobberingPayloadGenerator()

    # -- name / description --------------------------------------------------

    def test_tool_name(self):
        """Verify tool name is 'dom_clobbering_payload_generator'."""
        assert self.tool.name == "dom_clobbering_payload_generator"

    def test_tool_description_exists(self):
        """Verify description is a non-empty string."""
        assert isinstance(self.tool.description, str)
        assert len(self.tool.description) > 0

    # -- error handling ------------------------------------------------------

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not valid json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"variable": "x"}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "overwrite_var" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error listing valid ops."""
        result = self.tool.use(json.dumps({"operation": "destroy"}))
        assert "Error" in result
        assert "destroy" in result
        assert "overwrite_var" in result

    def test_empty_input(self):
        """Empty string input should request an operation."""
        result = self.tool.use("")
        assert "Error" in result
        assert "operation" in result.lower()

    # -- overwrite_var: 1-level (window.X) -----------------------------------

    def test_overwrite_var_single_level(self):
        """overwrite_var with 'myVar' should produce single-level clobber payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "myVar",
                    "value": "clobbered",
                }
            )
        )
        assert "Single-level clobber" in result or "window.X" in result
        assert 'id="myVar"' in result
        assert "clobbered" in result
        # Should contain <a> tag payload
        assert "<a " in result

    # -- overwrite_var: 2-level (X.Y) ----------------------------------------

    def test_overwrite_var_two_level(self):
        """overwrite_var with 'config.isAdmin' should produce two-level payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "config.isAdmin",
                    "value": "true",
                }
            )
        )
        assert "Two-level clobber" in result
        assert 'id="config"' in result
        assert "isAdmin" in result
        # Should contain multiple methods
        assert "Method 1" in result
        assert "Method 2" in result

    def test_overwrite_var_two_level_form_method(self):
        """Two-level clobber should include <form> with named <input>."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "app.debug",
                    "value": "1",
                }
            )
        )
        assert "<form" in result
        assert 'name="debug"' in result

    def test_overwrite_var_two_level_htmlcollection(self):
        """Two-level clobber should include HTMLCollection method."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "x.y",
                    "value": "val",
                }
            )
        )
        assert "HTMLCollection" in result

    # -- overwrite_var: 3-level (X.Y.Z) -------------------------------------

    def test_overwrite_var_three_level(self):
        """overwrite_var with 'a.b.c' should produce three-level payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "a.b.c",
                    "value": "pwned",
                }
            )
        )
        assert "Three-level clobber" in result
        assert 'id="a"' in result
        assert 'id="b"' in result
        assert "pwned" in result

    def test_overwrite_var_three_level_iframe(self):
        """Three-level clobber should include iframe srcdoc method."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "x.y.z",
                    "value": "v",
                }
            )
        )
        assert "iframe" in result
        assert "srcdoc" in result

    # -- overwrite_var: deep (4+ levels) ------------------------------------

    def test_overwrite_var_deep_nesting(self):
        """overwrite_var with 4+ levels should warn about difficulty."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "a.b.c.d",
                    "value": "x",
                }
            )
        )
        assert "very difficult" in result or "4-level" in result

    # -- overwrite_var: notes ------------------------------------------------

    def test_overwrite_var_includes_notes(self):
        """All overwrite_var outputs should include usage notes."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "overwrite_var",
                    "variable": "x",
                    "value": "1",
                }
            )
        )
        assert "Notes" in result
        assert "DOMPurify" in result
        assert "CSP" in result

    # -- form_hijack ---------------------------------------------------------

    def test_form_hijack_defaults(self):
        """form_hijack with defaults should target 'loginForm'."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "form_hijack",
                }
            )
        )
        assert "Form Action Hijack" in result
        assert "loginForm" in result
        assert "ATTACKER.com" in result

    def test_form_hijack_custom(self):
        """form_hijack with custom form_id and attacker_url."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "form_hijack",
                    "form_id": "signupForm",
                    "attacker_url": "https://evil.example.com/steal",
                }
            )
        )
        assert "signupForm" in result
        assert "evil.example.com" in result

    def test_form_hijack_techniques(self):
        """form_hijack should include multiple hijack techniques."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "form_hijack",
                }
            )
        )
        assert "base tag" in result.lower() or "<base" in result
        assert "formaction" in result
        assert "document.forms" in result

    # -- reference -----------------------------------------------------------

    def test_reference_returns_guide(self):
        """reference should return a comprehensive DOM clobbering guide."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "reference",
                }
            )
        )
        assert "DOM Clobbering Reference" in result
        assert "Named Access" in result
        assert "Clobbering Depth" in result
        assert "String Coercion" in result
        assert "DOMPurify" in result

    def test_reference_includes_examples(self):
        """reference should include concrete HTML examples."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "reference",
                }
            )
        )
        assert "<a id=" in result
        assert "window.x" in result
        assert "HTMLCollection" in result
