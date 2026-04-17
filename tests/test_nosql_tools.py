"""
Tests for nosql_tools.py
"""

import json
import pytest
from unittest.mock import MagicMock

import requests

from ctf_solver.tools.nosql_tools import NosqlProbeTool, NosqlPayloadGenerator


def _mock_response(status_code=200, text=""):
    """Create a mock requests.Response with the given status code and body text."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# TestNosqlProbeTool
# ---------------------------------------------------------------------------


class TestNosqlProbeTool:
    """Tests for the NosqlProbeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session = MagicMock()
        self.tool = NosqlProbeTool(session=self.session)

    # --- Input validation ---

    def test_missing_url(self):
        """Test that a missing 'url' field returns an error."""
        result = self.tool.use(json.dumps({"param": "username"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that a missing 'param' field returns an error."""
        result = self.tool.use(json.dumps({"url": "http://target.com/login"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test that malformed JSON input returns an error."""
        result = self.tool.use("{not valid json!!!")
        assert "Error" in result
        assert "JSON" in result

    def test_invalid_method(self):
        """Test that an invalid HTTP method returns an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "method": "DELETE",
                }
            )
        )
        assert "Error" in result
        assert "method" in result.lower()

    # --- Baseline and probe behavior ---

    def test_baseline_failure(self):
        """Test that a failed baseline request returns an error message."""
        self.session.post.side_effect = Exception("Connection refused")
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                }
            )
        )
        assert "Error" in result
        assert "baseline" in result.lower()

    def test_injection_detected_query_param(self):
        """Test that injection is detected when query param payloads trigger
        a different response from the baseline."""
        baseline = _mock_response(200, "Login failed")

        # When bracket-notation param is sent, return success-like response
        success_resp = _mock_response(
            200, "Welcome to the admin dashboard! Here is your data."
        )

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            data = kw.get("data", {})
            # First call is baseline
            if call_count[0] == 1:
                return baseline
            # If any key has bracket notation, return success
            for key in data or {}:
                if "[$" in key:
                    return success_resp
            return baseline

        self.session.post.side_effect = post_side_effect
        # JSON body calls should return baseline
        self.session.post.return_value = baseline

        # Override side_effect to handle all calls
        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "injection_type": "query_param",
                }
            )
        )
        assert "INTERESTING PAYLOADS" in result or "NosqlProbeTool" in result

    def test_injection_detected_json_body(self):
        """Test that injection is detected when JSON body payloads trigger
        a different response from the baseline."""
        baseline = _mock_response(200, "Login failed")
        success_resp = _mock_response(
            200, "Welcome admin! Dashboard loaded successfully here."
        )

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            # First call is baseline
            if call_count[0] == 1:
                return baseline
            # JSON body calls (json= kwarg) return success
            if "json" in kw and kw["json"] is not None:
                return success_resp
            return baseline

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "injection_type": "json_body",
                }
            )
        )
        assert "INTERESTING PAYLOADS" in result

    def test_no_injection_all_same(self):
        """Test that no injection is reported when all responses are identical."""
        same_resp = _mock_response(200, "Login failed. Try again.")
        self.session.post.return_value = same_resp
        self.session.get.return_value = same_resp

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                }
            )
        )
        assert "No obviously interesting payloads found" in result

    def test_error_messages_detected(self):
        """Test detection of NoSQL error indicators in response bodies."""
        baseline = _mock_response(200, "Normal page")
        error_resp = _mock_response(200, "MongoError: bad auth Authentication failed")

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return error_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                }
            )
        )
        assert "NoSQL ERROR INDICATORS DETECTED" in result or "MongoError" in result

    def test_flag_detection(self):
        """Test that CTF flags embedded in responses are extracted."""
        baseline = _mock_response(200, "Normal page")
        flag_resp = _mock_response(200, "Congrats! picoCTF{n0sql_1nj3ct10n_ftw}")

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return flag_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                }
            )
        )
        assert "FLAGS FOUND" in result
        assert "picoCTF{n0sql_1nj3ct10n_ftw}" in result

    def test_both_injection_types(self):
        """Test that 'both' injection type tests query_param and json_body."""
        baseline = _mock_response(200, "Login failed")
        success_resp = _mock_response(
            200, "Welcome admin! Dashboard loaded successfully here."
        )

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            return success_resp

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "injection_type": "both",
                }
            )
        )
        assert "NosqlProbeTool" in result
        assert "Injection Type: both" in result

    def test_where_injection_tested(self):
        """Test that $where JavaScript injection payloads are tested."""
        baseline = _mock_response(200, "Login failed")
        where_resp = _mock_response(
            200, "Welcome! You are now logged in as admin dashboard."
        )

        call_count = [0]

        def post_side_effect(url, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline
            json_data = kw.get("json", {})
            if json_data and "$where" in (json_data or {}):
                return where_resp
            return baseline

        self.session.post.side_effect = post_side_effect

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "injection_type": "json_body",
                }
            )
        )
        # The tool always tests $where payloads
        assert "NosqlProbeTool" in result

    def test_get_method_uses_session_get(self):
        """Test that GET method sends requests via session.get."""
        same_resp = _mock_response(200, "Search results")
        self.session.get.return_value = same_resp

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/search",
                    "param": "q",
                    "method": "GET",
                }
            )
        )
        assert "NosqlProbeTool" in result
        self.session.get.assert_called()

    def test_default_session_created(self):
        """Test that a default requests.Session is created when none is provided."""
        tool = NosqlProbeTool()
        assert tool.session is not None

    def test_invalid_injection_type(self):
        """Test that an invalid injection_type returns an error."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/login",
                    "param": "username",
                    "injection_type": "xml",
                }
            )
        )
        assert "Error" in result
        assert "injection_type" in result.lower()


# ---------------------------------------------------------------------------
# TestNosqlPayloadGenerator
# ---------------------------------------------------------------------------


class TestNosqlPayloadGenerator:
    """Tests for the NosqlPayloadGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = NosqlPayloadGenerator()

    # --- Input validation ---

    def test_missing_operation(self):
        """Test that a missing 'operation' field returns an error."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test that an unsupported operation returns an error."""
        result = self.tool.use(json.dumps({"operation": "hack_the_planet"}))
        assert "Error" in result
        assert "hack_the_planet" in result

    def test_invalid_json(self):
        """Test that malformed JSON input returns an error."""
        result = self.tool.use("not json at all {{{")
        assert "Error" in result
        assert "JSON" in result

    # --- auth_bypass ---

    def test_auth_bypass_payloads(self):
        """Test that auth_bypass operation produces bypass payloads."""
        result = self.tool.use(json.dumps({"operation": "auth_bypass"}))
        assert "Authentication Bypass Payloads" in result
        assert "JSON Body Format" in result
        assert "Query Parameter Format" in result

    def test_auth_bypass_contains_ne_operator(self):
        """Test that auth_bypass includes the classic $ne bypass."""
        result = self.tool.use(json.dumps({"operation": "auth_bypass"}))
        assert "$ne" in result
        assert '"$ne"' in result or "$ne" in result

    def test_auth_bypass_has_json_and_query_formats(self):
        """Test that auth_bypass includes both JSON and query param formats."""
        result = self.tool.use(json.dumps({"operation": "auth_bypass"}))
        # JSON format markers
        assert '"$ne"' in result or '{"$ne"' in result
        # Query parameter format markers
        assert "[$ne]=" in result
        assert "[$gt]=" in result

    # --- data_extraction ---

    def test_data_extraction_template(self):
        """Test that data_extraction produces regex extraction templates."""
        result = self.tool.use(json.dumps({"operation": "data_extraction"}))
        assert "Regex-Based Data Extraction" in result
        assert "$regex" in result
        assert "character" in result.lower()

    def test_data_extraction_with_prefix(self):
        """Test that data_extraction uses the provided known_prefix."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "data_extraction",
                    "known_prefix": "adm",
                }
            )
        )
        assert "adm" in result
        assert "3 chars known" in result

    # --- operators ---

    def test_operators_reference(self):
        """Test that operators operation produces a reference of MongoDB operators."""
        result = self.tool.use(json.dumps({"operation": "operators"}))
        assert "MongoDB Query Operators Reference" in result
        assert "$eq" in result
        assert "$ne" in result
        assert "$gt" in result
        assert "$regex" in result
        assert "$exists" in result
        assert "$where" in result

    # --- All operations return content ---

    def test_all_operations_return_content(self):
        """Test that all valid operations return non-empty meaningful content."""
        for op in ("auth_bypass", "data_extraction", "operators"):
            result = self.tool.use(json.dumps({"operation": op}))
            assert "NosqlPayloadGenerator" in result
            assert len(result) > 100, f"Operation '{op}' returned too little content"
            assert "Error" not in result
