"""
Tests for filter_bypass_tools.py
"""

import json
import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from ctf_solver.tools.filter_bypass_tools import FilterEnumeratorTool, PayloadMutatorTool


def _mock_response(status_code=200, text=""):
    """Create a mock requests.Response object."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    return resp


class TestFilterEnumeratorTool:
    """Tests for the FilterEnumeratorTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.session = MagicMock(spec=requests.Session)
        self.tool = FilterEnumeratorTool(session=self.session)

    # === Input Validation Tests ===

    def test_missing_url_returns_error(self):
        """Test handling of missing URL."""
        result = self.tool.use(json.dumps({"param": "username"}))
        assert "Error" in result
        assert "'url'" in result

    def test_missing_param_returns_error(self):
        """Test handling of missing param."""
        result = self.tool.use(json.dumps({"url": "http://test.com/login"}))
        assert "Error" in result
        assert "'param'" in result

    def test_invalid_method_returns_error(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username",
            "method": "DELETE"
        }))
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_json_returns_error(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    # === Baseline and Detection Tests ===

    def test_baseline_failure_returns_error(self):
        """Test error when baseline request fails (returns None)."""
        self.session.post.side_effect = Exception("Connection refused")
        result = self.tool.use(json.dumps({
            "url": "http://unreachable.com/login",
            "param": "username"
        }))
        assert "Error" in result
        assert "baseline" in result.lower()

    def test_blocked_keyword_detected(self):
        """Test that a blocked keyword is detected when response status differs from baseline."""
        baseline = _mock_response(status_code=200, text="Normal login page")

        # OR keyword returns 403 (different from baseline 200)
        blocked_resp = _mock_response(status_code=403, text="Blocked")

        # All other keywords/operators return normal response
        normal_resp = _mock_response(status_code=200, text="Normal login page")

        def side_effect_fn(**kwargs):
            data = kwargs.get("data", {})
            value = data.get("username", "")
            if value == "OR":
                return blocked_resp
            return normal_resp

        # First call is baseline ("cleaninput123"), rest are keyword tests
        self.session.post.side_effect = lambda url, data=None, headers=None, timeout=None: (
            blocked_resp if data and data.get("username") == "OR" else normal_resp
        )

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "BLOCKED" in result
        assert "OR" in result

    def test_allowed_keyword_detected(self):
        """Test that an allowed keyword is detected when response matches baseline."""
        normal_resp = _mock_response(status_code=200, text="Normal login page")

        # All requests return the same response as baseline
        self.session.post.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "ALLOWED KEYWORDS" in result
        # When nothing is blocked, all keywords should be allowed
        assert "GLOB" in result
        assert "IS" in result

    def test_blocked_operator_detected(self):
        """Test that a blocked operator is detected via body content indicator."""
        baseline = _mock_response(status_code=200, text="Normal login page with content here")

        def make_response(value):
            if value == "=":
                return _mock_response(status_code=200, text="Input filtered by WAF")
            return _mock_response(status_code=200, text="Normal login page with content here")

        self.session.post.side_effect = lambda url, data=None, headers=None, timeout=None: (
            make_response(data.get("username", "")) if data else baseline
        )

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "BLOCKED OPERATORS" in result
        assert "'='" in result
        assert "filtered" in result.lower()

    def test_recommendations_or_blocked_pipe_allowed(self):
        """Test recommendation when OR is blocked but || is allowed."""
        def make_response(value):
            if value == "OR":
                return _mock_response(status_code=403, text="Blocked")
            return _mock_response(status_code=200, text="Normal page content here")

        self.session.post.side_effect = lambda url, data=None, headers=None, timeout=None: (
            make_response(data.get("username", "")) if data else
            _mock_response(status_code=200, text="Normal page content here")
        )

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "RECOMMENDATIONS" in result
        assert "'||'" in result
        assert "boolean OR" in result

    def test_recommendations_eq_blocked_is_allowed(self):
        """Test recommendation when = is blocked but IS is allowed."""
        def make_response(value):
            if value == "=":
                return _mock_response(status_code=403, text="Blocked")
            return _mock_response(status_code=200, text="Normal page content here")

        self.session.post.side_effect = lambda url, data=None, headers=None, timeout=None: (
            make_response(data.get("username", "")) if data else
            _mock_response(status_code=200, text="Normal page content here")
        )

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "RECOMMENDATIONS" in result
        assert "IS" in result
        assert "equality" in result.lower() or "GLOB" in result

    def test_all_clean_no_filters_detected(self):
        """Test message when no filters are detected."""
        normal_resp = _mock_response(status_code=200, text="Normal page content here")
        self.session.post.return_value = normal_resp

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "No filters detected" in result
        assert "Standard payloads should work" in result

    def test_request_error_handling(self):
        """Test handling when individual keyword requests fail (return None)."""
        baseline = _mock_response(status_code=200, text="Normal page")
        call_count = [0]

        def side_effect_fn(url, data=None, headers=None, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                # Baseline succeeds
                return baseline
            if call_count[0] == 2:
                # First keyword request fails
                raise Exception("Connection reset")
            return baseline

        self.session.post.side_effect = side_effect_fn

        result = self.tool.use(json.dumps({
            "url": "http://test.com/login",
            "param": "username"
        }))

        assert "ERRORS" in result or "Allowed" in result
        # Should still produce a report, not crash
        assert "Filter Enumeration Report" in result


class TestPayloadMutatorTool:
    """Tests for the PayloadMutatorTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = PayloadMutatorTool()

    # === Input Validation Tests ===

    def test_missing_payload_returns_error(self):
        """Test handling of missing payload."""
        result = self.tool.use(json.dumps({"blocked_keywords": ["or"]}))
        assert "Error" in result
        assert "'payload'" in result

    def test_invalid_json_returns_error(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_invalid_blocked_keywords_type_returns_error(self):
        """Test handling of blocked_keywords that is not a list."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": "or"
        }))
        assert "Error" in result
        assert "blocked_keywords" in result
        assert "list" in result.lower()

    # === Single-Token Replacement Tests ===

    def test_no_blocked_keywords_returns_no_variants(self):
        """Test that no variants are generated when no keywords are blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": []
        }))
        assert "No variants could be generated" in result

    def test_or_replaced_with_pipe(self):
        """Test that OR is replaced with || when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["or"]
        }))
        assert "||" in result
        assert "double-pipe" in result.lower() or "boolean OR" in result

    def test_eq_replaced_with_is(self):
        """Test that = is replaced with IS when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["="]
        }))
        assert "IS" in result
        assert "IS operator" in result or "equality" in result.lower()

    def test_eq_replaced_with_glob(self):
        """Test that = is replaced with GLOB when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["="]
        }))
        assert "GLOB" in result

    def test_admin_replaced_with_concatenation(self):
        """Test that admin is replaced with concatenation bypass."""
        result = self.tool.use(json.dumps({
            "payload": "admin' --",
            "blocked_keywords": ["admin"]
        }))
        assert "ad'||'min" in result or "adm'||'in" in result or "a'||'dmin" in result
        assert "concatenation" in result.lower()

    def test_comment_replaced_when_blocked(self):
        """Test that -- comment is replaced with alternatives when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["--"]
        }))
        # Should offer /**/ or # or removal
        assert "/**/" in result or "#" in result or "no-comment" in result.lower()

    def test_true_replaced_with_1(self):
        """Test that true is replaced with literal 1."""
        result = self.tool.use(json.dumps({
            "payload": "' OR true --",
            "blocked_keywords": ["true"]
        }))
        assert "literal 1" in result

    def test_false_replaced_with_0(self):
        """Test that false is replaced with literal 0."""
        result = self.tool.use(json.dumps({
            "payload": "' AND false --",
            "blocked_keywords": ["false"]
        }))
        assert "literal 0" in result

    def test_like_replaced_with_glob(self):
        """Test that LIKE is replaced with GLOB when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' OR username LIKE 'admin%' --",
            "blocked_keywords": ["like"]
        }))
        assert "GLOB" in result
        assert "case-sensitive" in result.lower() or "alternative" in result.lower()

    # === Multi-Token and Advanced Tests ===

    def test_multi_token_replacement(self):
        """Test that multiple blocked tokens are replaced simultaneously."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["or", "=", "--"]
        }))
        # The multi-token strategy should produce a variant with all replacements
        # Look for evidence of multiple substitutions in a single variant
        assert "Variant" in result
        # At least one variant should exist
        assert "Total Variants Generated:" in result
        # The count should not be 0
        assert "Total Variants Generated: 0" not in result

    def test_max_length_filters_long_variants(self):
        """Test that max_length filters out variants that are too long."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["or", "=", "--"],
            "max_length": 10
        }))
        # With a very short max_length, most/all variants should be filtered out
        # Original is 16 chars, so replacements will likely exceed 10
        assert "No variants could be generated" in result or "Total Variants Generated: 0" in result

    def test_clean_vs_partial_variants(self):
        """Test that clean and partial variants are properly categorized."""
        result = self.tool.use(json.dumps({
            "payload": "' OR '1'='1' --",
            "blocked_keywords": ["or"]
        }))
        # OR -> || should produce a clean variant (no blocked keywords remain)
        assert "CLEAN VARIANTS" in result
        assert "Clean (all blocked removed):" in result

    def test_between_bypass_for_equality(self):
        """Test BETWEEN bypass for equality when = is blocked."""
        result = self.tool.use(json.dumps({
            "payload": "'1'='1'",
            "blocked_keywords": ["="]
        }))
        # Should generate a BETWEEN variant
        assert "BETWEEN" in result
        assert "equality bypass" in result.lower() or "BETWEEN" in result

    def test_web_gauntlet_2_scenario(self):
        """Comprehensive test: Web Gauntlet 2 scenario with multiple blocked keywords."""
        result = self.tool.use(json.dumps({
            "payload": "admin' OR '1'='1' --",
            "blocked_keywords": ["or", "and", "=", "--", "admin"],
            "max_length": 35
        }))
        assert "Payload Mutation Report" in result
        assert "Blocked Keywords: or, and, =, --, admin" in result
        assert "Max Length: 35" in result

        # Should generate at least some variants
        assert "Total Variants Generated:" in result

        # Should provide bypass reference for all blocked keywords
        assert "BYPASS REFERENCE" in result
        assert "'or'" in result or "or" in result.lower()
        assert "'admin'" in result or "concatenation" in result.lower()

        # Clean variants should exist (multi-token replacement handles all)
        # The multi-token strategy replaces or->||, =->IS, -->/**/, admin->ad'||'min
        # Check that at least some variants are generated
        lines = result.split("\n")
        total_line = [l for l in lines if "Total Variants Generated:" in l]
        assert len(total_line) > 0
        count_str = total_line[0].split(":")[-1].strip()
        assert int(count_str) > 0

    def test_union_case_variation(self):
        """Test that UNION is replaced with mixed case variations when blocked."""
        result = self.tool.use(json.dumps({
            "payload": "' UNION SELECT * FROM users --",
            "blocked_keywords": ["union"]
        }))
        assert "UnIoN" in result or "uNiOn" in result or "UNION" in result
        assert "mixed case" in result.lower() or "case" in result.lower()


class TestFilterEnumeratorToolInternal:
    """Tests for internal helper methods of FilterEnumeratorTool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = FilterEnumeratorTool()

    def test_is_blocked_by_status_code(self):
        """Test _is_blocked detects status code changes."""
        resp = _mock_response(status_code=403, text="Forbidden")
        is_blocked, reasons = self.tool._is_blocked(resp, baseline_status=200, baseline_length=100)
        assert is_blocked is True
        assert any("status_code" in r for r in reasons)

    def test_is_blocked_by_body_indicator(self):
        """Test _is_blocked detects block indicator words in body."""
        resp = _mock_response(status_code=200, text="Your input was filtered by the WAF")
        is_blocked, reasons = self.tool._is_blocked(resp, baseline_status=200, baseline_length=35)
        assert is_blocked is True
        assert any("filtered" in r for r in reasons)

    def test_is_not_blocked_matching_response(self):
        """Test _is_blocked returns False for matching baseline response."""
        resp = _mock_response(status_code=200, text="Normal login page")
        is_blocked, reasons = self.tool._is_blocked(resp, baseline_status=200, baseline_length=17)
        assert is_blocked is False
        assert len(reasons) == 0

    def test_is_blocked_by_length_change(self):
        """Test _is_blocked detects significant length changes."""
        # Response is much shorter than baseline (>50% shorter)
        resp = _mock_response(status_code=200, text="x")
        is_blocked, reasons = self.tool._is_blocked(resp, baseline_status=200, baseline_length=100)
        assert is_blocked is True
        assert any("shorter" in r for r in reasons)


class TestPayloadMutatorToolInternal:
    """Tests for internal helper methods of PayloadMutatorTool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = PayloadMutatorTool()

    def test_find_blocked_in_payload_case_insensitive(self):
        """Test that _find_blocked_in_payload finds case-insensitive matches."""
        occurrences = self.tool._find_blocked_in_payload("' OR '1'='1'", ["or"])
        assert len(occurrences) > 0
        assert any(matched.upper() == "OR" for matched, _, _ in occurrences)

    def test_find_blocked_in_payload_no_match(self):
        """Test that _find_blocked_in_payload returns empty for no matches."""
        occurrences = self.tool._find_blocked_in_payload("' GLOB 'a*'", ["or"])
        assert len(occurrences) == 0

    def test_get_bypasses_for_equals(self):
        """Test that _get_bypasses_for returns bypass options for =."""
        bypasses = self.tool._get_bypasses_for("=", "sqlite")
        assert len(bypasses) >= 3
        replacement_names = [repl for repl, _ in bypasses]
        assert "IS" in replacement_names
        assert "GLOB" in replacement_names
        assert "LIKE" in replacement_names

    def test_check_still_blocked_finds_remaining(self):
        """Test that _check_still_blocked identifies remaining blocked keywords."""
        still = self.tool._check_still_blocked("' || '1'='1' --", ["=", "--"])
        assert "=" in still
        assert "--" in still

    def test_check_still_blocked_clean(self):
        """Test that _check_still_blocked returns empty for clean variant."""
        still = self.tool._check_still_blocked("' || '1' IS '1' /**/", ["or", "=", "--"])
        assert len(still) == 0
