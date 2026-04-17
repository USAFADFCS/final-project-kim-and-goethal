"""
Tests for blind_sqli_tools.py
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from ctf_solver.tools.blind_sqli_tools import (
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
)


class TestBlindSqliBooleanTool:
    """Tests for the BlindSqliBooleanTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = BlindSqliBooleanTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(
            json.dumps(
                {
                    "method": "GET",
                    "param": "id",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test handling of missing param."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "DELETE",
                    "param": "id",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_operation(self):
        """Test handling of invalid operation."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "operation": "invalid_op",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )
        assert "Error" in result
        assert "operation" in result.lower()

    def test_missing_conditions(self):
        """Test handling of missing true/false conditions."""
        result = self.tool.use(
            json.dumps({"url": "http://test.com", "method": "GET", "param": "id"})
        )
        assert "Error" in result
        assert "condition" in result.lower()

    # === Payload Template Tests ===

    def test_payload_templates_exist(self):
        """Test that payload templates are defined for major databases."""
        templates = BlindSqliBooleanTool.PAYLOAD_TEMPLATES
        assert "mysql" in templates
        assert "postgresql" in templates
        assert "mssql" in templates
        assert "sqlite" in templates
        assert "oracle" in templates

    def test_payload_template_has_char_and_length(self):
        """Test that each template has char and length operations."""
        for db, templates in BlindSqliBooleanTool.PAYLOAD_TEMPLATES.items():
            assert "char" in templates, f"{db} missing char template"
            assert "length" in templates, f"{db} missing length template"

    # === Response Comparison Tests ===

    def test_responses_match_same_content(self):
        """Test that identical responses are considered matching."""
        resp1 = Mock()
        resp1.status_code = 200
        resp1.text = "Same content"

        resp2 = Mock()
        resp2.status_code = 200
        resp2.text = "Same content"

        assert self.tool._responses_match(resp1, resp2)

    def test_responses_dont_match_different_status(self):
        """Test that different status codes don't match."""
        resp1 = Mock()
        resp1.status_code = 200
        resp1.text = "Content"

        resp2 = Mock()
        resp2.status_code = 500
        resp2.text = "Content"

        assert not self.tool._responses_match(resp1, resp2)

    def test_responses_dont_match_very_different_lengths(self):
        """Test that very different length responses don't match."""
        resp1 = Mock()
        resp1.status_code = 200
        resp1.text = "Short"

        resp2 = Mock()
        resp2.status_code = 200
        resp2.text = "Very long response that is much longer than the short one"

        # With default 0.9 threshold, these shouldn't match
        assert not self.tool._responses_match(resp1, resp2, threshold=0.9)

    # === Test Condition Operation Tests ===

    def test_test_condition_detects_distinguishable_responses(self):
        """Test that test_condition operation detects distinguishable responses."""
        mock_session = Mock()

        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Welcome, user! Your data is here."

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Access denied."

        mock_session.get.side_effect = [true_response, false_response]

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "1' AND 1=1 --",
                    "false_condition": "1' AND 1=2 --",
                }
            )
        )

        assert "Boolean injection conditions are working" in result
        assert "NEXT STEPS" in result

    def test_test_condition_warns_indistinguishable_responses(self):
        """Test that test_condition warns when responses are similar."""
        mock_session = Mock()

        # Same response for both conditions
        same_response = Mock()
        same_response.status_code = 200
        same_response.text = "Identical response"

        mock_session.get.return_value = same_response

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "1' AND 1=1 --",
                    "false_condition": "1' AND 1=2 --",
                }
            )
        )

        assert "WARNING" in result or "similar" in result.lower()

    # === Extract Character Tests ===

    def test_extract_char_missing_query(self):
        """Test that extract_char requires query parameter."""
        mock_session = Mock()

        # Provide distinguishable responses so we get past baseline check
        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Welcome, you are logged in!"

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Access denied"

        mock_session.get.side_effect = [true_response, false_response]

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "extract_char",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )

        assert "Error" in result
        assert "query" in result.lower()

    def test_extract_char_binary_search(self):
        """Test binary search for character extraction."""
        mock_session = Mock()

        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Data found - true condition"

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "No data"

        # Simulate binary search for ASCII 65 ('A')
        # We're looking for: ASCII > 79 (False), ASCII > 47 (True), ...
        # Binary search sequence for 65: 79->47->63->71->67->65
        responses = [
            true_response,  # true baseline
            false_response,  # false baseline
            # Binary search: start mid = 79, target = 65
            false_response,  # ASCII > 79? FALSE (65 <= 79)
            true_response,  # ASCII > 55? TRUE (65 > 55)
            true_response,  # ASCII > 67? FALSE (65 <= 67) - wait, 65 < 67
            false_response,  # ASCII > 67? FALSE
            false_response,  # ASCII > 61? TRUE (65 > 61)
            true_response,  # ASCII > 61? TRUE
            false_response,  # ASCII > 64? TRUE (65 > 64)
            true_response,  # ASCII > 64? TRUE
            false_response,  # ASCII > 65? FALSE (65 == 65)
        ]
        mock_session.get.side_effect = responses

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "extract_char",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                    "query": "SELECT password FROM users LIMIT 1",
                    "position": 1,
                    "payload_template": "' AND (SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}) --",
                }
            )
        )

        # Should have extracted some character
        assert "Character at position" in result or "RESULT" in result

    # === Extract Length Tests ===

    def test_extract_length_missing_query(self):
        """Test that extract_length requires query parameter."""
        mock_session = Mock()

        # Provide distinguishable responses so we get past baseline check
        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Welcome, you are logged in!"

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Access denied"

        mock_session.get.side_effect = [true_response, false_response]

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "extract_length",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )

        assert "Error" in result
        assert "query" in result.lower()


class TestBlindSqliTimeTool:
    """Tests for the BlindSqliTimeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = BlindSqliTimeTool()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(json.dumps({"method": "GET", "param": "id"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test handling of missing param."""
        result = self.tool.use(json.dumps({"url": "http://test.com", "method": "GET"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps({"url": "http://test.com", "method": "PATCH", "param": "id"})
        )
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_operation(self):
        """Test handling of invalid operation."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "operation": "invalid",
                }
            )
        )
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_db_type(self):
        """Test handling of invalid database type."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "db_type": "unknown_db",
                }
            )
        )
        assert "Error" in result
        assert "db_type" in result.lower()

    # === Time Template Tests ===

    def test_time_templates_exist(self):
        """Test that time templates are defined for major databases."""
        templates = BlindSqliTimeTool.TIME_TEMPLATES
        assert "mysql" in templates
        assert "postgresql" in templates
        assert "mssql" in templates
        assert "sqlite" in templates
        assert "oracle" in templates

    def test_time_template_has_required_operations(self):
        """Test that each template has detect, char, and length operations."""
        for db, templates in BlindSqliTimeTool.TIME_TEMPLATES.items():
            assert "detect" in templates, f"{db} missing detect template"
            assert "char" in templates, f"{db} missing char template"
            assert "length" in templates, f"{db} missing length template"

    # === Delay Detection Tests ===

    def test_is_delayed_true(self):
        """Test that long response times are detected as delayed."""
        assert self.tool._is_delayed(3.5, 3.0)  # 3.5s > 3.0s * 0.8

    def test_is_delayed_false(self):
        """Test that short response times are not detected as delayed."""
        assert not self.tool._is_delayed(0.5, 3.0)  # 0.5s < 3.0s * 0.8

    def test_is_delayed_threshold(self):
        """Test delay detection with custom threshold."""
        assert self.tool._is_delayed(2.5, 3.0, threshold=0.8)  # 2.5 >= 2.4
        assert not self.tool._is_delayed(2.3, 3.0, threshold=0.8)  # 2.3 < 2.4

    # === Detect Operation Tests ===

    @patch("time.time")
    def test_detect_finds_time_based_injection(self, mock_time):
        """Test that detect operation finds time-based injection."""
        mock_session = Mock()

        # Fast baseline
        baseline_response = Mock()
        baseline_response.status_code = 200

        # Delayed injection response
        delay_response = Mock()
        delay_response.status_code = 200

        mock_session.get.side_effect = [baseline_response, delay_response]

        # Simulate timing: baseline fast (0.1s), injection slow (3.5s)
        mock_time.side_effect = [0, 0.1, 0, 3.5]

        tool = BlindSqliTimeTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "detect",
                    "db_type": "mysql",
                    "delay": 3,
                }
            )
        )

        assert "Time-Based Blind SQLi" in result
        assert "DETECTED" in result or "3." in result  # Should show timing

    @patch("time.time")
    def test_detect_not_found_when_fast(self, mock_time):
        """Test that detect operation reports not found when responses are fast."""
        mock_session = Mock()

        response = Mock()
        response.status_code = 200

        mock_session.get.return_value = response

        # All responses are fast
        mock_time.side_effect = [0, 0.1, 0, 0.1]

        tool = BlindSqliTimeTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "detect",
                    "db_type": "mysql",
                    "delay": 3,
                }
            )
        )

        assert "NOT detected" in result or "no delay" in result.lower()

    # === Extract Character Tests ===

    def test_extract_char_missing_query(self):
        """Test that extract_char requires query parameter."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "extract_char",
                    "db_type": "mysql",
                }
            )
        )

        assert "Error" in result
        assert "query" in result.lower()

    # === Extract Length Tests ===

    def test_extract_length_missing_query(self):
        """Test that extract_length requires query parameter."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "extract_length",
                    "db_type": "mysql",
                }
            )
        )

        assert "Error" in result
        assert "query" in result.lower()


class TestSqliDataDumper:
    """Tests for the SqliDataDumper class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = SqliDataDumper()

    # === Input Validation Tests ===

    def test_invalid_json_input(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test handling of missing URL."""
        result = self.tool.use(
            json.dumps(
                {"method": "GET", "param": "id", "query": "SELECT password FROM users"}
            )
        )
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test handling of missing param."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "query": "SELECT password FROM users",
                }
            )
        )
        assert "Error" in result
        assert "param" in result.lower()

    def test_missing_query(self):
        """Test handling of missing query."""
        result = self.tool.use(
            json.dumps({"url": "http://test.com", "method": "GET", "param": "id"})
        )
        assert "Error" in result
        assert "query" in result.lower()

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "OPTIONS",
                    "param": "id",
                    "query": "SELECT password FROM users",
                }
            )
        )
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_technique(self):
        """Test handling of invalid technique."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "query": "SELECT password FROM users",
                    "technique": "invalid_technique",
                }
            )
        )
        assert "Error" in result
        assert "technique" in result.lower()

    def test_boolean_technique_missing_conditions(self):
        """Test that boolean technique requires conditions."""
        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "query": "SELECT password FROM users",
                    "technique": "boolean",
                }
            )
        )
        assert "Error" in result
        assert "condition" in result.lower()

    # === Tool Composition Tests ===

    def test_has_boolean_and_time_tools(self):
        """Test that dumper has both boolean and time tools."""
        assert hasattr(self.tool, "boolean_tool")
        assert hasattr(self.tool, "time_tool")
        assert isinstance(self.tool.boolean_tool, BlindSqliBooleanTool)
        assert isinstance(self.tool.time_tool, BlindSqliTimeTool)

    def test_shares_session_with_subttools(self):
        """Test that dumper shares session with sub-tools."""
        import requests

        session = requests.Session()
        tool = SqliDataDumper(session=session)

        assert tool.boolean_tool.session is session
        assert tool.time_tool.session is session


class TestBlindSqliCTFScenarios:
    """Test CTF-specific scenarios with blind SQLi tools."""

    def test_boolean_based_password_extraction_setup(self):
        """Test setup for boolean-based password extraction."""
        mock_session = Mock()

        # Different responses for true vs false
        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Welcome! Here is your data."

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Access denied."

        mock_session.get.side_effect = [true_response, false_response]

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://ctf.challenge.com/user",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "1' AND 1=1 --",
                    "false_condition": "1' AND 1=2 --",
                }
            )
        )

        assert "Boolean injection conditions are working" in result
        assert "EXAMPLE PAYLOAD TEMPLATES" in result

    @patch("time.time")
    def test_time_based_detection_mysql(self, mock_time):
        """Test time-based injection detection for MySQL."""
        mock_session = Mock()

        response = Mock()
        response.status_code = 200

        mock_session.get.return_value = response

        # Baseline fast, injection slow
        mock_time.side_effect = [0, 0.1, 0, 5.2]

        tool = BlindSqliTimeTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://ctf.challenge.com/product",
                    "method": "GET",
                    "param": "id",
                    "operation": "detect",
                    "db_type": "mysql",
                    "delay": 5,
                    "prefix": "'",
                    "suffix": " --",
                }
            )
        )

        assert "mysql" in result.lower() or "MySQL" in result
        assert "SLEEP" in result or "delay" in result.lower()

    @patch("time.time")
    def test_time_based_detection_postgresql(self, mock_time):
        """Test time-based injection detection for PostgreSQL."""
        mock_session = Mock()

        response = Mock()
        response.status_code = 200

        mock_session.post.return_value = response

        # Baseline fast, injection slow
        mock_time.side_effect = [0, 0.1, 0, 3.5]

        tool = BlindSqliTimeTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://ctf.challenge.com/search",
                    "method": "POST",
                    "param": "query",
                    "operation": "detect",
                    "db_type": "postgresql",
                    "delay": 3,
                }
            )
        )

        assert "postgresql" in result.lower() or "PostgreSQL" in result


class TestBlindSqliEdgeCases:
    """Test edge cases and error conditions."""

    def test_boolean_tool_handles_connection_error(self):
        """Test boolean tool handles connection errors gracefully."""
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection refused")

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                }
            )
        )

        assert "Error" in result

    def test_time_tool_handles_timeout(self):
        """Test time tool handles request timeouts."""
        import requests

        mock_session = Mock()

        baseline = Mock()
        baseline.status_code = 200
        baseline.text = "Data"

        mock_session.get.side_effect = [
            baseline,
            requests.exceptions.Timeout("Request timed out"),
        ]

        tool = BlindSqliTimeTool(session=mock_session)

        with patch("time.time", side_effect=[0, 0.1, 0, 15.0]):
            result = tool.use(
                json.dumps(
                    {
                        "url": "http://test.com/page",
                        "method": "GET",
                        "param": "id",
                        "operation": "detect",
                        "db_type": "mysql",
                        "delay": 5,
                        "timeout": 10,
                    }
                )
            )

        # Should detect timeout as potential time-based injection
        assert "timeout" in result.lower() or "DETECTED" in result

    def test_boolean_tool_with_post_method(self):
        """Test boolean tool works with POST method."""
        mock_session = Mock()

        true_response = Mock()
        true_response.status_code = 200
        true_response.text = "Login successful"

        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Login failed"

        mock_session.post.side_effect = [true_response, false_response]

        tool = BlindSqliBooleanTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/login",
                    "method": "POST",
                    "param": "username",
                    "operation": "test_condition",
                    "true_condition": "admin' AND 1=1 --",
                    "false_condition": "admin' AND 1=2 --",
                    "data": {"password": "test"},
                }
            )
        )

        assert "Boolean injection conditions are working" in result
        mock_session.post.assert_called()

    def test_dumper_stops_after_consecutive_failures(self):
        """Test that dumper stops extraction after consecutive failures."""
        mock_session = Mock()

        # All requests return same response (no distinguishable difference)
        same_response = Mock()
        same_response.status_code = 200
        same_response.text = "Same response every time"

        mock_session.get.return_value = same_response

        tool = SqliDataDumper(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com/page",
                    "method": "GET",
                    "param": "id",
                    "query": "SELECT password FROM users",
                    "technique": "boolean",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                    "max_length": 10,
                }
            )
        )

        # Should stop early due to indistinguishable responses
        assert "EXTRACTED DATA" in result or "WARNING" in result

    def test_time_tool_all_db_types(self):
        """Test that all database types can be specified."""
        db_types = ["mysql", "postgresql", "mssql", "sqlite", "oracle"]

        for db_type in db_types:
            mock_session = Mock()
            response = Mock()
            response.status_code = 200
            mock_session.get.return_value = response

            tool = BlindSqliTimeTool(session=mock_session)

            with patch("time.time", side_effect=[0, 0.1, 0, 0.1]):
                result = tool.use(
                    json.dumps(
                        {
                            "url": "http://test.com/page",
                            "method": "GET",
                            "param": "id",
                            "operation": "detect",
                            "db_type": db_type,
                            "delay": 3,
                        }
                    )
                )

            # Should complete without error
            assert "Time-Based Blind SQLi" in result
            assert db_type in result.lower() or db_type.upper() in result


class TestBlindSqliIntegration:
    """Integration tests for blind SQLi tools."""

    def test_tools_importable_from_package(self):
        """Test that all tools are importable from the package."""
        from ctf_solver.tools import (
            BlindSqliBooleanTool,
            BlindSqliTimeTool,
            SqliDataDumper,
        )

        assert BlindSqliBooleanTool is not None
        assert BlindSqliTimeTool is not None
        assert SqliDataDumper is not None

    def test_tools_have_required_attributes(self):
        """Test that all tools have name and description."""
        tools = [BlindSqliBooleanTool(), BlindSqliTimeTool(), SqliDataDumper()]

        for tool in tools:
            assert hasattr(tool, "name"), f"{type(tool).__name__} missing name"
            assert hasattr(
                tool, "description"
            ), f"{type(tool).__name__} missing description"
            assert hasattr(tool, "use"), f"{type(tool).__name__} missing use method"
            assert isinstance(
                tool.name, str
            ), f"{type(tool).__name__} name not a string"
            assert isinstance(
                tool.description, str
            ), f"{type(tool).__name__} description not a string"
            assert (
                len(tool.description) > 50
            ), f"{type(tool).__name__} description too short"

    def test_tools_share_session_properly(self):
        """Test that tools can share a session."""
        import requests

        shared_session = requests.Session()

        boolean_tool = BlindSqliBooleanTool(session=shared_session)
        time_tool = BlindSqliTimeTool(session=shared_session)
        dumper = SqliDataDumper(session=shared_session)

        assert boolean_tool.session is shared_session
        assert time_tool.session is shared_session
        assert dumper.session is shared_session


class TestBlindSqliOracleInversion:
    """Tests for oracle inversion detection in BlindSqliBooleanTool."""

    def setup_method(self):
        self.tool = BlindSqliBooleanTool()

    def _mock_response(self, status_code=200, text=""):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        return resp

    def test_oracle_inversion_detected(self):
        """Test that inverted oracle is detected and baselines are swapped."""
        mock_session = MagicMock()

        # Responses: true_cond, false_cond, known_true (AND 1=1), known_false (AND 1=2)
        true_resp = self._mock_response(200, "A" * 100)  # true condition baseline
        false_resp = self._mock_response(200, "B" * 200)  # false condition baseline
        # Known-true matches FALSE baseline (inverted!)
        kt_resp = self._mock_response(200, "B" * 200)
        kf_resp = self._mock_response(200, "A" * 100)

        mock_session.get.side_effect = [true_resp, false_resp, kt_resp, kf_resp]

        tool = BlindSqliBooleanTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                    "detect_oracle_inversion": True,
                }
            )
        )

        assert "INVERTED ORACLE DETECTED" in result

    def test_oracle_normal_not_inverted(self):
        """Test that normal oracle is correctly identified as non-inverted."""
        mock_session = MagicMock()

        true_resp = self._mock_response(200, "A" * 100)
        false_resp = self._mock_response(200, "B" * 200)
        # Known-true matches TRUE baseline (normal)
        kt_resp = self._mock_response(200, "A" * 100)
        kf_resp = self._mock_response(200, "B" * 200)

        mock_session.get.side_effect = [true_resp, false_resp, kt_resp, kf_resp]

        tool = BlindSqliBooleanTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                    "detect_oracle_inversion": True,
                }
            )
        )

        assert "NORMAL" in result or "not inverted" in result.lower()

    def test_no_inversion_detection_when_disabled(self):
        """Test that oracle inversion detection is skipped when not requested."""
        mock_session = MagicMock()

        true_resp = self._mock_response(200, "A" * 100)
        false_resp = self._mock_response(200, "B" * 200)

        mock_session.get.side_effect = [true_resp, false_resp]

        tool = BlindSqliBooleanTool(session=mock_session)
        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.com",
                    "method": "GET",
                    "param": "id",
                    "operation": "test_condition",
                    "true_condition": "' AND 1=1 --",
                    "false_condition": "' AND 1=2 --",
                    "detect_oracle_inversion": False,
                }
            )
        )

        assert "INVERTED" not in result
        assert "Detecting oracle inversion" not in result
