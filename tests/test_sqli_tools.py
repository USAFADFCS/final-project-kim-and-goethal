"""
Tests for sqli_tools.py
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from ctf_solver.tools.sqli_tools import SqliProbeTool, SqliColumnCounter


class TestSqliProbeTool:
    """Tests for the SqliProbeTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = SqliProbeTool()

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
        result = self.tool.use(json.dumps({
            "url": "http://test.com",
            "method": "DELETE",
            "param": "id"
        }))
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_payload_set(self):
        """Test handling of invalid payload set."""
        result = self.tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "payload_set": "invalid_set"
        }))
        assert "Error" in result
        assert "payload_set" in result.lower()

    def test_custom_payloads_required(self):
        """Test that custom payloads are required when using custom set."""
        result = self.tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "payload_set": "custom"
        }))
        assert "Error" in result
        assert "custom_payloads" in result.lower()

    # === Payload Set Tests ===

    def test_auth_bypass_payloads_exist(self):
        """Test that auth bypass payloads are defined."""
        assert len(SqliProbeTool.AUTH_BYPASS_PAYLOADS) > 0
        assert "' OR '1'='1" in SqliProbeTool.AUTH_BYPASS_PAYLOADS

    def test_error_based_payloads_exist(self):
        """Test that error based payloads are defined."""
        assert len(SqliProbeTool.ERROR_BASED_PAYLOADS) > 0
        assert "'" in SqliProbeTool.ERROR_BASED_PAYLOADS

    def test_union_detect_payloads_exist(self):
        """Test that union detect payloads are defined."""
        assert len(SqliProbeTool.UNION_DETECT_PAYLOADS) > 0
        assert "' UNION SELECT NULL --" in SqliProbeTool.UNION_DETECT_PAYLOADS

    def test_get_payloads_auth_bypass(self):
        """Test getting auth bypass payloads."""
        payloads = self.tool._get_payloads("auth_bypass")
        assert payloads == SqliProbeTool.AUTH_BYPASS_PAYLOADS

    def test_get_payloads_error_based(self):
        """Test getting error based payloads."""
        payloads = self.tool._get_payloads("error_based")
        assert payloads == SqliProbeTool.ERROR_BASED_PAYLOADS

    def test_get_payloads_union_detect(self):
        """Test getting union detect payloads."""
        payloads = self.tool._get_payloads("union_detect")
        assert payloads == SqliProbeTool.UNION_DETECT_PAYLOADS

    def test_get_payloads_custom(self):
        """Test getting custom payloads."""
        custom = ["test1", "test2"]
        payloads = self.tool._get_payloads("custom", custom)
        assert payloads == custom

    # === SQL Error Detection Tests ===

    def test_detect_mysql_error(self):
        """Test detection of MySQL errors."""
        response = "You have an error in your SQL syntax near 'test'"
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) > 0
        assert any("mysql" in e.lower() or "syntax" in e.lower() for e in errors)

    def test_detect_postgresql_error(self):
        """Test detection of PostgreSQL errors."""
        response = "PostgreSQL ERROR: syntax error at or near"
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) > 0
        assert any("postgresql" in e.lower() for e in errors)

    def test_detect_mssql_error(self):
        """Test detection of MSSQL errors."""
        response = "Microsoft SQL Server Driver error"
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) > 0

    def test_detect_sqlite_error(self):
        """Test detection of SQLite errors."""
        response = "[SQLITE_ERROR] near \"test\": syntax error"
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) > 0
        assert any("sqlite" in e.lower() for e in errors)

    def test_detect_oracle_error(self):
        """Test detection of Oracle errors."""
        response = "ORA-00933: SQL command not properly ended"
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) > 0
        assert any("oracle" in e.lower() for e in errors)

    def test_no_error_in_clean_response(self):
        """Test no false positives on clean response."""
        response = "Welcome to our website! Please log in."
        errors = self.tool._detect_sql_errors(response)
        assert len(errors) == 0

    # === Success/Failure Detection Tests ===

    def test_detect_success_welcome(self):
        """Test detection of success indicators."""
        response = "Welcome admin! Your dashboard is ready."
        success = self.tool._detect_success(response)
        assert "welcome" in success or "dashboard" in success or "admin" in success

    def test_detect_success_flag(self):
        """Test detection of flag patterns."""
        response = "Here is your flag: picoCTF{test_flag}"
        success = self.tool._detect_success(response)
        assert "flag" in success or "picoctf{" in success

    def test_detect_failure_indicators(self):
        """Test detection of failure indicators."""
        response = "Invalid username or password. Authentication failed."
        failures = self.tool._detect_failure(response)
        assert any(f in failures for f in ["invalid", "failed"])

    # === Flag Extraction Tests ===

    def test_extract_flag_picoctf(self):
        """Test extraction of picoCTF flag."""
        response = "Congrats! picoCTF{sql_1nj3ct10n_ftw}"
        flag = self.tool._extract_flag(response)
        assert flag == "picoCTF{sql_1nj3ct10n_ftw}"

    def test_extract_flag_generic(self):
        """Test extraction of generic flag."""
        response = "You found it: flag{secret_data_123}"
        flag = self.tool._extract_flag(response)
        assert flag == "flag{secret_data_123}"

    def test_extract_flag_htb(self):
        """Test extraction of HackTheBox flag."""
        response = "Root flag: HTB{h4ck_th3_b0x}"
        flag = self.tool._extract_flag(response)
        assert flag == "HTB{h4ck_th3_b0x}"

    def test_no_flag_in_response(self):
        """Test no flag when none present."""
        response = "Login failed. Try again."
        flag = self.tool._extract_flag(response)
        assert flag is None

    # === HTTP Request Tests ===

    @patch.object(SqliProbeTool, '_detect_sql_errors')
    @patch.object(SqliProbeTool, '_detect_success')
    @patch.object(SqliProbeTool, '_detect_failure')
    @patch.object(SqliProbeTool, '_extract_flag')
    def test_probe_with_get_method(self, mock_flag, mock_fail, mock_success, mock_errors):
        """Test probing with GET method."""
        mock_errors.return_value = []
        mock_success.return_value = []
        mock_fail.return_value = []
        mock_flag.return_value = None

        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["'"]
        }))

        assert "SqliProbeTool" in result
        assert "SQL Injection Probe Results" in result
        mock_session.get.assert_called()

    @patch.object(SqliProbeTool, '_detect_sql_errors')
    @patch.object(SqliProbeTool, '_detect_success')
    @patch.object(SqliProbeTool, '_detect_failure')
    @patch.object(SqliProbeTool, '_extract_flag')
    def test_probe_with_post_method(self, mock_flag, mock_fail, mock_success, mock_errors):
        """Test probing with POST method."""
        mock_errors.return_value = []
        mock_success.return_value = []
        mock_fail.return_value = []
        mock_flag.return_value = None

        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Normal response"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["admin' --"],
            "data": {"password": "test"}
        }))

        assert "SqliProbeTool" in result
        mock_session.post.assert_called()

    def test_probe_detects_sql_error(self):
        """Test that probe detects SQL errors in response."""
        mock_session = Mock()

        # Baseline response
        baseline_response = Mock()
        baseline_response.text = "Normal page"
        baseline_response.status_code = 200

        # Error response
        error_response = Mock()
        error_response.text = "You have an error in your SQL syntax near '''"
        error_response.status_code = 200

        mock_session.get.side_effect = [baseline_response, error_response]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["'"]
        }))

        assert "INTERESTING PAYLOADS" in result
        assert "SQL errors" in result.lower() or "error" in result.lower()

    def test_probe_detects_auth_bypass(self):
        """Test that probe detects successful auth bypass."""
        mock_session = Mock()

        # Baseline (failed login)
        baseline_response = Mock()
        baseline_response.text = "Invalid username or password"
        baseline_response.status_code = 200

        # Bypass response (success)
        bypass_response = Mock()
        bypass_response.text = "Welcome admin! Dashboard loaded. Here is your flag: CTF{bypassed}"
        bypass_response.status_code = 200

        mock_session.post.side_effect = [baseline_response, bypass_response]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["' OR '1'='1' --"],
            "data": {"password": "x"}
        }))

        assert "INTERESTING PAYLOADS" in result
        assert "FLAG" in result or "CTF{bypassed}" in result

    def test_probe_handles_timeout(self):
        """Test that probe handles request timeouts."""
        import requests

        mock_session = Mock()
        baseline_response = Mock()
        baseline_response.text = "Normal"
        baseline_response.status_code = 200

        mock_session.get.side_effect = [
            baseline_response,
            requests.exceptions.Timeout("Connection timed out")
        ]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["' AND SLEEP(10) --"]
        }))

        assert "TIMEOUT" in result or "timed out" in result.lower()


class TestSqliColumnCounter:
    """Tests for the SqliColumnCounter class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = SqliColumnCounter()

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
        result = self.tool.use(json.dumps({
            "url": "http://test.com",
            "method": "PUT",
            "param": "id"
        }))
        assert "Error" in result
        assert "method" in result.lower()

    def test_invalid_technique(self):
        """Test handling of invalid technique."""
        result = self.tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "technique": "invalid"
        }))
        assert "Error" in result
        assert "technique" in result.lower()

    # === ORDER BY Technique Tests ===

    def test_order_by_finds_columns(self):
        """Test ORDER BY technique finds correct column count."""
        mock_session = Mock()

        # Baseline
        baseline = Mock()
        baseline.text = "Normal data"
        baseline.status_code = 200

        # ORDER BY 1, 2, 3 succeed, ORDER BY 4 fails
        ok_response = Mock()
        ok_response.text = "Normal data with results"
        ok_response.status_code = 200

        error_response = Mock()
        error_response.text = "Unknown column '4' in order clause"
        error_response.status_code = 200

        mock_session.get.side_effect = [
            baseline,
            ok_response,  # ORDER BY 1
            ok_response,  # ORDER BY 2
            ok_response,  # ORDER BY 3
            error_response  # ORDER BY 4
        ]

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id",
            "technique": "order_by",
            "prefix": "'",
            "suffix": " --",
            "max_columns": 10
        }))

        assert "3 columns detected" in result
        assert "ORDER BY 3: OK" in result

    def test_order_by_with_post(self):
        """Test ORDER BY technique with POST method."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "Login form"
        baseline.status_code = 200

        ok_response = Mock()
        ok_response.text = "Data"
        ok_response.status_code = 200

        error_response = Mock()
        error_response.text = "Error in ORDER BY"
        error_response.status_code = 200

        mock_session.post.side_effect = [
            baseline,
            ok_response,
            error_response
        ]

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/search",
            "method": "POST",
            "param": "query",
            "technique": "order_by"
        }))

        assert "Column Count Detection" in result
        mock_session.post.assert_called()

    # === UNION NULL Technique Tests ===

    def test_union_null_finds_columns(self):
        """Test UNION NULL technique finds correct column count."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "x" * 100  # 100 chars
        baseline.status_code = 200

        # UNION with wrong column count
        wrong_count = Mock()
        wrong_count.text = "different number of columns in UNION"
        wrong_count.status_code = 200

        # UNION with correct column count (3)
        correct_count = Mock()
        correct_count.text = "x" * 110  # Similar length to baseline
        correct_count.status_code = 200

        mock_session.get.side_effect = [
            baseline,
            wrong_count,  # 1 NULL
            wrong_count,  # 2 NULLs
            correct_count  # 3 NULLs - success
        ]

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id",
            "technique": "union_null",
            "max_columns": 5
        }))

        assert "3 columns detected" in result or "SUCCESS" in result

    # === Error Handling Tests ===

    def test_handles_connection_error(self):
        """Test handling of connection errors."""
        mock_session = Mock()
        mock_session.get.side_effect = Exception("Connection refused")

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com/page",
            "method": "GET",
            "param": "id"
        }))

        assert "Error" in result


class TestSqliToolsCTFScenarios:
    """Test CTF-specific scenarios with SQLi tools."""

    def test_login_bypass_scenario(self):
        """Test complete login bypass scenario."""
        mock_session = Mock()

        # Baseline - failed login
        baseline = Mock()
        baseline.text = "<html><body>Login failed. Invalid credentials.</body></html>"
        baseline.status_code = 200

        # Successful bypass
        success = Mock()
        success.text = """<html><body>
        <h1>Welcome admin!</h1>
        <p>You are logged in as administrator.</p>
        <p>Secret flag: picoCTF{sql_1nj3ct10n_m4st3r}</p>
        </body></html>"""
        success.status_code = 200

        mock_session.post.side_effect = [baseline, success]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://ctf.challenge.com/login",
            "method": "POST",
            "param": "username",
            "payload_set": "custom",
            "custom_payloads": ["admin' --"],
            "data": {"password": "anything"}
        }))

        assert "FLAGS FOUND" in result or "picoCTF" in result
        assert "INTERESTING PAYLOADS" in result

    def test_error_based_extraction_scenario(self):
        """Test error-based SQL injection detection scenario."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "Product not found"
        baseline.status_code = 200

        error_response = Mock()
        error_response.text = """
        Error: You have an error in your SQL syntax;
        check the manual that corresponds to your MySQL server version
        for the right syntax to use near ''1''' at line 1
        """
        error_response.status_code = 200

        mock_session.get.side_effect = [baseline, error_response]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://ctf.challenge.com/product",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["'"]
        }))

        assert "INTERESTING PAYLOADS" in result
        assert "MySQL" in result or "SQL errors" in result

    def test_union_column_count_scenario(self):
        """Test finding column count for UNION injection."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "<table><tr><td>Item1</td><td>Desc1</td><td>Price1</td></tr></table>"
        baseline.status_code = 200

        # Wrong column counts
        error1 = Mock()
        error1.text = "The used SELECT statements have a different number of columns"
        error1.status_code = 200

        error2 = Mock()
        error2.text = "The used SELECT statements have a different number of columns"
        error2.status_code = 200

        # Correct column count (3)
        success = Mock()
        success.text = "<table><tr><td>Item1</td><td>Desc1</td><td>Price1</td></tr></table>"
        success.status_code = 200

        mock_session.get.side_effect = [baseline, error1, error2, success]

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://ctf.challenge.com/products",
            "method": "GET",
            "param": "category",
            "technique": "union_null",
            "prefix": "'",
            "suffix": " --"
        }))

        assert "Column Count Detection" in result
        # Should suggest next steps
        assert "UNION SELECT" in result or "columns" in result.lower()


class TestSqliToolsEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_custom_payloads(self):
        """Test handling of empty custom payloads list."""
        tool = SqliProbeTool()
        result = tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": []
        }))
        assert "Error" in result

    def test_special_characters_in_payload(self):
        """Test payloads with special characters."""
        mock_session = Mock()
        response = Mock()
        response.text = "Normal"
        response.status_code = 200
        mock_session.get.return_value = response

        tool = SqliProbeTool(session=mock_session)

        # Should handle unicode and special chars
        result = tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["' OR '1'='1' --", "\" OR \"\"=\"", "';--"]
        }))

        assert "SqliProbeTool" in result

    def test_large_response_handling(self):
        """Test handling of large responses."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "x" * 10000
        baseline.status_code = 200

        large_response = Mock()
        large_response.text = "y" * 50000  # Large response
        large_response.status_code = 200

        mock_session.get.side_effect = [baseline, large_response]

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "payload_set": "custom",
            "custom_payloads": ["test"]
        }))

        assert "SqliProbeTool" in result

    def test_column_counter_max_columns_limit(self):
        """Test that column counter respects max_columns limit."""
        mock_session = Mock()

        baseline = Mock()
        baseline.text = "Data"
        baseline.status_code = 200

        # All attempts fail
        error_response = Mock()
        error_response.text = "Error in query"
        error_response.status_code = 200

        mock_session.get.side_effect = [baseline] + [error_response] * 5

        tool = SqliColumnCounter(session=mock_session)

        result = tool.use(json.dumps({
            "url": "http://test.com",
            "method": "GET",
            "param": "id",
            "technique": "order_by",
            "max_columns": 5
        }))

        # Should stop at max_columns, not test beyond
        assert mock_session.get.call_count <= 7  # baseline + up to 5 ORDER BY tests + potential extra


class TestSqliteBypassPayloadSet:
    """Tests for the sqlite_bypass payload set in SqliProbeTool."""

    def setup_method(self):
        self.tool = SqliProbeTool()

    def test_sqlite_bypass_payload_set_exists(self):
        """Test that SQLITE_BYPASS_PAYLOADS attribute exists and has payloads."""
        assert hasattr(self.tool, "SQLITE_BYPASS_PAYLOADS")
        assert len(self.tool.SQLITE_BYPASS_PAYLOADS) > 0

    def test_sqlite_bypass_in_get_payloads(self):
        """Test that _get_payloads returns sqlite_bypass payloads."""
        payloads = self.tool._get_payloads("sqlite_bypass")
        assert len(payloads) > 0
        assert payloads is self.tool.SQLITE_BYPASS_PAYLOADS

    def test_sqlite_bypass_validation_accepted(self):
        """Test that 'sqlite_bypass' is accepted as a valid payload_set."""
        mock_session = MagicMock()
        baseline = MagicMock()
        baseline.status_code = 200
        baseline.text = "Login failed"

        normal_resp = MagicMock()
        normal_resp.status_code = 200
        normal_resp.text = "Login failed"

        # baseline + one response per payload
        num_payloads = len(SqliProbeTool.SQLITE_BYPASS_PAYLOADS)
        mock_session.post.side_effect = [baseline] + [normal_resp] * num_payloads

        tool = SqliProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/login",
            "method": "POST",
            "param": "username",
            "payload_set": "sqlite_bypass",
        }))

        assert "Error" not in result or "Probe Results" in result

    def test_sqlite_bypass_contains_concatenation_payloads(self):
        """Test that bypass payloads include admin concatenation techniques."""
        payloads = self.tool.SQLITE_BYPASS_PAYLOADS
        concat_payloads = [p for p in payloads if "||" in p and "min" in p]
        assert len(concat_payloads) > 0, "Should have admin concatenation bypass payloads"

    def test_sqlite_bypass_contains_is_operator(self):
        """Test that bypass payloads include IS operator alternatives."""
        payloads = self.tool.SQLITE_BYPASS_PAYLOADS
        is_payloads = [p for p in payloads if " IS " in p]
        assert len(is_payloads) > 0, "Should have IS operator bypass payloads"

    def test_sqlite_bypass_contains_glob_operator(self):
        """Test that bypass payloads include GLOB operator alternatives."""
        payloads = self.tool.SQLITE_BYPASS_PAYLOADS
        glob_payloads = [p for p in payloads if "GLOB" in p]
        assert len(glob_payloads) > 0, "Should have GLOB operator bypass payloads"
