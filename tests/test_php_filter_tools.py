"""
Tests for PHP filter chain tools (PhpFilterChainTool).

Covers:
- Tool name/description
- All 4 operations: file_read, rce, oracle, reference
- Error handling for invalid JSON, missing operation, unknown operation
- Output content validation
"""

import json

import pytest

from ctf_solver.tools.php_filter_tools import PhpFilterChainTool


class TestPhpFilterChainTool:
    """Tests for PhpFilterChainTool."""

    def setup_method(self):
        self.tool = PhpFilterChainTool()

    # -- identity -----------------------------------------------------------

    def test_tool_name(self):
        assert self.tool.name == "php_filter_chain"

    def test_tool_description_mentions_php(self):
        assert "php" in self.tool.description.lower()

    # -- error handling -----------------------------------------------------

    def test_invalid_json(self):
        result = self.tool.use("not-json")
        assert "Error" in result
        assert "tool_input must be JSON" in result

    def test_missing_operation(self):
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_unknown_operation(self):
        result = self.tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in result
        assert "Unknown operation" in result

    # -- file_read ----------------------------------------------------------

    def test_file_read_default(self):
        result = self.tool.use(json.dumps({"operation": "file_read"}))
        assert "php://filter" in result
        assert "/etc/passwd" in result
        assert "base64" in result.lower()

    def test_file_read_custom_file(self):
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "file_read",
                    "file": "/flag.txt",
                }
            )
        )
        assert "/flag.txt" in result

    def test_file_read_contains_multiple_chains(self):
        """Should generate multiple filter chain variants."""
        result = self.tool.use(json.dumps({"operation": "file_read"}))
        assert result.count("php://filter") >= 3

    # -- rce ----------------------------------------------------------------

    def test_rce_default(self):
        result = self.tool.use(json.dumps({"operation": "rce"}))
        assert "RCE" in result
        assert "system" in result or "Synacktiv" in result

    def test_rce_custom_payload(self):
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "rce",
                    "payload": "phpinfo();",
                }
            )
        )
        assert "phpinfo" in result

    def test_rce_mentions_techniques(self):
        result = self.tool.use(json.dumps({"operation": "rce"}))
        # Should mention at least 2 techniques
        techniques = ["iconv", "data://", "expect://", "pearcmd"]
        found = sum(1 for t in techniques if t in result)
        assert found >= 2, f"Only found {found} RCE techniques"

    # -- oracle -------------------------------------------------------------

    def test_oracle_output(self):
        result = self.tool.use(json.dumps({"operation": "oracle"}))
        assert "oracle" in result.lower() or "error" in result.lower()

    def test_oracle_custom_file(self):
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "oracle",
                    "file": "/etc/shadow",
                }
            )
        )
        assert "/etc/shadow" in result

    # -- reference ----------------------------------------------------------

    def test_reference_output(self):
        result = self.tool.use(json.dumps({"operation": "reference"}))
        assert "php://" in result or "wrapper" in result.lower()

    def test_reference_mentions_wrappers(self):
        result = self.tool.use(json.dumps({"operation": "reference"}))
        wrappers = ["php://", "data://", "file://", "phar://"]
        found = sum(1 for w in wrappers if w in result)
        assert found >= 2

    # -- all operations valid -----------------------------------------------

    def test_all_operations_produce_output(self):
        for op in PhpFilterChainTool.VALID_OPERATIONS:
            result = self.tool.use(json.dumps({"operation": op}))
            # Check it doesn't start with a JSON parse error (the oracle output
            # legitimately contains the word "Error" in "Error-based oracle")
            assert not result.startswith(
                "[PhpFilterChainTool] Error:"
            ), f"Operation {op} returned error"
            assert len(result) > 50, f"Operation {op} output too short"
