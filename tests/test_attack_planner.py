"""
Tests for attack_planner.py
"""

import json
import pytest

from ctf_solver.tools.attack_planner import AttackPlannerTool


class TestAttackPlannerTool:
    """Tests for the AttackPlannerTool class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = AttackPlannerTool()

    # === Input Validation Tests ===

    def test_missing_operation(self):
        """Test handling of missing operation parameter."""
        result = self.tool.use(json.dumps({"challenge_type": "sql_injection"}))
        assert "[AttackPlannerTool] Error" in result
        assert "'operation'" in result

    def test_invalid_operation(self):
        """Test handling of invalid operation parameter."""
        result = self.tool.use(json.dumps({
            "operation": "invalid_op",
            "challenge_type": "sql_injection",
        }))
        assert "[AttackPlannerTool] Error" in result
        assert "Unknown operation" in result
        assert "suggest_plan" in result
        assert "suggest_next_step" in result

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "[AttackPlannerTool] Error" in result
        assert "JSON" in result

    def test_missing_challenge_type(self):
        """Test handling of missing challenge_type parameter."""
        result = self.tool.use(json.dumps({"operation": "suggest_plan"}))
        assert "[AttackPlannerTool] Error" in result
        assert "'challenge_type'" in result

    # === suggest_plan Tests ===

    def test_suggest_plan_sql_injection(self):
        """Test attack plan generation for SQL injection."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "sql_injection",
        }))
        assert "Attack Plan for: sql_injection" in result
        assert "sqli_probe" in result
        assert "filter_enumerator" in result
        assert "sqli_column_counter" in result
        assert "blind_sqli_boolean" in result
        assert "sqli_data_dumper" in result

    def test_suggest_plan_xpath(self):
        """Test attack plan generation for XPath injection."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "xpath_injection",
        }))
        assert "Attack Plan for: xpath_injection" in result
        assert "xpath_probe" in result
        assert "xpath_blind_boolean" in result

    def test_suggest_plan_lfi(self):
        """Test attack plan generation for file inclusion."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "file_inclusion",
        }))
        assert "Attack Plan for: file_inclusion" in result
        assert "lfi_probe" in result
        assert "lfi_payload_generator" in result

    def test_suggest_plan_cmdi(self):
        """Test attack plan generation for command injection."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "command_injection",
        }))
        assert "Attack Plan for: command_injection" in result
        assert "cmdi_probe" in result

    def test_suggest_plan_ssrf(self):
        """Test attack plan generation for SSRF."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "ssrf",
        }))
        assert "Attack Plan for: ssrf" in result
        assert "ssrf_probe" in result

    def test_suggest_plan_nosql(self):
        """Test attack plan generation for NoSQL injection."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "nosql_injection",
        }))
        assert "Attack Plan for: nosql_injection" in result
        assert "nosql_probe" in result

    def test_suggest_plan_crypto(self):
        """Test attack plan generation for crypto challenges."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "crypto",
        }))
        assert "Attack Plan for: crypto" in result
        assert "crypto_analyzer" in result
        assert "crypto_probe" in result
        assert "crypto_payload_generator" in result

    def test_suggest_plan_deserialization(self):
        """Test attack plan generation for deserialization attacks."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "deserialization",
        }))
        assert "Attack Plan for: deserialization" in result
        assert "deserialization_probe" in result
        assert "deserialization_payload_generator" in result

    def test_suggest_plan_unknown(self):
        """Test attack plan generation for unknown challenge type."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "unknown",
        }))
        assert "Attack Plan for: unknown" in result
        assert "http_fetch" in result
        assert "html_analyzer" in result
        assert "ctf_knowledge_query" in result

    def test_suggest_plan_with_tools_tried(self):
        """Test that plan skips steps for tools already tried."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "sql_injection",
            "tools_tried": ["sqli_probe", "filter_enumerator"],
        }))
        assert "SKIPPED STEPS" in result
        assert "sqli_probe" in result
        assert "already tried" in result
        # Remaining tools should still be present in the active plan
        assert "sqli_column_counter" in result
        assert "blind_sqli_boolean" in result

    def test_suggest_plan_with_current_findings(self):
        """Test that plan adjusts based on current findings."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_plan",
            "challenge_type": "sql_injection",
            "current_findings": "Found a login form with username and password fields",
        }))
        assert "Current findings:" in result
        assert "login" in result.lower() or "Login" in result
        assert "authentication bypass" in result.lower() or "Adjustments" in result

    # === suggest_next_step Tests ===

    def test_suggest_next_step_basic(self):
        """Test basic next step suggestion with no completed steps."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_next_step",
            "challenge_type": "sql_injection",
        }))
        assert "Next Step Suggestion" in result
        assert "RECOMMENDED NEXT STEP" in result
        assert "sqli_probe" in result
        assert "Phase 1/" in result

    def test_suggest_next_step_with_completed_steps(self):
        """Test next step suggestion after some steps are completed."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_next_step",
            "challenge_type": "sql_injection",
            "steps_completed": [
                "probed with sqli_probe and found error-based SQLi",
                "used filter_enumerator to check for blocked keywords",
            ],
            "last_result": "Found that OR, UNION, and -- are blocked",
        }))
        assert "Next Step Suggestion" in result
        assert "Steps completed so far: 2" in result
        # Should either suggest a next step or indicate all phases completed
        assert "sqli_column_counter" in result or "blind_sqli_boolean" in result or "sqli_data_dumper" in result or "completed" in result.lower()

    def test_suggest_next_step_unknown_type(self):
        """Test next step suggestion for an unrecognized challenge type falls back to unknown."""
        result = self.tool.use(json.dumps({
            "operation": "suggest_next_step",
            "challenge_type": "completely_made_up_type",
        }))
        assert "Next Step Suggestion" in result
        assert "RECOMMENDED NEXT STEP" in result
        # Should fall back to 'unknown' plan and suggest http_fetch
        assert "http_fetch" in result

    # === Cross-cutting Tests ===

    def test_plan_includes_tool_names(self):
        """Test that every plan step includes a specific tool name."""
        for challenge_type, steps in AttackPlannerTool.ATTACK_PLANS.items():
            result = self.tool.use(json.dumps({
                "operation": "suggest_plan",
                "challenge_type": challenge_type,
            }))
            assert "Tool:" in result, f"Plan for {challenge_type} missing 'Tool:' references"

    def test_all_challenge_types_have_plans(self):
        """Test that all expected challenge types have predefined plans."""
        expected_types = [
            "sql_injection", "xpath_injection", "file_inclusion",
            "command_injection", "ssrf", "nosql_injection", "crypto",
            "deserialization", "file_upload", "filter_bypass", "ssti",
            "xxe", "jwt", "unknown",
        ]
        for ct in expected_types:
            assert ct in AttackPlannerTool.ATTACK_PLANS, f"Missing plan for challenge type: {ct}"
            assert len(AttackPlannerTool.ATTACK_PLANS[ct]) > 0, f"Empty plan for: {ct}"
