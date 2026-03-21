"""
Tests for the guarded category override fix (v2.7.0).

The bug: _PARTIAL_SUCCESS_CATEGORY_OVERRIDE applied ssti_confirmed → "ssti"
whenever \b49\b appeared anywhere in tool outputs, regardless of whether any
SSTI-related tool or probe was actually used.  This caused two failure modes:

1. Cookie Monster: "49" appeared innocuously in output (path_enumerator, HTTP
   body size, etc.) → mislabeled as SSTI.
2. SSTI1 solved via form_submit + {{7*7}} (no ssti_probe used) → initial
   tool-name-only guard wrongly blocked the legitimate SSTI override.

Fix: _augment_tool_counts adds a virtual "_ssti_template_probe" key when any
tool input contained {{7*7}}-style arithmetic probes.  _guarded_category_override
accepts this virtual key as valid SSTI evidence alongside specialist tool names.
"""

from ctf_solver.failure_analyzer import (
    _augment_tool_counts,
    _detect_partial_successes,
    _guarded_category_override,
)


class TestAugmentToolCounts:
    """Unit tests for _augment_tool_counts (virtual probe-evidence keys)."""

    def test_adds_ssti_template_probe_for_7x7(self):
        log = [{"tool": "form_submit", "input": '{"data": {"content": "{{7*7}}"}}', "output": "49"}]
        result = _augment_tool_counts({"form_submit": 1}, log)
        assert "_ssti_template_probe" in result

    def test_adds_ssti_template_probe_for_8x8(self):
        log = [{"tool": "form_submit", "input": "{{8*8}}", "output": "64"}]
        result = _augment_tool_counts({"form_submit": 1}, log)
        assert "_ssti_template_probe" in result

    def test_adds_ssti_template_probe_for_7x7_with_quotes(self):
        log = [{"tool": "form_submit", "input": "{{7*'7'}}", "output": "7777777"}]
        result = _augment_tool_counts({"form_submit": 1}, log)
        assert "_ssti_template_probe" in result

    def test_no_probe_key_when_no_template_input(self):
        """Cookie Monster scenario: no {{N*N}} in any input."""
        log = [
            {"tool": "http_fetch", "input": '{"url": "http://example.com"}', "output": "49 paths found"},
            {"tool": "encoding", "input": '{"text": "abc==", "operation": "base64_decode"}', "output": "flag"},
        ]
        result = _augment_tool_counts({"http_fetch": 3, "encoding": 1}, log)
        assert "_ssti_template_probe" not in result

    def test_does_not_modify_original_dict(self):
        original = {"http_fetch": 2}
        log = [{"tool": "form_submit", "input": "{{7*7}}", "output": "49"}]
        _augment_tool_counts(original, log)
        assert "_ssti_template_probe" not in original

    def test_empty_log_returns_copy_of_counts(self):
        result = _augment_tool_counts({"http_fetch": 1}, [])
        assert result == {"http_fetch": 1}
        assert "_ssti_template_probe" not in result


class TestSstiConfirmedOutputPatterns:
    """ssti_confirmed must fire on all common arithmetic probe results, not just 49."""

    def _log_with_output(self, output: str):
        return [{"tool": "form_submit", "input": "{{8*8}}", "output": output}]

    def test_49_fires(self):
        assert "ssti_confirmed" in _detect_partial_successes(self._log_with_output("Hello 49!"))

    def test_64_fires(self):
        assert "ssti_confirmed" in _detect_partial_successes(self._log_with_output("Result: 64"))

    def test_36_fires(self):
        assert "ssti_confirmed" in _detect_partial_successes(self._log_with_output("value=36"))

    def test_81_fires(self):
        assert "ssti_confirmed" in _detect_partial_successes(self._log_with_output("output: 81"))

    def test_7777777_fires(self):
        assert "ssti_confirmed" in _detect_partial_successes(
            self._log_with_output("Hello 7777777!")
        )

    def test_unrelated_number_does_not_fire(self):
        assert "ssti_confirmed" not in _detect_partial_successes(
            self._log_with_output("Found 12 paths")
        )


class TestGuardedCategoryOverride:
    """Unit tests for _guarded_category_override."""

    # ------------------------------------------------------------------
    # ssti_confirmed guard — specialist tool names
    # ------------------------------------------------------------------

    def test_ssti_confirmed_with_ssti_probe_overrides(self):
        """ssti_confirmed overrides to 'ssti' when ssti_probe was used."""
        result = _guarded_category_override(
            ["ssti_confirmed"], {"ssti_probe": 2, "http_fetch": 5}, "client_side"
        )
        assert result == "ssti"

    def test_ssti_confirmed_with_ssti_exploit_suggester_overrides(self):
        """ssti_confirmed overrides to 'ssti' when ssti_exploit_suggester was used."""
        result = _guarded_category_override(
            ["ssti_confirmed"], {"ssti_exploit_suggester": 1, "form_submit": 3}, "recon"
        )
        assert result == "ssti"

    def test_ssti_confirmed_with_template_probe_virtual_key_overrides(self):
        """SSTI1 scenario: form_submit + {{7*7}} → _ssti_template_probe added by
        _augment_tool_counts — override must fire even without ssti_probe tool."""
        augmented = {"form_submit": 3, "http_fetch": 2, "_ssti_template_probe": 1}
        result = _guarded_category_override(["ssti_confirmed"], augmented, "client_side")
        assert result == "ssti"

    def test_ssti_confirmed_without_any_evidence_is_ignored(self):
        """Cookie Monster scenario: \b49\b fires but no SSTI evidence at all.

        No ssti_probe, no ssti_exploit_suggester, no {{7*7}} in inputs.
        Category must stay as client_side.
        """
        result = _guarded_category_override(
            ["ssti_confirmed"],
            {"http_fetch": 5, "javascript_source": 2, "path_enumerator": 3, "encoding": 1},
            "client_side",
        )
        assert result == "client_side"

    def test_ssti_confirmed_with_only_form_submit_no_probe_is_ignored(self):
        """form_submit alone (no {{N*N}} input, no ssti_probe) is not SSTI evidence."""
        result = _guarded_category_override(
            ["ssti_confirmed"], {"form_submit": 4, "robots_txt": 1}, "recon"
        )
        assert result == "recon"

    # ------------------------------------------------------------------
    # sqli_confirmed guard
    # ------------------------------------------------------------------

    def test_sqli_confirmed_with_sqli_probe_overrides(self):
        result = _guarded_category_override(
            ["sqli_confirmed"], {"sqli_probe": 3, "http_fetch": 2}, "recon"
        )
        assert result == "sql_injection"

    def test_sqli_confirmed_without_specialist_tool_is_ignored(self):
        result = _guarded_category_override(
            ["sqli_confirmed"], {"http_fetch": 3, "form_submit": 2}, "unknown"
        )
        assert result == "unknown"

    def test_schema_extracted_with_blind_sqli_overrides(self):
        result = _guarded_category_override(
            ["schema_extracted"], {"blind_sqli_boolean": 5}, "recon"
        )
        assert result == "sql_injection"

    def test_schema_extracted_without_specialist_tool_is_ignored(self):
        result = _guarded_category_override(
            ["schema_extracted"], {"http_fetch": 2}, "recon"
        )
        assert result == "recon"

    # ------------------------------------------------------------------
    # auth_bypassed has no required tool guard (observable from HTTP alone)
    # ------------------------------------------------------------------

    def test_auth_bypassed_always_overrides(self):
        """auth_bypassed has no specialist-tool guard — HTTP output is sufficient."""
        result = _guarded_category_override(
            ["auth_bypassed"], {"http_fetch": 3, "form_submit": 2}, "recon"
        )
        assert result == "cookies_auth"

    # ------------------------------------------------------------------
    # source_disclosed guard
    # ------------------------------------------------------------------

    def test_source_disclosed_with_lfi_probe_overrides(self):
        result = _guarded_category_override(
            ["source_disclosed"], {"lfi_probe": 2, "http_fetch": 4}, "recon"
        )
        assert result == "file_inclusion"

    def test_source_disclosed_without_lfi_tool_is_ignored(self):
        result = _guarded_category_override(
            ["source_disclosed"], {"http_fetch": 5}, "client_side"
        )
        assert result == "client_side"

    # ------------------------------------------------------------------
    # Priority: first matching signal wins
    # ------------------------------------------------------------------

    def test_first_valid_signal_wins(self):
        """When multiple signals fire, the first with a valid guard wins."""
        result = _guarded_category_override(
            ["ssti_confirmed", "sqli_confirmed"],
            {"ssti_probe": 1, "sqli_probe": 1},
            "unknown",
        )
        assert result == "ssti"

    def test_skips_invalid_guard_takes_next_valid(self):
        """If the first signal lacks its specialist tool, the next one is tried."""
        result = _guarded_category_override(
            ["ssti_confirmed", "sqli_confirmed"],
            {"sqli_probe": 2},  # no ssti_probe — skip ssti_confirmed
            "unknown",
        )
        assert result == "sql_injection"

    # ------------------------------------------------------------------
    # Empty / no-signal cases
    # ------------------------------------------------------------------

    def test_no_partial_successes_returns_current(self):
        result = _guarded_category_override([], {"http_fetch": 3}, "client_side")
        assert result == "client_side"

    def test_unknown_signal_returns_current(self):
        result = _guarded_category_override(
            ["recon_complete"], {"http_fetch": 5}, "recon"
        )
        assert result == "recon"

    def test_empty_tool_counts_with_guarded_signal_returns_current(self):
        result = _guarded_category_override(["ssti_confirmed"], {}, "unknown")
        assert result == "unknown"
