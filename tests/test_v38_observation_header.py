"""
v3.8 P1: standardized observation header on every LoggingToolWrapper output.

Format: ``[<tool>] result=<success|partial|error|info>; signal=<key>; <rest>``.
A 26B local model can grep one line to learn outcome instead of parsing
varied per-tool prose prefixes.
"""

from unittest.mock import MagicMock

from ctf_solver.tools.logging_wrapper import (
    LoggingToolWrapper,
    classify_result,
)

# ── classify_result ──────────────────────────────────────────────────


class TestClassifyResult:
    def test_flag_present_is_success(self):
        cls, sig = classify_result("found FLAG{x}", has_flag=True)
        assert cls == "success"
        assert sig == "flag_match"

    def test_error_prefix_is_error(self):
        cls, sig = classify_result(
            "[HttpFetchTool] Error: tool_input must be JSON", has_flag=False
        )
        assert cls == "error"
        assert sig == "tool_error"

    def test_warning_tag_is_partial(self):
        cls, sig = classify_result(
            "[WARNING] You have called same tool 3 times", has_flag=False
        )
        assert cls == "partial"
        assert "warning" in sig

    def test_phase_gate_is_partial(self):
        cls, sig = classify_result(
            "[PHASE-GATE] Tool gated behind sql_injection signal",
            has_flag=False,
        )
        assert cls == "partial"
        assert "phase-gate" in sig

    def test_vuln_keyword_is_partial(self):
        cls, sig = classify_result(
            "SQL injection detected via auth_bypass payload",
            has_flag=False,
        )
        assert cls == "partial"
        assert sig == "vuln_signal"

    def test_neutral_text_is_info(self):
        cls, sig = classify_result("Status: 200\nBody: ok\n", has_flag=False)
        assert cls == "info"

    def test_non_string_is_info(self):
        cls, sig = classify_result(42, has_flag=False)  # type: ignore[arg-type]
        assert cls == "info"


# ── LoggingToolWrapper integration ───────────────────────────────────


class _FakeInner:
    name = "fake_tool"
    description = "fake"

    def __init__(self, output):
        self._output = output

    def use(self, tool_input):
        return self._output


def _make_tracker():
    t = MagicMock()
    t.candidate_flags_found = []
    return t


class TestHeaderInjection:
    def test_info_path_gets_header(self):
        inner = _FakeInner("Status: 200\nBody: hello")
        wrapped = LoggingToolWrapper(inner, tracker=_make_tracker())
        out = wrapped.use('{"x": 1}')
        assert out.startswith("[fake_tool] result=info; ")

    def test_error_path_gets_header(self):
        inner = _FakeInner("[FakeTool] Error: bad input")
        wrapped = LoggingToolWrapper(inner, tracker=_make_tracker())
        out = wrapped.use('{"x": 1}')
        assert out.startswith("[fake_tool] result=error; signal=tool_error;")

    def test_partial_path_via_warning(self):
        inner = _FakeInner("normal output")
        # Run the same input twice → StuckDetector appends [WARNING].
        wrapped = LoggingToolWrapper(inner, tracker=_make_tracker())
        wrapped.use('{"x": 1}')
        wrapped.use('{"x": 1}')
        out = wrapped.use('{"x": 1}')
        assert out.startswith("[fake_tool] result=partial; ")

    def test_success_path_when_flag_in_output(self):
        inner = _FakeInner("Body: <p>FLAG{my_secret}</p>")
        wrapped = LoggingToolWrapper(
            inner,
            flag_regex=r"FLAG\{[^}]+\}",
            tracker=_make_tracker(),
        )
        out = wrapped.use('{"x": 1}')
        assert out.startswith("[fake_tool] result=success; signal=flag_match;")

    def test_idempotent_no_double_header(self):
        """Tools that already emit a v3.8-shaped header in their own output
        should not get a second header layered on."""
        inner = _FakeInner("[fake_tool] result=info; signal=; my body")
        wrapped = LoggingToolWrapper(inner, tracker=_make_tracker())
        out = wrapped.use('{"x": 1}')
        # Header appears exactly once at the start
        assert out.startswith("[fake_tool] result=info; signal=; my body")
        assert out.count("[fake_tool] result=") == 1
