"""
Tests for the failure analyzer module (post-legacy cleanup).

Covers:
- RAGMode enum + config integration (now lessons_* modes only)
- RunTracker study-specific fields
- LoggingToolWrapper detailed capture
- StuckDetection
"""

from ctf_solver.config import RAGMode, SolverConfig
from ctf_solver.run_tracker import RunTracker


class TestRAGModeConfig:
    """Tests for RAGMode enum and config integration."""

    def test_rag_mode_enum_values(self):
        assert RAGMode.NONE.value == "none"
        assert RAGMode.ORIGINAL.value == "original"
        assert RAGMode.LESSONS_WRITE.value == "lessons_write"
        assert RAGMode.LESSONS_READONLY.value == "lessons_readonly"
        assert RAGMode.LESSONS_BUILDONLY.value == "lessons_buildonly"

    def test_legacy_augmented_names_removed(self):
        # The old AUGMENTED / AUGMENTED_READONLY aliases were deleted when
        # the monolithic failure/success pipeline was retired.
        assert not hasattr(RAGMode, "AUGMENTED")
        assert not hasattr(RAGMode, "AUGMENTED_READONLY")

    def test_legacy_augmented_string_falls_back_to_original(self):
        # Previously "augmented" was a valid rag_mode string; now it's
        # unknown and the constructor falls back to ORIGINAL.
        config = SolverConfig(rag_mode="augmented")
        assert config.rag_mode == RAGMode.ORIGINAL

    def test_config_default_rag_mode(self):
        config = SolverConfig()
        assert config.rag_mode == RAGMode.ORIGINAL

    def test_config_rag_mode_from_string(self):
        config = SolverConfig(rag_mode="lessons_write")
        assert config.rag_mode == RAGMode.LESSONS_WRITE

    def test_config_rag_mode_none(self):
        config = SolverConfig(rag_mode="none")
        assert config.rag_mode == RAGMode.NONE

    def test_config_rag_mode_invalid_falls_back(self):
        config = SolverConfig(rag_mode="invalid_mode")
        assert config.rag_mode == RAGMode.ORIGINAL

    def test_config_failure_docs_dir_default(self):
        # failure_docs_dir is preserved as a legacy doc source (read-only
        # for _build_rag_config) even though we no longer write there.
        config = SolverConfig()
        assert config.failure_docs_dir == "out/failure_knowledge"

    def test_config_auto_analyze_default(self):
        config = SolverConfig()
        assert config.auto_analyze_failures is False

    def test_config_merge_preserves_rag_mode(self):
        config = SolverConfig(rag_mode="lessons_write")
        merged = config.merge_with_args(max_steps=30)
        assert merged.rag_mode == RAGMode.LESSONS_WRITE
        assert merged.max_steps == 30

    def test_config_merge_overrides_rag_mode(self):
        config = SolverConfig(rag_mode="original")
        merged = config.merge_with_args(rag_mode="none")
        assert merged.rag_mode == RAGMode.NONE


# ===========================================================================
# TestRunTracker
# ===========================================================================


class TestRunTrackerStudyFields:
    """Tests for RunTracker study-specific fields."""

    def test_default_values(self):
        tracker = RunTracker()
        assert tracker.rag_mode == ""
        assert tracker.challenge_url == ""
        assert tracker.run_succeeded is False
        assert tracker.candidate_flags_found == []
        assert tracker.failure_doc_generated is False
        assert tracker.tool_call_log == []

    def test_record_detailed_tool_call(self):
        tracker = RunTracker()
        tracker.record_detailed_tool_call(
            tool_name="sqli_probe",
            tool_input='{"url": "http://example.com"}',
            tool_output="Result: SQL error",
        )
        assert len(tracker.tool_call_log) == 1
        entry = tracker.tool_call_log[0]
        assert entry["tool"] == "sqli_probe"
        assert "example.com" in entry["input"]
        assert "SQL error" in entry["output"]
        assert "timestamp" in entry

    def test_detailed_tool_call_truncation(self):
        tracker = RunTracker()
        long_input = "x" * 5000
        long_output = "y" * 5000
        tracker.record_detailed_tool_call("test_tool", long_input, long_output)
        entry = tracker.tool_call_log[0]
        assert len(entry["input"]) == 2000
        assert len(entry["output"]) == 2000

    def test_to_dict_includes_study_fields(self):
        tracker = RunTracker()
        tracker.rag_mode = "augmented"
        tracker.run_succeeded = True
        tracker.candidate_flags_found = ["picoCTF{test}"]
        tracker.failure_doc_generated = True

        data = tracker.to_dict()
        assert data["rag_mode"] == "augmented"
        assert data["run_succeeded"] is True
        assert data["candidate_flags_found"] == ["picoCTF{test}"]
        assert data["failure_doc_generated"] is True


# ===========================================================================
# TestLoggingWrapper
# ===========================================================================


class TestLoggingWrapperDetailedCapture:
    """Tests that LoggingToolWrapper records detailed tool calls."""

    def test_records_detailed_call_when_tracker_has_method(self):
        from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

        class FakeTool:
            name = "fake_tool"
            description = "A fake tool"

            def use(self, tool_input):
                return "fake result"

        tracker = RunTracker()
        wrapper = LoggingToolWrapper(FakeTool(), tracker=tracker)
        wrapper.use('{"action": "test"}')

        assert len(tracker.tool_call_log) == 1
        assert tracker.tool_call_log[0]["tool"] == "fake_tool"
        assert "test" in tracker.tool_call_log[0]["input"]
        assert "fake result" in tracker.tool_call_log[0]["output"]

    def test_no_error_without_tracker(self):
        from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

        class FakeTool:
            name = "fake_tool"
            description = "A fake tool"

            def use(self, tool_input):
                return "result"

        wrapper = LoggingToolWrapper(FakeTool(), tracker=None)
        result = wrapper.use("input")
        # v3.8: wrapper now prepends a structured `[<tool>] result=…;`
        # header so a 26B model can grep one line for outcome.  The
        # original prose ("result") still follows verbatim.
        assert "result" in result
        assert result.startswith("[fake_tool] result=info;")


class TestStuckDetection:
    """Tests for StuckDetector and stuck detection in LoggingToolWrapper."""

    def test_no_warning_below_threshold(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        assert detector.check("tool_a", "input1") is None
        assert detector.check("tool_a", "input1") is None

    def test_warning_at_threshold(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        detector.check("tool_a", "input1")
        detector.check("tool_a", "input1")
        warning = detector.check("tool_a", "input1")
        assert warning is not None
        assert "3 times" in warning
        assert "stuck" in warning.lower()

    def test_warning_increases_count(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        for _ in range(3):
            detector.check("tool_a", "input1")
        warning = detector.check("tool_a", "input1")
        assert "4 times" in warning

    def test_different_inputs_no_warning(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        for i in range(10):
            result = detector.check("tool_a", f"input_{i}")
            assert result is None

    def test_different_tools_no_warning(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        assert detector.check("tool_a", "same_input") is None
        assert detector.check("tool_b", "same_input") is None
        assert detector.check("tool_c", "same_input") is None

    def test_no_stuck_detection_without_tracker(self):
        from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

        class FakeTool:
            name = "fake"
            description = "fake"

            def use(self, tool_input):
                return "result"

        wrapper = LoggingToolWrapper(FakeTool(), tracker=None)
        # Call 5 times with same input — no warning since no tracker
        for _ in range(5):
            result = wrapper.use("same_input")
            assert "[WARNING]" not in result

    def test_stuck_detector_reset(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        detector.check("tool_a", "input1")
        detector.check("tool_a", "input1")
        detector.reset()
        # After reset, count is back to 0
        assert detector.check("tool_a", "input1") is None

    def test_integration_with_logging_wrapper(self):
        from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

        class FakeTool:
            name = "fake"
            description = "fake"

            def use(self, tool_input):
                return "normal result"

        tracker = RunTracker()
        wrapper = LoggingToolWrapper(FakeTool(), tracker=tracker)

        # First two calls: no warning
        r1 = wrapper.use("same_input")
        assert "[WARNING]" not in r1 and "[SELF-REFLECTION]" not in r1
        r2 = wrapper.use("same_input")
        assert "[WARNING]" not in r2 and "[SELF-REFLECTION]" not in r2

        # Third call: warning or self-reflection appended
        r3 = wrapper.use("same_input")
        assert "[WARNING]" in r3 or "[SELF-REFLECTION]" in r3
        assert "stuck" in r3.lower()

    def test_whitespace_normalization(self):
        from ctf_solver.tools.logging_wrapper import StuckDetector

        detector = StuckDetector(threshold=3)
        detector.check("tool_a", "  input1  ")
        detector.check("tool_a", "input1")
        warning = detector.check("tool_a", "  input1")
        assert warning is not None
