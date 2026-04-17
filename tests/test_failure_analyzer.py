"""
Tests for the failure analysis engine.

Covers:
- Failure detection (detect_failure)
- Failure analysis (analyze_failure)
- Knowledge document generation (generate_failure_knowledge_doc)
- Full pipeline (run_failure_analysis_pipeline)
- RAG mode config (RAGMode enum, config defaults)
"""

import os
import tempfile
from pathlib import Path

import pytest

from ctf_solver.config import SolverConfig, RAGMode
from ctf_solver.failure_analyzer import (
    detect_failure,
    analyze_failure,
    generate_failure_knowledge_doc,
    run_failure_analysis_pipeline,
    FailureAnalysis,
)
from ctf_solver.run_tracker import RunTracker

# ===========================================================================
# TestFailureDetection
# ===========================================================================


class TestFailureDetection:
    """Tests for detect_failure()."""

    def test_no_response_is_failure(self):
        is_failure, reason = detect_failure(
            agent_response=None,
            candidate_flags=[],
            max_steps=20,
            actual_steps=5,
        )
        assert is_failure is True
        assert "no response" in reason.lower()

    def test_empty_response_is_failure(self):
        is_failure, reason = detect_failure(
            agent_response="   ",
            candidate_flags=[],
            max_steps=20,
            actual_steps=5,
        )
        assert is_failure is True
        assert "no response" in reason.lower()

    def test_no_flags_is_failure(self):
        is_failure, reason = detect_failure(
            agent_response="I analyzed the challenge but found nothing useful.",
            candidate_flags=[],
            max_steps=20,
            actual_steps=5,
        )
        assert is_failure is True
        assert "no candidate flags" in reason.lower()

    def test_max_steps_exhausted_is_failure(self):
        is_failure, reason = detect_failure(
            agent_response="Still working on it...",
            candidate_flags=["picoCTF{test}"],
            max_steps=20,
            actual_steps=20,
        )
        assert is_failure is True
        assert "max steps" in reason.lower()

    def test_agent_admits_failure(self):
        is_failure, reason = detect_failure(
            agent_response="I was unable to find the flag for this challenge.",
            candidate_flags=["picoCTF{maybe}"],
            max_steps=20,
            actual_steps=10,
        )
        assert is_failure is True
        assert "admitted failure" in reason.lower()

    def test_agent_admits_stuck(self):
        is_failure, reason = detect_failure(
            agent_response="I'm stuck and cannot determine the flag.",
            candidate_flags=["flag{test}"],
            max_steps=20,
            actual_steps=10,
        )
        assert is_failure is True

    def test_success_with_flag(self):
        is_failure, reason = detect_failure(
            agent_response="The flag is picoCTF{hello_world}",
            candidate_flags=["picoCTF{hello_world}"],
            max_steps=20,
            actual_steps=8,
        )
        assert is_failure is False
        assert "successful" in reason.lower()

    def test_success_with_flags_under_budget(self):
        is_failure, reason = detect_failure(
            agent_response="Found it!",
            candidate_flags=["flag{abc123}"],
            max_steps=20,
            actual_steps=3,
        )
        assert is_failure is False


# ===========================================================================
# TestFailureAnalysis
# ===========================================================================


class TestFailureAnalysis:
    """Tests for analyze_failure()."""

    @pytest.fixture
    def sample_config_data(self):
        return {
            "challenge_url": "http://example.com/login",
            "challenge_description": "SQL injection login bypass",
        }

    @pytest.fixture
    def sample_tracker_data(self):
        return {
            "duration_seconds": 45.2,
            "steps": 12,
            "llm_calls": 8,
            "tool_calls": {
                "http_fetch": 5,
                "sqli_probe": 4,
                "form_submit": 3,
            },
        }

    @pytest.fixture
    def sample_tool_call_log(self):
        return [
            {
                "tool": "http_fetch",
                "input": '{"url": "http://example.com/login"}',
                "output": "<html><form>...</form></html>",
                "timestamp": 1000.0,
            },
            {
                "tool": "sqli_probe",
                "input": '{"url": "http://example.com/login", "param": "username", "payload": "\' OR 1=1--"}',
                "output": "Error: blocked by WAF",
                "timestamp": 1001.0,
            },
            {
                "tool": "sqli_probe",
                "input": '{"url": "http://example.com/login", "param": "username", "payload": "\' OR 1=1--"}',
                "output": "Error: blocked by WAF",
                "timestamp": 1002.0,
            },
            {
                "tool": "sqli_probe",
                "input": '{"url": "http://example.com/login", "param": "username", "payload": "\' OR 1=1--"}',
                "output": "Error: blocked by WAF",
                "timestamp": 1003.0,
            },
            {
                "tool": "form_submit",
                "input": '{"url": "http://example.com/login", "data": {"username": "admin", "password": "test"}}',
                "output": "403 Forbidden",
                "timestamp": 1004.0,
            },
        ]

    def test_infers_sql_injection_category(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="I couldn't find the flag.",
            failure_reason="No candidate flags found",
        )
        assert analysis.inferred_category == "sql_injection"

    def test_extracts_urls(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="Failed.",
            failure_reason="No flags",
        )
        assert any("example.com" in url for url in analysis.urls_accessed)

    def test_extracts_errors(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="Failed.",
            failure_reason="No flags",
        )
        assert len(analysis.errors_encountered) > 0

    def test_detects_repeated_failures(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="Failed.",
            failure_reason="No flags",
        )
        # The sqli_probe was called 3 times with the same input
        assert len(analysis.repeated_failures) > 0

    def test_generates_suggestions(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="Failed.",
            failure_reason="No flags",
        )
        assert len(analysis.suggestions) > 0

    def test_tool_frequency_captured(
        self, sample_config_data, sample_tracker_data, sample_tool_call_log
    ):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=sample_tool_call_log,
            agent_response="Failed.",
            failure_reason="No flags",
        )
        assert analysis.tool_frequency.get("sqli_probe") == 4
        assert analysis.tool_frequency.get("http_fetch") == 5

    def test_empty_tool_log_still_works(self, sample_config_data, sample_tracker_data):
        analysis = analyze_failure(
            config_data=sample_config_data,
            tracker_data=sample_tracker_data,
            tool_call_log=[],
            agent_response="No output.",
            failure_reason="Agent produced no output",
        )
        assert isinstance(analysis, FailureAnalysis)
        assert analysis.inferred_category == "sql_injection"  # From tracker tool_calls

    def test_jwt_category_inference(self):
        analysis = analyze_failure(
            config_data={"challenge_url": "http://example.com"},
            tracker_data={
                "steps": 5,
                "tool_calls": {"jwt_tool": 10},
                "duration_seconds": 20,
            },
            tool_call_log=[],
            agent_response="Failed.",
            failure_reason="No flags",
        )
        assert analysis.inferred_category == "jwt_attacks"


# ===========================================================================
# TestDocGeneration
# ===========================================================================


class TestDocGeneration:
    """Tests for generate_failure_knowledge_doc()."""

    @pytest.fixture
    def sample_analysis(self):
        return FailureAnalysis(
            challenge_url="http://example.com/login",
            challenge_description="Bypass the login form",
            failure_reason="No candidate flags found",
            inferred_category="sql_injection",
            total_steps=12,
            duration_seconds=45.2,
            tools_used=["http_fetch", "sqli_probe", "form_submit"],
            tool_frequency={"http_fetch": 5, "sqli_probe": 4, "form_submit": 3},
            payloads_tried=["' OR 1=1--", "' UNION SELECT 1,2--"],
            urls_accessed=["http://example.com/login"],
            errors_encountered=["blocked", "forbidden"],
            repeated_failures=["' OR 1=1--"],
            suggestions=[
                "Try blind SQL injection",
                "Try alternative operators: GLOB, IS",
            ],
        )

    def test_generates_valid_markdown(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert doc.startswith("# Failure Analysis: SQL Injection")
        assert "## 1. Challenge Context" in doc
        assert "## 2. What Was Tried" in doc
        assert "## 7. Suggestions for Next Attempt" in doc

    def test_contains_tags(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "**Tags:**" in doc
        assert "failure-analysis" in doc
        assert "sql_injection" in doc

    def test_contains_payloads(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "OR 1=1" in doc
        assert "UNION SELECT" in doc

    def test_contains_errors(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "blocked" in doc
        assert "forbidden" in doc

    def test_contains_suggestions(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "blind SQL injection" in doc
        assert "GLOB" in doc

    def test_contains_stuck_patterns(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "Stuck Patterns" in doc

    def test_contains_agent_takeaway(self, sample_analysis):
        doc = generate_failure_knowledge_doc(sample_analysis, doc_index=1)
        assert "Agent Takeaway" in doc

    def test_no_errors_section_when_empty(self):
        analysis = FailureAnalysis(
            inferred_category="recon",
            failure_reason="No flags",
            suggestions=["Try something"],
        )
        doc = generate_failure_knowledge_doc(analysis, doc_index=1)
        assert "## 3. Errors Encountered" not in doc

    def test_no_stuck_section_when_empty(self):
        analysis = FailureAnalysis(
            inferred_category="recon",
            failure_reason="No flags",
            suggestions=["Try something"],
        )
        doc = generate_failure_knowledge_doc(analysis, doc_index=1)
        assert "Stuck Patterns" not in doc


# ===========================================================================
# TestPipeline
# ===========================================================================


class TestPipeline:
    """Tests for run_failure_analysis_pipeline()."""

    def test_success_returns_none(self):
        result = run_failure_analysis_pipeline(
            config_data={"challenge_url": "http://example.com"},
            tracker_data={"steps": 5, "tool_calls": {}, "duration_seconds": 10},
            tool_call_log=[],
            agent_response="Found the flag: picoCTF{hello}",
            candidate_flags=["picoCTF{hello}"],
            max_steps=20,
            actual_steps=5,
        )
        assert result is None

    def test_failure_generates_doc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_failure_analysis_pipeline(
                config_data={
                    "challenge_url": "http://example.com/challenge",
                    "challenge_description": "Test challenge",
                },
                tracker_data={
                    "steps": 10,
                    "tool_calls": {"http_fetch": 3, "sqli_probe": 2},
                    "duration_seconds": 30.5,
                },
                tool_call_log=[
                    {
                        "tool": "http_fetch",
                        "input": '{"url": "http://example.com/challenge"}',
                        "output": "<html>Login page</html>",
                    },
                ],
                agent_response="I couldn't solve this challenge.",
                candidate_flags=[],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=10,
            )

            assert result is not None
            assert os.path.exists(result)

            # Check file content
            content = Path(result).read_text()
            assert "Failure Analysis" in content
            assert "sql_injection" in content

    def test_failure_doc_filename_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_failure_analysis_pipeline(
                config_data={"challenge_url": "http://example.com"},
                tracker_data={
                    "steps": 5,
                    "tool_calls": {"jwt_tool": 3},
                    "duration_seconds": 10,
                },
                tool_call_log=[],
                agent_response="Nothing found.",
                candidate_flags=[],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=5,
            )

            filename = Path(result).name
            assert filename.startswith("failure_001_")
            assert filename.endswith(".md")
            assert "jwt_attacks" in filename

    def test_increments_doc_index(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a first doc
            run_failure_analysis_pipeline(
                config_data={"challenge_url": "http://example.com"},
                tracker_data={"steps": 5, "tool_calls": {}, "duration_seconds": 10},
                tool_call_log=[],
                agent_response="Failed.",
                candidate_flags=[],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=5,
            )

            # Create a second doc
            result = run_failure_analysis_pipeline(
                config_data={"challenge_url": "http://example.com/other"},
                tracker_data={"steps": 8, "tool_calls": {}, "duration_seconds": 15},
                tool_call_log=[],
                agent_response="Failed again.",
                candidate_flags=[],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=8,
            )

            filename = Path(result).name
            assert filename.startswith("failure_002_")

    def test_creates_directory_if_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = os.path.join(tmpdir, "deep", "nested", "dir")
            result = run_failure_analysis_pipeline(
                config_data={"challenge_url": "http://example.com"},
                tracker_data={"steps": 5, "tool_calls": {}, "duration_seconds": 10},
                tool_call_log=[],
                agent_response="Failed.",
                candidate_flags=[],
                failure_docs_dir=nested_dir,
                max_steps=20,
                actual_steps=5,
            )
            assert result is not None
            assert os.path.exists(result)

    def test_max_steps_triggers_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_failure_analysis_pipeline(
                config_data={"challenge_url": "http://example.com"},
                tracker_data={"steps": 20, "tool_calls": {}, "duration_seconds": 60},
                tool_call_log=[],
                agent_response="Still working...",
                candidate_flags=["picoCTF{maybe}"],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=20,
            )
            assert result is not None
            content = Path(result).read_text()
            assert "max steps" in content.lower() or "Max steps" in content


# ===========================================================================
# TestRAGModeConfig
# ===========================================================================


class TestRAGModeConfig:
    """Tests for RAGMode enum and config integration."""

    def test_rag_mode_enum_values(self):
        assert RAGMode.NONE.value == "none"
        assert RAGMode.ORIGINAL.value == "original"
        assert RAGMode.AUGMENTED.value == "augmented"

    def test_config_default_rag_mode(self):
        config = SolverConfig()
        assert config.rag_mode == RAGMode.ORIGINAL

    def test_config_rag_mode_from_string(self):
        config = SolverConfig(rag_mode="augmented")
        assert config.rag_mode == RAGMode.AUGMENTED

    def test_config_rag_mode_none(self):
        config = SolverConfig(rag_mode="none")
        assert config.rag_mode == RAGMode.NONE

    def test_config_rag_mode_invalid_falls_back(self):
        config = SolverConfig(rag_mode="invalid_mode")
        assert config.rag_mode == RAGMode.ORIGINAL

    def test_config_failure_docs_dir_default(self):
        config = SolverConfig()
        assert config.failure_docs_dir == "out/failure_knowledge"

    def test_config_auto_analyze_default(self):
        config = SolverConfig()
        assert config.auto_analyze_failures is False

    def test_config_merge_preserves_rag_mode(self):
        config = SolverConfig(rag_mode="augmented")
        merged = config.merge_with_args(max_steps=30)
        assert merged.rag_mode == RAGMode.AUGMENTED
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
        assert result == "result"


# ===========================================================================
# TestFailureDocDeduplication
# ===========================================================================


class TestFailureDocDeduplication:
    """Tests for _is_duplicate() and dedup integration in the pipeline."""

    def _make_pipeline_call(
        self, tmpdir, url="http://example.com/challenge", tools=None, description="Test"
    ):
        if tools is None:
            tools = {"http_fetch": 3, "sqli_probe": 2}
        return run_failure_analysis_pipeline(
            config_data={"challenge_url": url, "challenge_description": description},
            tracker_data={"steps": 10, "tool_calls": tools, "duration_seconds": 30},
            tool_call_log=[],
            agent_response="I couldn't solve this.",
            candidate_flags=[],
            failure_docs_dir=tmpdir,
            max_steps=20,
            actual_steps=10,
        )

    def test_no_duplicate_in_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self._make_pipeline_call(tmpdir)
            assert result is not None
            assert os.path.exists(result)

    def test_duplicate_detected_same_url_category_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(tmpdir)
            assert first is not None
            # Second call with same params should be skipped
            second = self._make_pipeline_call(tmpdir)
            assert second is None

    def test_not_duplicate_different_url(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(tmpdir, url="http://example.com/a")
            assert first is not None
            second = self._make_pipeline_call(tmpdir, url="http://example.com/b")
            assert second is not None

    def test_not_duplicate_different_category(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(tmpdir, tools={"sqli_probe": 5})
            assert first is not None
            # JWT tools → different category
            second = self._make_pipeline_call(tmpdir, tools={"jwt_tool": 5})
            assert second is not None

    def test_not_duplicate_low_tool_overlap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(
                tmpdir, tools={"sqli_probe": 5, "http_fetch": 3, "form_submit": 2}
            )
            assert first is not None
            # Completely different tool set but same category (sqli)
            second = self._make_pipeline_call(
                tmpdir,
                tools={
                    "sqli_probe": 1,
                    "blind_sqli_boolean": 5,
                    "blind_sqli_time": 3,
                    "sqli_data_dumper": 2,
                },
            )
            # Jaccard of {sqli_probe, http_fetch, form_submit} vs
            # {sqli_probe, blind_sqli_boolean, blind_sqli_time, sqli_data_dumper}
            # = 1/6 ≈ 0.17 < 0.7, so not duplicate
            assert second is not None

    def test_duplicate_high_tool_overlap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(
                tmpdir, tools={"sqli_probe": 5, "http_fetch": 3, "form_submit": 2}
            )
            assert first is not None
            # Same tools → Jaccard = 1.0
            second = self._make_pipeline_call(
                tmpdir, tools={"sqli_probe": 10, "http_fetch": 1, "form_submit": 1}
            )
            assert second is None

    def test_jaccard_empty_tools(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(tmpdir, tools={})
            assert first is not None
            second = self._make_pipeline_call(tmpdir, tools={})
            assert second is None

    def test_pipeline_skips_duplicate_preserves_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            first = self._make_pipeline_call(tmpdir)
            assert first is not None
            # Run 3 more times
            for _ in range(3):
                assert self._make_pipeline_call(tmpdir) is None
            # Only 1 file should exist
            docs = list(Path(tmpdir).glob("failure_*.md"))
            assert len(docs) == 1


# ===========================================================================
# TestStuckDetection
# ===========================================================================


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
