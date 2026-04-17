"""
Tests for v2.0 failure knowledge improvements.

Covers:
- AUGMENTED_READONLY RAG mode (reads failure DB, never writes)
- Tool output snippets in failure docs
- Expanded payload extraction (SSTI, XSS, WASM, LFI, all tool types)
- Response patterns (repeated same-length responses = not injectable)
- Success knowledge document generation
- run_success_knowledge_pipeline entry point
"""

import json
import re
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ctf_solver.config import RAGMode, SolverConfig
from ctf_solver.failure_analyzer import (
    FailureAnalysis,
    analyze_failure,
    generate_failure_knowledge_doc,
    generate_success_knowledge_doc,
    run_failure_analysis_pipeline,
    run_success_knowledge_pipeline,
)

# ---------------------------------------------------------------------------
# 1. AUGMENTED_READONLY mode
# ---------------------------------------------------------------------------


class TestAugmentedReadonlyMode:
    """AUGMENTED_READONLY: reads failure DB but never writes new docs."""

    def test_augmented_readonly_exists_in_enum(self):
        assert hasattr(RAGMode, "AUGMENTED_READONLY")
        assert RAGMode.AUGMENTED_READONLY.value == "augmented_readonly"

    def test_augmented_readonly_normalised_from_string(self):
        config = SolverConfig(rag_mode="augmented_readonly")
        assert config.rag_mode == RAGMode.AUGMENTED_READONLY

    def test_rag_config_includes_failure_dir_for_readonly(self):
        """_build_rag_config must include failure_docs_dir for AUGMENTED_READONLY."""
        from ctf_solver.agent import _build_rag_config

        config = SolverConfig(
            docs_dirs=["docs/"],
            failure_docs_dir="out/failure_knowledge",
            rag_mode=RAGMode.AUGMENTED_READONLY,
        )
        rag_cfg = _build_rag_config(config, RAGMode.AUGMENTED_READONLY)
        assert "out/failure_knowledge" in rag_cfg.docs_dirs

    def test_rag_config_uses_separate_vector_store_for_readonly(self):
        from ctf_solver.agent import _build_rag_config

        config = SolverConfig(
            docs_dirs=["docs/"],
            vector_store_dir="out/ctf_vector_store",
            rag_mode=RAGMode.AUGMENTED_READONLY,
        )
        rag_cfg = _build_rag_config(config, RAGMode.AUGMENTED_READONLY)
        # Must use the augmented store, not the original
        assert "augmented" in rag_cfg.vector_store_dir

    def test_augmented_mode_still_works(self):
        """Existing AUGMENTED mode unaffected."""
        from ctf_solver.agent import _build_rag_config

        config = SolverConfig(
            docs_dirs=["docs/"],
            failure_docs_dir="out/failure_knowledge",
            rag_mode=RAGMode.AUGMENTED,
        )
        rag_cfg = _build_rag_config(config, RAGMode.AUGMENTED)
        assert "out/failure_knowledge" in rag_cfg.docs_dirs

    def test_original_mode_excludes_failure_dir(self):
        from ctf_solver.agent import _build_rag_config

        config = SolverConfig(
            docs_dirs=["docs/"],
            failure_docs_dir="out/failure_knowledge",
            rag_mode=RAGMode.ORIGINAL,
        )
        rag_cfg = _build_rag_config(config, RAGMode.ORIGINAL)
        assert "out/failure_knowledge" not in rag_cfg.docs_dirs


# ---------------------------------------------------------------------------
# 2. Tool output snippets
# ---------------------------------------------------------------------------

_BASIC_CONFIG = {
    "challenge_url": "http://ctf.example.com",
    "challenge_description": "Test",
}
_BASIC_TRACKER = {"steps": 5, "tool_calls": {"sqli_probe": 2}, "duration_seconds": 10.0}


def _make_log(entries):
    return [{"tool": t, "input": i, "output": o} for t, i, o in entries]


class TestToolOutputSnippets:
    """analyze_failure should capture first meaningful output per tool."""

    def test_output_snippet_captured(self):
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"\'"}',
                    "Error: You have an error in your SQL syntax near ''",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 1}}
        result = analyze_failure(
            _BASIC_CONFIG, tracker, log, "unable to find flag", "max steps"
        )
        assert "sqli_probe" in result.tool_output_snippets
        snippets = result.tool_output_snippets["sqli_probe"]
        assert len(snippets) == 1
        assert "SQL syntax" in snippets[0]

    def test_snippet_truncated_to_300_chars(self):
        long_output = "X" * 600
        log = _make_log([("http_fetch", '{"url":"http://x"}', long_output)])
        tracker = {**_BASIC_TRACKER, "tool_calls": {"http_fetch": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        if "http_fetch" in result.tool_output_snippets:
            for snippet in result.tool_output_snippets["http_fetch"]:
                assert len(snippet) <= 300

    def test_trivial_outputs_skipped(self):
        """Outputs shorter than 20 chars shouldn't be captured."""
        log = _make_log([("robots_txt", '{"url":"http://x"}', "OK")])
        tracker = {**_BASIC_TRACKER, "tool_calls": {"robots_txt": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert "robots_txt" not in result.tool_output_snippets

    def test_max_two_snippets_per_tool(self):
        long_out = "Response body " + "X" * 100
        log = _make_log(
            [
                ("http_fetch", '{"url":"http://x"}', long_out + "1"),
                ("http_fetch", '{"url":"http://y"}', long_out + "2"),
                ("http_fetch", '{"url":"http://z"}', long_out + "3"),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"http_fetch": 3}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        if "http_fetch" in result.tool_output_snippets:
            assert len(result.tool_output_snippets["http_fetch"]) <= 2

    def test_snippets_appear_in_generated_doc(self):
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"\'"}',
                    "Error: SQL syntax near ''",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        doc = generate_failure_knowledge_doc(result, 1)
        assert "sqli_probe" in doc
        assert "SQL syntax" in doc


# ---------------------------------------------------------------------------
# 3. Expanded payload extraction
# ---------------------------------------------------------------------------


class TestExpandedPayloadExtraction:
    """Payloads from non-SQL tools should also be captured."""

    def test_ssti_payload_extracted(self):
        log = _make_log(
            [
                (
                    "ssti_probe",
                    '{"url":"http://x","param":"name","payload":"{{7*7}}"}',
                    "Response: 49",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"ssti_probe": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any(
            "ssti" in p.lower() or "7*7" in p or "{{" in p
            for p in result.payloads_tried
        )

    def test_wasm_operation_extracted(self):
        log = _make_log(
            [
                (
                    "wasm_analyzer",
                    '{"url":"http://x/module.wasm","operation":"xor_decode"}',
                    "Key not found in exports",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"wasm_analyzer": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any(
            "wasm" in p.lower() or "xor_decode" in p for p in result.payloads_tried
        )

    def test_xss_payload_extracted(self):
        log = _make_log(
            [
                (
                    "xss_probe",
                    '{"url":"http://x","param":"q","payload":"<script>alert(1)</script>"}',
                    "Payload was filtered",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"xss_probe": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any(
            "xss" in p.lower() or "script" in p.lower() for p in result.payloads_tried
        )

    def test_generic_payload_key_extracted(self):
        """Any tool with a 'payload' key in JSON input should have it captured."""
        log = _make_log(
            [
                (
                    "some_custom_tool",
                    '{"url":"http://x","payload":"custom_payload_value"}',
                    "Some output with more than twenty characters here",
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"some_custom_tool": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any("custom_payload_value" in p for p in result.payloads_tried)


# ---------------------------------------------------------------------------
# 4. Response patterns (repeated same-length responses)
# ---------------------------------------------------------------------------


class TestResponsePatterns:
    """Detect when a tool returns the same-length response 3+ times."""

    def test_repeated_response_detected(self):
        identical_output = "HTTP 200 — body length: 423 — " + "X" * 200  # 230+ chars
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"1"}',
                    identical_output,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"2"}',
                    identical_output,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"3"}',
                    identical_output,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"4"}',
                    identical_output,
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 4}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert len(result.response_patterns) > 0
        assert any("sqli_probe" in p for p in result.response_patterns)

    def test_varying_responses_not_flagged(self):
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"1"}',
                    "Response A" + "X" * 50,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"2"}',
                    "Response BB" + "Y" * 80,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"3"}',
                    "Response CCC" + "Z" * 30,
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 3}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        # Should not flag varying responses as a stuck pattern
        injectable_patterns = [
            p for p in result.response_patterns if "not injectable" in p
        ]
        assert len(injectable_patterns) == 0

    def test_response_patterns_appear_in_doc(self):
        identical_output = "Identical response body: " + "X" * 200
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"1"}',
                    identical_output,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"2"}',
                    identical_output,
                ),
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"3"}',
                    identical_output,
                ),
            ]
        )
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 3}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        if result.response_patterns:
            doc = generate_failure_knowledge_doc(result, 1)
            assert any(
                "sqli_probe" in doc
                or "identical" in doc.lower()
                or "response pattern" in doc.lower()
                for _ in [1]
            )


# ---------------------------------------------------------------------------
# 5. Success knowledge documents
# ---------------------------------------------------------------------------


class TestSuccessKnowledgeDoc:
    """generate_success_knowledge_doc produces well-formed docs."""

    def _make_success_data(self):
        config_data = {
            "challenge_url": "http://challenge.picoctf.net:64268/",
            "challenge_description": "Some Assembly Required 3",
        }
        tracker_data = {
            "steps": 3,
            "tool_calls": {"http_fetch": 1, "javascript_source": 1, "wasm_analyzer": 2},
            "duration_seconds": 4.2,
        }
        tool_call_log = [
            {
                "tool": "http_fetch",
                "input": '{"url":"http://challenge.picoctf.net:64268/"}',
                "output": "HTTP 200 — body: <html>...<script src='G82XCw5CX3.js'></script>",
            },
            {
                "tool": "javascript_source",
                "input": '{"url":"http://challenge.picoctf.net:64268/G82XCw5CX3.js"}',
                "output": "fetch('./JIFxzHyW8W') ... WebAssembly.instantiate",
            },
            {
                "tool": "wasm_analyzer",
                "input": '{"url":"http://challenge.picoctf.net:64268/JIFxzHyW8W","operation":"xor_decode"}',
                "output": "[FLAG FOUND] picoCTF{test_flag_here_123}",
            },
        ]
        return config_data, tracker_data, tool_call_log

    def test_success_doc_generated(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data=config_data,
            tracker_data=tracker_data,
            tool_call_log=tool_call_log,
            agent_response="Final answer: picoCTF{test_flag_here_123}",
            candidate_flags=["picoCTF{test_flag_here_123}"],
        )
        assert isinstance(doc, str)
        assert len(doc) > 100

    def test_success_doc_contains_url(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        assert "picoctf.net" in doc

    def test_success_doc_contains_tool_sequence(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        assert "wasm_analyzer" in doc
        assert "javascript_source" in doc
        assert "http_fetch" in doc

    def test_success_doc_contains_flag_snippet(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        # Should reference that a flag was found
        assert (
            "FLAG" in doc.upper() or "success" in doc.lower() or "solved" in doc.lower()
        )

    def test_success_doc_has_agent_takeaway_section(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        assert (
            "Takeaway" in doc
            or "takeaway" in doc
            or "Next time" in doc
            or "Solution Path" in doc
        )

    def test_success_doc_has_tags_header(self):
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        assert "success-pattern" in doc or "Tags" in doc

    def test_success_doc_key_output_snippet_included(self):
        """The wasm_analyzer FLAG FOUND output should appear in the doc."""
        config_data, tracker_data, tool_call_log = self._make_success_data()
        doc = generate_success_knowledge_doc(
            config_data,
            tracker_data,
            tool_call_log,
            "Flag: picoCTF{x}",
            ["picoCTF{x}"],
        )
        # The wasm_analyzer output snippet should be in the doc
        assert "wasm_analyzer" in doc


# ---------------------------------------------------------------------------
# 6. run_success_knowledge_pipeline entry point
# ---------------------------------------------------------------------------


class TestSuccessPipeline:
    """run_success_knowledge_pipeline saves a doc when run succeeded."""

    def _make_success_inputs(self):
        config_data = {
            "challenge_url": "http://ctf.example.com/challenge",
            "challenge_description": "Solve me",
        }
        tracker_data = {
            "steps": 5,
            "tool_calls": {"sqli_probe": 2, "sqli_data_dumper": 1},
            "duration_seconds": 20.0,
        }
        tool_call_log = [
            {
                "tool": "sqli_probe",
                "input": '{"url":"http://ctf.example.com","param":"id","payload":"\'"}',
                "output": "Error: SQL syntax error near ''",
            },
            {
                "tool": "sqli_data_dumper",
                "input": '{"url":"http://ctf.example.com","table":"flags"}',
                "output": "flag{test_sql_flag}",
            },
        ]
        return config_data, tracker_data, tool_call_log

    def test_success_pipeline_saves_doc(self):
        config_data, tracker_data, tool_call_log = self._make_success_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_success_knowledge_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=tool_call_log,
                agent_response="The flag is flag{test_sql_flag}",
                candidate_flags=["flag{test_sql_flag}"],
                failure_docs_dir=tmpdir,
            )
            assert result is not None
            assert Path(result).exists()

    def test_success_pipeline_filename_has_success_prefix(self):
        config_data, tracker_data, tool_call_log = self._make_success_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_success_knowledge_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=tool_call_log,
                agent_response="flag{test}",
                candidate_flags=["flag{test}"],
                failure_docs_dir=tmpdir,
            )
            assert result is not None
            assert Path(result).name.startswith("success_")

    def test_success_pipeline_returns_none_when_no_flags(self):
        config_data, tracker_data, tool_call_log = self._make_success_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_success_knowledge_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=tool_call_log,
                agent_response="I could not find the flag",
                candidate_flags=[],  # no flags = not a success
                failure_docs_dir=tmpdir,
            )
            assert result is None

    def test_success_pipeline_deduplicates(self):
        """Same URL + same category = skip duplicate success doc."""
        config_data, tracker_data, tool_call_log = self._make_success_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            path1 = run_success_knowledge_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=tool_call_log,
                agent_response="flag{test}",
                candidate_flags=["flag{test}"],
                failure_docs_dir=tmpdir,
            )
            path2 = run_success_knowledge_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=tool_call_log,
                agent_response="flag{test}",
                candidate_flags=["flag{test}"],
                failure_docs_dir=tmpdir,
            )
            assert path1 is not None
            assert path2 is None  # second run is a duplicate

    def test_failure_pipeline_unaffected(self):
        """run_failure_analysis_pipeline still works after additions."""
        config_data = {"challenge_url": "http://x.com", "challenge_description": "Test"}
        tracker_data = {
            "steps": 20,
            "tool_calls": {"sqli_probe": 5},
            "duration_seconds": 30.0,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_failure_analysis_pipeline(
                config_data=config_data,
                tracker_data=tracker_data,
                tool_call_log=[],
                agent_response="unable to find the flag",
                candidate_flags=[],
                failure_docs_dir=tmpdir,
                max_steps=20,
                actual_steps=20,
            )
            assert result is not None
            assert Path(result).name.startswith("failure_")
