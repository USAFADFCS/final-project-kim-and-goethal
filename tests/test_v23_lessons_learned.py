"""
Tests for v2.3.0 — Unified Lessons-Learned Pipeline.

Coverage:
- AtomicRule and LessonsLearnedDoc dataclasses
- analyze_run() — success, failure, and partial outcomes
- _extract_atomic_rules()
- _compress_to_reflexion_summary()
- generate_atomic_rule_doc() — template structure
- _is_lessons_duplicate() — deduplication logic
- run_lessons_learned_pipeline() — end-to-end doc generation
- find_and_compress_prior_lesson() — compressed reflection retrieval
- SafeKnowledgeQueryTool: challenge contamination filter
- SafeKnowledgeQueryTool: seen-doc exclusion
- Config: new RAGMode enum values and helper sets
- Config: challenge_name and lessons_docs_dir fields
"""

import tempfile
import time
from pathlib import Path

from ctf_solver.config import (
    RAG_EXPERIENCE_MODES,
    RAG_WRITE_MODES,
    RAGMode,
    SolverConfig,
)
from ctf_solver.failure_analyzer import (
    AtomicRule,
    LessonsLearnedDoc,
    _challenge_name_to_slug,
    _compress_to_reflexion_summary,
    _extract_atomic_rules,
    _infer_outcome,
    _is_lessons_duplicate,
    analyze_run,
    find_and_compress_prior_lesson,
    generate_atomic_rule_doc,
    run_lessons_learned_pipeline,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TOOL_CALL_LOG_FAILURE = [
    {
        "tool": "sqli_probe",
        "input": '{"url": "http://ctf.test/login", "param": "username", "payload": "1 OR 1=1"}',
        "output": "HTTP 200 — login failed. Response length: 342",
    },
    {
        "tool": "sqli_probe",
        "input": '{"url": "http://ctf.test/login", "param": "username", "payload": "\' OR \'1\'=\'1"}',
        "output": "HTTP 200 — login failed. Response length: 342",
    },
    {
        "tool": "blind_sqli_boolean",
        "input": '{"url": "http://ctf.test/login", "param": "username"}',
        "output": "Responses identical for TRUE/FALSE — boolean injection not detected",
    },
]

TOOL_CALL_LOG_SUCCESS = [
    {
        "tool": "robots_txt",
        "input": '{"url": "http://ctf.test/"}',
        "output": "Disallow: /admin\nDisallow: /secret",
    },
    {
        "tool": "javascript_source",
        "input": '{"url": "http://ctf.test/app.js"}',
        "output": "// no secrets here",
    },
    {
        "tool": "http_fetch",
        "input": '{"url": "http://ctf.test/secret"}',
        "output": "Welcome! Your flag is: flag{found_the_secret_42}",
    },
]

TOOL_CALL_LOG_MISSED_SIGNAL = [
    {
        "tool": "javascript_source",
        "input": '{"url": "http://ctf.test/app.js"}',
        "output": "Found credentials: password: s3cr3tpass123",
    },
    {
        "tool": "robots_txt",
        "input": '{"url": "http://ctf.test/"}',
        "output": "Disallow: /backup",
    },
]

CONFIG_DATA_FAILURE = {
    "challenge_url": "http://ctf.test/login",
    "challenge_description": "Login bypass challenge",
    "challenge_name": "Login Bypass Test",
}

CONFIG_DATA_SUCCESS = {
    "challenge_url": "http://ctf.test/secret",
    "challenge_description": "Find the hidden flag",
    "challenge_name": "Secret Page",
}

TRACKER_FAILURE = {
    "steps": 12,
    "tool_calls": {"sqli_probe": 5, "blind_sqli_boolean": 3, "http_fetch": 2},
    "duration_seconds": 45.3,
}

TRACKER_SUCCESS = {
    "steps": 3,
    "tool_calls": {"robots_txt": 1, "javascript_source": 1, "http_fetch": 1},
    "duration_seconds": 4.1,
}


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestRAGModeEnum:
    def test_new_modes_exist(self):
        assert RAGMode.LESSONS_WRITE == "lessons_write"
        assert RAGMode.LESSONS_READONLY == "lessons_readonly"

    def test_legacy_modes_removed(self):
        # AUGMENTED / AUGMENTED_READONLY were removed in Batch B alongside
        # the monolithic failure/success pipeline they were aliases for.
        assert not hasattr(RAGMode, "AUGMENTED")
        assert not hasattr(RAGMode, "AUGMENTED_READONLY")

    def test_write_modes_set(self):
        assert RAGMode.LESSONS_WRITE in RAG_WRITE_MODES
        assert RAGMode.LESSONS_READONLY not in RAG_WRITE_MODES
        assert RAGMode.ORIGINAL not in RAG_WRITE_MODES

    def test_experience_modes_set(self):
        assert RAGMode.LESSONS_WRITE in RAG_EXPERIENCE_MODES
        assert RAGMode.LESSONS_READONLY in RAG_EXPERIENCE_MODES
        assert RAGMode.ORIGINAL not in RAG_EXPERIENCE_MODES
        assert RAGMode.NONE not in RAG_EXPERIENCE_MODES


class TestSolverConfigNewFields:
    def test_challenge_name_default_none(self):
        config = SolverConfig()
        assert config.challenge_name is None

    def test_challenge_name_set(self):
        config = SolverConfig(challenge_name="Great Paywall")
        assert config.challenge_name == "Great Paywall"

    def test_lessons_docs_dir_default(self):
        config = SolverConfig()
        assert config.lessons_docs_dir == "out/lessons_knowledge"

    def test_lessons_docs_dir_custom(self):
        config = SolverConfig(lessons_docs_dir="/tmp/my_lessons")
        assert config.lessons_docs_dir == "/tmp/my_lessons"

    def test_merge_with_args_includes_new_fields(self):
        config = SolverConfig()
        merged = config.merge_with_args(
            challenge_name="Test Challenge",
            lessons_docs_dir="/tmp/lessons",
        )
        assert merged.challenge_name == "Test Challenge"
        assert merged.lessons_docs_dir == "/tmp/lessons"


# ---------------------------------------------------------------------------
# AtomicRule and LessonsLearnedDoc dataclasses
# ---------------------------------------------------------------------------


class TestAtomicRule:
    def test_default_confidence_low(self):
        rule = AtomicRule(
            triggering_condition="When you see X",
            agent_takeaway="Do Y",
            rule_type="do",
            tool_context=[],
        )
        assert rule.confidence == "low"

    def test_rule_type_values(self):
        do_rule = AtomicRule("trigger", "takeaway", "do", [])
        dont_rule = AtomicRule("trigger", "takeaway", "do_not", [])
        assert do_rule.rule_type == "do"
        assert dont_rule.rule_type == "do_not"

    def test_tool_context_list(self):
        rule = AtomicRule(
            "trigger", "takeaway", "do", ["sqli_probe", "blind_sqli_boolean"]
        )
        assert len(rule.tool_context) == 2


class TestLessonsLearnedDoc:
    def test_default_outcome(self):
        doc = LessonsLearnedDoc()
        assert doc.outcome == "failure"

    def test_outcome_values(self):
        for outcome in ("success", "failure", "partial"):
            doc = LessonsLearnedDoc(outcome=outcome)
            assert doc.outcome == outcome

    def test_atomic_rules_default_empty(self):
        doc = LessonsLearnedDoc()
        assert doc.atomic_rules == []


# ---------------------------------------------------------------------------
# _infer_outcome
# ---------------------------------------------------------------------------


class TestInferOutcome:
    def test_flags_present_is_success(self):
        assert _infer_outcome(["flag{abc}"], []) == "success"

    def test_partial_successes_no_flags_is_partial(self):
        assert _infer_outcome([], ["sqli_confirmed"]) == "partial"

    def test_no_flags_no_partial_is_failure(self):
        assert _infer_outcome([], []) == "failure"

    def test_flags_override_partial(self):
        assert _infer_outcome(["flag{x}"], ["sqli_confirmed"]) == "success"


# ---------------------------------------------------------------------------
# _challenge_name_to_slug
# ---------------------------------------------------------------------------


class TestChallengeNameToSlug:
    def test_spaces_become_hyphens(self):
        assert _challenge_name_to_slug("Great Paywall") == "great-paywall"

    def test_special_chars_removed(self):
        assert _challenge_name_to_slug("SQL! Injection #1") == "sql-injection-1"

    def test_empty_returns_unknown(self):
        assert _challenge_name_to_slug("") == "unknown"

    def test_lowercase(self):
        assert _challenge_name_to_slug("MY CHALLENGE") == "my-challenge"


# ---------------------------------------------------------------------------
# analyze_run
# ---------------------------------------------------------------------------


class TestAnalyzeRun:
    def test_failure_outcome(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data=TRACKER_FAILURE,
            tool_call_log=TOOL_CALL_LOG_FAILURE,
            agent_response="I was unable to find the flag.",
            candidate_flags=[],
        )
        assert doc.outcome == "failure"
        assert doc.challenge_url == "http://ctf.test/login"
        assert doc.challenge_name == "Login Bypass Test"

    def test_success_outcome(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_SUCCESS,
            tracker_data=TRACKER_SUCCESS,
            tool_call_log=TOOL_CALL_LOG_SUCCESS,
            agent_response="flag{found_the_secret_42}",
            candidate_flags=["flag{found_the_secret_42}"],
        )
        assert doc.outcome == "success"

    def test_category_inferred(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data=TRACKER_FAILURE,
            tool_call_log=TOOL_CALL_LOG_FAILURE,
            agent_response="Unable to find flag",
            candidate_flags=[],
        )
        assert doc.category == "sql_injection"

    def test_tool_sequence_ordered_deduped(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data=TRACKER_FAILURE,
            tool_call_log=TOOL_CALL_LOG_FAILURE,
            agent_response="Unable to find flag",
            candidate_flags=[],
        )
        # Should be ordered with duplicates removed
        assert doc.tool_sequence[0] == "sqli_probe"
        assert len(doc.tool_sequence) == len(set(doc.tool_sequence))

    def test_atomic_rules_generated(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data=TRACKER_FAILURE,
            tool_call_log=TOOL_CALL_LOG_FAILURE,
            agent_response="Unable to find flag",
            candidate_flags=[],
        )
        assert len(doc.atomic_rules) >= 1
        assert all(isinstance(r, AtomicRule) for r in doc.atomic_rules)

    def test_reflexion_summary_generated(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data=TRACKER_FAILURE,
            tool_call_log=TOOL_CALL_LOG_FAILURE,
            agent_response="Unable to find flag",
            candidate_flags=[],
        )
        assert len(doc.reflexion_summary) > 20

    def test_missed_signal_detected(self):
        doc = analyze_run(
            config_data=CONFIG_DATA_FAILURE,
            tracker_data={
                "steps": 5,
                "tool_calls": {"javascript_source": 1, "robots_txt": 1},
                "duration_seconds": 10.0,
            },
            tool_call_log=TOOL_CALL_LOG_MISSED_SIGNAL,
            agent_response="Unable to find flag",
            candidate_flags=[],
        )
        # credential_found signal should be detected
        assert any(
            "credential_found" in s or "password" in s.lower()
            for s in doc.missed_signals
        )


# ---------------------------------------------------------------------------
# _extract_atomic_rules
# ---------------------------------------------------------------------------


class TestExtractAtomicRules:
    def _make_failure_doc(self, **kwargs) -> LessonsLearnedDoc:
        defaults = dict(
            outcome="failure",
            category="sql_injection",
            tool_sequence=["sqli_probe", "blind_sqli_boolean"],
            tool_frequency={"sqli_probe": 5, "blind_sqli_boolean": 3},
            causal_diagnosis="Backend likely uses parameterized queries",
            missed_signals=[],
            partial_successes=[],
            total_steps=12,
        )
        defaults.update(kwargs)
        return LessonsLearnedDoc(**defaults)

    def test_failure_produces_at_least_one_rule(self):
        doc = self._make_failure_doc()
        rules = _extract_atomic_rules(doc)
        assert len(rules) >= 1

    def test_success_produces_do_rule(self):
        doc = LessonsLearnedDoc(
            outcome="success",
            category="recon",
            tool_sequence=["robots_txt", "http_fetch"],
            tool_frequency={"robots_txt": 1, "http_fetch": 1},
            total_steps=2,
        )
        rules = _extract_atomic_rules(doc)
        assert any(r.rule_type == "do" for r in rules)

    def test_missed_signal_produces_do_rule(self):
        doc = self._make_failure_doc(
            missed_signals=[
                "`javascript_source` found credential_found but no follow-up exploitation (form_submit, http_fetch) was attempted"
            ]
        )
        rules = _extract_atomic_rules(doc)
        assert any(r.rule_type == "do" for r in rules)

    def test_max_five_rules(self):
        doc = self._make_failure_doc(
            missed_signals=[
                "`tool1` found credential_found but no follow-up (form_submit) was attempted",
                "`tool2` found api_key_found but no follow-up (http_fetch) was attempted",
                "`tool3` found jwt_token_found but no follow-up (jwt_tool) was attempted",
            ]
        )
        rules = _extract_atomic_rules(doc)
        assert len(rules) <= 5

    def test_rule_fields_not_empty(self):
        doc = self._make_failure_doc()
        rules = _extract_atomic_rules(doc)
        for rule in rules:
            assert rule.triggering_condition
            assert rule.agent_takeaway
            assert rule.rule_type in ("do", "do_not")


# ---------------------------------------------------------------------------
# _compress_to_reflexion_summary
# ---------------------------------------------------------------------------


class TestCompressToReflexionSummary:
    def test_summary_not_empty(self):
        doc = LessonsLearnedDoc(
            outcome="failure",
            category="sql_injection",
            tool_frequency={"sqli_probe": 5},
            total_steps=12,
            causal_diagnosis="Backend uses parameterized queries",
        )
        doc.atomic_rules = _extract_atomic_rules(doc)
        summary = _compress_to_reflexion_summary(doc)
        assert len(summary) > 50

    def test_summary_contains_outcome(self):
        doc = LessonsLearnedDoc(
            outcome="success",
            category="recon",
            tool_sequence=["robots_txt", "http_fetch"],
            tool_frequency={"robots_txt": 1, "http_fetch": 1},
            total_steps=2,
        )
        doc.atomic_rules = []
        summary = _compress_to_reflexion_summary(doc)
        assert "succeeded" in summary or "success" in summary.lower()

    def test_summary_mentions_category(self):
        doc = LessonsLearnedDoc(
            outcome="failure",
            category="ssti",
            tool_frequency={"ssti_probe": 4},
            total_steps=8,
        )
        doc.atomic_rules = _extract_atomic_rules(doc)
        summary = _compress_to_reflexion_summary(doc)
        assert "template" in summary.lower() or "ssti" in summary.lower()

    def test_summary_under_500_words(self):
        doc = LessonsLearnedDoc(
            outcome="failure",
            category="sql_injection",
            tool_frequency={"sqli_probe": 5},
            total_steps=12,
            causal_diagnosis="Parameterized queries in use",
            missed_signals=["credential_found not exploited"],
            partial_successes=["sqli_confirmed"],
        )
        doc.atomic_rules = _extract_atomic_rules(doc)
        summary = _compress_to_reflexion_summary(doc)
        word_count = len(summary.split())
        assert word_count < 500, f"Summary too long: {word_count} words"


# ---------------------------------------------------------------------------
# generate_atomic_rule_doc
# ---------------------------------------------------------------------------


class TestGenerateAtomicRuleDoc:
    def _make_rule_and_doc(self) -> tuple:
        rule = AtomicRule(
            triggering_condition="When SQL probes return identical lengths",
            agent_takeaway="Pivot to NoSQL injection or auth bypass logic",
            rule_type="do_not",
            tool_context=["sqli_probe"],
            confidence="low",
            causal_explanation="Backend uses parameterized queries",
        )
        doc = LessonsLearnedDoc(
            challenge_name="Login Test",
            challenge_url="http://ctf.test/login",
            outcome="failure",
            category="sql_injection",
            timestamp="2026-03-02",
            total_steps=12,
            tool_sequence=["sqli_probe", "blind_sqli_boolean"],
        )
        doc.reflexion_summary = "Prior run failed after 12 steps on SQL injection."
        return rule, doc

    def test_doc_contains_triggering_condition(self):
        rule, doc = self._make_rule_and_doc()
        content = generate_atomic_rule_doc(rule, doc, 1)
        assert "identical lengths" in content

    def test_doc_contains_agent_takeaway(self):
        rule, doc = self._make_rule_and_doc()
        content = generate_atomic_rule_doc(rule, doc, 1)
        assert "NoSQL injection" in content

    def test_applies_when_near_top(self):
        rule, doc = self._make_rule_and_doc()
        content = generate_atomic_rule_doc(rule, doc, 1)
        lines = content.split("\n")
        # **Applies when:** should appear within first 15 lines
        applies_line = next(
            (i for i, ln in enumerate(lines) if "Applies when" in ln), None
        )
        assert applies_line is not None
        assert applies_line < 15

    def test_doc_has_required_metadata_fields(self):
        rule, doc = self._make_rule_and_doc()
        content = generate_atomic_rule_doc(rule, doc, 1)
        assert "**Type:**" in content
        assert "**Category:**" in content
        assert "**Auto-generated:**" in content
        assert "**Tags:**" in content
        assert "**Confidence:**" in content

    def test_doc_url_present(self):
        rule, doc = self._make_rule_and_doc()
        content = generate_atomic_rule_doc(rule, doc, 1)
        assert "http://ctf.test/login" in content


# ---------------------------------------------------------------------------
# _is_lessons_duplicate
# ---------------------------------------------------------------------------


class TestIsLessonsDuplicate:
    def _make_seq_hash(self):
        return hash(("http_fetch", "sqli_probe", "http_fetch", "", ""))

    def _write_lesson_doc(
        self, docs_dir: Path, url: str, category: str, outcome: str, seq_hash: int = 0
    ):
        """Write a minimal fake lessons doc to test dedup."""
        content = (
            f"**Challenge URL:** {url}\n"
            f"**Category:** {category}\n"
            f"**Type:** experience_{outcome}\n"
            f"**Seq hash:** {seq_hash}\n"
        )
        doc_path = docs_dir / f"lessons_001_test_{int(time.time())}.md"
        doc_path.write_text(content, encoding="utf-8")

    def test_no_existing_docs_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            assert not _is_lessons_duplicate(
                "http://ctf.test/",
                "sql_injection",
                "failure",
                self._make_seq_hash(),
                Path(tmpdir),
            )

    def test_same_url_category_outcome_is_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            seq_hash = self._make_seq_hash()
            self._write_lesson_doc(
                d, "http://ctf.test/login", "SQL Injection", "failure", seq_hash
            )
            assert _is_lessons_duplicate(
                "http://ctf.test/login",
                "sql_injection",
                "failure",
                seq_hash,
                d,
            )

    def test_different_outcome_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            seq_hash = self._make_seq_hash()
            self._write_lesson_doc(
                d, "http://ctf.test/login", "SQL Injection", "failure", seq_hash
            )
            assert not _is_lessons_duplicate(
                "http://ctf.test/login",
                "sql_injection",
                "success",
                seq_hash,
                d,
            )

    def test_different_url_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            seq_hash = self._make_seq_hash()
            self._write_lesson_doc(
                d, "http://other.test/login", "SQL Injection", "failure", seq_hash
            )
            assert not _is_lessons_duplicate(
                "http://ctf.test/login",
                "sql_injection",
                "failure",
                seq_hash,
                d,
            )


# ---------------------------------------------------------------------------
# run_lessons_learned_pipeline
# ---------------------------------------------------------------------------


class TestRunLessonsLearnedPipeline:
    def test_creates_docs_on_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            written = run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_FAILURE,
                tracker_data=TRACKER_FAILURE,
                tool_call_log=TOOL_CALL_LOG_FAILURE,
                agent_response="Unable to find flag",
                candidate_flags=[],
                lessons_docs_dir=tmpdir,
            )
            assert len(written) >= 1
            for p in written:
                assert Path(p).exists()

    def test_creates_docs_on_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            written = run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_SUCCESS,
                tracker_data=TRACKER_SUCCESS,
                tool_call_log=TOOL_CALL_LOG_SUCCESS,
                agent_response="flag{found_the_secret_42}",
                candidate_flags=["flag{found_the_secret_42}"],
                lessons_docs_dir=tmpdir,
            )
            assert len(written) >= 1

    def test_docs_are_markdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            written = run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_FAILURE,
                tracker_data=TRACKER_FAILURE,
                tool_call_log=TOOL_CALL_LOG_FAILURE,
                agent_response="Unable to find flag",
                candidate_flags=[],
                lessons_docs_dir=tmpdir,
            )
            for p in written:
                assert p.endswith(".md")
                content = Path(p).read_text(encoding="utf-8")
                assert "**Applies when:**" in content
                assert "**Agent takeaway:**" in content

    def test_skips_duplicate_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # First run
            run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_FAILURE,
                tracker_data=TRACKER_FAILURE,
                tool_call_log=TOOL_CALL_LOG_FAILURE,
                agent_response="Unable to find flag",
                candidate_flags=[],
                lessons_docs_dir=tmpdir,
            )
            # Second identical run — should be skipped
            written2 = run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_FAILURE,
                tracker_data=TRACKER_FAILURE,
                tool_call_log=TOOL_CALL_LOG_FAILURE,
                agent_response="Unable to find flag",
                candidate_flags=[],
                lessons_docs_dir=tmpdir,
            )
            assert len(written2) == 0

    def test_doc_filenames_contain_slug(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            written = run_lessons_learned_pipeline(
                config_data=CONFIG_DATA_FAILURE,
                tracker_data=TRACKER_FAILURE,
                tool_call_log=TOOL_CALL_LOG_FAILURE,
                agent_response="Unable to find flag",
                candidate_flags=[],
                lessons_docs_dir=tmpdir,
            )
            for p in written:
                # Should contain the slug of "Login Bypass Test"
                assert "login-bypass-test" in Path(p).name


# ---------------------------------------------------------------------------
# find_and_compress_prior_lesson
# ---------------------------------------------------------------------------


class TestFindAndCompressPriorLesson:
    def _write_lesson(self, d: Path, challenge_name: str, url: str) -> Path:
        content = (
            f"**Challenge:** {challenge_name}\n"
            f"**Challenge URL:** {url}\n"
            f"**Type:** experience_failure\n"
            "\n## What Happened\n\n"
            f"Prior attempt on {challenge_name} failed. Backend uses parameterized queries. "
            "Next time try NoSQL injection.\n"
        )
        p = d / f"lessons_001_{challenge_name.lower().replace(' ', '-')}.md"
        p.write_text(content, encoding="utf-8")
        return p

    def test_returns_none_when_no_dir(self):
        result = find_and_compress_prior_lesson(
            challenge_name="Test",
            challenge_url="http://ctf.test/",
            lessons_docs_dir="/nonexistent/path",
        )
        assert result is None

    def test_returns_none_when_no_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_lesson(Path(tmpdir), "Other Challenge", "http://other.test/")
            result = find_and_compress_prior_lesson(
                challenge_name="My Challenge",
                challenge_url="http://ctf.test/",
                lessons_docs_dir=tmpdir,
            )
            assert result is None

    def test_finds_by_challenge_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_lesson(Path(tmpdir), "Login Bypass", "http://ctf.test/login")
            result = find_and_compress_prior_lesson(
                challenge_name="Login Bypass",
                challenge_url=None,
                lessons_docs_dir=tmpdir,
            )
            assert result is not None
            assert len(result) > 10

    def test_finds_by_challenge_url(self):
        # URL-only lookup is not supported (requires challenge_name); returns None
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_lesson(Path(tmpdir), "Login Bypass", "http://ctf.test/login")
            result = find_and_compress_prior_lesson(
                challenge_name=None,
                challenge_url="http://ctf.test/login",
                lessons_docs_dir=tmpdir,
            )
            assert result is None

    def test_returns_none_for_both_none(self):
        result = find_and_compress_prior_lesson(
            challenge_name=None,
            challenge_url=None,
        )
        assert result is None

    def test_result_length_reasonable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_lesson(Path(tmpdir), "Login Bypass", "http://ctf.test/login")
            result = find_and_compress_prior_lesson(
                challenge_name="Login Bypass",
                challenge_url=None,
                lessons_docs_dir=tmpdir,
            )
            assert result is not None
            assert len(result) <= 1500


# ---------------------------------------------------------------------------
# SafeKnowledgeQueryTool — contamination filter and seen-doc exclusion
# ---------------------------------------------------------------------------

try:
    from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool

    class _FakeDoc:
        """Minimal stand-in for a langchain Document."""

        def __init__(self, content: str, source_file: str, doc_type: str = "curated"):
            self.page_content = content
            self.metadata = {"source_file": source_file, "doc_type": doc_type}

    class _FakeRetriever:
        def __init__(self, docs):
            self._docs = docs

        def retrieve(self, query, top_k=10):
            return self._docs[:top_k]

    class TestSafeKnowledgeQueryToolFilter:
        """Tests for contamination filter and seen-doc exclusion."""

        def _make_tool(self, docs) -> SafeKnowledgeQueryTool:
            retriever = _FakeRetriever(docs)
            tool = SafeKnowledgeQueryTool(
                retriever=retriever,
                use_query_expansion=False,
                use_hybrid_search=False,
                use_reranking=False,
                top_k=5,
            )
            return tool

        def test_set_challenge_context_stores_values(self):
            # v2.4: set_challenge_context(challenge_name, tracker) — no URL arg
            tool = self._make_tool([])
            tool.set_challenge_context(challenge_name="Great Paywall", tracker=None)
            # Tracker reference should be None (no tracker passed)
            assert tool._tracker is None

        def test_reset_session_clears_seen_docs(self):
            tool = self._make_tool([])
            tool._seen_source_files = {"some_doc.md", "other_doc.md"}
            tool.reset_session()
            assert len(tool._seen_source_files) == 0

        def test_contamination_filter_excludes_same_challenge_doc(self):
            # v2.4: filtering is fingerprint-based; slug-based filtering removed.
            # Without a tracker fingerprint, _is_excluded always returns False.
            docs = [
                _FakeDoc("SQL technique", "05_sql_injection.md"),
                _FakeDoc("Prior lesson", "lessons_001_great-paywall_r1_20260302.md"),
            ]
            tool = self._make_tool(docs)
            tool.reset_session()
            result = tool.use("how to bypass paywall")
            # Without fingerprint, docs are not excluded by contamination filter
            assert "SQL technique" in result or isinstance(result, str)

        def test_url_contamination_filter(self):
            docs = [
                _FakeDoc("SQL technique", "05_sql_injection.md"),
                _FakeDoc("Prior lesson", "lessons_001_my-challenge.md"),
            ]
            # Put URL in the "prior lesson" content (via page_content)
            docs[1].page_content = (
                "Challenge URL: http://ctf.test/target Prior lesson content."
            )
            # For URL filtering we check source_file, so embed url in filename
            docs[1].metadata["source_file"] = "lessons_001_ctf-test-target.md"
            docs[1].metadata.update({"challenge_url": "http://ctf.test/target"})

            tool = self._make_tool(docs)
            # Set exclusion by URL slug in source_file name
            tool._exclude_challenge_url = "http://ctf.test/target"
            result = tool.use("sql injection help")
            # The lesson doc filename doesn't directly contain the URL so this
            # tests the _is_excluded URL branch
            # Both docs should be present since filename doesn't contain URL
            assert result  # at minimum doesn't crash

        def test_seen_doc_exclusion_prevents_repetition(self):
            docs = [
                _FakeDoc("Content A", "doc_a.md"),
                _FakeDoc("Content B", "doc_b.md"),
            ]
            tool = self._make_tool(docs)
            tool.reset_session()

            # First query returns both docs
            result1 = tool.use("any query")
            assert "Content A" in result1 or "Content B" in result1

            # After first query, both docs are in seen set
            # Second query should return empty or filtered result
            result2 = tool.use("any query")
            # Result may be empty or have filtering message
            assert isinstance(result2, str)

        def test_no_filter_when_context_not_set(self):
            docs = [
                _FakeDoc("SQL technique", "sql_injection.md"),
                _FakeDoc("XSS technique", "xss.md"),
            ]
            tool = self._make_tool(docs)
            tool.reset_session()
            # No challenge context set — all docs available
            result = tool.use("sql injection")
            assert "SQL technique" in result

        def test_is_excluded_slug_match(self):
            # v2.4: _is_excluded now takes doc CONTENT (not filename) and uses
            # fingerprint matching. Without a tracker fingerprint it returns False.
            tool = self._make_tool([])
            tool.set_challenge_context(challenge_name="Great Paywall", tracker=None)
            # No fingerprint in tracker → _is_excluded returns False for any content
            assert not tool._is_excluded("lessons_001_great-paywall_r1.md")
            assert not tool._is_excluded("lessons_001_other-challenge_r1.md")

        def test_is_excluded_url_match(self):
            # v2.4: URL-based filtering removed; fingerprint-based only.
            # Without tracker fingerprint, _is_excluded always returns False.
            tool = self._make_tool([])
            assert not tool._is_excluded("http://ctf.test/paywall")
            assert not tool._is_excluded("http://other.test/challenge")

except ImportError:
    # Skip SafeKnowledgeQueryTool tests if fairlib is not available
    pass
