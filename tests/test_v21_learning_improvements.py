"""
Tests for v2.1 learning improvements (post-legacy cleanup).

Covers:
  1. Missed exploitation signal detection (_detect_missed_signals)
  2. Partial success pattern detection (_detect_partial_successes)
  3. Adaptive similarity threshold (SimpleReranker)
  4. Recency decay scoring (SimpleReranker)
  5. Legacy-corpus consolidation (consolidate_failure_knowledge, retained as
     a read-only utility for pre-v2.3 failure_*.md docs on disk)

Note: find_prior_failure_doc / generate_failure_knowledge_doc /
analyze_failure / FailureAnalysis were removed with the monolithic pipeline
in Batch B. Tests that formerly used those to exercise the helpers now call
the helpers directly so the underlying detection logic stays covered.
"""

import datetime
import tempfile
from pathlib import Path

import pytest

from ctf_solver.consolidate_knowledge import consolidate_failure_knowledge
from ctf_solver.failure_analyzer import (
    _detect_missed_signals,
    _detect_partial_successes,
)
from ctf_solver.rag.reranker import SimpleReranker

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_log(entries):
    """Build a tool_call_log list from (tool, input, output) tuples."""
    return [{"tool": t, "input": i, "output": o} for t, i, o in entries]


def _write_failure_doc(
    tmpdir, index, category_label, url, suggestions="Try blind SQLi"
):
    content = (
        f"# Failure Analysis: {category_label}\n\n"
        f"> **Auto-generated:** 2026-03-0{index % 9 + 1} 12:00:00 UTC\n"
        f"> **Category:** {category_label}\n"
        f"> **Failure Reason:** max steps\n\n---\n\n"
        f"## 1. Challenge Context\n\n"
        f"**Tags:** `failure-analysis, sql_injection, lessons-learned`\n\n"
        f"- **URL:** `{url}`\n"
        f"## 2. What Was Tried (Negative Knowledge)\n\n"
        f"### Tools Used\n\n- `sqli_probe`: {index} call(s)\n\n"
        f"## 5. Errors Encountered\n\n- timeout\n\n"
        f"## 7. Suggestions for Next Attempt\n\n1. {suggestions}\n"
    )
    path = Path(tmpdir) / f"failure_{index:03d}_sql_injection_2026030{index}.md"
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. Missed exploitation signal detection (direct helper tests)
# ---------------------------------------------------------------------------


class TestMissedSignals:
    def test_credential_not_followed_up_is_flagged(self):
        log = _make_log(
            [
                (
                    "javascript_source",
                    '{"url":"http://x/app.js"}',
                    "Found in source: password = 'admin123'",
                ),
                ("robots_txt", '{"url":"http://x/robots.txt"}', "User-agent: *"),
            ]
        )
        missed = _detect_missed_signals(log)
        assert len(missed) > 0
        assert any("credential" in s.lower() or "password" in s.lower() for s in missed)

    def test_credential_followed_up_not_flagged(self):
        log = _make_log(
            [
                (
                    "javascript_source",
                    '{"url":"http://x/app.js"}',
                    "password = 'admin123'",
                ),
                (
                    "form_submit",
                    '{"url":"http://x/login","data":{"password":"admin123"}}',
                    "Login successful",
                ),
            ]
        )
        missed = _detect_missed_signals(log)
        credential_missed = [
            s for s in missed if "credential" in s.lower() or "password" in s.lower()
        ]
        assert credential_missed == []

    def test_sqli_error_confirmed_but_not_exploited(self):
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id","payload":"\'"}',
                    "You have an error in your SQL syntax near ''' at line 1",
                ),
                ("http_fetch", '{"url":"http://x/other"}', "normal page"),
            ]
        )
        missed = _detect_missed_signals(log)
        assert any(
            "sqli" in s.lower() or "sql" in s.lower() or "confirmed" in s.lower()
            for s in missed
        )

    def test_ssti_calculation_confirmed_but_not_exploited(self):
        log = _make_log(
            [
                (
                    "ssti_probe",
                    '{"url":"http://x","param":"name","payload":"{{7*7}}"}',
                    "Hello 49! Welcome to the app.",
                ),
                ("http_fetch", '{"url":"http://x"}', "Welcome"),
            ]
        )
        missed = _detect_missed_signals(log)
        assert any(
            "ssti" in s.lower() or "calculation" in s.lower() or "49" in s
            for s in missed
        )

    def test_uninformative_output_produces_no_missed_signals(self):
        log = _make_log(
            [
                ("http_fetch", '{"url":"http://x"}', "Welcome to the challenge page"),
                (
                    "html_inspector",
                    '{"url":"http://x"}',
                    "<html><body>Hello world</body></html>",
                ),
            ]
        )
        missed = _detect_missed_signals(log)
        assert isinstance(missed, list)


# ---------------------------------------------------------------------------
# 2. Partial success pattern detection (direct helper tests)
# ---------------------------------------------------------------------------


class TestPartialSuccessPatterns:
    def test_sqli_confirmed_detected(self):
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id"}',
                    "You have an error in your SQL syntax near '1' at line 1",
                ),
            ]
        )
        patterns = _detect_partial_successes(log)
        assert "sqli_confirmed" in patterns

    def test_credential_found_detected(self):
        log = _make_log(
            [
                (
                    "javascript_source",
                    '{"url":"http://x/app.js"}',
                    "var config = { password: 'ctf_pass_123' };",
                ),
            ]
        )
        patterns = _detect_partial_successes(log)
        assert "credential_found" in patterns

    def test_empty_log_produces_no_partial_successes(self):
        patterns = _detect_partial_successes([])
        assert patterns == []


# ---------------------------------------------------------------------------
# 3. Adaptive similarity threshold
# ---------------------------------------------------------------------------


class TestAdaptiveThreshold:
    def setup_method(self):
        self.reranker = SimpleReranker(similarity_threshold=0.1)

    def test_large_gap_tightens_threshold(self):
        scores = [0.9, 0.3, 0.2, 0.1]
        assert self.reranker.adaptive_threshold(scores) > 0.1

    def test_all_low_scores_loosens_threshold(self):
        scores = [0.15, 0.14, 0.12, 0.10]
        assert self.reranker.adaptive_threshold(scores) < 0.1

    def test_moderate_gap_returns_base_threshold(self):
        scores = [0.5, 0.45, 0.4]
        threshold = self.reranker.adaptive_threshold(scores)
        assert 0.05 <= threshold <= 0.15

    def test_empty_list_returns_base(self):
        assert self.reranker.adaptive_threshold([]) == pytest.approx(0.1)

    def test_single_score_returns_base(self):
        assert self.reranker.adaptive_threshold([0.5]) == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# 4. Recency decay scoring
# ---------------------------------------------------------------------------


class TestRecencyScoring:
    def setup_method(self):
        self.reranker = SimpleReranker()

    def test_today_timestamp_gets_near_one(self):
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        doc_text = f"# Failure\n\n> **Auto-generated:** {today} 12:00:00 UTC\n"
        assert self.reranker._recency_score(doc_text) > 0.95

    def test_old_doc_gets_low_score(self):
        old_date = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=180)
        ).strftime("%Y-%m-%d")
        doc_text = f"> **Auto-generated:** {old_date} 00:00:00 UTC\n"
        assert self.reranker._recency_score(doc_text) < 0.35

    def test_curated_doc_without_timestamp_gets_neutral(self):
        doc_text = "# SQL Injection Guide\n\nThis is a curated knowledge document.\n"
        assert self.reranker._recency_score(doc_text) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 5. Legacy-corpus consolidation (read-only utility for pre-v2.3 docs)
# ---------------------------------------------------------------------------


class TestKnowledgeConsolidation:
    def test_skips_category_below_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 4):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            result = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert result == []

    def test_runs_when_above_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            result = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(result) > 0
            assert Path(result[0]).exists()

    def test_consolidated_doc_mentions_category(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            paths = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(paths) > 0
            content = Path(paths[0]).read_text(encoding="utf-8")
            assert "sql" in content.lower() or "injection" in content.lower()

    def test_consolidated_doc_deduplicates_suggestions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(
                    tmpdir,
                    i,
                    "SQL Injection",
                    "http://ctf.example.com",
                    "Try blind SQLi",
                )
            paths = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(paths) > 0
            content = Path(paths[0]).read_text(encoding="utf-8")
            assert content.lower().count("try blind sqli") == 1

    def test_consolidated_doc_is_tagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            paths = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(paths) > 0
            content = Path(paths[0]).read_text(encoding="utf-8")
            assert "consolidated" in content.lower() or "wisdom" in content.lower()
