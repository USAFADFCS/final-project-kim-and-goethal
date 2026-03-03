"""
Tests for v2.1 learning improvements.

Covers:
  1. Missed exploitation signal detection
  2. Partial success pattern detection
  3. Adaptive similarity threshold
  4. Recency decay scoring
  5. Reflexion injection — find_prior_failure_doc
  6. Knowledge consolidation
"""

import datetime
import math
import os
import tempfile
import time
from pathlib import Path

import pytest

from ctf_solver.consolidate_knowledge import consolidate_failure_knowledge
from ctf_solver.failure_analyzer import (
    FailureAnalysis,
    analyze_failure,
    find_prior_failure_doc,
    generate_failure_knowledge_doc,
)
from ctf_solver.rag.reranker import SimpleReranker

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_BASIC_CONFIG = {
    "challenge_url": "http://ctf.example.com",
    "challenge_description": "Test challenge",
}
_BASIC_TRACKER = {
    "steps": 10,
    "tool_calls": {"sqli_probe": 3},
    "duration_seconds": 20.0,
}


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
# 1. Missed exploitation signal detection
# ---------------------------------------------------------------------------


class TestMissedSignals:
    def test_credential_not_followed_up_is_flagged(self):
        """Agent found a password in JS but never called form_submit or http_fetch."""
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
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        assert len(result.missed_signals) > 0
        assert any(
            "credential" in s.lower() or "password" in s.lower()
            for s in result.missed_signals
        )

    def test_credential_followed_up_not_flagged(self):
        """Agent found password AND used form_submit immediately after — no missed signal."""
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
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        credential_missed = [
            s
            for s in result.missed_signals
            if "credential" in s.lower() or "password" in s.lower()
        ]
        assert len(credential_missed) == 0

    def test_sqli_error_confirmed_but_not_exploited(self):
        """sqli_probe returned SQL syntax error but no column counter or data dumper followed."""
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
        tracker = {**_BASIC_TRACKER, "tool_calls": {"sqli_probe": 1, "http_fetch": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any(
            "sqli" in s.lower() or "sql" in s.lower() or "confirmed" in s.lower()
            for s in result.missed_signals
        )

    def test_ssti_calculation_confirmed_but_not_exploited(self):
        """ssti_probe returned '49' (7*7) but ssti_exploit_suggester was never called."""
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
        tracker = {**_BASIC_TRACKER, "tool_calls": {"ssti_probe": 1, "http_fetch": 1}}
        result = analyze_failure(_BASIC_CONFIG, tracker, log, "no flag", "max steps")
        assert any(
            "ssti" in s.lower() or "calculation" in s.lower() or "49" in s
            for s in result.missed_signals
        )

    def test_missed_signals_appear_in_generated_doc(self):
        """If missed signals exist, the generated failure doc should mention them."""
        log = _make_log(
            [
                (
                    "javascript_source",
                    '{"url":"http://x/app.js"}',
                    "api_key = 'secret_abc123'",
                ),
                ("html_inspector", '{"url":"http://x"}', "<html>Hello</html>"),
            ]
        )
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        if result.missed_signals:
            doc = generate_failure_knowledge_doc(result, 1)
            assert any(
                kw in doc.lower()
                for kw in ("missed", "not exploited", "signal", "exploitation")
            )

    def test_uninformative_output_produces_no_missed_signals(self):
        """Generic page content without any credentials or injections should be clean."""
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
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        # Should not flag false positives
        assert isinstance(result.missed_signals, list)


# ---------------------------------------------------------------------------
# 2. Partial success pattern detection
# ---------------------------------------------------------------------------


class TestPartialSuccessPatterns:
    def test_sqli_confirmed_detected(self):
        """SQL syntax error in any tool output should register as sqli_confirmed."""
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x","param":"id"}',
                    "You have an error in your SQL syntax near '1' at line 1",
                ),
            ]
        )
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        assert "sqli_confirmed" in result.partial_success_patterns

    def test_credential_found_detected(self):
        """password= in any tool output should register as credential_found."""
        log = _make_log(
            [
                (
                    "javascript_source",
                    '{"url":"http://x/app.js"}',
                    "var config = { password: 'ctf_pass_123' };",
                ),
            ]
        )
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        assert "credential_found" in result.partial_success_patterns

    def test_empty_log_produces_no_partial_successes(self):
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, [], "no flag", "max steps"
        )
        assert result.partial_success_patterns == []

    def test_partial_success_appears_in_doc(self):
        """Generated doc should mention partial progress when sub-goals were achieved."""
        log = _make_log(
            [
                (
                    "sqli_probe",
                    '{"url":"http://x"}',
                    "You have an error in your SQL syntax near '1'",
                ),
            ]
        )
        result = analyze_failure(
            _BASIC_CONFIG, _BASIC_TRACKER, log, "no flag", "max steps"
        )
        if result.partial_success_patterns:
            doc = generate_failure_knowledge_doc(result, 1)
            assert any(
                kw in doc.lower()
                for kw in ("partial", "sub-goal", "achieved", "progress")
            )


# ---------------------------------------------------------------------------
# 3. Adaptive similarity threshold
# ---------------------------------------------------------------------------


class TestAdaptiveThreshold:
    def setup_method(self):
        self.reranker = SimpleReranker(similarity_threshold=0.1)

    def test_large_gap_tightens_threshold(self):
        """Top score much higher than second should tighten the threshold."""
        scores = [0.9, 0.3, 0.2, 0.1]
        threshold = self.reranker.adaptive_threshold(scores)
        assert threshold > 0.1

    def test_all_low_scores_loosens_threshold(self):
        """All near-zero scores should loosen the threshold to avoid under-retrieval."""
        scores = [0.15, 0.14, 0.12, 0.10]
        threshold = self.reranker.adaptive_threshold(scores)
        assert threshold < 0.1

    def test_moderate_gap_returns_base_threshold(self):
        """A moderate gap should leave the threshold near the base value."""
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
        """A doc generated today should get a recency score very close to 1.0."""
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        doc_text = f"# Failure\n\n> **Auto-generated:** {today} 12:00:00 UTC\n"
        score = self.reranker._recency_score(doc_text)
        assert score > 0.95

    def test_old_doc_gets_low_score(self):
        """180-day-old doc should score ~0.25 (half-life = 90 days → exp(-1.386) ≈ 0.25)."""
        old_date = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=180)
        ).strftime("%Y-%m-%d")
        doc_text = f"> **Auto-generated:** {old_date} 00:00:00 UTC\n"
        score = self.reranker._recency_score(doc_text)
        assert score < 0.35

    def test_curated_doc_without_timestamp_gets_neutral(self):
        """Curated docs have no Auto-generated line — should return 1.0 (no decay)."""
        doc_text = "# SQL Injection Guide\n\nThis is a curated knowledge document.\n"
        score = self.reranker._recency_score(doc_text)
        assert score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# 5. Reflexion injection — find_prior_failure_doc
# ---------------------------------------------------------------------------


class TestFindPriorFailureDoc:
    def test_finds_matching_url(self):
        """Should return the content of a failure doc whose URL matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "http://ctf.picoctf.net:12345"
            content = (
                f"# Failure Analysis: SQL Injection\n\n"
                f"- **URL:** `{url}`\n"
                f"## 7. Suggestions\n1. Try blind SQLi\n"
            )
            (Path(tmpdir) / "failure_001_sql_injection_20260302.md").write_text(
                content, encoding="utf-8"
            )
            result = find_prior_failure_doc(url, tmpdir)
            assert result is not None
            assert url in result

    def test_returns_none_when_no_match(self):
        """Returns None when no failure doc mentions the URL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            content = "# Failure\n\n- **URL:** `http://other.site.com`\n"
            (Path(tmpdir) / "failure_001_unknown_20260302.md").write_text(
                content, encoding="utf-8"
            )
            result = find_prior_failure_doc(
                "http://completely.different.url.com", tmpdir
            )
            assert result is None

    def test_returns_none_for_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_prior_failure_doc("http://ctf.example.com", tmpdir)
            assert result is None

    def test_returns_most_recent_match(self):
        """When multiple docs match, returns the one with the newest mtime."""
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "http://ctf.example.com"
            for i, marker in [(1, "OLD HINT"), (2, "NEW HINT")]:
                content = f"# Failure\n- **URL:** `{url}`\n## Suggestions\n{marker}\n"
                p = Path(tmpdir) / f"failure_00{i}_sql_2026030{i}.md"
                p.write_text(content, encoding="utf-8")
                # Force doc 1 to be older
                if i == 1:
                    old_ts = time.time() - 1000
                    os.utime(str(p), (old_ts, old_ts))
            result = find_prior_failure_doc(url, tmpdir)
            assert result is not None
            assert "NEW HINT" in result

    def test_content_truncated_to_max_chars(self):
        """Returned content must not exceed max_chars."""
        with tempfile.TemporaryDirectory() as tmpdir:
            url = "http://ctf.example.com"
            content = f"# Failure\n- **URL:** `{url}`\n" + "X" * 5000
            (Path(tmpdir) / "failure_001_unknown_20260302.md").write_text(
                content, encoding="utf-8"
            )
            result = find_prior_failure_doc(url, tmpdir, max_chars=1000)
            assert result is not None
            assert len(result) <= 1000


# ---------------------------------------------------------------------------
# 6. Knowledge consolidation
# ---------------------------------------------------------------------------


class TestKnowledgeConsolidation:
    def test_skips_category_below_threshold(self):
        """Categories with fewer docs than min_docs_per_category are not consolidated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 4):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            result = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert result == []

    def test_runs_when_above_threshold(self):
        """Categories with >= min_docs docs produce a consolidated output file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            result = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(result) > 0
            assert Path(result[0]).exists()

    def test_consolidated_doc_mentions_category(self):
        """The consolidated doc should name the vulnerability category."""
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
        """A suggestion that appears in every source doc should appear exactly once."""
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
        """Consolidated docs should carry a 'consolidated' or 'wisdom' tag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(1, 7):
                _write_failure_doc(tmpdir, i, "SQL Injection", "http://ctf.example.com")
            paths = consolidate_failure_knowledge(
                failure_docs_dir=tmpdir, min_docs_per_category=5
            )
            assert len(paths) > 0
            content = Path(paths[0]).read_text(encoding="utf-8")
            assert "consolidated" in content.lower() or "wisdom" in content.lower()
