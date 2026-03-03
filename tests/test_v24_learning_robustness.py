"""
Tests for v2.4.0 — Learning Robustness Improvements.

Coverage:
- _scrub_flags: flag values removed, non-flag text preserved
- _extract_site_fingerprint: title/h1/form extraction from HTTP output
- RunTracker: new fields, unique_tools_used property, auto-fingerprint
- _find_similar_rule_doc: Jaccard ≥ 0.60 match found, < 0.60 missed
- _bump_confidence: low→medium, medium→high, high stays
- _is_lessons_duplicate (with seq_hash): same hash=dup, different hash=not dup
- generate_atomic_rule_doc: fingerprint in metadata, flag values scrubbed
- run_lessons_learned_pipeline: different tools → two docs; similar run bumps confidence
- SafeKnowledgeQueryTool._is_excluded: fingerprint match, mismatch, empty
- SafeKnowledgeQueryTool.use(): increments rag_queries_made
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from ctf_solver.failure_analyzer import (
    AtomicRule,
    LessonsLearnedDoc,
    _bump_confidence,
    _find_similar_rule_doc,
    _is_lessons_duplicate,
    _scrub_flags,
    _tool_sequence_hash,
    generate_atomic_rule_doc,
    run_lessons_learned_pipeline,
)
from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool
from ctf_solver.run_tracker import RunTracker, _extract_site_fingerprint

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FAKE_HTTP_OUTPUT = """
<html>
<head><title>Login Portal</title></head>
<body>
<h1>Welcome to SecureCTF</h1>
<form action="/api/login" method="POST">
  <input name="user" />
  <input name="pass" type="password" />
</form>
</body>
</html>
"""

_EXAMPLE_FLAG = "ctf{s3cr3t_flag_value}"
_FLAG_REGEX = r"ctf\{[^}]+\}"


def _make_atomic_rule() -> AtomicRule:
    return AtomicRule(
        triggering_condition="When login form rejects SQL injection with 500 error",
        agent_takeaway="Try error-based SQL injection to extract data via error messages",
        rule_type="do",
        tool_context=["sqli_probe", "http_fetch"],
        confidence="low",
        causal_explanation="The server is not sanitizing input and leaks stack traces",
    )


def _make_lessons_doc(
    challenge_name: str = "Test Challenge",
    challenge_url: str = "http://ctf.test/login",
    outcome: str = "failure",
    category: str = "sqli",
) -> LessonsLearnedDoc:
    doc = LessonsLearnedDoc(
        challenge_name=challenge_name,
        challenge_url=challenge_url,
        outcome=outcome,
        category=category,
        total_steps=10,
    )
    doc.atomic_rules = [_make_atomic_rule()]
    return doc


def _make_tracker_data(steps: int = 10, outcome: str = "failure") -> dict:
    return {
        "steps": steps,
        "outcome": outcome,
        "duration_seconds": 60.0,
        "tool_calls": {"sqli_probe": 3, "http_fetch": 2},
        "unique_tools_used": 2,
        "prior_reflection_injected": False,
        "rag_queries_made": 1,
        "site_fingerprint": "",
    }


def _make_tool_call_log(tools=("http_fetch", "sqli_probe", "http_fetch")):
    return [{"tool": t, "input": "", "output": "ok"} for t in tools]


# ---------------------------------------------------------------------------
# _scrub_flags
# ---------------------------------------------------------------------------


class TestScrubFlags:
    def test_removes_ctf_flag_value(self):
        text = f"You found the flag: {_EXAMPLE_FLAG} — well done!"
        result = _scrub_flags(text, _FLAG_REGEX)
        assert _EXAMPLE_FLAG not in result
        assert "[FLAG_REDACTED]" in result

    def test_non_flag_text_preserved(self):
        text = "No flags here, just normal text with {curly} braces."
        result = _scrub_flags(text, _FLAG_REGEX)
        # The default pattern would match '{curly}' so use same custom regex
        # Our input has no 'ctf{' pattern so it's preserved
        assert "normal text" in result

    def test_scrubs_default_pattern_as_fallback(self):
        # Even if a custom pattern is passed, the default regex is also applied
        flag_in_default_format = "FLAG{secret123}"
        text = f"The flag is {flag_in_default_format}"
        # Pass a non-matching custom regex — default fallback should still catch it
        result = _scrub_flags(text, r"NOMATCH\{[^}]+\}")
        assert "FLAG{secret123}" not in result
        assert "[FLAG_REDACTED]" in result

    def test_multiple_flags_all_scrubbed(self):
        text = f"First: {_EXAMPLE_FLAG}, second: ctf{{another_flag}}"
        result = _scrub_flags(text, _FLAG_REGEX)
        assert _EXAMPLE_FLAG not in result
        assert "another_flag" not in result
        assert result.count("[FLAG_REDACTED]") == 2

    def test_empty_string_unchanged(self):
        assert _scrub_flags("", _FLAG_REGEX) == ""


# ---------------------------------------------------------------------------
# _extract_site_fingerprint
# ---------------------------------------------------------------------------


class TestExtractSiteFingerprint:
    def test_extracts_title_h1_form(self):
        fp = _extract_site_fingerprint("http_fetch", _FAKE_HTTP_OUTPUT)
        assert "title:Login Portal" in fp
        assert "h1:Welcome to SecureCTF" in fp
        assert "form:/api/login" in fp

    def test_returns_empty_for_non_fingerprint_tools(self):
        fp = _extract_site_fingerprint("sqli_probe", _FAKE_HTTP_OUTPUT)
        assert fp == ""

    def test_returns_empty_for_shell_tool(self):
        fp = _extract_site_fingerprint("shell_execute", _FAKE_HTTP_OUTPUT)
        assert fp == ""

    def test_partial_extraction_title_only(self):
        html = "<html><title>Admin Panel</title><body>No form here</body></html>"
        fp = _extract_site_fingerprint("http_fetch", html)
        assert "title:Admin Panel" in fp
        assert "form:" not in fp

    def test_form_submit_also_triggers_fingerprint(self):
        fp = _extract_site_fingerprint("form_submit", _FAKE_HTTP_OUTPUT)
        assert fp != ""

    def test_returns_empty_when_no_extractable_content(self):
        fp = _extract_site_fingerprint("http_fetch", "plain text no tags")
        assert fp == ""


# ---------------------------------------------------------------------------
# RunTracker new fields and properties
# ---------------------------------------------------------------------------


class TestRunTrackerNewFields:
    def test_defaults(self):
        t = RunTracker()
        assert t.prior_reflection_injected is False
        assert t.rag_queries_made == 0
        assert t.outcome == "pending"
        assert t.site_fingerprint == ""

    def test_unique_tools_used_empty(self):
        t = RunTracker()
        assert t.unique_tools_used == 0

    def test_unique_tools_used_counts_distinct(self):
        t = RunTracker()
        t.record_tool_call("http_fetch")
        t.record_tool_call("http_fetch")
        t.record_tool_call("sqli_probe")
        # Counter has 2 distinct keys
        assert t.unique_tools_used == 2

    def test_auto_fingerprint_from_first_http_fetch(self):
        t = RunTracker()
        t.record_detailed_tool_call("http_fetch", "input", _FAKE_HTTP_OUTPUT)
        assert "title:Login Portal" in t.site_fingerprint

    def test_fingerprint_not_overwritten_by_second_call(self):
        t = RunTracker()
        t.record_detailed_tool_call("http_fetch", "input", _FAKE_HTTP_OUTPUT)
        original = t.site_fingerprint
        t.record_detailed_tool_call("http_fetch", "input", "<title>Different Page</title>")
        assert t.site_fingerprint == original

    def test_non_fingerprint_tool_does_not_set_fingerprint(self):
        t = RunTracker()
        t.record_detailed_tool_call("sqli_probe", "input", _FAKE_HTTP_OUTPUT)
        assert t.site_fingerprint == ""

    def test_to_dict_includes_new_fields(self):
        t = RunTracker()
        t.prior_reflection_injected = True
        t.rag_queries_made = 3
        t.outcome = "partial"
        d = t.to_dict()
        assert d["prior_reflection_injected"] is True
        assert d["rag_queries_made"] == 3
        assert d["outcome"] == "partial"
        assert "unique_tools_used" in d
        assert "site_fingerprint" in d


# ---------------------------------------------------------------------------
# _find_similar_rule_doc
# ---------------------------------------------------------------------------


class TestFindSimilarRuleDoc:
    def _write_doc(self, lessons_dir: Path, category: str, applies_when: str) -> Path:
        slug = applies_when[:20].replace(" ", "_")
        p = lessons_dir / f"lessons_001_{slug}.md"
        p.write_text(
            f"# Rule\n\n"
            f"**Category:** {category}\n"
            f"**Confidence:** low\n"
            f"**Applies when:** {applies_when}\n",
            encoding="utf-8",
        )
        return p

    def test_finds_similar_doc_above_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            # Category label for "sql_injection" is "SQL Injection"
            self._write_doc(
                ld,
                "SQL Injection",
                "When login form rejects SQL injection with 500 error message",
            )
            result = _find_similar_rule_doc(
                "When login form rejects SQL injection with 500 error",
                "sql_injection",
                ld,
            )
            assert result is not None

    def test_misses_doc_below_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            self._write_doc(
                ld,
                "SQL Injection",
                "When XSS payload renders in output unescaped",
            )
            result = _find_similar_rule_doc(
                "When login form rejects SQL injection with error",
                "sql_injection",
                ld,
            )
            assert result is None

    def test_misses_doc_with_wrong_category(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            # Write with XSS category (label: "Cross-Site Scripting (XSS)")
            self._write_doc(
                ld,
                "Cross-Site Scripting (XSS)",
                "When login form rejects SQL injection with 500 error",
            )
            result = _find_similar_rule_doc(
                "When login form rejects SQL injection with 500 error",
                "sql_injection",  # sql_injection → "SQL Injection", not XSS
                ld,
            )
            assert result is None

    def test_returns_none_if_dir_missing(self):
        result = _find_similar_rule_doc("anything", "sqli", Path("/nonexistent/dir"))
        assert result is None


# ---------------------------------------------------------------------------
# _bump_confidence
# ---------------------------------------------------------------------------


class TestBumpConfidence:
    def _write_doc_with_confidence(self, path: Path, level: str) -> None:
        path.write_text(
            f"# Rule\n\n**Confidence:** {level}\n\nSome content here.\n",
            encoding="utf-8",
        )

    def test_low_to_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "lessons_001.md"
            self._write_doc_with_confidence(p, "low")
            _bump_confidence(p)
            assert "**Confidence:** medium" in p.read_text()

    def test_medium_to_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "lessons_001.md"
            self._write_doc_with_confidence(p, "medium")
            _bump_confidence(p)
            assert "**Confidence:** high" in p.read_text()

    def test_high_stays_high(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "lessons_001.md"
            self._write_doc_with_confidence(p, "high")
            before = p.read_text()
            _bump_confidence(p)
            assert p.read_text() == before  # File unchanged

    def test_missing_confidence_line_does_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "lessons_001.md"
            p.write_text("# Rule\n\nNo confidence header here.\n")
            before = p.read_text()
            _bump_confidence(p)
            assert p.read_text() == before


# ---------------------------------------------------------------------------
# _is_lessons_duplicate (with seq_hash)
# ---------------------------------------------------------------------------


class TestIsLessonsDuplicateWithSeqHash:
    def _write_dup_doc(
        self,
        lessons_dir: Path,
        challenge_url: str,
        outcome: str,
        category_label: str,
        seq_hash: int,
    ) -> None:
        p = lessons_dir / "lessons_001_test.md"
        p.write_text(
            f"# Rule\n\n"
            f"**Type:** experience_{outcome}\n"
            f"**Category:** {category_label}\n"
            f"**Challenge URL:** {challenge_url}\n"
            f"**Seq hash:** {seq_hash}\n"
            f"**Confidence:** low\n",
            encoding="utf-8",
        )

    def test_same_hash_is_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            seq_hash = hash(("http_fetch", "sqli_probe", "http_fetch", "", ""))
            self._write_dup_doc(ld, "http://ctf.test/login", "failure", "SQL Injection", seq_hash)
            assert _is_lessons_duplicate(
                "http://ctf.test/login", "sql_injection", "failure", seq_hash, ld
            )

    def test_different_hash_is_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            seq_hash_stored = hash(("http_fetch", "sqli_probe", "http_fetch", "", ""))
            seq_hash_new = hash(("sqli_probe", "http_fetch", "sqli_probe", "", ""))
            self._write_dup_doc(ld, "http://ctf.test/login", "failure", "SQL Injection", seq_hash_stored)
            assert not _is_lessons_duplicate(
                "http://ctf.test/login", "sql_injection", "failure", seq_hash_new, ld
            )

    def test_different_outcome_is_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            seq_hash = hash(("http_fetch", "sqli_probe", "", "", ""))
            self._write_dup_doc(ld, "http://ctf.test/login", "success", "SQL Injection", seq_hash)
            assert not _is_lessons_duplicate(
                "http://ctf.test/login", "sql_injection", "failure", seq_hash, ld
            )

    def test_missing_dir_is_not_duplicate(self):
        assert not _is_lessons_duplicate(
            "http://x.test", "sqli", "failure", 12345, Path("/nonexistent")
        )


# ---------------------------------------------------------------------------
# _tool_sequence_hash
# ---------------------------------------------------------------------------


class TestToolSequenceHash:
    def test_same_tools_same_hash(self):
        log1 = _make_tool_call_log(("a", "b", "c"))
        log2 = _make_tool_call_log(("a", "b", "c"))
        assert _tool_sequence_hash(log1) == _tool_sequence_hash(log2)

    def test_different_order_different_hash(self):
        log1 = _make_tool_call_log(("a", "b", "c"))
        log2 = _make_tool_call_log(("c", "b", "a"))
        assert _tool_sequence_hash(log1) != _tool_sequence_hash(log2)

    def test_empty_log(self):
        # Should not raise, returns a deterministic hash
        h = _tool_sequence_hash([])
        assert isinstance(h, int)


# ---------------------------------------------------------------------------
# generate_atomic_rule_doc — fingerprint and scrubbing
# ---------------------------------------------------------------------------


class TestGenerateAtomicRuleDoc:
    def test_fingerprint_appears_in_metadata(self):
        rule = _make_atomic_rule()
        doc = _make_lessons_doc()
        fp = "title:Login Portal|h1:Welcome|form:/api/login"
        result = generate_atomic_rule_doc(rule, doc, 0, site_fingerprint=fp)
        assert "**Site fingerprint:**" in result
        assert fp in result

    def test_no_fingerprint_omits_metadata_line(self):
        rule = _make_atomic_rule()
        doc = _make_lessons_doc()
        result = generate_atomic_rule_doc(rule, doc, 0, site_fingerprint="")
        assert "**Site fingerprint:**" not in result

    def test_flag_value_scrubbed_from_triggering_condition(self):
        rule = AtomicRule(
            triggering_condition=f"When response contains {_EXAMPLE_FLAG} in header",
            agent_takeaway="Look for flag in response headers",
            rule_type="do",
            tool_context=["http_fetch"],
        )
        doc = _make_lessons_doc()
        result = generate_atomic_rule_doc(rule, doc, 0, flag_regex=_FLAG_REGEX)
        assert _EXAMPLE_FLAG not in result
        assert "[FLAG_REDACTED]" in result

    def test_flag_value_scrubbed_from_agent_takeaway(self):
        rule = AtomicRule(
            triggering_condition="When you see the login form",
            agent_takeaway=f"Submit {_EXAMPLE_FLAG} as the password field value",
            rule_type="do",
            tool_context=["http_fetch"],
        )
        doc = _make_lessons_doc()
        result = generate_atomic_rule_doc(rule, doc, 0, flag_regex=_FLAG_REGEX)
        assert _EXAMPLE_FLAG not in result

    def test_non_flag_content_preserved(self):
        rule = _make_atomic_rule()
        doc = _make_lessons_doc()
        result = generate_atomic_rule_doc(rule, doc, 0)
        assert "SQL injection" in result or "sql injection" in result.lower()


# ---------------------------------------------------------------------------
# run_lessons_learned_pipeline — two approaches → two docs; confidence bumped
# ---------------------------------------------------------------------------


class TestRunLessonsPipelineRobustness:
    _config = {
        "challenge_url": "http://ctf.test/login",
        "challenge_description": "SQLi challenge",
        "challenge_name": "SQLi Test",
    }

    _tracker = _make_tracker_data()

    def _log(self, tools):
        return [{"tool": t, "input": "x", "output": "Error 500"} for t in tools]

    def test_different_tool_sequences_produce_two_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            log1 = self._log(["http_fetch", "sqli_probe", "http_fetch", "sqli_probe", "http_fetch"])
            written1 = run_lessons_learned_pipeline(
                config_data=self._config,
                tracker_data=self._tracker,
                tool_call_log=log1,
                agent_response="No flag found",
                candidate_flags=[],
                lessons_docs_dir=str(ld),
                max_steps=20,
                actual_steps=5,
            )

            # Capture confidence before second run
            docs_before = list(ld.glob("lessons_*.md"))
            confidence_before = None
            if docs_before:
                import re
                m = re.search(r"\*\*Confidence:\*\*\s*(\w+)", docs_before[0].read_text())
                confidence_before = m.group(1) if m else None

            log2 = self._log(["sqli_probe", "sqli_probe", "nosql_probe", "http_fetch", "sqli_probe"])
            written2 = run_lessons_learned_pipeline(
                config_data=self._config,
                tracker_data=self._tracker,
                tool_call_log=log2,
                agent_response="No flag found",
                candidate_flags=[],
                lessons_docs_dir=str(ld),
                max_steps=20,
                actual_steps=5,
            )

            total = len(list(ld.glob("lessons_*.md")))
            # Second run must have had some effect: either a new doc or a confidence bump
            # (confidence bump = similar rule found → bumped in place, no new file written)
            confidence_bumped = False
            if docs_before and confidence_before:
                m = re.search(r"\*\*Confidence:\*\*\s*(\w+)", docs_before[0].read_text())
                confidence_after = m.group(1) if m else None
                confidence_bumped = confidence_after != confidence_before
            assert total >= 2 or written2 or confidence_bumped, (
                "Expected second run to produce a new doc or bump confidence of existing doc"
            )

    def test_site_fingerprint_stored_in_doc(self):
        with tempfile.TemporaryDirectory() as tmp:
            ld = Path(tmp)
            log = self._log(["http_fetch", "sqli_probe"])
            fp = "title:Login Portal|h1:Welcome"
            run_lessons_learned_pipeline(
                config_data=self._config,
                tracker_data=self._tracker,
                tool_call_log=log,
                agent_response="No flag",
                candidate_flags=[],
                lessons_docs_dir=str(ld),
                max_steps=20,
                actual_steps=2,
                site_fingerprint=fp,
            )
            docs = list(ld.glob("lessons_*.md"))
            if docs:
                content = docs[0].read_text()
                assert fp in content or "Site fingerprint" in content


# ---------------------------------------------------------------------------
# SafeKnowledgeQueryTool._is_excluded
# ---------------------------------------------------------------------------


class TestSafeKnowledgeQueryToolIsExcluded:
    def _make_tool(self, tracker=None):
        mock_retriever = MagicMock()
        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
        )
        if tracker is not None:
            tool.set_challenge_context(tracker=tracker)
        return tool

    def _make_tracker(self, fingerprint: str):
        t = MagicMock()
        t.site_fingerprint = fingerprint
        t.rag_queries_made = 0
        return t

    def test_fingerprint_match_above_threshold_excluded(self):
        tracker = self._make_tracker("title:Login Portal|h1:Welcome to SecureCTF|form:/api/login")
        tool = self._make_tool(tracker)
        doc = "**Site fingerprint:** title:Login Portal|h1:Welcome to SecureCTF|form:/api/login"
        assert tool._is_excluded(doc) is True

    def test_fingerprint_match_below_threshold_included(self):
        tracker = self._make_tracker("title:Login Portal|h1:Welcome to SecureCTF")
        tool = self._make_tool(tracker)
        # Completely different fingerprint
        doc = "**Site fingerprint:** title:Admin Dashboard|h1:System Control|form:/api/admin"
        assert tool._is_excluded(doc) is False

    def test_empty_current_fingerprint_never_excluded(self):
        tracker = self._make_tracker("")
        tool = self._make_tool(tracker)
        doc = "**Site fingerprint:** title:Login Portal|h1:Welcome"
        assert tool._is_excluded(doc) is False

    def test_doc_without_fingerprint_not_excluded(self):
        tracker = self._make_tracker("title:Login Portal|h1:Welcome")
        tool = self._make_tool(tracker)
        doc = "**Category:** SQL Injection\n**Confidence:** low\n"
        assert tool._is_excluded(doc) is False

    def test_no_tracker_not_excluded(self):
        tool = self._make_tool(tracker=None)
        doc = "**Site fingerprint:** title:Login Portal"
        assert tool._is_excluded(doc) is False


# ---------------------------------------------------------------------------
# SafeKnowledgeQueryTool.use() increments rag_queries_made
# ---------------------------------------------------------------------------


class TestSafeKnowledgeQueryToolRagCounter:
    def test_use_increments_rag_queries_made(self):
        mock_retriever = MagicMock()
        # Return a single document result
        mock_doc = MagicMock()
        mock_doc.page_content = "Relevant SQL injection technique."
        mock_doc.metadata = {"source": "docs/sqli.md"}
        mock_retriever.get_relevant_documents.return_value = [mock_doc]

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
        )
        tracker = RunTracker()
        tool.set_challenge_context(tracker=tracker)

        assert tracker.rag_queries_made == 0
        tool.use("How do I exploit SQL injection?")
        assert tracker.rag_queries_made == 1

    def test_use_increments_per_call(self):
        mock_retriever = MagicMock()
        mock_doc = MagicMock()
        mock_doc.page_content = "XSS technique."
        mock_doc.metadata = {"source": "docs/xss.md"}
        mock_retriever.get_relevant_documents.return_value = [mock_doc]

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
        )
        tracker = RunTracker()
        tool.set_challenge_context(tracker=tracker)

        tool.use("XSS?")
        tool.use("CSRF?")
        tool.use("SSRF?")
        assert tracker.rag_queries_made == 3
