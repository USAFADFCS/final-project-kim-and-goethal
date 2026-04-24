"""
Tests for Phase 1 of the agent-reliability plan:

1a. OllamaAdapter empty-content escalation ladder:
    - 1st empty → ``ctf_knowledge_query`` (accepts plain-string input)
    - 2nd+ empty → ``final_answer`` with CONTEXT_OVERFLOW diagnostic
    - Non-empty content resets the counter

1b. SafeKnowledgeQueryTool dedupes chunks whose (source_file, first
    200 chars) key collides, so the reranker and top_k budget see
    unique candidates only.
"""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest
from fairlib import Message

from ctf_solver.llm import OLLAMA_INSTALLED, OllamaAdapter
from ctf_solver.llm.adapters import _REACT_SCHEMA
from ctf_solver.rag.knowledge_base import SafeKnowledgeQueryTool

# ----------------------------------------------------------------------------
# Phase 1a — empty-content escalation ladder
# ----------------------------------------------------------------------------


@pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
class TestOllamaEmptyContentEscalation:
    """Replaces the old ``attack_planner``-on-empty fallback, which
    produced tool-error cascades (see recentTestRun.txt run 4 steps
    5–7, run 5 steps 5–7)."""

    def _mock_client_returning(self, *contents):
        """Build a mock Ollama client whose .chat() yields the given
        contents in order. After exhausting the list, repeats the last."""
        mock = Mock()
        seq = iter(list(contents))
        last = [contents[-1]]

        def _chat(**_kwargs):
            try:
                c = next(seq)
            except StopIteration:
                c = last[0]
            return {"message": {"content": c}}

        mock.chat.side_effect = _chat
        return mock

    def test_first_empty_pivots_to_knowledge_query(self):
        mock_client = self._mock_client_returning("")
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            result = adapter.invoke([Message(role="user", content="hi")])

        parsed = json.loads(result.content)
        assert parsed["action"]["tool_name"] == "ctf_knowledge_query"
        # Plain-string tool_input is the whole point — ctf_knowledge_query
        # accepts strings, so the next turn won't produce a tool error.
        assert isinstance(parsed["action"]["tool_input"], str)
        assert adapter._consecutive_empty == 1

    def test_second_empty_emits_final_answer(self):
        mock_client = self._mock_client_returning("", "")
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            adapter.invoke([Message(role="user", content="hi")])
            second = adapter.invoke([Message(role="user", content="hi again")])

        parsed = json.loads(second.content)
        assert parsed["action"]["tool_name"] == "final_answer"
        assert "CONTEXT_OVERFLOW" in parsed["action"]["tool_input"]
        assert adapter._consecutive_empty == 2

    def test_non_empty_content_resets_counter(self):
        mock_client = self._mock_client_returning("", '{"ok": true}')
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            adapter.invoke([Message(role="user", content="hi")])
            assert adapter._consecutive_empty == 1
            adapter.invoke([Message(role="user", content="hi again")])
            assert adapter._consecutive_empty == 0

    def test_counter_does_not_persist_after_single_empty_then_real(self):
        """Regression guard: a single empty followed by a real response,
        then another empty much later, should restart the ladder at 1 —
        not escalate straight to final_answer."""
        mock_client = self._mock_client_returning("", '{"x": 1}', "")
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            adapter.invoke([Message(role="user", content="a")])  # empty → query
            adapter.invoke([Message(role="user", content="b")])  # real → reset
            third = adapter.invoke([Message(role="user", content="c")])  # empty → query

        parsed = json.loads(third.content)
        # Still at step 1 of the ladder — knowledge_query, NOT final_answer.
        assert parsed["action"]["tool_name"] == "ctf_knowledge_query"
        assert adapter._consecutive_empty == 1

    def test_no_fallback_when_schema_disabled(self):
        """When grammar_schema is None, empty content passes through
        verbatim and the counter is not touched (back-compat)."""
        mock_client = self._mock_client_returning("")
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=None)
            result = adapter.invoke([Message(role="user", content="hi")])

        assert result.content == ""
        assert adapter._consecutive_empty == 0


# ----------------------------------------------------------------------------
# Phase 1b — RAG chunk dedup
# ----------------------------------------------------------------------------


def _doc(content: str, source: str, section: str = "") -> MagicMock:
    """Build a mock retriever document with page_content + metadata."""
    d = MagicMock()
    d.page_content = content
    d.metadata = {"source_file": source}
    if section:
        d.metadata["section"] = section
    return d


class TestSafeKnowledgeQueryDedup:
    """Hash by (source_file, first 200 chars). Duplicates should not
    pass the Step-3.5 filter into the reranker or into the final output."""

    def test_duplicate_chunks_collapsed_to_one(self):
        # Five copies of the same section — the exact pattern from
        # recentTestRun.txt run 5 step 8.
        dup_content = (
            "# Client-Side Access Control Bypass — CTF Exploitation Reference. "
            "This is a long doc section that the hybrid retriever returned as "
            "five separate hits because the chunker split on nearby boundaries. "
            "The LLM does not need five copies — one is sufficient signal."
        )
        duplicates = [_doc(dup_content, "40_client_side_bypass.md") for _ in range(5)]

        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = duplicates

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("How do I bypass a paywall?")

        # Only one [Result N] header should appear — the other four were
        # duplicates and got collapsed.
        assert output.count("[Result 1]") == 1
        assert "[Result 2]" not in output

    def test_distinct_chunks_preserved(self):
        """Different source files → different keys → all kept (up to top_k)."""
        docs = [
            _doc("Doc A about XSS.", "xss.md"),
            _doc("Doc B about SQLi.", "sqli.md"),
            _doc("Doc C about SSRF.", "ssrf.md"),
        ]
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = docs

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("general query")

        assert "[Result 1]" in output
        assert "[Result 2]" in output
        assert "[Result 3]" in output

    def test_same_source_different_opening_not_deduped(self):
        """The key is (source, first 200 chars). Two chunks from the same
        source file but different opening text are legitimately distinct
        sections and must both survive."""
        docs = [
            _doc("A" * 300 + " first section", "same.md"),
            _doc("B" * 300 + " second section", "same.md"),
        ]
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = docs

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        output = tool.use("q")

        assert "[Result 1]" in output
        assert "[Result 2]" in output

    def test_dedup_runs_before_seen_tracking(self):
        """If dedup ran *after* ``_seen_source_files`` recording, the
        single kept copy could pollute the set and hide the source from
        later queries. Verify the set contains exactly one source after
        five duplicate hits."""
        duplicates = [_doc("same opening text.", "only.md") for _ in range(5)]
        mock_retriever = MagicMock()
        mock_retriever.retrieve.return_value = duplicates

        tool = SafeKnowledgeQueryTool(
            retriever=mock_retriever,
            use_query_expansion=False,
            use_hybrid_search=False,
            use_reranking=False,
            top_k=5,
        )

        tool.use("q")
        assert tool._seen_source_files == {"only.md"}
