"""
Tests for v3.2 grammar-constrained decoding on the Ollama adapter.

Covers:
- OllamaAdapter passes ``format=<schema>`` when ``grammar_schema`` is set
- Back-compat: no ``format=`` when ``grammar_schema`` is None
- TypeError probe: older clients that reject ``format`` degrade silently
- Empty-response fallback synthesizes a valid ReAct JSON envelope
- ``create_adapter`` wires ``grammar_mode`` → concrete schema
- ``SolverConfig.from_env`` reads ``CTF_GRAMMAR_MODE``
- ``create_adapter(provider="anthropic")`` is untouched by the new path
"""

import json
import os
from unittest.mock import Mock, patch

import pytest
from fairlib import Message

from ctf_solver.config import SolverConfig
from ctf_solver.llm import OLLAMA_INSTALLED, OllamaAdapter, create_adapter
from ctf_solver.llm.adapters import _REACT_SCHEMA

# ----------------------------------------------------------------------------
# OllamaAdapter — grammar_schema threading
# ----------------------------------------------------------------------------


@pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
class TestOllamaGrammarSchema:
    """Behaviour of the new ``grammar_schema`` / ``format=`` path."""

    def test_schema_passed_to_client_chat(self):
        """When grammar_schema is set, client.chat receives ``format=``."""
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "{}"}}

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            adapter.invoke([Message(role="user", content="hi")])

        call_kwargs = mock_client.chat.call_args.kwargs
        assert call_kwargs.get("format") == _REACT_SCHEMA

    def test_no_schema_no_format_kwarg(self):
        """Back-compat: no ``format=`` when grammar_schema is None."""
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "hello"}}

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=None)
            adapter.invoke([Message(role="user", content="hi")])

        call_kwargs = mock_client.chat.call_args.kwargs
        assert "format" not in call_kwargs

    def test_typeerror_on_format_degrades_silently(self):
        """Older Ollama clients raise TypeError for ``format=``; the
        adapter should flip its support flag and retry without it."""
        mock_client = Mock()

        def chat_side_effect(**kwargs):
            if "format" in kwargs:
                raise TypeError("chat() got an unexpected keyword argument 'format'")
            return {"message": {"content": "fallback content"}}

        mock_client.chat.side_effect = chat_side_effect

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            # Force the "think" probe to the off state so the retry loop
            # is exercising only the format path.
            adapter._think_supported = False
            result = adapter.invoke([Message(role="user", content="hi")])

            assert adapter._format_supported is False
            assert result.content == "fallback content"

            # Second call should skip ``format`` entirely.
            mock_client.chat.reset_mock()
            adapter.invoke([Message(role="user", content="hi again")])
            second_kwargs = mock_client.chat.call_args.kwargs
            assert "format" not in second_kwargs

    def test_empty_response_fallback_synthesizes_valid_json(self):
        """When grammar is enforced and Ollama still returns empty
        content, the adapter synthesizes a valid ReAct envelope so the
        parser never sees garbage."""
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": ""}}

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            result = adapter.invoke([Message(role="user", content="hi")])

        parsed = json.loads(result.content)
        assert "thought" in parsed
        assert "action" in parsed
        assert "tool_name" in parsed["action"]
        assert "tool_input" in parsed["action"]

    def test_empty_response_no_fallback_when_unconstrained(self):
        """When grammar_schema is None, empty content passes through
        verbatim — don't synthesize on behalf of legacy callers."""
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": ""}}

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(grammar_schema=None)
            result = adapter.invoke([Message(role="user", content="hi")])

        assert result.content == ""


# ----------------------------------------------------------------------------
# create_adapter — grammar_mode wiring
# ----------------------------------------------------------------------------


@pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
class TestCreateAdapterGrammarMode:
    """The factory should translate ``grammar_mode`` into a concrete schema
    only for Ollama, and leave every other provider untouched."""

    def test_ollama_auto_attaches_schema(self):
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = create_adapter(provider="ollama", grammar_mode="auto")
        assert isinstance(adapter, OllamaAdapter)
        assert adapter.grammar_schema == _REACT_SCHEMA

    def test_ollama_none_leaves_schema_off(self):
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = create_adapter(provider="ollama", grammar_mode="none")
        assert isinstance(adapter, OllamaAdapter)
        assert adapter.grammar_schema is None

    def test_ollama_json_schema_attaches_schema(self):
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = create_adapter(provider="ollama", grammar_mode="json_schema")
        assert isinstance(adapter, OllamaAdapter)
        assert adapter.grammar_schema == _REACT_SCHEMA

    def test_ollama_default_mode_is_auto(self):
        """Omitting grammar_mode should still enable the constraint for
        Ollama, because SolverConfig defaults to 'auto' and create_adapter
        should treat a missing value the same way."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = create_adapter(provider="ollama")
        assert adapter.grammar_schema == _REACT_SCHEMA

    def test_anthropic_is_untouched_by_grammar_mode(self):
        """Regression guard: passing grammar_mode to a non-Ollama provider
        must not crash and must not affect the resulting adapter."""
        # Skip if anthropic not installed — this test is about the factory
        # not blowing up, which requires the provider branch to be reachable.
        anthropic = pytest.importorskip("anthropic")
        del anthropic  # only needed for the import check
        with patch("ctf_solver.llm.adapters.Anthropic"):
            adapter = create_adapter(
                provider="anthropic",
                api_key="sk-test",
                grammar_mode="auto",
            )
        # The Anthropic adapter has no grammar_schema attr; asserting its
        # absence is the strongest guarantee that nothing leaked across.
        assert not hasattr(adapter, "grammar_schema")


# ----------------------------------------------------------------------------
# SolverConfig — env var + merge_with_args
# ----------------------------------------------------------------------------


class TestSolverConfigGrammarMode:
    def test_default_is_auto(self):
        cfg = SolverConfig()
        assert cfg.grammar_mode == "auto"

    def test_from_env_reads_ctf_grammar_mode(self):
        with patch.dict(os.environ, {"CTF_GRAMMAR_MODE": "none"}, clear=False):
            cfg = SolverConfig.from_env()
        assert cfg.grammar_mode == "none"

    def test_merge_with_args_overrides(self):
        cfg = SolverConfig(grammar_mode="auto")
        merged = cfg.merge_with_args(grammar_mode="json_schema")
        assert merged.grammar_mode == "json_schema"

    def test_merge_with_args_preserves_when_none_passed(self):
        """merge_with_args should only update when value is not None — so
        passing grammar_mode=None should leave the original in place."""
        cfg = SolverConfig(grammar_mode="none")
        merged = cfg.merge_with_args(grammar_mode=None)
        assert merged.grammar_mode == "none"
