"""
Tests for the local-LLM performance audit fixes (2026-05-18).

Plan reference: ~/.claude/plans/jaunty-baking-reddy.md.

Each section guards one fix:
- TestEnableThinkingFlag (fix #1): think= kwarg is OPT-IN
- TestOllamaSchemaCache (fix #2): build_react_schema runs at most once
  between set_tool_descriptors calls
- TestTokenTrackingSkip (fix #3): tiktoken bypass via skip_token_estimation
- TestFlagRegexPrecompile (fix #4): re.compile fires only at wrapper init
- TestObservationTruncation (fix #5): _truncate_observation honors the cap
- TestMlxSchemaCache (regression for the already-fixed MLX cache)
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, Mock, patch

import pytest
from fairlib import Message

from ctf_solver.config import SolverConfig
from ctf_solver.llm import OLLAMA_INSTALLED, OllamaAdapter
from ctf_solver.llm.adapters import _REACT_SCHEMA
from ctf_solver.run_tracker import RunTracker, TokenTrackingAdapter
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

DEFAULT_FLAG_REGEX = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}"

# ---------------------------------------------------------------------------
# Fix #1 — enable_thinking is opt-in
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
class TestEnableThinkingFlag:
    def test_think_kwarg_omitted_by_default(self):
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "{}"}}
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter()
            adapter.invoke([Message(role="user", content="hi")])
        call_kwargs = mock_client.chat.call_args.kwargs
        assert (
            "think" not in call_kwargs
        ), f"think= must NOT be sent by default; got kwargs={call_kwargs}"

    def test_think_kwarg_sent_when_enabled(self):
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "{}"}}
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter(enable_thinking=True)
            adapter.invoke([Message(role="user", content="hi")])
        assert mock_client.chat.call_args.kwargs.get("think") is True

    def test_config_default_off(self):
        assert SolverConfig().enable_thinking is False

    def test_config_merge_with_args(self):
        cfg = SolverConfig().merge_with_args(enable_thinking=True)
        assert cfg.enable_thinking is True

    def test_config_from_env(self, monkeypatch):
        monkeypatch.delenv("CTF_ENABLE_THINKING", raising=False)
        assert SolverConfig.from_env().enable_thinking is False
        monkeypatch.setenv("CTF_ENABLE_THINKING", "true")
        assert SolverConfig.from_env().enable_thinking is True


# ---------------------------------------------------------------------------
# Fix #2 — Ollama format schema cache
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
class TestOllamaSchemaCache:
    def _descriptors(self):
        # build_react_schema is permissive about descriptor shape; matches
        # the tuple signature in adapters.py:1140.
        return [
            ("http_fetch", "fetch a URL", None, None),
            ("regex_search", "search via regex", None, None),
        ]

    def test_schema_built_once_across_invokes(self, monkeypatch):
        from ctf_solver.llm import adapters

        calls = {"n": 0}
        real = adapters.build_react_schema

        def counting(descs):
            calls["n"] += 1
            return real(descs)

        monkeypatch.setattr(adapters, "build_react_schema", counting)
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "{}"}}
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            a = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            a.set_tool_descriptors(self._descriptors())
            for _ in range(5):
                a.invoke([Message(role="user", content="hi")])
        assert calls["n"] == 1, f"expected exactly 1 schema build, got {calls['n']}"

    def test_set_tool_descriptors_invalidates_cache(self, monkeypatch):
        from ctf_solver.llm import adapters

        calls = {"n": 0}
        real = adapters.build_react_schema

        def counting(descs):
            calls["n"] += 1
            return real(descs)

        monkeypatch.setattr(adapters, "build_react_schema", counting)
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "{}"}}
        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            a = OllamaAdapter(grammar_schema=_REACT_SCHEMA)
            a.set_tool_descriptors(self._descriptors())
            a.invoke([Message(role="user", content="hi")])  # build 1
            a.invoke([Message(role="user", content="hi")])  # cached
            # Rewire descriptors — should invalidate.
            a.set_tool_descriptors([("http_fetch", "fetch a URL", None, None)])
            a.invoke([Message(role="user", content="hi")])  # build 2
        assert (
            calls["n"] == 2
        ), f"expected 2 schema builds (one per rewire), got {calls['n']}"


# ---------------------------------------------------------------------------
# Fix #3 — TokenTrackingAdapter skip path
# ---------------------------------------------------------------------------


class TestTokenTrackingSkip:
    def test_skip_uses_char_fallback_not_tiktoken(self):
        tracker = RunTracker()
        inner = MagicMock()
        inner.invoke.return_value = Message(role="assistant", content="abcd")
        adapter = TokenTrackingAdapter(inner, tracker, skip_token_estimation=True)
        with patch.object(adapter, "_resolve_encoder") as resolver:
            adapter.invoke([Message(role="user", content="user-content")])
            resolver.assert_not_called()
        assert tracker.llm_calls == 1
        # record_llm_call writes chars/4 into prompt_tokens / completion_tokens.
        # Prompt content "user-content" = 12 chars → ≥3 tokens. Completion
        # "abcd" = 4 chars → ≥1 token.
        assert tracker.prompt_tokens >= 3
        assert tracker.completion_tokens >= 1

    def test_default_path_still_calls_estimate(self):
        # When skip_token_estimation defaults to False, _estimate is
        # the normal code path. We don't assert tiktoken specifically
        # (it may not be installed), but the call must succeed and
        # increment the counter.
        tracker = RunTracker()
        inner = MagicMock()
        inner.invoke.return_value = Message(role="assistant", content="x")
        adapter = TokenTrackingAdapter(inner, tracker)
        adapter.invoke([Message(role="user", content="y")])
        assert tracker.llm_calls == 1


# ---------------------------------------------------------------------------
# Fix #4 — flag regex precompile
# ---------------------------------------------------------------------------


class TestFlagRegexPrecompile:
    def test_compile_fires_only_at_init(self, monkeypatch):
        calls = {"n": 0}
        real_compile = re.compile

        def counting(pattern, *args, **kwargs):
            calls["n"] += 1
            return real_compile(pattern, *args, **kwargs)

        monkeypatch.setattr(re, "compile", counting)
        inner = MagicMock()
        inner.name = "mock"
        inner.description = ""
        inner.use.return_value = "no flags here"
        # Reset counter AFTER construction so we measure only .use() compiles.
        wrapper = LoggingToolWrapper(
            inner, flag_regex=DEFAULT_FLAG_REGEX, log_callback=lambda m: None
        )
        baseline = calls["n"]
        for _ in range(10):
            wrapper.use("{}")
        assert calls["n"] == baseline, (
            f"expected zero new re.compile() calls during .use(); "
            f"saw {calls['n'] - baseline}"
        )

    def test_bad_regex_disables_flag_scan_without_crash(self):
        inner = MagicMock()
        inner.name = "mock"
        inner.description = ""
        inner.use.return_value = "flag{whatever}"
        wrapper = LoggingToolWrapper(
            inner, flag_regex="[unclosed", log_callback=lambda m: None
        )
        assert wrapper._flag_pattern is None
        # .use() must not raise even though scanning is disabled.
        wrapper.use("{}")

    def test_set_flag_regex_recompiles(self):
        inner = MagicMock()
        inner.name = "mock"
        inner.description = ""
        inner.use.return_value = "matched-FLAG{good}"
        wrapper = LoggingToolWrapper(
            inner, flag_regex=DEFAULT_FLAG_REGEX, log_callback=lambda m: None
        )
        original = wrapper._flag_pattern
        wrapper.set_flag_regex(r"NEW\{[^}]+\}")
        assert wrapper._flag_pattern is not None
        assert wrapper._flag_pattern is not original


# ---------------------------------------------------------------------------
# Fix #5 — observation truncation
# ---------------------------------------------------------------------------


class TestObservationTruncation:
    def _bare_agent(self, max_chars):
        from ctf_solver.agent import CTFAgent

        agent = CTFAgent.__new__(CTFAgent)
        agent._observation_max_chars = max_chars
        return agent

    def test_no_cap_is_passthrough(self):
        agent = self._bare_agent(None)
        big = "A" * 50_000
        assert agent._truncate_observation(big) == big

    def test_zero_cap_is_passthrough(self):
        # Defensive: 0 must NOT truncate to empty.
        agent = self._bare_agent(0)
        assert agent._truncate_observation("hello") == "hello"

    def test_short_text_unchanged(self):
        agent = self._bare_agent(4000)
        assert agent._truncate_observation("hello world") == "hello world"

    def test_oversized_truncated_with_marker(self):
        agent = self._bare_agent(100)
        out = agent._truncate_observation("A" * 5000)
        assert out.endswith("chars]")
        # 100 char prefix + "\n...[truncated 4900 chars]" suffix (~27 chars)
        assert len(out) <= 100 + 50
        assert out.startswith("A" * 100)

    def test_truncated_chars_count_correct(self):
        agent = self._bare_agent(10)
        out = agent._truncate_observation("X" * 30)
        # Marker should reflect the 20 chars dropped.
        assert "truncated 20 chars" in out

    def test_config_default_is_none(self):
        assert SolverConfig().observation_max_chars is None

    def test_config_merge_with_args(self):
        cfg = SolverConfig().merge_with_args(observation_max_chars=4000)
        assert cfg.observation_max_chars == 4000

    def test_config_from_env(self, monkeypatch):
        monkeypatch.delenv("CTF_OBSERVATION_MAX_CHARS", raising=False)
        assert SolverConfig.from_env().observation_max_chars is None
        monkeypatch.setenv("CTF_OBSERVATION_MAX_CHARS", "1500")
        assert SolverConfig.from_env().observation_max_chars == 1500


# ---------------------------------------------------------------------------
# MLX schema cache — regression test only (already-fixed behavior).
# Skip when mlx_lm isn't importable so non-MLX dev machines pass.
# ---------------------------------------------------------------------------


class TestMlxSchemaCache:
    def test_mlx_cache_holds_across_invokes(self, monkeypatch):
        try:
            from ctf_solver.llm.adapters import (  # noqa: F401
                MLXAdapter,
                build_react_schema,
            )
        except Exception:
            pytest.skip("MLX stack not importable")

        from ctf_solver.llm import adapters

        # Sidestep MLX model loading entirely by constructing without
        # __init__ and seeding only the cache-relevant attributes.
        adapter = MLXAdapter.__new__(MLXAdapter)
        adapter._tool_descriptors = [("http_fetch", "x", None, None)]
        adapter._output_type_cache = None
        adapter._descriptors_key = None
        adapter._allowed_tool_names = None
        adapter.grammar_schema = _REACT_SCHEMA

        calls = {"n": 0}
        real_fn = adapters.build_react_schema

        def counting(descs):
            calls["n"] += 1
            return real_fn(descs)

        monkeypatch.setattr(adapters, "build_react_schema", counting)

        # The helper itself; call it directly without doing real inference.
        out1 = adapter._build_output_type()
        out2 = adapter._build_output_type()
        out3 = adapter._build_output_type()
        # Exact value comparison is implementation-specific; the contract
        # is that the build function isn't called again on cache hits.
        assert calls["n"] <= 1
        assert out1 is out2 is out3
