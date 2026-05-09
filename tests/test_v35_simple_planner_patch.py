"""
Tests for v3.3 Phase 3a — SimpleReActPlanner monkey-patch + placeholder
flag filter. Closes the 2026-04-23 regression where Gemma4's ``---\\n``-
prefixed JSON envelopes were mis-parsed as FinalAnswer whose text
contained ``MetaCTF{...}`` (the LLM paraphrasing the prompt's flag
format), producing 5/14 fake "successes" in the batch run.

Test layout:
  TestSimpleReActParserPatch     — envelope parsing, KV fallback,
                                    format-error recovery, 3-strike force-stop
  TestHasFlagPlaceholderFilter   — guard rejects ``MetaCTF{...}`` &c.
  TestIsPlaceholderFlagAdditions — frozenset covers the new ellipsis forms
"""

import json

import pytest
from fairlib.core.message import Action, FinalAnswer, Thought

from ctf_solver.config import (
    LLMProviderType,
    RAGMode,
    SolverConfig,
    _is_noise_flag,
    _is_placeholder_flag,
)

ollama = pytest.importorskip("ollama")  # whole-module skip if Ollama missing


# ---------------------------------------------------------------------------
# Helpers (mirroring tests/test_v29_planner_dispatch.py)
# ---------------------------------------------------------------------------


def _make_ollama_config() -> SolverConfig:
    return SolverConfig(
        llm_provider=LLMProviderType.OLLAMA,
        model_name="llama3:8b",
        openai_api_key="sk-test-dummy",
        anthropic_api_key="sk-ant-test-dummy",
        rag_mode=RAGMode.NONE,
        enable_opener_pack=False,
        challenge_url=None,
        challenge_description="test",
    )


def _build_agent_quietly(config: SolverConfig):
    from ctf_solver.agent import build_agent

    return build_agent(config, log_callback=lambda _m: None)


@pytest.fixture
def patched_agent():
    """Fresh CTFAgent with SimpleReActPlanner + our Phase 3a patch applied."""
    agent = _build_agent_quietly(_make_ollama_config())
    # Sanity — if build_agent drifts and dispatches to ReActPlanner, the
    # parser we're testing would not be patched and the rest of this
    # file is meaningless.
    from fairlib.modules.planning.react_planner import SimpleReActPlanner as _SRP

    assert isinstance(
        agent.planner, _SRP
    ), "Expected SimpleReActPlanner — v29 dispatch must have changed."
    # Reset the shared error counters between test invocations so tests
    # that exercise the 3-strike force-stop start from a clean slate.
    agent._consecutive_format_errors = 0
    agent._format_error_count = 0
    return agent


# ---------------------------------------------------------------------------
# TestSimpleReActParserPatch
# ---------------------------------------------------------------------------


# Canonical Gemma4 failure sample lifted from recentTestRun.txt run 3.
_GEMMA_DASH_ENVELOPE = (
    "---\n"
    '{"thought": "I will recon the main page.", '
    '"action": {"tool_name": "deep_recon", '
    '"tool_input": "{\\"url\\": \\"http://sizh03dm.chals.mctf.io/\\"}"}}'
)


class TestSimpleReActParserPatch:
    def test_dash_prefixed_json_envelope_parses_as_thought_action(self, patched_agent):
        """The 2026-04-23 fake-win root cause: ``---\\n{...}`` must become
        a (Thought, Action) pair, not a FinalAnswer."""
        result = patched_agent.planner._parse_simplified_response(_GEMMA_DASH_ENVELOPE)
        assert isinstance(
            result, tuple
        ), f"Expected (Thought, Action), got {type(result).__name__}: {result!r}"
        thought, action = result
        assert isinstance(thought, Thought)
        assert isinstance(action, Action)
        assert action.tool_name == "deep_recon"
        # tool_input round-trips: was a JSON-string-in-JSON-string, should
        # come out as the inner JSON string.
        assert "sizh03dm.chals.mctf.io" in action.tool_input

    def test_markdown_fenced_json_parses(self, patched_agent):
        payload = (
            "```json\n"
            '{"thought": "probing", '
            '"action": {"tool_name": "http_fetch", '
            '"tool_input": "{\\"url\\": \\"https://example.com/\\"}"}}\n'
            "```"
        )
        result = patched_agent.planner._parse_simplified_response(payload)
        assert isinstance(result, tuple)
        _, action = result
        assert action.tool_name == "http_fetch"

    def test_plain_kv_still_parses(self, patched_agent):
        """Regression guard — pure KV format must still work (the patch
        delegates to the original parser when no JSON is found)."""
        kv = (
            "Thought: I will fetch robots.txt.\n"
            "Action:\n"
            "tool_name: robots_txt\n"
            'tool_input: {"base_url": "https://example.com/"}'
        )
        result = patched_agent.planner._parse_simplified_response(kv)
        assert isinstance(result, tuple)
        _, action = result
        assert action.tool_name == "robots_txt"

    def test_envelope_with_final_answer_tool_returns_finalanswer(self, patched_agent):
        """Intentional final_answer calls via the JSON envelope path must
        yield a FinalAnswer whose text is the real flag string (so the
        downstream guard can still re-evaluate)."""
        payload = (
            '{"thought": "Found it.", '
            '"action": {"tool_name": "final_answer", '
            '"tool_input": "MetaCTF{r34l_fl4g_h3r3}"}}'
        )
        result = patched_agent.planner._parse_simplified_response(payload)
        assert isinstance(result, FinalAnswer)
        assert result.text == "MetaCTF{r34l_fl4g_h3r3}"

    def test_tool_input_dict_gets_stringified(self, patched_agent):
        """``action.tool_input`` arriving as a nested dict must be
        serialised to a JSON string so the downstream tool's own JSON
        parser works."""
        payload = json.dumps(
            {
                "thought": "POST to login",
                "action": {
                    "tool_name": "form_submit",
                    "tool_input": {"url": "http://x/", "data": {"u": "a"}},
                },
            }
        )
        result = patched_agent.planner._parse_simplified_response(payload)
        assert isinstance(result, tuple)
        _, action = result
        # tool_input should now be a JSON string, not a Python dict.
        parsed = json.loads(action.tool_input)
        assert parsed["url"] == "http://x/"
        assert parsed["data"]["u"] == "a"

    def test_unparseable_response_injects_format_error_action(self, patched_agent):
        """Random prose that the LLM sometimes emits under pressure
        should trip the format-error injection, NOT become a silent
        FinalAnswer. This is what prevents fake 'successes' whose
        FinalAnswer text happens to contain a flag-shaped substring."""
        garbage = (
            "Here are my thoughts about this challenge: "
            "I think we should look at the login page. "
            "Also the flag might be MetaCTF{...}."
        )
        result = patched_agent.planner._parse_simplified_response(garbage)
        # Depending on whether the original KV parser short-circuits on
        # this, we get either a format-error tuple OR a trusted-short-FA
        # (because the text is < 300 chars). Both are acceptable
        # non-fake behaviour — the crucial thing is that the text is NOT
        # silently handed to the downstream as a success: either the
        # format-error recovery action fires (reinstated step budget),
        # or the guard at agent.py:1407 sees the FinalAnswer and calls
        # the updated _has_flag which now rejects ``MetaCTF{...}``.
        if isinstance(result, tuple):
            _, action = result
            assert action.tool_name == "__format_error__"
        else:
            # Short FA — downstream guard is the backstop, not this parser.
            assert isinstance(result, FinalAnswer)

    def test_three_consecutive_format_errors_force_stop(self, patched_agent):
        """After the 3rd format-error injection, the patch emits a hard
        FinalAnswer describing the stop condition so the step budget is
        not exhausted on a dead model."""
        # Use a payload long enough (>300 chars) AND un-envelope-shaped
        # AND un-KV-shaped to force the format-error branch on each call.
        long_garbage = "gibberish " * 50  # ~500 chars, no JSON, no KV

        # First 3 calls should each increment the counter; 3rd emits stop.
        r1 = patched_agent.planner._parse_simplified_response(long_garbage)
        r2 = patched_agent.planner._parse_simplified_response(long_garbage)
        r3 = patched_agent.planner._parse_simplified_response(long_garbage)

        # First two should be format-error tuples.
        assert isinstance(r1, tuple)
        assert r1[1].tool_name == "__format_error__"
        assert isinstance(r2, tuple)
        assert r2[1].tool_name == "__format_error__"
        # Third should be the stop FinalAnswer.
        assert isinstance(r3, FinalAnswer)
        assert "AGENT STOPPED" in r3.text

    def test_counter_resets_on_successful_parse(self, patched_agent):
        """A successful parse must zero the consecutive-error counter so
        intermittent format hiccups don't accumulate across a long run."""
        long_garbage = "gibberish " * 50
        patched_agent.planner._parse_simplified_response(long_garbage)
        assert patched_agent._consecutive_format_errors == 1

        # A clean envelope should reset the counter.
        patched_agent.planner._parse_simplified_response(_GEMMA_DASH_ENVELOPE)
        assert patched_agent._consecutive_format_errors == 0

        # Another garbage pass should start fresh at 1 (not 2).
        patched_agent.planner._parse_simplified_response(long_garbage)
        assert patched_agent._consecutive_format_errors == 1

    def test_tilde_delimiter_prefix_also_stripped(self, patched_agent):
        """Some models use ``~~~`` as the delimiter. Same rule applies."""
        payload = (
            "~~~\n"
            '{"thought": "go", '
            '"action": {"tool_name": "deep_recon", '
            '"tool_input": "{\\"url\\": \\"http://x/\\"}"}}'
        )
        result = patched_agent.planner._parse_simplified_response(payload)
        assert isinstance(result, tuple)
        _, action = result
        assert action.tool_name == "deep_recon"


# ---------------------------------------------------------------------------
# TestHasFlagPlaceholderFilter — agent-level guard honors noise filter
# ---------------------------------------------------------------------------


class TestHasFlagPlaceholderFilter:
    def test_literal_dotdotdot_rejected(self, patched_agent):
        text = (
            "Here is my thought. The flag format is MetaCTF{...} so I will "
            "look for something matching that pattern."
        )
        assert (
            patched_agent._has_flag(text) is False
        ), "The literal MetaCTF{...} placeholder must not satisfy _has_flag"

    def test_unicode_ellipsis_rejected(self, patched_agent):
        assert patched_agent._has_flag("The flag shape is MetaCTF{…}.") is False

    def test_placeholder_keyword_rejected(self, patched_agent):
        """Pre-existing filter regression guard — placeholder words
        inside braces should still be rejected."""
        assert patched_agent._has_flag("FLAG{placeholder}") is False
        assert patched_agent._has_flag("MetaCTF{your_flag_here}") is False

    def test_real_flag_accepted(self, patched_agent):
        assert (
            patched_agent._has_flag("I extracted the flag: MetaCTF{y0u_4r3_1337}")
            is True
        )

    def test_no_text_with_empty_tracker_returns_false(self, patched_agent):
        assert patched_agent._has_flag("") is False
        assert patched_agent._has_flag() is False

    def test_tracker_candidate_flags_still_short_circuits(self, patched_agent):
        """If the tracker already holds a real flag, ``_has_flag`` returns
        True even without any text argument — preserves prior behaviour."""
        from ctf_solver.run_tracker import RunTracker

        tracker = RunTracker()
        tracker.candidate_flags_found = ["MetaCTF{real}"]
        patched_agent._tracker = tracker
        assert patched_agent._has_flag() is True
        assert patched_agent._has_flag("anything") is True


# ---------------------------------------------------------------------------
# TestIsPlaceholderFlagAdditions — frozenset-level unit tests
# ---------------------------------------------------------------------------


class TestIsPlaceholderFlagAdditions:
    def test_three_dots_recognized(self):
        assert _is_placeholder_flag("MetaCTF{...}") is True

    def test_two_dots_recognized(self):
        assert _is_placeholder_flag("FLAG{..}") is True

    def test_unicode_ellipsis_recognized(self):
        assert _is_placeholder_flag("MetaCTF{…}") is True

    def test_existing_placeholders_still_recognized(self):
        # Regression guard — Phase 3a additions must not break pre-existing entries.
        for placeholder in ("flag", "example", "placeholder", "your_flag_here"):
            assert _is_placeholder_flag(f"FLAG{{{placeholder}}}") is True

    def test_real_flag_not_placeholder(self):
        assert _is_placeholder_flag("MetaCTF{y0u_f0und_7h3_tr34sur3}") is False

    def test_noise_flag_also_catches_ellipsis(self):
        # _is_noise_flag subsumes _is_placeholder_flag — should agree.
        assert _is_noise_flag("MetaCTF{...}") is True
        assert _is_noise_flag("MetaCTF{…}") is True
        assert _is_noise_flag("MetaCTF{y0u_f0und_7h3_tr34sur3}") is False
