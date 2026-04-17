"""
Tests for the CTFAgent class — markdown stripping and premature FinalAnswer guard.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fairlib.core.message import Action, FinalAnswer, Message, Thought
from fairlib.modules.planning.react_planner import ReActPlanner

from ctf_solver.agent import CTFAgent, _MD_FENCE_OPEN, _MD_FENCE_CLOSE

# ── Helpers ──────────────────────────────────────────────────────────


@dataclass
class FakeTracker:
    """Minimal tracker stub with candidate_flags_found."""

    candidate_flags_found: List[str] = field(default_factory=list)
    tool_call_log: List[Dict[str, Any]] = field(default_factory=list)


class FakePlanner:
    """Planner stub whose aplan results are controlled by a list."""

    def __init__(self, results):
        self._results = list(results)
        self._call_count = 0
        self.prompt_builder = MagicMock()

    async def aplan(self, history, user_input):
        idx = min(self._call_count, len(self._results) - 1)
        self._call_count += 1
        return self._results[idx]


class FakeExecutor:
    """ToolExecutor stub that returns canned observations."""

    def __init__(self, observation="tool result"):
        self._observation = observation

    def execute(self, tool_name, tool_input):
        return self._observation


class FakeMemory:
    """Minimal memory stub."""

    def __init__(self):
        self._messages: List[Message] = []

    def get_history(self):
        return list(self._messages)

    def add_message(self, msg):
        self._messages.append(msg)

    def clear(self):
        self._messages.clear()


def _make_agent(
    planner_results,
    tracker=None,
    flag_regex=r"FLAG\{[^}]+\}",
    max_steps=10,
    observation="tool result",
):
    """Helper to build a CTFAgent with fake components."""
    planner = FakePlanner(planner_results)
    executor = FakeExecutor(observation)
    memory = FakeMemory()

    agent = CTFAgent(
        llm=MagicMock(),
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=max_steps,
        tracker=tracker,
        flag_regex=flag_regex,
        log_callback=lambda msg: None,  # suppress prints
    )
    return agent


# ── Markdown fence regex tests ───────────────────────────────────────


class TestMarkdownFenceRegex:
    """Test the compiled regexes used for stripping markdown fences."""

    def test_strips_opening_json_fence(self):
        text = '```json\n{"key": 1}'
        result = _MD_FENCE_OPEN.sub("", text)
        assert result == '{"key": 1}'

    def test_strips_opening_fence_no_lang(self):
        text = '```\n{"key": 1}'
        result = _MD_FENCE_OPEN.sub("", text)
        assert result == '{"key": 1}'

    def test_strips_closing_fence(self):
        text = '{"key": 1}\n```'
        result = _MD_FENCE_CLOSE.sub("", text)
        assert result == '{"key": 1}'

    def test_strips_closing_fence_with_trailing_space(self):
        text = '{"key": 1}\n```  '
        result = _MD_FENCE_CLOSE.sub("", text)
        assert result == '{"key": 1}'

    def test_no_fence_no_change(self):
        text = '{"key": 1}'
        assert _MD_FENCE_OPEN.sub("", text) == text
        assert _MD_FENCE_CLOSE.sub("", text) == text


# ── Markdown stripping in planner parse ──────────────────────────────


class TestMarkdownStrippingPatch:
    """Test that CTFAgent patches the planner to strip markdown fences."""

    def test_planner_parse_strips_markdown_fences(self):
        """JSON wrapped in ```json ... ``` should parse correctly."""
        planner = ReActPlanner(llm=MagicMock(), tool_registry=MagicMock())

        # The unpatched parser would fail on this input (return FinalAnswer)
        md_wrapped = '```json\n{"thought": "testing", "action": {"tool_name": "http_fetch", "tool_input": "test"}}\n```'
        unpatched_result = planner._parse_json_response(md_wrapped)
        assert isinstance(
            unpatched_result, FinalAnswer
        ), "Unpatched parser should fail on markdown"

        # Create CTFAgent which patches the planner
        agent = CTFAgent(
            llm=MagicMock(),
            planner=planner,
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=5,
        )

        # Now the patched parser should handle it correctly
        patched_result = planner._parse_json_response(md_wrapped)
        assert not isinstance(patched_result, FinalAnswer)
        thought, action = patched_result
        assert thought.text == "testing"
        assert action.tool_name == "http_fetch"

    def test_planner_parse_still_works_without_markdown(self):
        """Normal JSON (no markdown) should still parse fine."""
        planner = ReActPlanner(llm=MagicMock(), tool_registry=MagicMock())
        agent = CTFAgent(
            llm=MagicMock(),
            planner=planner,
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=5,
        )

        raw_json = '{"thought": "normal", "action": {"tool_name": "robots_txt", "tool_input": "x"}}'
        result = planner._parse_json_response(raw_json)
        assert not isinstance(result, FinalAnswer)
        thought, action = result
        assert action.tool_name == "robots_txt"

    def test_planner_parse_final_answer_still_works(self):
        """final_answer tool should still produce FinalAnswer."""
        planner = ReActPlanner(llm=MagicMock(), tool_registry=MagicMock())
        agent = CTFAgent(
            llm=MagicMock(),
            planner=planner,
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=5,
        )

        raw_json = '{"thought": "found it", "action": {"tool_name": "final_answer", "tool_input": "FLAG{test}"}}'
        result = planner._parse_json_response(raw_json)
        assert isinstance(result, FinalAnswer)
        assert "FLAG{test}" in result.text

    def test_planner_parse_strips_JSON_uppercase(self):
        """```JSON fence should also be stripped."""
        planner = ReActPlanner(llm=MagicMock(), tool_registry=MagicMock())
        agent = CTFAgent(
            llm=MagicMock(),
            planner=planner,
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=5,
        )

        md_wrapped = '```JSON\n{"thought": "test", "action": {"tool_name": "http_fetch", "tool_input": "x"}}\n```'
        result = planner._parse_json_response(md_wrapped)
        assert not isinstance(result, FinalAnswer)

    def test_no_patch_when_planner_lacks_parse_method(self):
        """If planner has no _parse_json_response, patching is skipped gracefully."""
        fake_planner = MagicMock(spec=[])  # no attributes
        # Should not raise
        agent = CTFAgent(
            llm=MagicMock(),
            planner=fake_planner,
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=5,
        )


# ── FinalAnswer guard tests ─────────────────────────────────────────


class TestFinalAnswerGuard:
    """Test premature FinalAnswer prevention."""

    def test_allows_final_answer_with_flag_in_text(self):
        """FinalAnswer containing a flag should be accepted immediately."""
        agent = _make_agent(
            planner_results=[FinalAnswer(text="The flag is FLAG{found_it}")],
        )
        result = asyncio.run(agent.arun("solve challenge"))
        assert "FLAG{found_it}" in result

    def test_allows_final_answer_with_flag_in_tracker(self):
        """FinalAnswer should be accepted if tracker has candidate flags."""
        tracker = FakeTracker(candidate_flags_found=["FLAG{from_tracker}"])
        agent = _make_agent(
            planner_results=[FinalAnswer(text="I found the answer")],
            tracker=tracker,
        )
        result = asyncio.run(agent.arun("solve challenge"))
        assert "I found the answer" in result

    def test_blocks_premature_final_answer_no_flag(self):
        """FinalAnswer without a flag should be blocked and loop continues."""
        # First: premature FinalAnswer (no flag) → blocked, continuation injected
        # Second: a real tool call → executes
        # Third: FinalAnswer with flag → accepted
        agent = _make_agent(
            planner_results=[
                FinalAnswer(text="I don't know the answer"),
                (
                    Thought(text="Let me try robots_txt"),
                    Action(tool_name="robots_txt", tool_input="test"),
                ),
                FinalAnswer(text="FLAG{after_retry}"),
            ],
        )
        result = asyncio.run(agent.arun("solve challenge"))
        assert "FLAG{after_retry}" in result

    def test_guard_injects_continuation_message(self):
        """When FinalAnswer is blocked, a [GUARD] system message should be added to memory."""
        agent = _make_agent(
            planner_results=[
                FinalAnswer(text="giving up"),
                FinalAnswer(text="FLAG{found}"),
            ],
        )
        asyncio.run(agent.arun("solve challenge"))

        # Check memory for the guard message
        history = agent.memory.get_history()
        guard_msgs = [m for m in history if "[GUARD]" in m.content]
        assert len(guard_msgs) == 1
        assert "NO FLAG" in guard_msgs[0].content

    def test_max_premature_retries_then_allows(self):
        """After MAX_PREMATURE_RETRIES, FinalAnswer is allowed even without a flag."""
        results = []
        for i in range(CTFAgent.MAX_PREMATURE_RETRIES + 1):
            results.append(FinalAnswer(text=f"no flag attempt {i}"))

        agent = _make_agent(planner_results=results)
        result = asyncio.run(agent.arun("solve challenge"))
        assert f"no flag attempt {CTFAgent.MAX_PREMATURE_RETRIES}" in result

    def test_premature_count_resets_not_across_calls(self):
        """Each agent instance starts with 0 premature count."""
        agent1 = _make_agent(
            planner_results=[FinalAnswer(text="no flag"), FinalAnswer(text="FLAG{ok}")],
        )
        asyncio.run(agent1.arun("test"))
        assert agent1._premature_fa_count == 1

        # New agent starts fresh
        agent2 = _make_agent(
            planner_results=[FinalAnswer(text="FLAG{immediate}")],
        )
        asyncio.run(agent2.arun("test"))
        assert agent2._premature_fa_count == 0

    def test_guard_counts_correctly(self):
        """Each blocked FinalAnswer increments the premature count."""
        results = [FinalAnswer(text="no flag")] * 3 + [FinalAnswer(text="FLAG{done}")]
        agent = _make_agent(planner_results=results)
        asyncio.run(agent.arun("solve"))
        assert agent._premature_fa_count == 3


# ── Integration-style tests ──────────────────────────────────────────


class TestCTFAgentIntegration:
    """Higher-level tests combining both guards."""

    def test_markdown_wrapped_action_doesnt_cause_premature_stop(self):
        """
        Simulate the bug: LLM wraps JSON in markdown → parser returns FinalAnswer
        → guard catches it (no flag) → loop continues.
        """
        # We use FakePlanner which returns results directly, so we simulate
        # "what would happen if markdown stripping fails" by returning FinalAnswer
        # for the first attempt, then a real action, then a final answer with flag.
        agent = _make_agent(
            planner_results=[
                FinalAnswer(text="```json\n{...attempted action...}\n```"),
                (
                    Thought(text="trying http_fetch"),
                    Action(tool_name="http_fetch", tool_input="test"),
                ),
                FinalAnswer(text="The flag is FLAG{markdown_bug_fixed}"),
            ],
        )
        result = asyncio.run(agent.arun("solve challenge"))
        assert "FLAG{markdown_bug_fixed}" in result

    def test_normal_flow_no_guard_interference(self):
        """Normal flow (tool calls → final answer with flag) is not affected."""
        agent = _make_agent(
            planner_results=[
                (
                    Thought(text="recon"),
                    Action(tool_name="http_fetch", tool_input="url"),
                ),
                (
                    Thought(text="inspect"),
                    Action(tool_name="html_inspector", tool_input="url"),
                ),
                FinalAnswer(text="Flag: FLAG{normal_flow}"),
            ],
        )
        result = asyncio.run(agent.arun("solve challenge"))
        assert "FLAG{normal_flow}" in result
        assert agent._premature_fa_count == 0

    def test_max_steps_still_respected(self):
        """Agent should stop at max_steps even if guard keeps blocking."""
        # All FinalAnswers without flags, but only 3 steps allowed
        agent = _make_agent(
            planner_results=[FinalAnswer(text="no flag")] * 10,
            max_steps=3,
        )
        result = asyncio.run(agent.arun("solve challenge"))
        # Should hit max_steps limit: 3 blocked FinalAnswers → max_steps reached
        assert "max steps" in result.lower() or "no flag" in result.lower()

    def test_stateless_clears_memory(self):
        """Stateless agent clears memory before each run."""
        agent = _make_agent(
            planner_results=[FinalAnswer(text="FLAG{stateless}")],
        )
        agent.stateless = True
        agent.memory.add_message(Message(role="user", content="old"))
        asyncio.run(agent.arun("new task"))
        # Memory should only have messages from the current run
        history = agent.memory.get_history()
        old_msgs = [m for m in history if m.content == "old"]
        assert len(old_msgs) == 0


# ── _has_flag unit tests ─────────────────────────────────────────────


class TestHasFlag:
    """Test the _has_flag method directly."""

    def test_flag_in_text(self):
        agent = _make_agent(planner_results=[])
        assert agent._has_flag("The flag is FLAG{test123}")

    def test_no_flag_in_text(self):
        agent = _make_agent(planner_results=[])
        assert not agent._has_flag("No flag here")

    def test_empty_text(self):
        agent = _make_agent(planner_results=[])
        assert not agent._has_flag("")

    def test_flag_in_tracker(self):
        tracker = FakeTracker(candidate_flags_found=["FLAG{tracker}"])
        agent = _make_agent(planner_results=[], tracker=tracker)
        assert agent._has_flag("")

    def test_no_tracker_no_text(self):
        agent = _make_agent(planner_results=[])
        assert not agent._has_flag()

    def test_custom_flag_regex(self):
        agent = _make_agent(
            planner_results=[],
            flag_regex=r"picoCTF\{[^}]+\}",
        )
        assert agent._has_flag("picoCTF{custom_format}")
        assert not agent._has_flag("FLAG{wrong_format}")


# ── Prompt template tests ────────────────────────────────────────────


class TestPromptGuardrails:
    """Verify prompt templates include the new guardrail instructions."""

    def test_system_prompt_has_json_format_rules(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "CRITICAL RESPONSE FORMAT RULES" in DEFAULT_SYSTEM_PROMPT
        assert "single, valid JSON object" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_final_answer_rules(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "FINAL ANSWER RULES" in DEFAULT_SYSTEM_PROMPT
        assert (
            "ONLY use 'final_answer' when you have actually found a string"
            in DEFAULT_SYSTEM_PROMPT
        )

    def test_system_prompt_warns_against_premature_final(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "do NOT call 'final_answer'" in DEFAULT_SYSTEM_PROMPT

    def test_system_prompt_has_recon_priority_order(self):
        from ctf_solver.prompts.templates import DEFAULT_SYSTEM_PROMPT

        assert "RECONNAISSANCE PRIORITY ORDER" in DEFAULT_SYSTEM_PROMPT
        assert "try fetching those URLs DIRECTLY first" in DEFAULT_SYSTEM_PROMPT
        assert "ONLY after these simple checks fail" in DEFAULT_SYSTEM_PROMPT

    def test_initial_message_has_simple_checks_guidance(self):
        from ctf_solver.prompts.templates import get_initial_message

        msg = get_initial_message(challenge_url="http://example.com")
        assert "SIMPLE approaches first" in msg
        assert "try fetching them directly" in msg
