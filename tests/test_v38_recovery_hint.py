"""
v3.8 P1: recovery-prompt tag.

When a tool observation carries a ``→ Hint:`` line from
``parse_json_input``'s malformed-input classifier, the agent loop
surfaces a separate ``[RECOVERY-HINT]`` system message so the next
planner turn sees the directive prominently instead of as buried
prose.
"""

import asyncio
from unittest.mock import MagicMock

from fairlib.core.message import Action, Thought

from ctf_solver.agent import CTFAgent
from tests.test_ctf_agent import FakeMemory, FakePlanner


class TestRecoveryHint:
    def _make_agent(self):
        return CTFAgent(
            llm=MagicMock(),
            planner=MagicMock(_parse_json_response=MagicMock()),
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=20,
            log_callback=lambda msg: None,
        )

    def _run(self, observation: str, tool_name: str = "http_fetch"):
        agent = self._make_agent()
        executor = MagicMock()
        executor.execute.return_value = observation
        agent.tool_executor = executor
        agent.planner = FakePlanner(
            [
                (Thought(text="t"), Action(tool_name=tool_name, tool_input="bad")),
                (Thought(text="t2"), Action(tool_name=tool_name, tool_input="bad2")),
            ]
        )
        agent.max_steps = 1
        asyncio.run(agent.arun("solve"))
        return agent

    def test_hint_triggers_recovery_message(self):
        obs = (
            "[HttpFetchTool] Error: tool_input must be JSON. "
            "Decoding failed with: x\n  → Hint: Input is not JSON. "
            'Pass a JSON object like `{"url": "..."}`.'
        )
        agent = self._run(obs)
        history = agent.memory.get_history()
        recovery = [m for m in history if "[RECOVERY-HINT]" in m.content]
        assert len(recovery) == 1
        assert "http_fetch" in recovery[0].content
        assert "JSON object" in recovery[0].content

    def test_no_hint_no_recovery_message(self):
        """Non-malformed-input errors don't trigger recovery hints."""
        obs = "[HttpFetchTool] Error: connection refused"
        agent = self._run(obs)
        history = agent.memory.get_history()
        recovery = [m for m in history if "[RECOVERY-HINT]" in m.content]
        assert len(recovery) == 0

    def test_hint_in_unrelated_text_no_recovery(self):
        """A `→ Hint:` substring without `tool_input must be JSON` does
        not trigger recovery — avoids false positives on tool outputs
        that happen to contain the arrow."""
        obs = "[XssProbeTool] Reflection found. → Hint: Try DOM context next."
        agent = self._run(obs)
        history = agent.memory.get_history()
        recovery = [m for m in history if "[RECOVERY-HINT]" in m.content]
        assert len(recovery) == 0
