"""
v3.8 hard-stop on the StuckDetector.

After ``hard_stop_threshold`` (default 5) identical (tool, input) pairs the
detector emits a ``[STUCK-HARD-STOP]``-tagged message.  The agent loop greps
for that tag in observations and advances the stall-nudge machinery so the
model sees an escalating system message on its next turn instead of waiting
for the soft stall-window clock.
"""

from unittest.mock import MagicMock

from ctf_solver.tools.logging_wrapper import (
    STUCK_HARD_STOP_TAG,
    StuckDetector,
)


class TestStuckDetectorHardStop:
    def test_below_threshold_no_warning(self):
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(2):
            assert det.check("http_fetch", '{"url": "x"}') is None

    def test_soft_warning_at_threshold(self):
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(2):
            det.check("http_fetch", '{"url": "x"}')
        out = det.check("http_fetch", '{"url": "x"}')
        assert out is not None
        assert "[WARNING]" in out
        assert STUCK_HARD_STOP_TAG not in out

    def test_hard_stop_at_hard_threshold(self):
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(4):
            det.check("http_fetch", '{"url": "x"}')
        out = det.check("http_fetch", '{"url": "x"}')
        assert out is not None
        assert STUCK_HARD_STOP_TAG in out
        assert "5" in out
        assert "different tool" in out.lower()

    def test_hard_stop_persists_after_threshold(self):
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(5):
            det.check("http_fetch", '{"url": "x"}')
        # 6th call: hard-stop continues firing, not regressing to soft warning
        out = det.check("http_fetch", '{"url": "x"}')
        assert STUCK_HARD_STOP_TAG in out

    def test_hard_stop_disabled(self):
        """Setting hard_stop_threshold=None disables the hard stop entirely."""
        det = StuckDetector(threshold=3, hard_stop_threshold=None)
        for _ in range(10):
            out = det.check("http_fetch", '{"url": "x"}')
            assert out is None or STUCK_HARD_STOP_TAG not in out

    def test_separate_keys_track_independently(self):
        """Different (tool, input) pairs do not aggregate."""
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(4):
            det.check("http_fetch", '{"url": "a"}')
        # Different input — fresh count
        for _ in range(2):
            assert det.check("http_fetch", '{"url": "b"}') is None


class TestAgentReactsToHardStop:
    """The agent loop should detect ``STUCK_HARD_STOP_TAG`` in tool
    observations and advance ``_stall_checks`` / pull ``_last_progress_step``
    back so the next iteration's stall nudge fires."""

    def _make_agent(self):
        from ctf_solver.agent import CTFAgent
        from tests.test_ctf_agent import FakeMemory

        agent = CTFAgent(
            llm=MagicMock(),
            planner=MagicMock(_parse_json_response=MagicMock()),
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=20,
            log_callback=lambda msg: None,
        )
        return agent

    def test_hard_stop_tag_advances_stall_checks(self):
        import asyncio

        from fairlib.core.message import Action, Thought

        from tests.test_ctf_agent import FakePlanner

        agent = self._make_agent()
        # Override the FakeExecutor to return a hard-stop-tagged observation.
        executor = MagicMock()
        executor.execute.return_value = (
            f"some result\n\n{STUCK_HARD_STOP_TAG} you are stuck"
        )
        agent.tool_executor = executor
        agent.planner = FakePlanner(
            [
                (Thought(text="t"), Action(tool_name="x", tool_input="y")),
                (Thought(text="t2"), Action(tool_name="x", tool_input="y")),
            ]
        )
        agent.max_steps = 1
        asyncio.run(agent.arun("solve"))
        assert agent._stall_checks >= 1
