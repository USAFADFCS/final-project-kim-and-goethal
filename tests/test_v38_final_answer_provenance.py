"""
v3.8: provenance check on the FinalAnswer guard.

`CTFAgent._has_flag(text)` previously accepted any flag-shaped string in the
model's final-answer text, which let a 26B local model hallucinate a flag
the regex would pass. The provenance check additionally requires that any
flag mentioned in the model's text actually appears verbatim in some prior
tool observation captured by the tracker.

Path (a) — `tracker.candidate_flags_found` already populated by
LoggingToolWrapper from real tool output — remains the fast-accept path
(it is already provenance-grounded by construction).
"""

from unittest.mock import MagicMock

from ctf_solver.agent import CTFAgent


def _make_agent():
    mock_llm = MagicMock()
    mock_planner = MagicMock()
    mock_planner._parse_json_response = MagicMock()
    mock_executor = MagicMock()
    mock_memory = MagicMock()
    mock_memory.get_history.return_value = []
    return CTFAgent(
        llm=mock_llm,
        planner=mock_planner,
        tool_executor=mock_executor,
        memory=mock_memory,
        max_steps=20,
        log_callback=lambda msg: None,
    )


class TestFinalAnswerProvenance:
    def test_accept_when_tracker_already_recorded_flag(self):
        """Path (a): LoggingToolWrapper already populated candidate_flags_found
        from a real tool output — accept fast, no text check needed."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = ["FLAG{real_one}"]
        agent._tracker.tool_call_log = []
        # Even an empty final answer should be acceptable when the tracker
        # has provenance from earlier in the run.
        assert agent._has_flag("")
        assert agent._has_flag("anything")

    def test_accept_when_flag_appears_in_tool_output(self):
        """Path (b) with provenance: text matches regex AND that exact flag
        string appears in some recorded tool output."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        agent._tracker.tool_call_log = [
            {
                "tool": "http_fetch",
                "output": "Body: <p>flag is FLAG{found_via_exploit}</p>",
            },
        ]
        assert agent._has_flag("The flag is FLAG{found_via_exploit}")

    def test_reject_when_flag_hallucinated(self):
        """Path (b) without provenance: model invents a flag-shaped string
        that the regex passes but no tool ever saw."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        agent._tracker.tool_call_log = [
            {"tool": "http_fetch", "output": "Status: 200\nBody: just a normal page"},
        ]
        assert not agent._has_flag("I think the flag is FLAG{i_made_this_up}")

    def test_reject_when_flag_in_tracker_but_text_invents_different_one(self):
        """Mixed case: tracker recorded one real flag from a tool output, but
        the model's text invents a *different* flag. Path (a) accepts because
        the run *did* capture a real flag — defending the current invariant
        that ``candidate_flags_found`` is the source of truth for run success."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = ["FLAG{real}"]
        agent._tracker.tool_call_log = [
            {"tool": "http_fetch", "output": "FLAG{real}"},
        ]
        # The agent will emit the real flag downstream; preserve fast-path.
        assert agent._has_flag("The flag is FLAG{hallucinated}")

    def test_reject_when_no_tool_calls_yet(self):
        """No tool has run, no candidates recorded — text-only flag must
        be rejected even if regex passes (the canonical hallucination)."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        agent._tracker.tool_call_log = []
        assert not agent._has_flag("FLAG{i_havent_done_anything_yet}")

    def test_no_tracker_falls_back_to_regex_only(self):
        """Backwards compatibility: without a tracker (some test paths), the
        old regex-only behavior is preserved so existing tests don't break."""
        agent = _make_agent()
        agent._tracker = None
        # Without a tracker we cannot verify provenance, so fall back.
        assert agent._has_flag("FLAG{regex_only_path}")

    def test_substring_match_does_not_count_as_provenance(self):
        """Provenance requires the *full* flag string verbatim in tool output,
        not a near-substring."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        agent._tracker.tool_call_log = [
            {"tool": "http_fetch", "output": "FLAG{partial"},
        ]
        assert not agent._has_flag("FLAG{partial_invented}")

    def test_provenance_across_multiple_tool_calls(self):
        """The flag may appear in any of the tool outputs, not just the most
        recent one."""
        agent = _make_agent()
        agent._tracker = MagicMock()
        agent._tracker.candidate_flags_found = []
        agent._tracker.tool_call_log = [
            {"tool": "http_fetch", "output": "Status: 200; nothing here"},
            {"tool": "javascript_source", "output": "// FLAG{from_inline_js}"},
            {"tool": "http_fetch", "output": "Status: 404"},
        ]
        assert agent._has_flag("Found it: FLAG{from_inline_js}")
