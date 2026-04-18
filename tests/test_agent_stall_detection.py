"""Tests for CTFAgent's stall detector and the 3-tier RAG nudge.

Tier 1 ([STALLED-DETECTOR]) fires when:
  - 5+ tool calls happened without any new URL / status / flag signal, AND
  - ``tracker.rag_queries_made == 0``.

Tier 2 ([STALLED-TIER-2]) fires 5+ stall steps after tier 1, regardless of
RAG usage — pushes the agent off a dead-end vulnerability hypothesis.

Tier 3 ([STALLED-TIER-3]) fires 5+ stall steps after tier 2 — tells the
agent to emit 'Final Answer' with its current best guess and stop.

If progress is observed before the threshold, the counter resets.
"""

from fairlib import Message

from ctf_solver.agent import CTFAgent
from ctf_solver.run_tracker import RunTracker


def _agent_with_tracker() -> CTFAgent:
    """Build a bare CTFAgent we can poke at directly. We skip fairlib's
    normal constructor path by instantiating the class and then running the
    init work needed for these unit tests — no LLM, no tools, no loop."""
    agent = CTFAgent.__new__(CTFAgent)
    agent._tracker = RunTracker()
    agent._flag_regex = r"MetaCTF\{[^}]+\}"
    agent._log_fn = lambda *_a, **_k: None
    agent._last_progress_step = 0
    agent._stall_nudge_tier = 0
    agent._stall_checks = 0
    agent._seen_paths = set()
    agent._seen_statuses = set()
    agent._tool_call_history = []
    return agent


class TestProgressSignal:
    def test_new_url_path_counts_as_progress(self):
        agent = _agent_with_tracker()
        obs = "Status: 200 URL: http://target/admin body"
        assert agent._observation_shows_progress(obs) is True
        assert "/admin" in agent._seen_paths

    def test_repeat_url_path_does_not_count(self):
        agent = _agent_with_tracker()
        obs = "Status: 200 http://target/admin"
        agent._observation_shows_progress(obs)  # first time: progress
        # Same path, same status → no new signals.
        assert agent._observation_shows_progress(obs) is False

    def test_new_status_code_counts_as_progress(self):
        agent = _agent_with_tracker()
        agent._observation_shows_progress("Status: 200 http://x/a")
        assert agent._observation_shows_progress("Status: 302 http://x/a") is True

    def test_flag_match_always_counts_as_progress(self):
        agent = _agent_with_tracker()
        # Even without a new URL or status, a flag in the text is progress.
        obs = "Got it: MetaCTF{example}"
        assert agent._observation_shows_progress(obs) is True

    def test_empty_observation_is_not_progress(self):
        agent = _agent_with_tracker()
        assert agent._observation_shows_progress("") is False


class TestStallNudge:
    def test_tier1_fires_after_threshold_with_zero_rag(self):
        agent = _agent_with_tracker()
        # Simulate: we're on step 5, last progress was at step 0.
        turn_messages = []
        agent._maybe_inject_stall_nudge(step=5, turn_messages=turn_messages)
        assert agent._stall_nudge_tier == 1
        assert len(turn_messages) == 1
        assert "[STALLED-DETECTOR]" in turn_messages[0].content
        assert agent._tracker.stall_nudges_fired == [6]

    def test_tier1_suppressed_below_threshold(self):
        agent = _agent_with_tracker()
        turn_messages = []
        agent._maybe_inject_stall_nudge(step=4, turn_messages=turn_messages)
        assert agent._stall_nudge_tier == 0
        assert turn_messages == []

    def test_tier1_suppressed_when_rag_already_queried(self):
        """Tier 1 exists to FORCE a first RAG query. If RAG has already been
        queried, tier 1 is redundant and stays suppressed. Tiers 2 and 3
        bypass this check (see TestStallNudgeTiers)."""
        agent = _agent_with_tracker()
        agent._tracker.rag_queries_made = 1
        turn_messages = []
        agent._maybe_inject_stall_nudge(step=10, turn_messages=turn_messages)
        assert agent._stall_nudge_tier == 0
        assert turn_messages == []

    def test_recent_progress_resets_the_window(self):
        """If progress happened at step 4, step 8 is only 4 calls behind —
        below threshold, so no nudge."""
        agent = _agent_with_tracker()
        agent._last_progress_step = 4
        turn_messages = []
        agent._maybe_inject_stall_nudge(step=8, turn_messages=turn_messages)
        assert turn_messages == []
        # But step 9 is 5 behind → fires.
        agent._maybe_inject_stall_nudge(step=9, turn_messages=turn_messages)
        assert len(turn_messages) == 1


class TestStallNudgeTiers:
    """Gap B: escalating stall nudges. Before this change the detector
    fired exactly once per run — MetaCTF runs #4 and #14 (2026-04-17) burned
    15+ post-nudge steps looping because no second nudge could land."""

    def test_tier2_fires_after_another_5_stalls(self):
        """Tier 1 at step 5, then 5 more stalls (step 10) → tier 2 fires.
        The first firing resets the progress clock so the stall window for
        tier 2 is relative to tier 1's step, not step 0."""
        agent = _agent_with_tracker()
        # Tier 1 at step 5.
        turn_a = []
        agent._maybe_inject_stall_nudge(step=5, turn_messages=turn_a)
        assert agent._stall_nudge_tier == 1
        # Step 10: 5 stalls since tier 1 reset the clock.
        turn_b = []
        agent._maybe_inject_stall_nudge(step=10, turn_messages=turn_b)
        assert agent._stall_nudge_tier == 2
        assert len(turn_b) == 1
        assert "[STALLED-TIER-2]" in turn_b[0].content
        # Content must push the agent toward a DIFFERENT vulnerability class.
        assert (
            "different" in turn_b[0].content.lower()
            or "alternative" in turn_b[0].content.lower()
        )

    def test_tier2_bypasses_rag_suppression(self):
        """Even if the agent already queried RAG (suppressing tier 1), tier
        2 should fire — the agent is demonstrably stuck despite retrieval."""
        agent = _agent_with_tracker()
        agent._tracker.rag_queries_made = 1
        # Tier 1 suppressed.
        turn_a = []
        agent._maybe_inject_stall_nudge(step=5, turn_messages=turn_a)
        assert agent._stall_nudge_tier == 0
        assert turn_a == []
        # But tier 2 still fires when stall continues — bypasses RAG gate.
        # With tier 0 state, tier 1 will try first at step 5 (still suppressed).
        # At step 10 we expect tier 2 to fire. The implementation tracks
        # stall steps independent of tier-1 firing.
        turn_b = []
        agent._maybe_inject_stall_nudge(step=10, turn_messages=turn_b)
        assert agent._stall_nudge_tier == 2
        assert len(turn_b) == 1
        assert "[STALLED-TIER-2]" in turn_b[0].content

    def test_tier3_fires_after_tier2_stalls(self):
        agent = _agent_with_tracker()
        # Tier 1 at step 5, tier 2 at step 10, tier 3 at step 15.
        agent._maybe_inject_stall_nudge(step=5, turn_messages=[])
        agent._maybe_inject_stall_nudge(step=10, turn_messages=[])
        turn_c = []
        agent._maybe_inject_stall_nudge(step=15, turn_messages=turn_c)
        assert agent._stall_nudge_tier == 3
        assert len(turn_c) == 1
        assert "[STALLED-TIER-3]" in turn_c[0].content
        assert "final answer" in turn_c[0].content.lower()

    def test_no_tier4_fires(self):
        """After tier 3, no more nudges — the agent was already told to
        stop. Further stalls are silent."""
        agent = _agent_with_tracker()
        agent._maybe_inject_stall_nudge(step=5, turn_messages=[])
        agent._maybe_inject_stall_nudge(step=10, turn_messages=[])
        agent._maybe_inject_stall_nudge(step=15, turn_messages=[])
        turn_d = []
        agent._maybe_inject_stall_nudge(step=20, turn_messages=turn_d)
        assert agent._stall_nudge_tier == 3
        assert turn_d == []

    def test_tracker_records_all_three_tier_steps(self):
        agent = _agent_with_tracker()
        agent._maybe_inject_stall_nudge(step=5, turn_messages=[])
        agent._maybe_inject_stall_nudge(step=10, turn_messages=[])
        agent._maybe_inject_stall_nudge(step=15, turn_messages=[])
        # Step numbers are 1-indexed in tracker output (step+1).
        assert agent._tracker.stall_nudges_fired == [6, 11, 16]


class TestRagQueryStepRecording:
    def test_records_first_rag_query_step(self):
        agent = _agent_with_tracker()
        agent._record_rag_query_step(step=2, tool_name="ctf_knowledge_query")
        assert agent._tracker.first_rag_query_step == 3

    def test_ignores_non_rag_tool(self):
        agent = _agent_with_tracker()
        agent._record_rag_query_step(step=1, tool_name="http_fetch")
        assert agent._tracker.first_rag_query_step is None

    def test_does_not_overwrite_first_query(self):
        agent = _agent_with_tracker()
        agent._record_rag_query_step(step=2, tool_name="ctf_knowledge_query")
        agent._record_rag_query_step(step=9, tool_name="ctf_knowledge_query")
        assert agent._tracker.first_rag_query_step == 3  # still the first


class TestRunTrackerStallFields:
    def test_defaults(self):
        t = RunTracker()
        assert t.stall_nudges_fired == []
        assert t.first_rag_query_step is None
        assert t.redundant_tool_calls == 0

    def test_serialized_in_to_dict(self):
        t = RunTracker()
        t.stall_nudges_fired = [6, 11, 16]
        t.first_rag_query_step = 7
        t.redundant_tool_calls = 4
        d = t.to_dict()
        assert d["stall_nudges_fired"] == [6, 11, 16]
        assert d["first_rag_query_step"] == 7
        assert d["redundant_tool_calls"] == 4


class TestRepetitionAntiProgress:
    """Gap C: the same (tool_name, normalized_input) invoked 3+ times in
    a run counts as ANTI-progress. Observed in MetaCTF run #4: 15 file_upload
    calls including pure repeats of (file_upload, shell.php) that still
    advanced _last_progress_step because the observation mentioned new URLs."""

    def test_input_hash_stable_across_whitespace(self):
        agent = _agent_with_tracker()
        h1 = agent._input_repetition_hash('{"url": "http://x/a"}')
        h2 = agent._input_repetition_hash('{ "url":"http://x/a" }')
        assert h1 == h2

    def test_input_hash_distinguishes_different_urls(self):
        agent = _agent_with_tracker()
        h1 = agent._input_repetition_hash('{"url":"http://x/a"}')
        h2 = agent._input_repetition_hash('{"url":"http://x/b"}')
        assert h1 != h2

    def test_input_hash_handles_non_json_fallback(self):
        agent = _agent_with_tracker()
        h1 = agent._input_repetition_hash("raw_non_json_input")
        h2 = agent._input_repetition_hash("raw_non_json_input")
        assert h1 == h2
        assert h1 != agent._input_repetition_hash("different_raw")

    def test_repeat_tool_call_third_time_is_redundant(self):
        agent = _agent_with_tracker()
        key = ("file_upload", agent._input_repetition_hash('{"file":"shell.php"}'))
        # First call → not redundant.
        assert agent._record_tool_call_for_progress(*key) is False
        # Second call → not redundant yet (counter at 2, threshold is 3).
        assert agent._record_tool_call_for_progress(*key) is False
        # Third call → redundant.
        assert agent._record_tool_call_for_progress(*key) is True
        # Tracker recorded the redundant hit.
        assert agent._tracker.redundant_tool_calls == 1

    def test_different_invocations_not_redundant(self):
        agent = _agent_with_tracker()
        k_a = ("file_upload", agent._input_repetition_hash('{"file":"a.php"}'))
        k_b = ("file_upload", agent._input_repetition_hash('{"file":"b.php"}'))
        k_c = ("file_upload", agent._input_repetition_hash('{"file":"c.php"}'))
        assert agent._record_tool_call_for_progress(*k_a) is False
        assert agent._record_tool_call_for_progress(*k_b) is False
        assert agent._record_tool_call_for_progress(*k_c) is False

    def test_redundant_call_blocks_progress_advance(self):
        """If the call is redundant, _observation_shows_progress must
        return False even if the observation text contains new URLs."""
        agent = _agent_with_tracker()
        obs = "Status: 200 http://target/newly-seen-path"
        # On the redundant path, the signal must be suppressed.
        assert agent._observation_shows_progress(obs, is_redundant=True) is False
        # Normal path: same observation still counts.
        agent2 = _agent_with_tracker()
        assert agent2._observation_shows_progress(obs) is True


# Touching the Message import keeps the stub readable for reviewers who
# expect every fairlib-shaped test to import Message.
_ = Message
