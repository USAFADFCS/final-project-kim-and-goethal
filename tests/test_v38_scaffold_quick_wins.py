"""
v3.8 scaffold quick wins:
- History-window default (16, with 0 as the disable sentinel).
- Proactive-RAG mode-gate extended to RAGMode.ORIGINAL via RAG_ALL_READ_MODES.
"""

from unittest.mock import MagicMock

from fairlib.core.message import Message

from ctf_solver.agent import CTFAgent
from ctf_solver.config import (
    RAG_ALL_READ_MODES,
    RAG_EXPERIENCE_MODES,
    RAGMode,
    SolverConfig,
)

# ── History window ───────────────────────────────────────────────────


class TestHistoryWindowDefault:
    # 2026-05-17: defaults flipped from (16, "messages") to (7, "observations")
    # after the window-mode A/B experiment (memory/window_mode_experiment.md).
    def test_solver_config_default_is_7(self):
        cfg = SolverConfig()
        assert cfg.history_window_size == 7

    def test_from_env_default_is_7(self, monkeypatch):
        monkeypatch.delenv("CTF_HISTORY_WINDOW", raising=False)
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size == 7

    def test_from_env_explicit_value(self, monkeypatch):
        monkeypatch.setenv("CTF_HISTORY_WINDOW", "8")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size == 8

    def test_from_env_disabled_via_off(self, monkeypatch):
        monkeypatch.setenv("CTF_HISTORY_WINDOW", "off")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size is None

    def test_from_env_disabled_via_none_string(self, monkeypatch):
        monkeypatch.setenv("CTF_HISTORY_WINDOW", "none")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size is None

    def test_from_env_disabled_via_zero(self, monkeypatch):
        monkeypatch.setenv("CTF_HISTORY_WINDOW", "0")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size is None


def _make_history(n: int):
    return [Message(role="user", content=f"msg{i}") for i in range(n)]


def _make_windowed_agent(window):
    mock_memory = MagicMock()
    agent = CTFAgent(
        llm=MagicMock(),
        planner=MagicMock(_parse_json_response=MagicMock()),
        tool_executor=MagicMock(),
        memory=mock_memory,
        max_steps=20,
        log_callback=lambda msg: None,
        history_window_size=window,
    )
    return agent, mock_memory


class TestWindowedHistory:
    def test_no_window_returns_full(self):
        agent, mem = _make_windowed_agent(None)
        mem.get_history.return_value = _make_history(50)
        assert len(agent._windowed_history()) == 50

    def test_zero_window_disables_truncation(self):
        """0 is the sentinel for 'disable' — round-trips through
        merge_with_args' non-None filter without aliasing to a real cap."""
        agent, mem = _make_windowed_agent(0)
        mem.get_history.return_value = _make_history(50)
        assert len(agent._windowed_history()) == 50

    def test_history_shorter_than_window_unchanged(self):
        agent, mem = _make_windowed_agent(16)
        mem.get_history.return_value = _make_history(10)
        assert len(agent._windowed_history()) == 10

    def test_window_keeps_anchors_plus_tail(self):
        agent, mem = _make_windowed_agent(16)
        history = _make_history(40)
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        assert len(windowed) == 16
        # First two anchors preserved
        assert windowed[0] is history[0]
        assert windowed[1] is history[1]
        # Last 14 messages preserved
        assert windowed[-1] is history[-1]
        assert windowed[-14] is history[-14]


# ── History window mode (messages vs. observations) ──────────────────


def _make_windowed_agent_obs(window, mode="observations"):
    """Build a CTFAgent in observations-counting mode."""
    mock_memory = MagicMock()
    agent = CTFAgent(
        llm=MagicMock(),
        planner=MagicMock(_parse_json_response=MagicMock()),
        tool_executor=MagicMock(),
        memory=mock_memory,
        max_steps=20,
        log_callback=lambda msg: None,
        history_window_size=window,
        history_window_mode=mode,
    )
    return agent, mock_memory


def _make_interleaved_history(num_turns: int):
    """Build a realistic conversation: 2 anchors + num_turns × (assistant + observation)."""
    history = [
        Message(role="system", content="system anchor — challenge framing"),
        Message(role="user", content="user anchor — the original task"),
    ]
    for i in range(num_turns):
        history.append(Message(role="assistant", content=f"Thought {i}; calling tool"))
        history.append(Message(role="system", content=f"Observation: result {i}"))
    return history


class TestHistoryWindowModeConfig:
    # 2026-05-17: default mode flipped from "messages" to "observations".
    def test_default_mode_is_observations(self):
        cfg = SolverConfig()
        assert cfg.history_window_mode == "observations"

    def test_from_env_default_is_observations(self, monkeypatch):
        monkeypatch.delenv("CTF_HISTORY_WINDOW_MODE", raising=False)
        cfg = SolverConfig.from_env()
        assert cfg.history_window_mode == "observations"

    def test_from_env_messages_legacy(self, monkeypatch):
        # The legacy mode is still accessible via opt-in.
        monkeypatch.setenv("CTF_HISTORY_WINDOW_MODE", "messages")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_mode == "messages"

    def test_from_env_invalid_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("CTF_HISTORY_WINDOW_MODE", "garbage")
        cfg = SolverConfig.from_env()
        assert cfg.history_window_mode == "observations"

    def test_merge_with_args_carries_mode(self):
        cfg = SolverConfig().merge_with_args(history_window_mode="messages")
        assert cfg.history_window_mode == "messages"


class TestWindowedHistoryObservationsMode:
    def test_unknown_mode_falls_back_to_messages(self):
        # Constructor accepts any string but stores only the two valid values.
        agent, _ = _make_windowed_agent_obs(window=16, mode="bogus")
        assert agent._history_window_mode == "messages"

    def test_observations_mode_short_history_unchanged(self):
        # 2 anchors + 3 turns = 8 messages; window 16 leaves it untouched.
        agent, mem = _make_windowed_agent_obs(window=16)
        history = _make_interleaved_history(num_turns=3)
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        assert windowed == history

    def test_observations_mode_keeps_anchors_plus_last_N_observations(self):
        # 2 anchors + 10 turns = 22 messages, 10 observations total.
        # window=7 → 2 anchors + 5 observations.  The 5 kept observations
        # are the last 5 (indices for observation #6..#10).
        agent, mem = _make_windowed_agent_obs(window=7)
        history = _make_interleaved_history(num_turns=10)
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        # Anchors preserved.
        assert windowed[0] is history[0]
        assert windowed[1] is history[1]
        # Count observation messages in the windowed view.
        obs_in_view = [
            m
            for m in windowed
            if getattr(m, "role", None) == "system"
            and isinstance(m.content, str)
            and m.content.startswith("Observation:")
        ]
        assert len(obs_in_view) == 5
        # The kept observations are the *last* 5 (results 5..9).
        kept_results = [m.content for m in obs_in_view]
        assert kept_results == [
            "Observation: result 5",
            "Observation: result 6",
            "Observation: result 7",
            "Observation: result 8",
            "Observation: result 9",
        ]

    def test_observations_mode_includes_preceding_assistant(self):
        # The cutoff observation should be paired with its preceding assistant
        # message so the kept observation has the call that produced it.
        agent, mem = _make_windowed_agent_obs(window=4)  # 2 anchors + 2 obs
        history = _make_interleaved_history(num_turns=5)  # 5 obs available
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        # The third message of the window (right after the 2 anchors) must be
        # the assistant message that produced the first kept observation.
        assert windowed[0] is history[0]
        assert windowed[1] is history[1]
        assert getattr(windowed[2], "role", None) == "assistant"
        # The first kept observation comes right after that assistant message.
        assert getattr(windowed[3], "role", None) == "system"
        assert windowed[3].content.startswith("Observation:")

    def test_observations_mode_budget_zero_returns_just_anchors(self):
        # window=2 = anchor_count, obs_budget = 0 → only anchors.
        # But: short_history_unchanged short-circuits when len <= window.
        # So we need a history strictly longer than 2 to hit obs_budget==0.
        agent, mem = _make_windowed_agent_obs(window=2)
        history = _make_interleaved_history(num_turns=3)  # 8 messages
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        assert len(windowed) == 2
        assert windowed[0] is history[0]
        assert windowed[1] is history[1]

    def test_messages_mode_still_works_after_changes(self):
        # Regression: existing "messages" behavior unchanged.
        agent, mem = _make_windowed_agent_obs(window=16, mode="messages")
        history = _make_history(40)
        mem.get_history.return_value = history
        windowed = agent._windowed_history()
        assert len(windowed) == 16
        assert windowed[0] is history[0]
        assert windowed[1] is history[1]
        assert windowed[-1] is history[-1]


# ── Proactive RAG mode gate ──────────────────────────────────────────


class TestRagAllReadModes:
    def test_includes_original(self):
        assert RAGMode.ORIGINAL in RAG_ALL_READ_MODES

    def test_excludes_none(self):
        assert RAGMode.NONE not in RAG_ALL_READ_MODES

    def test_superset_of_experience_modes(self):
        assert RAG_EXPERIENCE_MODES.issubset(RAG_ALL_READ_MODES)

    def test_includes_all_lessons_modes(self):
        for mode in (
            RAGMode.LESSONS_WRITE,
            RAGMode.LESSONS_READONLY,
            RAGMode.LESSONS_BUILDONLY,
        ):
            assert mode in RAG_ALL_READ_MODES

    def test_runner_uses_all_read_modes_for_proactive_rag(self):
        """Smoke check: runner.py imports the broader gate so curated-only
        ORIGINAL setups also get proactive injection — previously gated only
        on the experience modes."""
        from ctf_solver import runner

        src = open(runner.__file__).read()
        # The proactive-RAG block guard should reference the broader gate.
        assert "RAG_ALL_READ_MODES" in src

    def test_streamlit_uses_all_read_modes_for_proactive_rag(self):
        from ctf_solver.ui import streamlit_app

        src = open(streamlit_app.__file__).read()
        assert "RAG_ALL_READ_MODES" in src
