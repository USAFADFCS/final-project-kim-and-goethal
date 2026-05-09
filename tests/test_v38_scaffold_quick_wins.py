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
    def test_solver_config_default_is_16(self):
        cfg = SolverConfig()
        assert cfg.history_window_size == 16

    def test_from_env_default_is_16(self, monkeypatch):
        monkeypatch.delenv("CTF_HISTORY_WINDOW", raising=False)
        cfg = SolverConfig.from_env()
        assert cfg.history_window_size == 16

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
