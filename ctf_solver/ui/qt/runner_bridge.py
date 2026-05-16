"""Bridge between the async agent runtime and Qt's signal/slot system.

``AgentRunner`` is a ``QObject`` that:

- Wires the agent's ``trace_callback`` directly to a Qt signal so trace
  events flow into the UI without thread marshalling (qasync shares the
  GUI thread).
- Orchestrates the same single-run flow as the CLI / Streamlit paths,
  using the helpers extracted in Phase 1 (``inject_reflexion``,
  ``inject_proactive_rag``, ``extract_flags_from_run``, ``determine_outcome``,
  ``write_lessons_if_enabled``).
- Uses the CLI-style "good defaults" identified in the v3.10 effectiveness
  audit: append+directive reflexion, RAG trimmed to 1500 chars, deduped
  flags. Streamlit retains its legacy defaults via its existing code path.
- Supports mid-run cancellation via ``cancel()`` — propagates
  ``asyncio.CancelledError`` through ``agent.arun(...)``.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional

from PySide6.QtCore import QObject, Signal

from ctf_solver.config import SolverConfig


async def execute_qt_run(
    config: SolverConfig,
    *,
    event_emitter: Optional[Callable[[dict], None]] = None,
    log_emitter: Optional[Callable[[str], None]] = None,
) -> tuple[str, list[str], Dict[str, Any]]:
    """Run one challenge from the Qt UI.

    Shape mirrors ``runner.run_agent`` (CLI) but:
    - callbacks always wired so the UI can stream events and logs;
    - CLI-style "good defaults" applied uniformly (trim proactive RAG to
      1500 chars, append+directive reflexion, dedup flags) per the v3.10
      effectiveness audit;
    - returns ``(response, candidate_flags, stats_dict)`` instead of bare
      response — caller never has to dig into the tracker.
    """
    from ctf_solver.agent import build_agent
    from ctf_solver.prompts import get_initial_message
    from ctf_solver.run_tracker import RunTracker
    from ctf_solver.ui.core import (
        determine_outcome,
        extract_flags_from_run,
        inject_proactive_rag,
        inject_reflexion,
        write_lessons_if_enabled,
    )

    def _emit_event(evt: dict) -> None:
        if event_emitter is not None:
            event_emitter(evt)

    def _emit_log(msg: str) -> None:
        if log_emitter is not None:
            log_emitter(msg)

    tracker = RunTracker()
    tracker.challenge_url = config.challenge_url or ""
    tracker.challenge_description = config.challenge_description or ""

    def _event_writer(evt: Dict[str, Any]) -> None:
        tracker.events_buffer.append(evt)

    agent = build_agent(
        config,
        log_callback=_emit_log,
        tracker=tracker,
        trace_callback=_emit_event,
        event_writer=_event_writer,
    )

    initial_message = get_initial_message(
        platform_name=config.platform_name,
        flag_regex=config.flag_regex,
        challenge_url=config.challenge_url,
        challenge_description=config.challenge_description,
        challenge_hints=config.challenge_hints,
        source_files=config.source_files or None,
    )

    initial_message = inject_reflexion(
        initial_message, config, tracker, prepend=False, log_callback=_emit_log
    )
    initial_message = inject_proactive_rag(
        initial_message, config, tracker, trim=True, log_callback=_emit_log
    )

    tracker.start()
    try:
        response = await agent.arun(initial_message)
    finally:
        tracker.stop()

    candidate_flags = extract_flags_from_run(
        response, tracker.tool_call_log, config.flag_regex, dedup=True
    )
    tracker.candidate_flags_found = candidate_flags
    tracker.run_succeeded = bool(candidate_flags)
    tracker.outcome = determine_outcome(candidate_flags, tracker.tool_call_log)

    if tracker.per_call_tokens:
        tracker.set_token_usage_from_adapter(
            list(tracker.per_call_tokens), config.model_name
        )

    write_lessons_if_enabled(
        config, tracker, response, candidate_flags, log_callback=_emit_log
    )

    stats = tracker.to_dict()
    stats["tool_call_log"] = list(tracker.tool_call_log)
    return response, candidate_flags, stats


class AgentRunner(QObject):
    """Async run lifecycle, exposed via Qt signals."""

    # Trace event from the agent (one dict per Thought/Action/Observation/
    # final_answer/stall_nudge/llm_thinking — see agent.py event contract).
    event = Signal(dict)
    # Human-readable log line (e.g. "[RAG] Proactive ... injected").
    log = Signal(str)
    # Run completed successfully: response, candidate_flags, stats_dict.
    finished = Signal(str, list, dict)
    # Run failed (exception text). ``error`` and ``finished`` are mutually
    # exclusive on a given run.
    error = Signal(str)
    # Emitted when the task transitions running → idle (regardless of
    # success/failure/cancellation) so the UI can re-enable the Run button.
    state_changed = Signal(bool)  # is_running

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._task: Optional[asyncio.Task[Any]] = None

    # ------------------------------------------------------------------ API

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, config: SolverConfig) -> None:
        """Schedule a single run on the qasync event loop. No-op if a run is
        already in flight."""
        if self.is_running():
            return
        self._task = asyncio.create_task(self._run(config))
        self.state_changed.emit(True)

    def cancel(self) -> None:
        """Request cancellation. The underlying ``asyncio.CancelledError`` will
        propagate up through ``agent.arun(...)`` and the task transitions to
        ``finished`` with no flags."""
        if self._task is not None and not self._task.done():
            self._task.cancel()

    # ------------------------------------------------------------- internal

    async def _run(self, config: SolverConfig) -> None:
        try:
            response, flags, stats = await self._execute(config)
            self.finished.emit(response, flags, stats)
        except asyncio.CancelledError:
            self.error.emit("Run cancelled.")
        except Exception as exc:  # pragma: no cover - safety net
            self.error.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self.state_changed.emit(False)

    async def _execute(
        self, config: SolverConfig
    ) -> tuple[str, list[str], Dict[str, Any]]:
        return await execute_qt_run(
            config,
            event_emitter=self.event.emit,
            log_emitter=self.log.emit,
        )
