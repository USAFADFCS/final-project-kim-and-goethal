"""Shared run-and-grade core for the eval harness.

``run_against_target`` builds a ``SolverConfig``, runs the agent against a
target exactly as the production runner does (same ``build_agent`` →
``agent.arun`` → strict/broad flag split), and returns a structured
``RunResult`` instead of a printed string. Both benchmark adapters
(``nyu_adapter``, ``cybench_adapter``) and the A/B harness call it.

Design choices that matter for measurement integrity:

* **No learning side effects.** Unlike ``runner.run_agent``, the core never
  calls ``write_lessons_if_enabled`` and (by default) never injects prior
  Reflexion/RAG. Eval runs must not write to the experience DB nor read
  cross-run lessons, or paired A/B comparisons get a hidden confound. Pass
  ``inject_rag=True`` to opt into the full production retrieval path.
* **Grading against a known flag.** When ``expected_flag`` is provided
  (benchmark mode) ``solved`` is a *substring* match of that exact flag in
  the agent's response or any tool output — the grading both NYU CTF Bench
  and Cybench converge on. When it's absent (live-URL mode) ``solved`` falls
  back to "the agent confirmed a strict-regex flag-shaped token".
* **Honest cost.** ``est_cost_usd_v2`` is the local-corrected figure
  (parity-sprint item #2): $0 for Ollama/MLX.

The heavy agent imports are deferred to call time so importing this module
(and unit-testing the dataclass/grading) stays cheap.
"""

import asyncio
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, List, Optional

from ctf_solver.config import RAGMode, SolverConfig
from ctf_solver.run_tracker import RunTracker


@dataclass
class RunResult:
    """Structured outcome of a single agent run against one target.

    Consumed by the benchmark adapters, the A/B harness (one JSONL record
    per run), and — per memory/comparative_agent_loops.md — the future
    multi-agent decision gate (paired ``solved`` + ``est_cost_usd_v2``).
    """

    challenge: str
    solved: bool
    # First strict-regex-confirmed flag the agent surfaced (audit value).
    flag_seen: Optional[str] = None
    # The benchmark's known-good flag, when grading against one.
    expected_flag: Optional[str] = None
    # True iff ``expected_flag`` appeared (substring) in the run output.
    flag_match: bool = False
    outcome: str = "failure"  # success | partial | failure
    steps: int = 0
    tool_calls: int = 0
    unique_tools: int = 0
    duration_seconds: float = 0.0
    est_cost_usd: float = 0.0
    est_cost_usd_v2: float = 0.0
    candidate_flags: List[str] = field(default_factory=list)
    confirmed_flags: List[str] = field(default_factory=list)
    model: str = ""
    provider: str = ""
    error: Optional[str] = None
    # Final agent response, truncated for the record.
    response: str = ""
    # Full RunTracker.to_dict() for deep post-hoc analysis.
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_record(self, **extra: Any) -> Dict[str, Any]:
        """A flat, JSONL-friendly record for ``eval_results.jsonl``.

        Drops the bulky ``stats``/``response`` blobs and the full flag lists
        (the harness keeps the headline metrics the stats layer pairs on),
        then merges any ``extra`` cell metadata (config_label, seed, run_idx).
        """
        rec = {
            "challenge": self.challenge,
            "solved": self.solved,
            "flag_match": self.flag_match,
            "outcome": self.outcome,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "unique_tools": self.unique_tools,
            "duration_seconds": round(self.duration_seconds, 3),
            "est_cost_usd": round(self.est_cost_usd, 6),
            "est_cost_usd_v2": round(self.est_cost_usd_v2, 6),
            "model": self.model,
            "provider": self.provider,
            "error": self.error,
        }
        rec.update(extra)
        return rec


def _provider_str(provider: Any) -> str:
    if provider is None:
        return ""
    return str(getattr(provider, "value", provider))


def expected_flag_seen(
    expected_flag: Optional[str],
    response: str,
    tool_call_log: List[Dict[str, Any]],
) -> bool:
    """Substring-grade a known flag across the response + all tool outputs.

    Mirrors NYU ``challenge.py`` (``flag in response``) and Cybench
    ``grade_benchmark.py`` (``flag in stdout`` for any iteration): both count
    the challenge solved if the exact flag string appears anywhere the agent
    produced. Empty/None ``expected_flag`` is never "seen".
    """
    if not expected_flag:
        return False
    if expected_flag in (response or ""):
        return True
    for entry in tool_call_log or []:
        if expected_flag in (entry.get("output") or ""):
            return True
    return False


def _build_eval_config(
    *,
    config: Optional[SolverConfig],
    url: Optional[str],
    description: Optional[str],
    hints: Optional[str],
    challenge_name: Optional[str],
    files: Optional[Dict[str, str]],
    model: Optional[str],
    provider: Any,
    max_steps: Optional[int],
    flag_regex: Optional[str],
    inject_rag: bool,
) -> SolverConfig:
    """Construct (or clone) the SolverConfig for one eval run.

    A base ``config`` may be supplied so an A/B cell can carry prompt /
    model / flag-regex overrides; only the per-challenge target fields are
    replaced on top of it. When no base is given, defaults are used with
    ``rag_mode=ORIGINAL`` so no experience-DB read/write happens.
    """
    overrides: Dict[str, Any] = {
        "challenge_url": url,
        "challenge_description": description,
        "challenge_hints": hints,
        "challenge_name": challenge_name,
        "source_files": dict(files) if files else {},
    }
    if model is not None:
        overrides["model_name"] = model
    if provider is not None:
        overrides["llm_provider"] = provider
    if max_steps is not None:
        overrides["max_steps"] = max_steps
    if flag_regex is not None:
        overrides["flag_regex"] = flag_regex
    if not inject_rag:
        # Force a non-retrieving mode so eval never reads/writes lessons.
        overrides["rag_mode"] = RAGMode.ORIGINAL

    if config is not None:
        return replace(config, **overrides)
    return SolverConfig(**overrides)


async def run_against_target(
    *,
    url: Optional[str] = None,
    description: Optional[str] = None,
    hints: Optional[str] = None,
    expected_flag: Optional[str] = None,
    flag_regex: Optional[str] = None,
    files: Optional[Dict[str, str]] = None,
    model: Optional[str] = None,
    provider: Optional[Any] = None,
    challenge_name: Optional[str] = None,
    max_steps: Optional[int] = None,
    config: Optional[SolverConfig] = None,
    inject_rag: bool = False,
    log_callback: Optional[Any] = None,
) -> RunResult:
    """Run the agent against one target and return a structured ``RunResult``.

    Mirrors ``runner.run_agent``'s build → run → strict/broad grade, minus
    the printing, lessons-writing, and (by default) RAG injection. Any
    exception from the agent is caught and surfaced as ``RunResult.error``
    with ``solved=False`` — the harness must never crash a whole sweep on one
    bad challenge.
    """
    log_fn = log_callback or (lambda *_a, **_k: None)

    # Deferred heavy imports (agent graph, fairlib) — keep module import cheap.
    from ctf_solver.agent import build_agent
    from ctf_solver.prompts import get_initial_message
    from ctf_solver.ui.core import (
        determine_outcome,
        extract_flags_from_run,
        inject_proactive_rag,
        inject_reflexion,
    )

    cfg = _build_eval_config(
        config=config,
        url=url,
        description=description,
        hints=hints,
        challenge_name=challenge_name,
        files=files,
        model=model,
        provider=provider,
        max_steps=max_steps,
        flag_regex=flag_regex,
        inject_rag=inject_rag,
    )
    challenge_label = challenge_name or url or "(unknown)"

    tracker = RunTracker()
    tracker.challenge_url = cfg.challenge_url or ""
    tracker.challenge_description = cfg.challenge_description or ""

    response = ""
    error: Optional[str] = None
    try:
        agent = build_agent(cfg, tracker=tracker)
        initial_message = get_initial_message(
            platform_name=cfg.platform_name,
            flag_regex=cfg.flag_regex,
            challenge_url=cfg.challenge_url,
            challenge_description=cfg.challenge_description,
            challenge_hints=cfg.challenge_hints,
            source_files=cfg.source_files or None,
        )
        if inject_rag:
            initial_message = inject_reflexion(
                initial_message, cfg, tracker, prepend=False, log_callback=log_fn
            )
            initial_message = inject_proactive_rag(
                initial_message, cfg, tracker, trim=True, log_callback=log_fn
            )
        tracker.start()
        try:
            response = await agent.arun(initial_message)
        finally:
            tracker.stop()
    except Exception as exc:  # noqa: BLE001 — sweep robustness; surfaced below
        error = f"{type(exc).__name__}: {exc}"
        log_fn(f"[eval] run against {challenge_label} errored: {error}")
        tracker.stop()

    # Grade exactly as runner.run_agent does: broad extract → strict filter.
    candidate_flags = extract_flags_from_run(
        response, tracker.tool_call_log, cfg.flag_regex, dedup=True
    )
    import re as _re

    strict_re = _re.compile(cfg.strict_flag_regex)
    confirmed_flags = [f for f in candidate_flags if strict_re.search(f)]
    tracker.candidate_flags_found = candidate_flags
    tracker.confirmed_flags_found = confirmed_flags
    tracker.run_succeeded = bool(confirmed_flags)
    tracker.outcome = determine_outcome(confirmed_flags, tracker.tool_call_log)
    if tracker.per_call_tokens:
        tracker.set_token_usage_from_adapter(
            list(tracker.per_call_tokens), cfg.model_name, cfg.llm_provider
        )

    flag_match = expected_flag_seen(expected_flag, response, tracker.tool_call_log)
    # Benchmark mode grades against the known flag; live mode falls back to
    # "confirmed any strict flag-shaped token".
    solved = flag_match if expected_flag else bool(confirmed_flags)

    # to_dict() omits the bulky tool_call_log; attach it (as runner/streamlit
    # do) so the Cybench output-replay emitter can read tool outputs.
    stats = tracker.to_dict()
    stats["tool_call_log"] = list(tracker.tool_call_log)

    return RunResult(
        challenge=challenge_label,
        solved=solved,
        flag_seen=confirmed_flags[0] if confirmed_flags else None,
        expected_flag=expected_flag,
        flag_match=flag_match,
        outcome=tracker.outcome,
        steps=tracker.steps,
        tool_calls=sum(tracker.tool_calls.values()),
        unique_tools=tracker.unique_tools_used,
        duration_seconds=tracker.duration_seconds,
        est_cost_usd=tracker.est_cost_usd,
        est_cost_usd_v2=tracker.est_cost_usd_v2,
        candidate_flags=candidate_flags,
        confirmed_flags=confirmed_flags,
        model=cfg.model_name,
        provider=_provider_str(cfg.llm_provider),
        error=error,
        response=(response or "")[:4000],
        stats=stats,
    )


def run_against_target_sync(**kwargs: Any) -> RunResult:
    """Blocking wrapper around :func:`run_against_target` for sync callers
    (the adapters and the A/B harness run sequentially)."""
    return asyncio.run(run_against_target(**kwargs))
