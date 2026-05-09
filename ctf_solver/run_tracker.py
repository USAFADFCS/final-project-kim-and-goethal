"""
Run statistics tracker for CTF Solver.

Tracks solve time, token usage (estimated), step count, and tool usage
across an agent run. Designed to integrate with LoggingToolWrapper and
LLM adapters without modifying the fairlib framework.
"""

import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

from fairlib.core.interfaces.llm import AbstractChatModel
from fairlib.core.message import Message

# Tools whose first successful output we use for site fingerprinting
_FINGERPRINT_TOOLS = {"http_fetch", "form_submit"}

# Phase B2: per-million-token prices for cost estimation. Conservative
# public list-prices as of 2026-05; cached input is priced per OpenAI's
# documented schedule. Unknown models fall back to the gpt-5.2 row, which
# is fine for "$X order of magnitude" reporting on the brief.
_PRICE_PER_M_TOKENS: Dict[str, Dict[str, float]] = {
    "gpt-5.2": {"input": 1.25, "cached": 0.125, "output": 10.0},
    "gpt-5.1": {"input": 1.25, "cached": 0.125, "output": 10.0},
    "gpt-4o": {"input": 2.50, "cached": 1.25, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "cached": 0.075, "output": 0.60},
    "claude-opus-4-7": {"input": 15.0, "cached": 1.50, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "cached": 0.30, "output": 15.0},
}

# Regex patterns for fingerprint extraction (compiled once)
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,80})</title>", re.IGNORECASE)
_H1_RE = re.compile(r"<h1[^>]*>([^<]{1,80})</h1>", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'action=["\']([^"\']{1,80})["\']', re.IGNORECASE)


def _extract_site_fingerprint(tool_name: str, output: str) -> str:
    """Extract a short content fingerprint from an HTTP tool output.

    Only fires on http_fetch / form_submit outputs. Returns a string like
    "title:Login Page|h1:Welcome|form:/api/login" that identifies the page
    by content rather than URL, making contamination filtering robust to
    URL changes and similar-looking challenges at different paths.
    """
    if tool_name not in _FINGERPRINT_TOOLS:
        return ""
    parts = []
    m = _TITLE_RE.search(output)
    if m:
        parts.append(f"title:{m.group(1).strip()[:60]}")
    m = _H1_RE.search(output)
    if m:
        parts.append(f"h1:{m.group(1).strip()[:60]}")
    m = _FORM_ACTION_RE.search(output)
    if m:
        parts.append(f"form:{m.group(1).strip()[:60]}")
    return "|".join(parts)


@dataclass
class RunTracker:
    """Collects statistics for a single agent run."""

    start_time: float = 0.0
    end_time: float = 0.0
    steps: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_calls: Counter = field(default_factory=Counter)

    # Academic study tracking
    rag_mode: str = ""
    challenge_url: str = ""
    challenge_description: str = ""
    run_succeeded: bool = False
    candidate_flags_found: List[str] = field(default_factory=list)
    failure_doc_generated: bool = False

    # Learning-quality metrics
    prior_reflection_injected: bool = False
    rag_queries_made: int = 0
    outcome: str = "pending"  # "success" | "partial" | "failure"
    site_fingerprint: str = ""  # Content-based page identity for contamination filter

    # Count of turns where the LLM provider's content filter rejected the
    # prompt (OpenAI 400 "invalid_prompt"). Distinct from format errors —
    # the model response itself never happened. Tracked so post-run
    # diagnostics can distinguish "agent gave up" from "API refused".
    moderation_hits: int = 0

    # Steps at which the stall detector fired each nudge tier (1-indexed).
    # Tier 1 = [STALLED-DETECTOR] RAG nudge (suppressed if RAG already used).
    # Tier 2 = [STALLED-TIER-2] pivot-category nudge (bypasses RAG gate).
    # Tier 3 = [STALLED-TIER-3] emit-final-answer nudge.
    # Empty list when nothing fired. Step at which the first
    # ctf_knowledge_query landed — lets post-run analysis correlate
    # nudge firing with behavior change.
    stall_nudges_fired: List[int] = field(default_factory=list)
    first_rag_query_step: Optional[int] = None

    # Number of tool invocations where the same (tool_name, normalized_input)
    # tuple had already been seen 2+ times — the 3rd+ identical call is
    # marked redundant and does NOT advance the progress clock. Lets
    # post-run analysis spot loop behavior even when nudges didn't fire.
    redundant_tool_calls: int = 0

    # Detailed tool call log for failure analysis
    tool_call_log: List[Dict[str, Any]] = field(default_factory=list)

    # Phase A1+A4: structured Reflexion injection payload, captured at
    # injection time so post-run analysis can show the agent the exact
    # compressed text and the source lessons_*.md filenames it was
    # distilled from. None when no reflexion fired.
    reflexion_payload: Optional[Dict[str, Any]] = None

    # Phase A2+A4: structured proactive-RAG payload, with the query, the
    # raw retrieved text, the trimmed text actually injected, and per-chunk
    # retrieval records (source_file, score, match_details, etc.). None when
    # no proactive injection fired or returned no relevant results.
    proactive_rag_payload: Optional[Dict[str, Any]] = None

    # Phase B2: real token usage drained from the LLM adapter at end-of-run
    # (replaces the chars/4 estimate in prompt_tokens / completion_tokens).
    actual_prompt_tokens: int = 0
    actual_completion_tokens: int = 0
    cached_prompt_tokens: int = 0
    est_cost_usd: float = 0.0
    per_call_tokens: List[Dict[str, Any]] = field(default_factory=list)

    # Phase C: in-memory buffer of structured per-step events (one dict per
    # tool call, RAG injection, stall nudge, etc.). The batch log writer
    # flushes this to ``<slug>.events.jsonl`` at end-of-run. Emission is
    # never on the hot path — the LoggingToolWrapper appends here via an
    # event_writer callback wired in by build_agent / runner.
    events_buffer: List[Dict[str, Any]] = field(default_factory=list)

    def start(self) -> None:
        self.start_time = time.time()

    def stop(self) -> None:
        self.end_time = time.time()

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def unique_tools_used(self) -> int:
        """Number of distinct tools invoked this run."""
        return len(self.tool_calls)

    def record_tool_call(self, tool_name: str) -> None:
        self.tool_calls[tool_name] += 1
        self.steps += 1

    def record_llm_call(self, prompt_chars: int, completion_chars: int) -> None:
        self.llm_calls += 1
        # Rough estimate: ~4 characters per token for English text
        self.prompt_tokens += prompt_chars // 4
        self.completion_tokens += completion_chars // 4

    def record_detailed_tool_call(
        self, tool_name: str, tool_input: str, tool_output: str
    ) -> None:
        """Record full tool call details for failure analysis.

        Also extracts site fingerprint from the first http_fetch / form_submit
        output so contamination filtering can use content rather than URL.
        """
        self.tool_call_log.append(
            {
                "tool": tool_name,
                "input": tool_input[:2000],
                "output": tool_output[:2000],
                "timestamp": time.time(),
            }
        )
        # Lazily extract fingerprint from first eligible tool output
        if not self.site_fingerprint:
            fp = _extract_site_fingerprint(tool_name, tool_output)
            if fp:
                self.site_fingerprint = fp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": round(self.duration_seconds, 2),
            "steps": self.steps,
            "llm_calls": self.llm_calls,
            "prompt_tokens_est": self.prompt_tokens,
            "completion_tokens_est": self.completion_tokens,
            "total_tokens_est": self.total_tokens,
            "tool_calls": dict(self.tool_calls),
            "unique_tools_used": self.unique_tools_used,
            "rag_mode": self.rag_mode,
            "challenge_url": self.challenge_url,
            "challenge_description": self.challenge_description,
            "run_succeeded": self.run_succeeded,
            "outcome": self.outcome,
            "prior_reflection_injected": self.prior_reflection_injected,
            "rag_queries_made": self.rag_queries_made,
            "candidate_flags_found": self.candidate_flags_found,
            "failure_doc_generated": self.failure_doc_generated,
            "site_fingerprint": self.site_fingerprint,
            "moderation_hits": self.moderation_hits,
            "stall_nudges_fired": list(self.stall_nudges_fired),
            "first_rag_query_step": self.first_rag_query_step,
            "redundant_tool_calls": self.redundant_tool_calls,
            # Phase A: structured injection payloads (None when not fired)
            "reflexion_payload": self.reflexion_payload,
            "proactive_rag_payload": self.proactive_rag_payload,
            # Phase B: real token usage from adapter (0 when adapter doesn't
            # populate per-call stats — e.g. local Ollama path)
            "actual_prompt_tokens": self.actual_prompt_tokens,
            "actual_completion_tokens": self.actual_completion_tokens,
            "cached_prompt_tokens": self.cached_prompt_tokens,
            "est_cost_usd": round(self.est_cost_usd, 6),
            # Phase C: per-step events buffer (flushed to events.jsonl by the
            # batch log writer). Kept as a list of dicts for direct
            # JSONL serialization.
            "events_buffer": list(self.events_buffer),
        }

    def set_token_usage_from_adapter(
        self, call_stats: List[Dict[str, Any]], model: str
    ) -> None:
        """Drain per-call token records from the LLM adapter and roll them
        up into ``actual_prompt_tokens`` / ``actual_completion_tokens`` /
        ``cached_prompt_tokens`` / ``est_cost_usd``.

        Each entry in ``call_stats`` is a dict with keys ``prompt_tokens``,
        ``completion_tokens``, ``cached_tokens`` (all int). Anything missing
        is treated as 0. ``per_call_tokens`` is replaced verbatim so the
        sidecar JSON can show per-step token usage if needed.
        """
        self.per_call_tokens = list(call_stats)
        prompt = sum(int(s.get("prompt_tokens", 0) or 0) for s in call_stats)
        completion = sum(int(s.get("completion_tokens", 0) or 0) for s in call_stats)
        cached = sum(int(s.get("cached_tokens", 0) or 0) for s in call_stats)
        self.actual_prompt_tokens = prompt
        self.actual_completion_tokens = completion
        self.cached_prompt_tokens = cached
        prices = _PRICE_PER_M_TOKENS.get(model, _PRICE_PER_M_TOKENS["gpt-5.2"])
        billed_prompt = max(prompt - cached, 0)
        self.est_cost_usd = (
            billed_prompt * prices["input"]
            + cached * prices["cached"]
            + completion * prices["output"]
        ) / 1_000_000


class TokenTrackingAdapter(AbstractChatModel):
    """
    Transparent wrapper around any AbstractChatModel that records token
    estimates in a RunTracker.

    Delegates all calls to the inner adapter. By default uses tiktoken for
    accurate token counts when available (Phase B1) — falls back to the
    legacy ~4-chars-per-token estimate when tiktoken can't load an encoding
    for the model. Per-call records are appended to ``tracker.per_call_tokens``
    so post-run cost rollup works without touching fairlib internals.
    """

    def __init__(self, inner: AbstractChatModel, tracker: RunTracker) -> None:
        self.inner = inner
        self.tracker = tracker
        # Lazy-init tiktoken encoder (one per process). None when tiktoken
        # is unavailable or the model name doesn't map to an encoding —
        # in which case we fall back to chars/4.
        self._encoder: Optional[Any] = None
        self._encoder_resolved = False

    # Forward attribute access so fairlib sees model_name, etc.
    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _resolve_encoder(self) -> Optional[Any]:
        if self._encoder_resolved:
            return self._encoder
        self._encoder_resolved = True
        try:
            import tiktoken  # type: ignore

            model_name = getattr(self.inner, "model_name", "") or ""
            try:
                self._encoder = tiktoken.encoding_for_model(model_name)
            except Exception:
                # Unknown model (e.g. gpt-5.2 not yet in tiktoken's table):
                # cl100k_base is the right default for current OpenAI models.
                self._encoder = tiktoken.get_encoding("cl100k_base")
        except ImportError:
            self._encoder = None
        return self._encoder

    def _count_tokens(self, text: str) -> Optional[int]:
        if not text:
            return 0
        encoder = self._resolve_encoder()
        if encoder is None:
            return None
        try:
            return len(encoder.encode(text, disallowed_special=()))
        except Exception:
            return None

    def _estimate(self, messages: List[Message], result: Message) -> None:
        prompt_text = "".join(m.content or "" for m in messages)
        completion_text = result.content or ""
        prompt_tokens = self._count_tokens(prompt_text)
        completion_tokens = self._count_tokens(completion_text)
        if prompt_tokens is None or completion_tokens is None:
            # Tiktoken unavailable — fall back to chars/4 estimate.
            prompt_chars = len(prompt_text)
            completion_chars = len(completion_text)
            self.tracker.record_llm_call(prompt_chars, completion_chars)
            return
        # Update legacy estimate fields (tiktoken counts are the new
        # estimate). prompt_tokens / completion_tokens carry forward to
        # to_dict() as *_est columns; per_call_tokens carries them as the
        # authoritative numbers for cost rollup.
        self.tracker.llm_calls += 1
        self.tracker.prompt_tokens += prompt_tokens
        self.tracker.completion_tokens += completion_tokens
        self.tracker.per_call_tokens.append(
            {
                "ts": time.time(),
                "model": getattr(self.inner, "model_name", ""),
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cached_tokens": 0,  # tiktoken can't see cache hits
                "source": "tiktoken",
            }
        )

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        result = self.inner.invoke(messages, **kwargs)
        self._estimate(messages, result)
        return result

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        result = await self.inner.ainvoke(messages, **kwargs)
        self._estimate(messages, result)
        return result

    def stream(self, messages: List[Message], **kwargs: Any) -> Iterator[Message]:
        prompt_chars = sum(len(m.content or "") for m in messages)
        completion_chars = 0
        for msg in self.inner.stream(messages, **kwargs):
            completion_chars += len(msg.content or "")
            yield msg
        self.tracker.record_llm_call(prompt_chars, completion_chars)

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncIterator[Message]:
        prompt_chars = sum(len(m.content or "") for m in messages)
        completion_chars = 0
        async for msg in self.inner.astream(messages, **kwargs):
            completion_chars += len(msg.content or "")
            yield msg
        self.tracker.record_llm_call(prompt_chars, completion_chars)

    def get_model_capabilities(self) -> Dict[str, Any]:
        return self.inner.get_model_capabilities()
