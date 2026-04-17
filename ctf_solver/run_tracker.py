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
from typing import Any, AsyncIterator, Dict, Iterator, List

from fairlib.core.interfaces.llm import AbstractChatModel
from fairlib.core.message import Message

# Tools whose first successful output we use for site fingerprinting
_FINGERPRINT_TOOLS = {"http_fetch", "form_submit"}

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

    # Detailed tool call log for failure analysis
    tool_call_log: List[Dict[str, Any]] = field(default_factory=list)

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
        }


class TokenTrackingAdapter(AbstractChatModel):
    """
    Transparent wrapper around any AbstractChatModel that records token
    estimates in a RunTracker.

    Delegates all calls to the inner adapter and estimates token counts
    from message character lengths (~4 chars/token).
    """

    def __init__(self, inner: AbstractChatModel, tracker: RunTracker) -> None:
        self.inner = inner
        self.tracker = tracker

    # Forward attribute access so fairlib sees model_name, etc.
    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _estimate(self, messages: List[Message], result: Message) -> None:
        prompt_chars = sum(len(m.content or "") for m in messages)
        completion_chars = len(result.content or "")
        self.tracker.record_llm_call(prompt_chars, completion_chars)

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
