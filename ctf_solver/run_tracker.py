"""
Run statistics tracker for CTF Solver.

Tracks solve time, token usage (estimated), step count, and tool usage
across an agent run. Designed to integrate with LoggingToolWrapper and
LLM adapters without modifying the fairlib framework.
"""

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional

from fairlib.core.interfaces.llm import AbstractChatModel
from fairlib.core.message import Message


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

    def record_tool_call(self, tool_name: str) -> None:
        self.tool_calls[tool_name] += 1
        self.steps += 1

    def record_llm_call(self, prompt_chars: int, completion_chars: int) -> None:
        self.llm_calls += 1
        # Rough estimate: ~4 characters per token for English text
        self.prompt_tokens += prompt_chars // 4
        self.completion_tokens += completion_chars // 4

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": round(self.duration_seconds, 2),
            "steps": self.steps,
            "llm_calls": self.llm_calls,
            "prompt_tokens_est": self.prompt_tokens,
            "completion_tokens_est": self.completion_tokens,
            "total_tokens_est": self.total_tokens,
            "tool_calls": dict(self.tool_calls),
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
        yield from self.inner.stream(messages, **kwargs)

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncIterator[Message]:
        async for msg in self.inner.astream(messages, **kwargs):
            yield msg

    def get_model_capabilities(self) -> Dict[str, Any]:
        return self.inner.get_model_capabilities()
