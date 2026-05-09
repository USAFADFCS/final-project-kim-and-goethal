"""Tests for v4.1 injection-tracing instrumentation (Phases A, B, C).

Coverage:
- Phase A1: ``find_and_compress_prior_lesson_with_sources`` returns the
  list of contributing lessons_*.md filenames and the back-compat wrapper
  ``find_and_compress_prior_lesson`` still returns just the string.
- Phase A2: ``SafeKnowledgeQueryTool.use()`` populates
  ``last_retrieval_records`` with rank/source_file/score/is_lesson.
- Phase A3+B2: RunTracker carries the structured payloads and rolls up
  per-call tokens into actual_*/cached_*/est_cost_usd. Cost math correct.
- Phase B3: ``write_batch_summary`` emits the new token / cost columns.
- Phase C: LoggingToolWrapper emits a tool_call event per use(), with
  the canonicalized input_hash, duration_ms, and output_len fields.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

from ctf_solver.batch import BatchItem, BatchResult, write_batch_summary
from ctf_solver.failure_analyzer import (
    find_and_compress_prior_lesson,
    find_and_compress_prior_lesson_with_sources,
)
from ctf_solver.run_tracker import (
    _PRICE_PER_M_TOKENS,
    RunTracker,
    TokenTrackingAdapter,
)
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper

# ---------------------------------------------------------------------------
# Phase A1 — find_and_compress_prior_lesson_with_sources
# ---------------------------------------------------------------------------


def _write_lesson(
    docs_dir: Path, name: str, outcome: str, what_happened: str = "test"
) -> Path:
    """Write a minimal lessons_*.md file with the given Type and content."""
    p = docs_dir / name
    p.write_text(
        f"**Type:** experience_{outcome}\n\n"
        f"## What Happened\n\n{what_happened}\n\n"
        f"## Key Exploit Inputs\n\nfoo\n\n- payload-bar\n",
        encoding="utf-8",
    )
    return p


def test_with_sources_returns_basenames_for_per_challenge_match():
    with tempfile.TemporaryDirectory() as td:
        docs = Path(td)
        _write_lesson(
            docs,
            "lessons_001_open-application_r1_20260101_010101.md",
            "success",
            "Solved via upload",
        )
        _write_lesson(
            docs,
            "lessons_002_open-application_r1_20260101_020202.md",
            "failure",
            "Got stuck on traversal",
        )

        text, sources = find_and_compress_prior_lesson_with_sources(
            challenge_name="Open Application",
            challenge_url=None,
            lessons_docs_dir=str(docs),
        )

        assert text is not None
        assert "MOST RECENT SUCCESS" in text
        assert "PRIOR FAILURE" in text
        # One success + one failure contribute. Order depends on sort but
        # both basenames must be present.
        assert sorted(sources) == sorted(
            [
                "lessons_001_open-application_r1_20260101_010101.md",
                "lessons_002_open-application_r1_20260101_020202.md",
            ]
        )


def test_with_sources_returns_empty_when_no_match():
    with tempfile.TemporaryDirectory() as td:
        text, sources = find_and_compress_prior_lesson_with_sources(
            challenge_name="Brand New Challenge",
            challenge_url=None,
            lessons_docs_dir=str(td),
        )
        assert text is None
        assert sources == []


def test_legacy_wrapper_returns_string_only():
    """The Optional[str]-returning wrapper keeps existing tests working."""
    with tempfile.TemporaryDirectory() as td:
        docs = Path(td)
        _write_lesson(
            docs,
            "lessons_001_widget-test_r1_20260101_010101.md",
            "success",
            "Solved",
        )

        result = find_and_compress_prior_lesson(
            challenge_name="Widget Test",
            challenge_url=None,
            lessons_docs_dir=str(docs),
        )
        assert isinstance(result, str)
        assert "MOST RECENT SUCCESS" in result


# ---------------------------------------------------------------------------
# Phase A3 + B2 — RunTracker payloads + token rollup + cost
# ---------------------------------------------------------------------------


def test_tracker_to_dict_carries_injection_payloads():
    t = RunTracker()
    t.reflexion_payload = {
        "text": "Prior runs ...",
        "sources": ["lessons_001.md"],
        "char_count": 13,
    }
    t.proactive_rag_payload = {
        "query": "ssti",
        "raw_text": "blob",
        "trimmed_text": "blob",
        "raw_char_count": 4,
        "trimmed_char_count": 4,
        "retrieval_records": [
            {"rank": 0, "source_file": "ssti.md", "score": 0.9, "is_lesson": False},
        ],
        "injected": True,
    }
    d = t.to_dict()
    assert d["reflexion_payload"]["sources"] == ["lessons_001.md"]
    assert (
        d["proactive_rag_payload"]["retrieval_records"][0]["source_file"] == "ssti.md"
    )


def test_set_token_usage_from_adapter_sums_and_prices_correctly():
    """Cost = (prompt-cached)*input + cached*cached + completion*output.

    Hand-computation for gpt-5.2 (input 1.25, cached 0.125, output 10):
        billed_prompt = 3000 - 200 = 2800
        2800 * 1.25 = 3500   (per million-tokens)
        200  * 0.125 = 25
        150  * 10    = 1500
        total = 5025  per million → $0.005025
    """
    t = RunTracker()
    t.set_token_usage_from_adapter(
        [
            {"prompt_tokens": 1000, "completion_tokens": 100, "cached_tokens": 200},
            {"prompt_tokens": 2000, "completion_tokens": 50, "cached_tokens": 0},
        ],
        "gpt-5.2",
    )
    assert t.actual_prompt_tokens == 3000
    assert t.actual_completion_tokens == 150
    assert t.cached_prompt_tokens == 200
    assert t.est_cost_usd == pytest.approx(0.005025, abs=1e-9)


def test_set_token_usage_unknown_model_falls_back_to_gpt52_prices():
    t = RunTracker()
    t.set_token_usage_from_adapter(
        [{"prompt_tokens": 1000, "completion_tokens": 100, "cached_tokens": 0}],
        "fictitious-model",
    )
    expected = (1000 * 1.25 + 100 * 10) / 1_000_000
    assert t.est_cost_usd == pytest.approx(expected, abs=1e-9)


def test_price_table_has_gpt52_row():
    """Brief slide depends on this row existing."""
    assert "gpt-5.2" in _PRICE_PER_M_TOKENS
    row = _PRICE_PER_M_TOKENS["gpt-5.2"]
    assert {"input", "output", "cached"} <= set(row.keys())


def test_token_tracking_adapter_uses_tiktoken_when_available():
    """Real-token path emits per_call_tokens entries with source='tiktoken'."""

    class _FakeMessage:
        def __init__(self, content: str = ""):
            self.content = content
            self.role = "assistant"

    class _FakeInner:
        model_name = "gpt-5.2"

        def invoke(self, messages, **kwargs):
            return _FakeMessage("hello there")

        async def ainvoke(self, messages, **kwargs):  # pragma: no cover
            return _FakeMessage("hello there")

        def stream(self, messages, **kwargs):  # pragma: no cover
            yield _FakeMessage("hi")

        async def astream(self, messages, **kwargs):  # pragma: no cover
            yield _FakeMessage("hi")

        def get_model_capabilities(self):  # pragma: no cover
            return {}

    pytest.importorskip("tiktoken")

    t = RunTracker()
    adapter = TokenTrackingAdapter(_FakeInner(), t)
    adapter.invoke([_FakeMessage("question?")])
    assert t.per_call_tokens, "TokenTrackingAdapter should record one entry"
    entry = t.per_call_tokens[0]
    assert entry["source"] == "tiktoken"
    assert entry["prompt_tokens"] > 0
    assert entry["completion_tokens"] > 0


# ---------------------------------------------------------------------------
# Phase B3 — write_batch_summary new columns
# ---------------------------------------------------------------------------


def test_write_batch_summary_emits_token_and_cost_columns():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "results.tsv"
        item = BatchItem(name="t", url="http://x")
        result = BatchResult(
            item=item,
            outcome="success",
            flag="F{x}",
            steps=4,
            duration_seconds=12.0,
            stats={
                "actual_prompt_tokens": 1500,
                "actual_completion_tokens": 80,
                "cached_prompt_tokens": 0,
                "est_cost_usd": 0.002675,
            },
        )
        write_batch_summary([result], out)
        rows = out.read_text().splitlines()
        assert rows[0].split("\t")[7:11] == [
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens",
            "est_cost_usd",
        ]
        cells = rows[1].split("\t")
        assert cells[7] == "1500"
        assert cells[8] == "80"
        assert cells[10] == "0.002675"


# ---------------------------------------------------------------------------
# Phase C — LoggingToolWrapper event emission
# ---------------------------------------------------------------------------


class _RecordingTool:
    name = "fake_tool"
    description = "just for tests"

    def __init__(self, output: str = "ok"):
        self.output = output

    def use(self, tool_input: str) -> str:
        return self.output


def test_logging_wrapper_emits_event_per_use():
    events: List[Dict[str, Any]] = []
    tracker = RunTracker()
    wrapper = LoggingToolWrapper(
        _RecordingTool(),
        tracker=tracker,
        event_writer=events.append,
        log_callback=lambda _msg: None,
    )
    wrapper.use('{"x": 1}')
    wrapper.use('{"x": 2}')

    assert len(events) == 2
    e0 = events[0]
    assert e0["event"] == "tool_call"
    assert e0["tool"] == "fake_tool"
    assert e0["step"] == 1
    assert "input_hash" in e0
    assert e0["output_len"] > 0
    assert e0["truncated"] is False


def test_logging_wrapper_no_emit_when_writer_unset():
    tracker = RunTracker()
    wrapper = LoggingToolWrapper(
        _RecordingTool(),
        tracker=tracker,
        log_callback=lambda _msg: None,
    )
    # Should not raise even with no writer.
    wrapper.use('{"x": 1}')
    assert tracker.events_buffer == []


def test_input_hash_is_canonicalized_for_json():
    """Reordered JSON keys produce the same input_hash (v3.10 P2 + v4.1 C)."""
    events: List[Dict[str, Any]] = []
    tracker = RunTracker()
    wrapper = LoggingToolWrapper(
        _RecordingTool(),
        tracker=tracker,
        event_writer=events.append,
        log_callback=lambda _msg: None,
    )
    wrapper.use('{"a": 1, "b": 2}')
    wrapper.use('{"b": 2, "a": 1}')
    assert events[0]["input_hash"] == events[1]["input_hash"]


def test_event_writer_failure_does_not_break_use():
    """A broken writer must not crash the run."""

    def _broken(_evt: Dict[str, Any]) -> None:
        raise RuntimeError("writer failed")

    tracker = RunTracker()
    wrapper = LoggingToolWrapper(
        _RecordingTool(),
        tracker=tracker,
        event_writer=_broken,
        log_callback=lambda _msg: None,
    )
    # Must not raise.
    out = wrapper.use('{"x": 1}')
    assert isinstance(out, str)


# ---------------------------------------------------------------------------
# Moderation/refusal detection (verified against OpenAI docs 2026-05)
# ---------------------------------------------------------------------------


def _is_moderation_error(content: str) -> bool:
    """Lazy shim — keeps adapter import inside the test."""
    from ctf_solver.llm.adapters import CTFOpenAIAdapter

    return CTFOpenAIAdapter._is_moderation_error(content)


def test_moderation_detect_canonical_content_policy_violation_code():
    """OpenAI's documented error code is ``content_policy_violation``."""
    msg = (
        "Error code: 400 - {'error': {'message': 'Your request was rejected ...', "
        "'type': 'invalid_request_error', 'code': 'content_policy_violation'}}"
    )
    assert _is_moderation_error(msg) is True


def test_moderation_detect_human_readable_message():
    msg = (
        "Error: Your request was flagged as potentially violating our usage "
        "policy. Please modify your prompt and try again."
    )
    assert _is_moderation_error(msg) is True


def test_moderation_detect_azure_content_filter_variant():
    """Azure OpenAI returns ``code: 'content_filter'`` instead."""
    msg = (
        "Error code: 400 - {'error': {'code': 'content_filter', "
        "'message': 'Filtered.'}}"
    )
    assert _is_moderation_error(msg) is True


def test_moderation_detect_image_api_moderation_blocked():
    """gpt-image-2 / DALL·E variant uses ``code: 'moderation_blocked'``."""
    msg = "Error: code=moderation_blocked"
    assert _is_moderation_error(msg) is True


def test_moderation_no_false_positive_on_normal_error():
    msg = "Error code: 500 - internal server error"
    assert _is_moderation_error(msg) is False


def test_moderation_no_false_positive_on_obsolete_invalid_prompt_alone():
    """Pre-2026 detector matched ``invalid_prompt`` — confirm we no longer
    fire on that string alone (it isn't a documented OpenAI moderation
    code; only ``content_policy_violation`` / ``content_filter`` are)."""
    msg = "Error: invalid_prompt format somewhere unrelated"
    assert _is_moderation_error(msg) is False


def test_native_tools_path_surfaces_finish_reason_content_filter():
    """openai_invoke_with_tools must expose ``moderation_signal`` when the
    response object's ``finish_reason`` is the typed ``content_filter`` value
    (output-side filter — not visible through fairlib's string-path)."""
    from unittest.mock import MagicMock, patch

    from fairlib import Message  # type: ignore

    from ctf_solver.llm.adapters import openai_invoke_with_tools

    mock_response = MagicMock()
    mock_response.choices[0].message.tool_calls = []
    mock_response.choices[0].message.content = ""
    mock_response.choices[0].message.refusal = None  # not a refusal-field case
    mock_response.choices[0].finish_reason = "content_filter"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    with patch("openai.OpenAI", return_value=mock_client):
        result = openai_invoke_with_tools(
            messages=[Message(role="user", content="anything")],
            tools=[{"type": "function", "function": {"name": "noop"}}],
            model_name="gpt-5.2",
            api_key="test-key",
        )

    assert result["moderation_signal"] == "content_filter"
    assert result["stop_reason"] == "content_filter"


def test_native_tools_path_surfaces_typed_refusal_field():
    """When the model returns a ``message.refusal`` string, surface it as
    a ``refusal`` moderation_signal so the tracker can count it."""
    from unittest.mock import MagicMock, patch

    from fairlib import Message  # type: ignore

    from ctf_solver.llm.adapters import openai_invoke_with_tools

    mock_response = MagicMock()
    mock_response.choices[0].message.tool_calls = []
    mock_response.choices[0].message.content = ""
    mock_response.choices[0].message.refusal = "I can't help with that."
    mock_response.choices[0].finish_reason = "stop"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    with patch("openai.OpenAI", return_value=mock_client):
        result = openai_invoke_with_tools(
            messages=[Message(role="user", content="anything")],
            tools=[{"type": "function", "function": {"name": "noop"}}],
            model_name="gpt-5.2",
            api_key="test-key",
        )

    assert result["moderation_signal"] == "refusal"
    assert result["refusal"] == "I can't help with that."


def test_native_tools_path_no_signal_for_normal_response():
    """No moderation signal when response is normal (finish_reason in
    {'stop', 'tool_calls'} and refusal is None)."""
    from unittest.mock import MagicMock, patch

    from fairlib import Message  # type: ignore

    from ctf_solver.llm.adapters import openai_invoke_with_tools

    mock_response = MagicMock()
    mock_response.choices[0].message.tool_calls = []
    mock_response.choices[0].message.content = "all good"
    mock_response.choices[0].message.refusal = None
    mock_response.choices[0].finish_reason = "stop"

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_response

    with patch("openai.OpenAI", return_value=mock_client):
        result = openai_invoke_with_tools(
            messages=[Message(role="user", content="anything")],
            tools=[{"type": "function", "function": {"name": "noop"}}],
            model_name="gpt-5.2",
            api_key="test-key",
        )

    assert result["moderation_signal"] == ""
    assert result["refusal"] == ""
