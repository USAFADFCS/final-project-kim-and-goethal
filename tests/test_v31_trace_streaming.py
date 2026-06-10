"""
Tests for live trace-event streaming from ``CTFAgent`` (v3.1.0).

The agent now accepts an optional ``trace_callback`` that receives
structured event dicts as each step of ``arun()`` progresses. Streamlit
uses this to render a live "Agent Thinking" panel — see
``ctf_solver/ui/streamlit_app.py``.

These tests exercise:
- the constructor kwarg plumbing
- the ``_emit_trace`` helper's error safety (user callback must not be
  able to crash the agent loop)
- the default ``trace_callback=None`` path (no events, no crash)
- the three hook points in ``arun()`` — thought_action, observation,
  final_answer — by monkey-patching the planner and tool executor
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest
from fairlib.core.message import Action, FinalAnswer, Thought

from ctf_solver.config import LLMProviderType, RAGMode, SolverConfig


def _make_config(provider: LLMProviderType, model: str) -> SolverConfig:
    """Minimal config — same shape used by test_v29_planner_dispatch."""
    return SolverConfig(
        llm_provider=provider,
        model_name=model,
        openai_api_key="sk-test-dummy",
        anthropic_api_key="sk-ant-test-dummy",
        rag_mode=RAGMode.NONE,
        enable_opener_pack=False,
        challenge_url=None,
        challenge_description="test",
    )


def _build_agent_quietly(config: SolverConfig, **kwargs: Any):
    from ctf_solver.agent import build_agent

    return build_agent(config, log_callback=lambda _m: None, **kwargs)


class TestTraceCallbackConstructorWiring:
    """``trace_callback`` kwarg propagates from build_agent → CTFAgent."""

    def test_default_trace_callback_is_none(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        agent = _build_agent_quietly(config)
        assert agent._trace_callback is None

    def test_trace_callback_stored_when_passed(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        sink: List[Dict[str, Any]] = []

        def callback(event: Dict[str, Any]) -> None:
            sink.append(event)

        agent = _build_agent_quietly(config, trace_callback=callback)
        # Identity-check with a named callable (list.append creates fresh
        # bound-method instances each access, so `is` would always fail).
        assert agent._trace_callback is callback


class TestEmitTraceHelper:
    """``_emit_trace`` is the single invocation site — must be crash-safe."""

    def test_noop_when_callback_is_none(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        agent = _build_agent_quietly(config)
        # Must not raise even though _trace_callback is None.
        agent._emit_trace({"type": "thought_action", "step": 1})

    def test_invokes_callback_with_event(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)

        event = {"type": "observation", "step": 3, "tool": "http_fetch"}
        agent._emit_trace(event)
        assert captured == [event]

    def test_exception_in_callback_is_swallowed(self):
        """A buggy UI consumer must never take down the agent loop.
        ``_emit_trace`` wraps the call in a broad try/except."""
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")

        def boom(_event: Dict[str, Any]) -> None:
            raise RuntimeError("UI is on fire")

        agent = _build_agent_quietly(config, trace_callback=boom)
        # Must not raise.
        agent._emit_trace({"type": "thought_action", "step": 1})


class TestArunHookPoints:
    """Integration-flavored — monkey-patch planner and tool executor to
    drive ``arun()`` through known event shapes and verify the right
    callback events fire."""

    def test_thought_action_and_observation_emitted(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)
        agent.max_steps = 1  # one step then max-steps termination

        async def fake_aplan(_history, _user_input):
            return (
                Thought(text="I will fetch the homepage first."),
                Action(tool_name="http_fetch", tool_input='{"url": "http://ex/"}'),
            )

        agent.planner.aplan = fake_aplan  # type: ignore[assignment]
        agent.tool_executor.execute = (  # type: ignore[assignment]
            lambda name, inp: "[HttpFetchTool] Status 200, body: hello world"
        )

        asyncio.run(agent.arun("solve this please"))

        types = [e["type"] for e in captured]
        assert "thought_action" in types
        assert "observation" in types

        ta = next(e for e in captured if e["type"] == "thought_action")
        assert ta["step"] == 1
        assert ta["thought"] == "I will fetch the homepage first."
        assert ta["tool"] == "http_fetch"

        obs = next(e for e in captured if e["type"] == "observation")
        assert obs["step"] == 1
        assert obs["tool"] == "http_fetch"
        assert "hello world" in obs["observation"]

    def test_final_answer_event_fires_when_flag_present(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)
        agent.max_steps = 3

        # Return FinalAnswer with a valid flag so the premature-answer
        # guard doesn't block it — we want the genuine final-answer path.
        async def fake_aplan(_history, _user_input):
            return FinalAnswer(text="The flag is picoCTF{hooked_the_trace}.")

        agent.planner.aplan = fake_aplan  # type: ignore[assignment]

        asyncio.run(agent.arun("solve"))

        fa_events = [e for e in captured if e["type"] == "final_answer"]
        assert len(fa_events) == 1
        assert "picoCTF{hooked_the_trace}" in fa_events[0]["text"]

    def test_observation_truncated_to_500_chars(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)
        agent.max_steps = 1

        async def fake_aplan(_history, _user_input):
            return (
                Thought(text="fetch"),
                Action(tool_name="http_fetch", tool_input='{"url": "http://ex/"}'),
            )

        huge = "A" * 2000
        agent.planner.aplan = fake_aplan  # type: ignore[assignment]
        agent.tool_executor.execute = lambda n, i: huge  # type: ignore[assignment]

        asyncio.run(agent.arun("solve"))

        obs_events = [e for e in captured if e["type"] == "observation"]
        assert len(obs_events) == 1
        assert len(obs_events[0]["observation"]) == 500


class TestOllamaThinkingStream:
    """Surface ``message.thinking`` from thinking-capable Ollama models
    (gpt-oss, gemma4) as ``llm_thinking`` trace events."""

    def _make_mock_response(self, content: str, thinking: str = "") -> Dict[str, Any]:
        """Build an Ollama-shaped chat response. The real ollama client
        returns a Pydantic ChatResponse but it is dict-indexable, which
        is all our extraction code relies on."""
        msg: Dict[str, Any] = {"role": "assistant", "content": content}
        if thinking:
            msg["thinking"] = thinking
        return {"message": msg}

    def test_adapter_forwards_thinking_to_callback(self):
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        captured: List[str] = []

        adapter = OllamaAdapter(
            model_name="gemma4:26b",
            thinking_callback=captured.append,
            enable_thinking=True,
        )

        # Pretend the Ollama client supports think=True and returns thinking.
        def _fake_chat(**kwargs):
            assert kwargs.get("think") is True  # adapter requested thinking
            return self._make_mock_response(
                content='{"thought": "ok", "action": {"tool_name": "x", "tool_input": "y"}}',
                thinking="Let me reason carefully about the login form...",
            )

        adapter.client.chat = _fake_chat  # type: ignore[assignment]

        result = adapter.invoke([FairMessage(role="user", content="hi")])
        assert result.content.startswith('{"thought"')
        assert captured == ["Let me reason carefully about the login form..."]

    def test_adapter_silent_when_no_thinking_field(self):
        """Non-thinking models never produce a thinking payload; the
        callback must stay silent (not fire with empty string)."""
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        captured: List[str] = []

        adapter = OllamaAdapter(
            model_name="llama3.1:latest",
            thinking_callback=captured.append,
            enable_thinking=True,
        )
        adapter.client.chat = lambda **kw: self._make_mock_response(  # type: ignore
            content="just content, no thinking"
        )

        adapter.invoke([FairMessage(role="user", content="hi")])
        assert captured == []

    def test_adapter_graceful_fallback_on_old_ollama_client(self):
        """Older Ollama clients raise TypeError when given ``think=True``.
        Adapter should retry without the kwarg and still produce a
        Message. Subsequent calls avoid the probe (cached False)."""
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        adapter = OllamaAdapter(
            model_name="gpt-oss:20b",
            thinking_callback=lambda _t: None,
            enable_thinking=True,
        )

        # First call: raises TypeError on think, then a retry without it
        # succeeds.
        call_log: List[Dict[str, Any]] = []

        def _fake_chat(**kwargs):
            call_log.append(dict(kwargs))
            if "think" in kwargs:
                raise TypeError("chat() got an unexpected keyword argument 'think'")
            return self._make_mock_response(content="hello")

        adapter.client.chat = _fake_chat  # type: ignore[assignment]

        result = adapter.invoke([FairMessage(role="user", content="hi")])
        assert result.content == "hello"
        assert adapter._think_supported is False
        # Second call should NOT attempt think=True anymore.
        adapter.invoke([FairMessage(role="user", content="hi2")])
        assert not any("think" in c for c in call_log[1:])

    def test_adapter_callback_exceptions_do_not_crash_invoke(self):
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        def boom(_text: str) -> None:
            raise RuntimeError("UI callback error")

        adapter = OllamaAdapter(
            model_name="gemma4:26b", thinking_callback=boom, enable_thinking=True
        )
        adapter.client.chat = lambda **kw: self._make_mock_response(  # type: ignore
            content="x", thinking="reasoning"
        )

        # Must not raise — the broken callback should be swallowed.
        result = adapter.invoke([FairMessage(role="user", content="hi")])
        assert result.content == "x"


class TestBuildAgentThinkingWiring:
    """End-to-end: build_agent wires the adapter's thinking channel
    through to a user-supplied ``trace_callback`` with the correct
    ``step`` tag based on what the agent is about to process."""

    def test_thinking_step_ref_passed_to_agent(self):
        pytest.importorskip("ollama")
        config = _make_config(LLMProviderType.OLLAMA, "gemma4:26b")
        agent = _build_agent_quietly(config, trace_callback=lambda _e: None)
        # Agent carries a one-key dict ctx that build_agent also wired to
        # the adapter's thinking_callback closure.
        assert isinstance(agent._thinking_step_ref, dict)
        assert agent._thinking_step_ref == {"step": 0}

    def test_llm_thinking_event_fires_through_trace_callback(self):
        """Simulate an Ollama response with thinking by swapping the
        adapter's ``client.chat`` after build_agent returns. Then run a
        single arun step and assert trace_callback saw the thinking."""
        pytest.importorskip("ollama")

        config = _make_config(LLMProviderType.OLLAMA, "gemma4:26b")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)
        agent.max_steps = 1

        # Drive the planner with a canned response so we go through one
        # normal step. The thinking_callback is fired inside invoke —
        # which the planner calls via ainvoke — so we also need to mock
        # the adapter chain. Simpler: directly fire the stored callback
        # after tagging the step via the shared ctx (matches runtime).
        agent._thinking_step_ref["step"] = 1  # simulate "about to start step 1"

        # Find the inner OllamaAdapter underneath the TokenTracking wrapper
        # so we can reach its thinking_callback (the closure from build_agent).
        inner = getattr(agent.llm, "inner", agent.llm)
        assert inner.thinking_callback is not None, (
            "build_agent should have wired a thinking_callback onto the "
            "OllamaAdapter when a trace_callback was supplied"
        )
        inner.thinking_callback("I will analyze the HTML first...")

        thinking_events = [e for e in captured if e["type"] == "llm_thinking"]
        assert len(thinking_events) == 1
        assert thinking_events[0]["step"] == 1
        assert "analyze the HTML" in thinking_events[0]["content"]

    def test_thinking_step_ref_updates_each_iteration(self):
        """The ref is bumped at the top of each arun loop so each round's
        thinking is tagged with the correct step."""
        pytest.importorskip("ollama")

        config = _make_config(LLMProviderType.OLLAMA, "gemma4:26b")
        captured: List[Dict[str, Any]] = []
        agent = _build_agent_quietly(config, trace_callback=captured.append)
        agent.max_steps = 3

        async def fake_aplan(_history, _user_input):
            # Capture the ref at the moment the planner fires — that's
            # exactly when the OllamaAdapter would be mid-invoke and
            # publishing thinking, so the step tag must be correct.
            assert agent._thinking_step_ref is not None
            return (
                Thought(text="t"),
                Action(tool_name="http_fetch", tool_input='{"url": "http://ex/"}'),
            )

        agent.planner.aplan = fake_aplan  # type: ignore[assignment]
        agent.tool_executor.execute = lambda n, i: "obs"  # type: ignore

        asyncio.run(agent.arun("solve"))

        # After 3 iterations, the ref should reflect the last step started.
        assert agent._thinking_step_ref["step"] == 3
