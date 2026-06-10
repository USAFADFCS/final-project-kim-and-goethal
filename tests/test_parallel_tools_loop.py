"""Stage 2b tests for the native parallel-tools loop on CTFAgent.

Covers:
- Tool-spec builder (_build_anthropic_tool_specs)
- tool_use input extraction (_extract_native_tool_input)
- tool_result assembly (_execute_native_tool_calls)
- response splitting (_parse_anthropic_native_response)
- adapter duck-check (_is_anthropic_llm)
- Full loop integration (_arun_native_tools)
- arun() branching and non-Anthropic fallback
"""

from __future__ import annotations

import asyncio
from typing import List
from unittest.mock import MagicMock, Mock

from fairlib.core.message import Message

from ctf_solver.agent import CTFAgent

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _FakeTool:
    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    def use(self, tool_input: str) -> str:  # pragma: no cover - not called
        return f"output:{self.name}:{tool_input}"


class _FakeRegistry:
    def __init__(self, tools: List[_FakeTool]) -> None:
        self._tools = tools

    def get_all_tools(self) -> List[_FakeTool]:
        return list(self._tools)


class _FakeExecutor:
    """Record every execute() call; return the configured observation per tool name."""

    def __init__(self, observations=None, tools=None):
        self.observations = observations or {}
        self.tool_registry = _FakeRegistry(tools or [])
        self.calls: List[tuple] = []

    def execute(self, tool_name: str, tool_input: str) -> str:
        self.calls.append((tool_name, tool_input))
        return self.observations.get(tool_name, f"[stub]{tool_name}")


class _FakeMemory:
    def __init__(self) -> None:
        self._msgs: List[Message] = []

    def get_history(self):
        return list(self._msgs)

    def add_message(self, msg):
        self._msgs.append(msg)

    def clear(self):
        self._msgs.clear()


class _FakeAnthropicAdapter:
    """Duck-types AnthropicAdapter for the agent's _is_anthropic_llm check."""

    model_name = "claude-test"
    max_tokens = 4096

    def __init__(self, responses):
        # ``responses`` is a list of Mocks to return on successive .create() calls
        self._responses = list(responses)
        self.sync_client = MagicMock()
        self.sync_client.messages.create.side_effect = self._responses

    def _cached_system(self, s: str):  # mirrors AnthropicAdapter.method
        return s  # bypass cache wrapping for tests


# Force __class__.__name__ == "AnthropicAdapter" so _is_anthropic_llm() trips.
_FakeAnthropicAdapter.__name__ = "AnthropicAdapter"


def _block(type_name: str, **fields):
    m = Mock()
    m.type = type_name
    for k, v in fields.items():
        setattr(m, k, v)
    return m


def _response(blocks, stop_reason="tool_use"):
    r = Mock()
    r.content = blocks
    r.stop_reason = stop_reason
    return r


def _make_native_agent(
    llm,
    tools=None,
    observations=None,
    max_steps=3,
    system_prompt="You are a CTF agent.",
    flag_regex=r"FLAG\{[^}]+\}",
):
    tools = tools or [
        _FakeTool("robots_txt", "Fetch robots.txt"),
        _FakeTool("path_enumerator", "Enumerate paths"),
        _FakeTool("http_fetch", "Fetch a URL"),
    ]
    executor = _FakeExecutor(observations=observations, tools=tools)
    memory = _FakeMemory()
    agent = CTFAgent(
        llm=llm,
        planner=MagicMock(),
        tool_executor=executor,
        memory=memory,
        max_steps=max_steps,
        flag_regex=flag_regex,
        log_callback=lambda msg: None,
        enable_parallel_tools=True,
        native_system_prompt=system_prompt,
    )
    return agent, executor, memory


# ---------------------------------------------------------------------------
# _is_anthropic_llm
# ---------------------------------------------------------------------------


class TestIsAnthropicLLM:
    def test_recognizes_anthropic_adapter(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter(responses=[]))
        assert agent._is_anthropic_llm() is True

    def test_rejects_other_adapters(self):
        class _OpenAIAdapter:
            pass

        agent, _, _ = _make_native_agent(_OpenAIAdapter())
        assert agent._is_anthropic_llm() is False


# ---------------------------------------------------------------------------
# _build_anthropic_tool_specs
# ---------------------------------------------------------------------------


class TestBuildAnthropicToolSpecs:
    def test_all_registered_tools_produce_specs(self):
        tools = [
            _FakeTool("foo", "does foo"),
            _FakeTool("bar", "does bar"),
        ]
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]), tools=tools)
        specs = agent._build_anthropic_tool_specs()
        assert [s["name"] for s in specs] == ["foo", "bar"]
        assert specs[0]["description"] == "does foo"
        assert specs[0]["input_schema"]["type"] == "object"
        assert "tool_input" in specs[0]["input_schema"]["properties"]
        assert specs[0]["input_schema"]["required"] == ["tool_input"]


# ---------------------------------------------------------------------------
# _extract_native_tool_input
# ---------------------------------------------------------------------------


class TestExtractNativeToolInput:
    def test_tool_input_string_passthrough(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        result = agent._extract_native_tool_input({"tool_input": '{"url":"x"}'})
        assert result == '{"url":"x"}'

    def test_tool_input_non_string_json_encodes(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        result = agent._extract_native_tool_input({"tool_input": {"url": "x"}})
        # Model gave us a dict instead of a string — re-encode.
        import json as _json

        assert _json.loads(result) == {"url": "x"}

    def test_structured_object_without_tool_input_key(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        result = agent._extract_native_tool_input({"url": "http://x", "depth": 2})
        import json as _json

        assert _json.loads(result) == {"url": "http://x", "depth": 2}

    def test_empty_input_yields_empty_object(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        assert agent._extract_native_tool_input({}) == "{}"


# ---------------------------------------------------------------------------
# _execute_native_tool_calls
# ---------------------------------------------------------------------------


class TestExecuteNativeToolCalls:
    def test_sequential_execution_preserves_order(self):
        agent, executor, _ = _make_native_agent(
            _FakeAnthropicAdapter([]),
            observations={
                "robots_txt": "ROBOTS",
                "path_enumerator": "PATHS",
                "http_fetch": "HTML",
            },
        )
        calls = [
            {"id": "a", "name": "robots_txt", "input": {"tool_input": "{}"}},
            {"id": "b", "name": "path_enumerator", "input": {"tool_input": "{}"}},
            {"id": "c", "name": "http_fetch", "input": {"tool_input": "{}"}},
        ]
        results = agent._execute_native_tool_calls(calls)
        assert [r["tool_use_id"] for r in results] == ["a", "b", "c"]
        assert [r["content"] for r in results] == ["ROBOTS", "PATHS", "HTML"]
        # Each call went through the executor once.
        assert [c[0] for c in executor.calls] == [
            "robots_txt",
            "path_enumerator",
            "http_fetch",
        ]

    def test_tool_exception_becomes_error_string(self):
        agent, executor, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        executor.execute = MagicMock(side_effect=RuntimeError("boom"))
        executor.tool_registry = _FakeRegistry([])
        result = agent._execute_native_tool_calls(
            [{"id": "x", "name": "broken", "input": {"tool_input": "{}"}}]
        )
        assert len(result) == 1
        assert "Error" in result[0]["content"]
        assert "boom" in result[0]["content"]
        assert result[0]["tool_use_id"] == "x"


# ---------------------------------------------------------------------------
# _parse_anthropic_native_response
# ---------------------------------------------------------------------------


class TestParseAnthropicNativeResponse:
    def test_splits_text_and_tool_calls(self):
        agent, _, _ = _make_native_agent(_FakeAnthropicAdapter([]))
        resp = _response(
            [
                _block("text", text="planning"),
                _block("tool_use", id="a", name="x", input={"tool_input": "{}"}),
                _block("text", text=" and"),
                _block("tool_use", id="b", name="y", input={"tool_input": "{}"}),
            ],
            stop_reason="tool_use",
        )
        parsed = agent._parse_anthropic_native_response(resp)
        assert parsed["text"] == "planning and"
        assert [c["name"] for c in parsed["tool_calls"]] == ["x", "y"]
        # raw_blocks preserved in order for echo into history
        assert len(parsed["raw_blocks"]) == 4


# ---------------------------------------------------------------------------
# _arun_native_tools — integration
# ---------------------------------------------------------------------------


class TestArunNativeLoop:
    def test_multi_tool_batch_then_final_answer(self):
        # Turn 1: batched recon of 3 tools.
        turn_1 = _response(
            [
                _block("text", text="let me batch"),
                _block(
                    "tool_use", id="t1", name="robots_txt", input={"tool_input": "{}"}
                ),
                _block(
                    "tool_use",
                    id="t2",
                    name="path_enumerator",
                    input={"tool_input": "{}"},
                ),
                _block(
                    "tool_use", id="t3", name="http_fetch", input={"tool_input": "{}"}
                ),
            ],
        )
        # Turn 2: final answer with the flag.
        turn_2 = _response(
            [_block("text", text="The flag is FLAG{batched_win}")],
            stop_reason="end_turn",
        )
        llm = _FakeAnthropicAdapter([turn_1, turn_2])
        agent, executor, _ = _make_native_agent(llm)

        final = asyncio.run(agent.arun("solve"))

        assert "FLAG{batched_win}" in final
        # Three tool executions in one step (not three steps).
        assert [c[0] for c in executor.calls] == [
            "robots_txt",
            "path_enumerator",
            "http_fetch",
        ]
        # Two LLM calls: the batch turn and the final-answer turn.
        assert llm.sync_client.messages.create.call_count == 2

    def test_native_early_terminates_on_confirmed_flag(self):
        # Follow-on #4 native path: a batched tool output carrying a confirmed
        # flag ends the run after turn 1 — the second turn is never reached.
        turn_1 = _response(
            [
                _block("text", text="batch recon"),
                _block(
                    "tool_use", id="t1", name="http_fetch", input={"tool_input": "{}"}
                ),
            ],
        )
        turn_2 = _response(
            [_block("text", text="unreached FLAG{later}")], stop_reason="end_turn"
        )
        llm = _FakeAnthropicAdapter([turn_1, turn_2])
        agent, _, _ = _make_native_agent(
            llm, observations={"http_fetch": "page body FLAG{native_win}"}
        )
        final = asyncio.run(agent.arun("solve"))
        assert final == "Flag captured: FLAG{native_win}"
        # Terminated after the first batched turn — only ONE LLM call.
        assert llm.sync_client.messages.create.call_count == 1

    def test_native_no_terminate_on_broad_noise(self):
        # A JS literal in a tool output (broad match, no CTF prefix) must NOT
        # terminate the native loop; it proceeds to the real flag on turn 2.
        turn_1 = _response(
            [
                _block(
                    "tool_use", id="t1", name="http_fetch", input={"tool_input": "{}"}
                ),
            ],
        )
        turn_2 = _response(
            [_block("text", text="solved FLAG{after_noise}")], stop_reason="end_turn"
        )
        llm = _FakeAnthropicAdapter([turn_1, turn_2])
        agent, _, _ = _make_native_agent(
            llm, observations={"http_fetch": "code: try{return null}"}
        )
        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{after_noise}" in final  # reached turn 2 — no false terminate
        assert llm.sync_client.messages.create.call_count == 2

    def test_premature_final_answer_triggers_guard(self):
        # Turn 1: final answer with NO flag → should be blocked.
        turn_1 = _response(
            [_block("text", text="I think we should stop")],
            stop_reason="end_turn",
        )
        # Turn 2: now with a flag.
        turn_2 = _response(
            [_block("text", text="Ok: FLAG{retried}")],
            stop_reason="end_turn",
        )
        llm = _FakeAnthropicAdapter([turn_1, turn_2])
        agent, _, _ = _make_native_agent(llm)

        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{retried}" in final
        # Two LLM calls: premature + retry with guard continuation.
        assert llm.sync_client.messages.create.call_count == 2
        # Premature count bumped once.
        assert agent._premature_fa_count == 1

    def test_max_steps_exhausts(self):
        # Agent always calls a tool → never a final answer.
        def _tool_turn(n):
            return _response(
                [
                    _block(
                        "tool_use",
                        id=f"tc{n}",
                        name="robots_txt",
                        input={"tool_input": "{}"},
                    )
                ],
            )

        llm = _FakeAnthropicAdapter([_tool_turn(i) for i in range(10)])
        agent, executor, _ = _make_native_agent(llm, max_steps=2)

        final = asyncio.run(agent.arun("solve"))
        assert "max steps" in final
        # Exactly max_steps LLM calls.
        assert llm.sync_client.messages.create.call_count == 2

    def test_system_prompt_threaded_through_cache_wrapper(self):
        turn_1 = _response(
            [_block("text", text="FLAG{done}")],
            stop_reason="end_turn",
        )
        llm = _FakeAnthropicAdapter([turn_1])
        llm._cached_system = MagicMock(return_value=[{"cache_hit": True}])
        agent, _, _ = _make_native_agent(llm, system_prompt="SYSTEM")

        asyncio.run(agent.arun("solve"))
        llm._cached_system.assert_called_once_with("SYSTEM")
        call_kwargs = llm.sync_client.messages.create.call_args[1]
        assert call_kwargs["system"] == [{"cache_hit": True}]

    def test_opener_observations_seeded_into_first_message(self):
        turn_1 = _response(
            [_block("text", text="FLAG{done}")],
            stop_reason="end_turn",
        )
        llm = _FakeAnthropicAdapter([turn_1])
        agent, _, memory = _make_native_agent(llm)
        # Simulate an opener-pack observation already written to memory.
        memory.add_message(
            Message(
                role="system",
                content="[Opener Observation — robots_txt] /admin disallowed",
            )
        )
        # Disable stateless so the pre-populated memory isn't wiped.
        agent.stateless = False

        asyncio.run(agent.arun("solve"))
        call_kwargs = llm.sync_client.messages.create.call_args[1]
        messages = call_kwargs["messages"]
        # First user message should now have opener context appended.
        assert "Pre-flight recon" in messages[0]["content"]
        assert "/admin disallowed" in messages[0]["content"]


# ---------------------------------------------------------------------------
# arun() branching
# ---------------------------------------------------------------------------


class TestArunBranching:
    def test_flag_off_uses_legacy_path_not_native(self):
        """enable_parallel_tools=False must never hit _arun_native_tools."""
        llm = _FakeAnthropicAdapter([])
        agent, _, _ = _make_native_agent(llm)
        agent._parallel_tools_enabled = False  # turn off
        # Ensure the native loop is never invoked by stubbing it to raise.
        agent._arun_native_tools = MagicMock(
            side_effect=AssertionError("native loop should not fire")
        )
        # JSON-ReAct path uses the planner; stub to FinalAnswer quickly.
        from fairlib.core.message import FinalAnswer

        agent.planner.aplan = MagicMock(
            return_value=_make_async_result(FinalAnswer(text="FLAG{legacy}"))
        )
        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{legacy}" in final
        agent._arun_native_tools.assert_not_called()

    def test_flag_on_unknown_provider_falls_back_with_warning(self):
        class _OllamaOrOther:
            pass

        # Ollama/unknown providers don't match either of the two native
        # paths, so the agent must log a warning and fall back to JSON-ReAct.
        _OllamaOrOther.__name__ = "OllamaAdapter"

        logs: List[str] = []
        agent, _, _ = _make_native_agent(_OllamaOrOther())
        agent._log_fn = logs.append
        agent._arun_native_tools = MagicMock(
            side_effect=AssertionError("anthropic loop should not fire")
        )
        agent._arun_native_tools_openai = MagicMock(
            side_effect=AssertionError("openai loop should not fire")
        )
        from fairlib.core.message import FinalAnswer

        agent.planner.aplan = MagicMock(
            return_value=_make_async_result(FinalAnswer(text="FLAG{fallback}"))
        )

        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{fallback}" in final
        agent._arun_native_tools.assert_not_called()
        agent._arun_native_tools_openai.assert_not_called()
        assert any("falling back" in m for m in logs)

    def test_flag_on_openai_routes_to_openai_native(self):
        """enable_parallel_tools=True + OpenAI adapter → OpenAI native loop."""

        class _OpenAIAdapterStub:
            model_name = "gpt-test"
            max_tokens = 4096

        _OpenAIAdapterStub.__name__ = "OpenAIAdapter"

        agent, _, _ = _make_native_agent(_OpenAIAdapterStub())
        agent._arun_native_tools = MagicMock(
            side_effect=AssertionError("anthropic loop should not fire")
        )
        agent._arun_native_tools_openai = MagicMock(
            return_value=_make_async_result("FLAG{openai_routed}")
        )

        final = asyncio.run(agent.arun("solve"))
        assert final == "FLAG{openai_routed}"
        agent._arun_native_tools_openai.assert_called_once_with("solve")
        agent._arun_native_tools.assert_not_called()


def _make_async_result(value):
    async def _coro():
        return value

    return _coro()


# ---------------------------------------------------------------------------
# OpenAI native loop — helpers + integration
# ---------------------------------------------------------------------------


class _FakeOpenAIAdapter:
    """Duck-types fairlib.OpenAIAdapter for the agent's _is_openai_llm check."""

    model_name = "gpt-test"
    max_tokens = 4096


_FakeOpenAIAdapter.__name__ = "OpenAIAdapter"


def _oa_tool_call(call_id: str, name: str, arguments: str):
    """Build a MagicMock that mirrors an OpenAI tool_call object."""
    tc = MagicMock()
    tc.id = call_id
    tc.function = MagicMock()
    tc.function.name = name
    tc.function.arguments = arguments
    return tc


def _oa_response(content=None, tool_calls=None):
    """Build a MagicMock mirroring openai chat.completions.create() response."""
    r = MagicMock()
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or None
    r.choices = [MagicMock()]
    r.choices[0].message = msg
    return r


def _make_openai_agent(
    responses,
    tools=None,
    observations=None,
    max_steps=3,
    system_prompt="You are a CTF agent.",
    flag_regex=r"FLAG\{[^}]+\}",
):
    """Build a native-OpenAI agent with a patched _openai_client()."""
    tools = tools or [
        _FakeTool("robots_txt", "Fetch robots.txt"),
        _FakeTool("path_enumerator", "Enumerate paths"),
        _FakeTool("http_fetch", "Fetch a URL"),
    ]
    executor = _FakeExecutor(observations=observations, tools=tools)
    memory = _FakeMemory()
    agent = CTFAgent(
        llm=_FakeOpenAIAdapter(),
        planner=MagicMock(),
        tool_executor=executor,
        memory=memory,
        max_steps=max_steps,
        flag_regex=flag_regex,
        log_callback=lambda msg: None,
        enable_parallel_tools=True,
        native_system_prompt=system_prompt,
    )
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = list(responses)
    agent._openai_client = MagicMock(return_value=mock_client)
    return agent, executor, memory, mock_client


class TestIsOpenAILLM:
    def test_recognizes_openai_adapter(self):
        agent, _, _ = _make_native_agent(_FakeOpenAIAdapter())
        assert agent._is_openai_llm() is True

    def test_rejects_anthropic(self):
        class _Foo:
            pass

        _Foo.__name__ = "AnthropicAdapter"
        agent, _, _ = _make_native_agent(_Foo())
        assert agent._is_openai_llm() is False


class TestBuildOpenAIToolSpecs:
    def test_openai_function_envelope_shape(self):
        tools = [_FakeTool("foo", "does foo"), _FakeTool("bar", "does bar")]
        agent, _, _, _ = _make_openai_agent([], tools=tools)
        specs = agent._build_openai_tool_specs()
        assert [s["type"] for s in specs] == ["function", "function"]
        assert [s["function"]["name"] for s in specs] == ["foo", "bar"]
        assert specs[0]["function"]["description"] == "does foo"
        props = specs[0]["function"]["parameters"]["properties"]
        assert "tool_input" in props
        assert specs[0]["function"]["parameters"]["required"] == ["tool_input"]


class TestExtractOpenAIToolInput:
    def test_tool_input_wrapped_string(self):
        agent, _, _, _ = _make_openai_agent([])
        assert (
            agent._extract_openai_tool_input('{"tool_input": "{\\"url\\":\\"x\\"}"}')
            == '{"url":"x"}'
        )

    def test_tool_input_structured_object_passthrough(self):
        agent, _, _, _ = _make_openai_agent([])
        # OpenAI sometimes emits its own structured args instead of the
        # wrapped schema — the tools still expect a JSON string.
        result = agent._extract_openai_tool_input('{"url": "http://x", "depth": 2}')
        import json as _json

        assert _json.loads(result) == {"url": "http://x", "depth": 2}

    def test_malformed_json_falls_back_to_raw(self):
        agent, _, _, _ = _make_openai_agent([])
        result = agent._extract_openai_tool_input("not-json")
        assert result == "not-json"

    def test_nested_tool_input_value_gets_json_encoded(self):
        agent, _, _, _ = _make_openai_agent([])
        # Arguments is already a dict (non-standard but possible), and the
        # inner tool_input value is itself a dict — that must be re-encoded
        # into a JSON string so the target tool's json.loads() works.
        result = agent._extract_openai_tool_input({"tool_input": {"url": "x"}})
        import json as _json

        assert _json.loads(result) == {"url": "x"}

    def test_bare_string_tool_input_passthrough(self):
        agent, _, _, _ = _make_openai_agent([])
        # If the caller already puts a JSON-string inside tool_input, pass
        # it through untouched — the tool expects that exact string.
        result = agent._extract_openai_tool_input('{"tool_input": "{\\"k\\":1}"}')
        assert result == '{"k":1}'


class TestArunNativeOpenAILoop:
    def test_multi_tool_batch_then_final_answer(self):
        turn_1 = _oa_response(
            content="batching",
            tool_calls=[
                _oa_tool_call("c1", "robots_txt", '{"tool_input": "{}"}'),
                _oa_tool_call("c2", "path_enumerator", '{"tool_input": "{}"}'),
                _oa_tool_call("c3", "http_fetch", '{"tool_input": "{}"}'),
            ],
        )
        turn_2 = _oa_response(content="The flag is FLAG{openai_win}")
        agent, executor, _, mock_client = _make_openai_agent([turn_1, turn_2])

        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{openai_win}" in final
        assert [c[0] for c in executor.calls] == [
            "robots_txt",
            "path_enumerator",
            "http_fetch",
        ]
        assert mock_client.chat.completions.create.call_count == 2

    def test_tool_result_messages_keyed_by_tool_call_id(self):
        turn_1 = _oa_response(
            content=None,
            tool_calls=[_oa_tool_call("abc123", "robots_txt", '{"tool_input": "{}"}')],
        )
        turn_2 = _oa_response(content="FLAG{ok}")
        agent, _, _, mock_client = _make_openai_agent(
            [turn_1, turn_2],
            observations={"robots_txt": "ROBOTS_OUTPUT"},
        )
        asyncio.run(agent.arun("solve"))

        # Inspect the second call's messages: must contain a tool-role
        # message with tool_call_id="abc123" and the executor's output.
        second_call_kwargs = mock_client.chat.completions.create.call_args_list[1][1]
        msgs = second_call_kwargs["messages"]
        tool_msgs = [m for m in msgs if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        assert tool_msgs[0]["tool_call_id"] == "abc123"
        assert tool_msgs[0]["content"] == "ROBOTS_OUTPUT"

    def test_premature_final_answer_guard(self):
        turn_1 = _oa_response(content="I give up")  # no flag
        turn_2 = _oa_response(content="Actually: FLAG{retried}")
        agent, _, _, mock_client = _make_openai_agent([turn_1, turn_2])

        final = asyncio.run(agent.arun("solve"))
        assert "FLAG{retried}" in final
        assert mock_client.chat.completions.create.call_count == 2
        assert agent._premature_fa_count == 1

    def test_max_steps_exhausts(self):
        # Every turn emits a tool call and never a final answer.
        def _tool_turn(n):
            return _oa_response(
                content=None,
                tool_calls=[
                    _oa_tool_call(f"tc{n}", "robots_txt", '{"tool_input": "{}"}')
                ],
            )

        agent, _, _, mock_client = _make_openai_agent(
            [_tool_turn(i) for i in range(10)], max_steps=2
        )
        final = asyncio.run(agent.arun("solve"))
        assert "max steps" in final
        assert mock_client.chat.completions.create.call_count == 2

    def test_system_prompt_included_as_first_message(self):
        turn_1 = _oa_response(content="FLAG{done}")
        agent, _, _, mock_client = _make_openai_agent(
            [turn_1], system_prompt="SYSTEM PROMPT"
        )
        asyncio.run(agent.arun("solve"))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "SYSTEM PROMPT"

    def test_parallel_tool_calls_param_sent(self):
        turn_1 = _oa_response(content="FLAG{done}")
        agent, _, _, mock_client = _make_openai_agent([turn_1])
        asyncio.run(agent.arun("solve"))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["parallel_tool_calls"] is True
        assert call_kwargs["tool_choice"] == "auto"

    def test_opener_observations_seeded_into_first_user_message(self):
        turn_1 = _oa_response(content="FLAG{done}")
        agent, _, memory, mock_client = _make_openai_agent([turn_1])
        memory.add_message(
            Message(
                role="system",
                content="[Opener Observation — robots_txt] /admin disallowed",
            )
        )
        agent.stateless = False

        asyncio.run(agent.arun("solve"))
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        # First message is system; second is the user message with opener context.
        user_msgs = [m for m in messages if m["role"] == "user"]
        assert "Pre-flight recon" in user_msgs[0]["content"]
        assert "/admin disallowed" in user_msgs[0]["content"]

    def test_api_error_returns_error_string(self):
        mock_responses = MagicMock()
        mock_responses.chat.completions.create.side_effect = RuntimeError("api down")
        agent, _, _, _ = _make_openai_agent([])
        agent._openai_client = MagicMock(return_value=mock_responses)
        logs: List[str] = []
        agent._log_fn = logs.append

        final = asyncio.run(agent.arun("solve"))
        assert "api down" in final
        assert any("API error" in m for m in logs)
