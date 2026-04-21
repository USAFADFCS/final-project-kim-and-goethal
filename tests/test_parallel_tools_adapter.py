"""Stage 2a tests for native parallel tool use on the LLM adapters.

These cover the adapter layer only — the agent loop is not yet wired to
use this path. Goal is to lock in the result shape so Stage 2b (loop
integration) has a stable contract to build against.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest
from fairlib import Message

from ctf_solver.config import SolverConfig
from ctf_solver.llm.adapters import (
    ANTHROPIC_INSTALLED,
    AnthropicAdapter,
    openai_invoke_with_tools,
)

# ---------------------------------------------------------------------------
# SolverConfig.enable_parallel_tools flag
# ---------------------------------------------------------------------------


class TestParallelToolsConfigFlag:
    def test_default_off(self):
        config = SolverConfig()
        assert config.enable_parallel_tools is False

    def test_opt_in(self):
        config = SolverConfig(enable_parallel_tools=True)
        assert config.enable_parallel_tools is True


# ---------------------------------------------------------------------------
# Anthropic prompt-cache wrapper
# ---------------------------------------------------------------------------


class TestAnthropicCacheControl:
    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_cache_enabled_wraps_system_as_block_list(self):
        with (
            patch("ctf_solver.llm.adapters.Anthropic"),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key", enable_prompt_cache=True)
            wrapped = adapter._cached_system("hello system")
            assert isinstance(wrapped, list)
            assert wrapped[0]["type"] == "text"
            assert wrapped[0]["text"] == "hello system"
            assert wrapped[0]["cache_control"] == {"type": "ephemeral"}

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_cache_disabled_returns_plain_string(self):
        with (
            patch("ctf_solver.llm.adapters.Anthropic"),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key", enable_prompt_cache=False)
            assert adapter._cached_system("hello system") == "hello system"


# ---------------------------------------------------------------------------
# AnthropicAdapter.invoke_with_tools
# ---------------------------------------------------------------------------


def _make_anthropic_block(type_name: str, **fields):
    block = Mock()
    block.type = type_name
    for k, v in fields.items():
        setattr(block, k, v)
    return block


class TestAnthropicInvokeWithTools:
    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_single_tool_call_returns_structured_dict(self):
        mock_client = Mock()
        response = Mock()
        response.stop_reason = "tool_use"
        response.content = [
            _make_anthropic_block(
                "tool_use",
                id="call_1",
                name="robots_txt",
                input={"base_url": "http://example.com"},
            )
        ]
        mock_client.messages.create.return_value = response

        with (
            patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key")
            result = adapter.invoke_with_tools(
                messages=[Message(role="user", content="go")],
                tools=[{"name": "robots_txt", "description": "fetch robots"}],
            )

        assert result["text"] == ""
        assert result["stop_reason"] == "tool_use"
        assert len(result["tool_calls"]) == 1
        call = result["tool_calls"][0]
        assert call["id"] == "call_1"
        assert call["name"] == "robots_txt"
        assert call["input"] == {"base_url": "http://example.com"}

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_multiple_tool_calls_returned_in_order(self):
        """The whole point of Stage 2a — multiple tool_use blocks in one response."""
        mock_client = Mock()
        response = Mock()
        response.stop_reason = "tool_use"
        response.content = [
            _make_anthropic_block("text", text="let me batch these"),
            _make_anthropic_block(
                "tool_use", id="c1", name="robots_txt", input={"base_url": "http://x"}
            ),
            _make_anthropic_block(
                "tool_use",
                id="c2",
                name="path_enumerator",
                input={"url": "http://x", "wordlist": "common"},
            ),
            _make_anthropic_block(
                "tool_use",
                id="c3",
                name="http_fetch",
                input={"url": "http://x/"},
            ),
        ]
        mock_client.messages.create.return_value = response

        with (
            patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key")
            result = adapter.invoke_with_tools(
                messages=[Message(role="user", content="recon")],
                tools=[
                    {"name": "robots_txt", "description": "x"},
                    {"name": "path_enumerator", "description": "y"},
                    {"name": "http_fetch", "description": "z"},
                ],
            )

        assert result["text"] == "let me batch these"
        assert [c["name"] for c in result["tool_calls"]] == [
            "robots_txt",
            "path_enumerator",
            "http_fetch",
        ]

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_text_only_response_has_empty_tool_calls(self):
        mock_client = Mock()
        response = Mock()
        response.stop_reason = "end_turn"
        response.content = [_make_anthropic_block("text", text="I found the flag.")]
        mock_client.messages.create.return_value = response

        with (
            patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key")
            result = adapter.invoke_with_tools(
                messages=[Message(role="user", content="summarize")],
                tools=[{"name": "x", "description": "y"}],
            )

        assert result["text"] == "I found the flag."
        assert result["tool_calls"] == []
        assert result["stop_reason"] == "end_turn"

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_forwards_tool_choice_kwarg(self):
        mock_client = Mock()
        response = Mock()
        response.stop_reason = "end_turn"
        response.content = [_make_anthropic_block("text", text="")]
        mock_client.messages.create.return_value = response

        with (
            patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key")
            adapter.invoke_with_tools(
                messages=[Message(role="user", content="go")],
                tools=[{"name": "x", "description": "y"}],
                tool_choice={"type": "auto", "disable_parallel_tool_use": True},
            )
        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs["tool_choice"] == {
            "type": "auto",
            "disable_parallel_tool_use": True,
        }

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_applies_cache_control_when_system_present(self):
        mock_client = Mock()
        response = Mock()
        response.stop_reason = "end_turn"
        response.content = [_make_anthropic_block("text", text="")]
        mock_client.messages.create.return_value = response

        with (
            patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client),
            patch("ctf_solver.llm.adapters.AsyncAnthropic"),
        ):
            adapter = AnthropicAdapter(api_key="test-key", enable_prompt_cache=True)
            adapter.invoke_with_tools(
                messages=[
                    Message(role="system", content="sys prompt"),
                    Message(role="user", content="go"),
                ],
                tools=[{"name": "x", "description": "y"}],
            )
        call_kwargs = mock_client.messages.create.call_args[1]
        system = call_kwargs["system"]
        assert isinstance(system, list)
        assert system[0]["cache_control"] == {"type": "ephemeral"}


# ---------------------------------------------------------------------------
# openai_invoke_with_tools
# ---------------------------------------------------------------------------


class TestOpenAIInvokeWithTools:
    def test_single_tool_call_shape(self):
        mock_response = MagicMock()
        mock_tc = MagicMock()
        mock_tc.id = "call_1"
        mock_tc.function.name = "robots_txt"
        mock_tc.function.arguments = '{"base_url": "http://example.com"}'
        mock_response.choices[0].message.tool_calls = [mock_tc]
        mock_response.choices[0].message.content = None
        mock_response.choices[0].finish_reason = "tool_calls"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            result = openai_invoke_with_tools(
                messages=[Message(role="user", content="go")],
                tools=[{"type": "function", "function": {"name": "robots_txt"}}],
                model_name="gpt-4o-mini",
                api_key="test-key",
            )

        assert result["text"] == ""
        assert result["stop_reason"] == "tool_calls"
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["name"] == "robots_txt"
        assert result["tool_calls"][0]["input"] == {"base_url": "http://example.com"}

    def test_multiple_tool_calls_preserve_order(self):
        mock_response = MagicMock()

        def _mk_tc(tc_id, name, args):
            tc = MagicMock()
            tc.id = tc_id
            tc.function.name = name
            tc.function.arguments = args
            return tc

        mock_response.choices[0].message.tool_calls = [
            _mk_tc("a", "robots_txt", '{"base_url": "http://x"}'),
            _mk_tc("b", "path_enumerator", '{"url": "http://x"}'),
        ]
        mock_response.choices[0].message.content = "batching"
        mock_response.choices[0].finish_reason = "tool_calls"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            result = openai_invoke_with_tools(
                messages=[Message(role="user", content="recon")],
                tools=[
                    {"type": "function", "function": {"name": "robots_txt"}},
                    {"type": "function", "function": {"name": "path_enumerator"}},
                ],
                model_name="gpt-4o-mini",
                api_key="test-key",
            )

        assert result["text"] == "batching"
        assert [c["name"] for c in result["tool_calls"]] == [
            "robots_txt",
            "path_enumerator",
        ]

    def test_parallel_tool_calls_kwarg_forwarded(self):
        mock_response = MagicMock()
        mock_response.choices[0].message.tool_calls = []
        mock_response.choices[0].message.content = "text only"
        mock_response.choices[0].finish_reason = "stop"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            openai_invoke_with_tools(
                messages=[Message(role="user", content="go")],
                tools=[{"type": "function", "function": {"name": "x"}}],
                model_name="gpt-4o-mini",
                api_key="test-key",
                parallel_tool_calls=False,
            )
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["parallel_tool_calls"] is False
        assert call_kwargs["tool_choice"] == "auto"

    def test_malformed_arguments_fall_back_to_tool_input_wrapper(self):
        mock_response = MagicMock()
        mock_tc = MagicMock()
        mock_tc.id = "call_x"
        mock_tc.function.name = "legacy_tool"
        mock_tc.function.arguments = "not-json-at-all"
        mock_response.choices[0].message.tool_calls = [mock_tc]
        mock_response.choices[0].message.content = None
        mock_response.choices[0].finish_reason = "tool_calls"

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            result = openai_invoke_with_tools(
                messages=[Message(role="user", content="go")],
                tools=[{"type": "function", "function": {"name": "legacy_tool"}}],
                model_name="gpt-4o-mini",
                api_key="test-key",
            )

        assert result["tool_calls"][0]["input"] == {"tool_input": "not-json-at-all"}
