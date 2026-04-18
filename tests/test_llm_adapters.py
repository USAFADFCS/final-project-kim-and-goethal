"""
Tests for the multi-model LLM adapters.

Tests cover:
- LLMProvider enum
- ModelConfig dataclass
- AnthropicAdapter (mocked)
- OllamaAdapter (mocked)
- HybridAdapter
- Factory functions
- Config integration
"""

import json
import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from dataclasses import asdict

from fairlib import Message

from ctf_solver.llm import (
    LLMProvider,
    ModelConfig,
    DEFAULT_CONFIGS,
    AnthropicAdapter,
    OllamaAdapter,
    HybridAdapter,
    create_adapter,
    create_adapter_from_config,
    check_provider_available,
    ANTHROPIC_INSTALLED,
    OLLAMA_INSTALLED,
)
from ctf_solver.config import SolverConfig, LLMProviderType

# =============================================================================
# LLMProvider Enum Tests
# =============================================================================


class TestLLMProvider:
    """Tests for LLMProvider enum."""

    def test_provider_values(self):
        """Test all provider values are accessible."""
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.ANTHROPIC.value == "anthropic"
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.HYBRID.value == "hybrid"

    def test_provider_from_string(self):
        """Test creating provider from string."""
        assert LLMProvider("openai") == LLMProvider.OPENAI
        assert LLMProvider("anthropic") == LLMProvider.ANTHROPIC
        assert LLMProvider("ollama") == LLMProvider.OLLAMA
        assert LLMProvider("hybrid") == LLMProvider.HYBRID

    def test_invalid_provider(self):
        """Test invalid provider raises ValueError."""
        with pytest.raises(ValueError):
            LLMProvider("invalid")

    def test_provider_is_string(self):
        """Test provider enum is string subclass."""
        assert isinstance(LLMProvider.OPENAI, str)
        assert LLMProvider.OPENAI == "openai"


# =============================================================================
# ModelConfig Tests
# =============================================================================


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    def test_default_values(self):
        """Test ModelConfig with default values."""
        config = ModelConfig(
            provider=LLMProvider.OPENAI,
            model_name="gpt-4o",
        )
        assert config.provider == LLMProvider.OPENAI
        assert config.model_name == "gpt-4o"
        assert config.api_key is None
        assert config.base_url is None
        assert config.temperature == 0.7
        assert config.max_tokens == 4096
        assert config.timeout == 60.0

    def test_custom_values(self):
        """Test ModelConfig with custom values."""
        config = ModelConfig(
            provider=LLMProvider.ANTHROPIC,
            model_name="claude-sonnet-4-20250514",
            api_key="test-key",
            base_url="https://custom.api.com",
            temperature=0.5,
            max_tokens=8192,
            timeout=120.0,
        )
        assert config.provider == LLMProvider.ANTHROPIC
        assert config.model_name == "claude-sonnet-4-20250514"
        assert config.api_key == "test-key"
        assert config.base_url == "https://custom.api.com"
        assert config.temperature == 0.5
        assert config.max_tokens == 8192
        assert config.timeout == 120.0

    def test_default_configs_exist(self):
        """Test DEFAULT_CONFIGS contains expected providers."""
        assert LLMProvider.OPENAI in DEFAULT_CONFIGS
        assert LLMProvider.ANTHROPIC in DEFAULT_CONFIGS
        assert LLMProvider.OLLAMA in DEFAULT_CONFIGS

    def test_default_openai_config(self):
        """Test default OpenAI config."""
        config = DEFAULT_CONFIGS[LLMProvider.OPENAI]
        assert config.provider == LLMProvider.OPENAI
        assert config.model_name in ("gpt-4o", "gpt-5.2")

    def test_default_anthropic_config(self):
        """Test default Anthropic config."""
        config = DEFAULT_CONFIGS[LLMProvider.ANTHROPIC]
        assert config.provider == LLMProvider.ANTHROPIC
        assert "claude" in config.model_name.lower()

    def test_default_ollama_config(self):
        """Test default Ollama config."""
        config = DEFAULT_CONFIGS[LLMProvider.OLLAMA]
        assert config.provider == LLMProvider.OLLAMA
        assert config.base_url == "http://localhost:11434"


# =============================================================================
# AnthropicAdapter Tests (Mocked)
# =============================================================================


class TestAnthropicAdapter:
    """Tests for AnthropicAdapter."""

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_init_requires_api_key(self):
        """Test initialization requires API key."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="API key not found"):
                AnthropicAdapter()

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_init_with_api_key(self):
        """Test initialization with API key."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                assert adapter.model_name == "claude-sonnet-4-20250514"
                assert adapter.max_tokens == 4096

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_init_with_custom_model(self):
        """Test initialization with custom model."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(
                    api_key="test-key",
                    model_name="claude-opus-4-20250514",
                    max_tokens=8192,
                )
                assert adapter.model_name == "claude-opus-4-20250514"
                assert adapter.max_tokens == 8192

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_prepare_messages_system(self):
        """Test first system message becomes system parameter."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                messages = [
                    Message(role="system", content="You are helpful"),
                    Message(role="user", content="Hello"),
                ]
                system, prepared = adapter._prepare_messages(messages)
                assert system == "You are helpful"
                # Last message should be user (conversation ends with user)
                assert prepared[-1]["role"] == "user"
                assert prepared[0]["role"] == "user"
                assert prepared[0]["content"] == "Hello"

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_prepare_messages_inline_system(self):
        """Test subsequent system messages stay inline as user messages."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                messages = [
                    Message(role="system", content="System prompt"),
                    Message(role="user", content="Challenge description"),
                    Message(role="assistant", content="First response"),
                    Message(role="system", content="Observation: tool result"),
                ]
                system, prepared = adapter._prepare_messages(messages)
                # Only first system message becomes the system parameter
                assert system == "System prompt"
                # Observation stays inline as user message (not in system)
                assert prepared[0]["role"] == "user"
                assert prepared[0]["content"] == "Challenge description"
                assert prepared[1]["role"] == "assistant"
                assert prepared[1]["content"] == "First response"
                # Inline system → user
                assert prepared[2]["role"] == "user"
                assert "Observation: tool result" in prepared[2]["content"]
                # Last message should be user (continuation added)
                assert prepared[-1]["role"] == "user"

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_prepare_messages_tool(self):
        """Test message preparation with tool message."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                messages = [
                    Message(role="tool", content="Result", name="my_tool"),
                ]
                system, prepared = adapter._prepare_messages(messages)
                assert system is None
                # First is user (tool mapped to user)
                assert prepared[0]["role"] == "user"
                assert "[Tool Result (my_tool)]" in prepared[0]["content"]
                # Last message should be user
                assert prepared[-1]["role"] == "user"

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_get_model_capabilities(self):
        """Test model capabilities."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                caps = adapter.get_model_capabilities()
                assert caps["supports_streaming"] is True
                assert caps["supports_async"] is True
                assert caps["supports_tool_calling"] is True
                assert caps["provider"] == "anthropic"
                assert caps["max_context_window"] == 200000

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_invoke_success(self):
        """Test successful invoke."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.stop_reason = "end_turn"
        mock_block = Mock()
        mock_block.text = (
            '{"thought": "test", "action": {"tool_name": "t", "tool_input": "i"}}'
        )
        mock_block.type = "text"
        mock_response.content = [mock_block]
        mock_client.messages.create.return_value = mock_response

        with patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                result = adapter.invoke([Message(role="user", content="Hi")])

                assert result.role == "assistant"
                assert '"thought"' in result.content
                mock_client.messages.create.assert_called_once()

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_invoke_refusal_fallback(self):
        """Test that refusal produces valid JSON fallback."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.stop_reason = "refusal"
        mock_response.content = []  # No text blocks on refusal
        mock_client.messages.create.return_value = mock_response

        with patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                result = adapter.invoke([Message(role="user", content="Hi")])

                assert result.role == "assistant"
                import json

                parsed = json.loads(result.content)
                assert "thought" in parsed
                assert "action" in parsed

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_invoke_error(self):
        """Test invoke handles errors with JSON fallback."""
        mock_client = Mock()
        mock_client.messages.create.side_effect = Exception("API Error")

        with patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                result = adapter.invoke([Message(role="user", content="Hi")])

                assert result.role == "assistant"
                # Error handler now returns valid JSON with error context
                import json

                parsed = json.loads(result.content)
                assert "thought" in parsed
                assert "API error" in parsed["thought"]

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_invoke_sets_default_temperature(self):
        """Test that invoke sets temperature=0.2 by default."""
        mock_client = Mock()
        mock_response = Mock()
        mock_response.stop_reason = "end_turn"
        mock_block = Mock()
        mock_block.text = (
            '{"thought": "hi", "action": {"tool_name": "t", "tool_input": "i"}}'
        )
        mock_block.type = "text"
        mock_response.content = [mock_block]
        mock_client.messages.create.return_value = mock_response

        with patch("ctf_solver.llm.adapters.Anthropic", return_value=mock_client):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = AnthropicAdapter(api_key="test-key")
                adapter.invoke([Message(role="user", content="Hi")])
                call_kwargs = mock_client.messages.create.call_args[1]
                assert call_kwargs["temperature"] == 0.2

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_factory_defaults_anthropic(self):
        """Test create_adapter uses correct defaults for Anthropic."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = create_adapter(
                    provider=LLMProvider.ANTHROPIC,
                    api_key="test-key",
                )
                assert isinstance(adapter, AnthropicAdapter)
                assert adapter.max_tokens == 4096
                # timeout is stored on the sync_client, not easily checked
                # but we verify the factory doesn't override with 60.0


# =============================================================================
# OllamaAdapter Tests (Mocked)
# =============================================================================


class TestOllamaAdapter:
    """Tests for OllamaAdapter."""

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_init_defaults(self):
        """Test initialization with defaults."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = OllamaAdapter()
            assert adapter.model_name == "llama3.2"
            assert adapter.base_url == "http://localhost:11434"

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_init_custom(self):
        """Test initialization with custom values."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = OllamaAdapter(
                model_name="codellama",
                base_url="http://localhost:11435",
            )
            assert adapter.model_name == "codellama"
            assert adapter.base_url == "http://localhost:11435"

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_prepare_messages(self):
        """Test message preparation."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = OllamaAdapter()
            messages = [
                Message(role="system", content="You are helpful"),
                Message(role="user", content="Hello"),
                Message(role="assistant", content="Hi there"),
            ]
            prepared = adapter._prepare_messages(messages)
            assert len(prepared) == 3
            assert prepared[0]["role"] == "system"
            assert prepared[1]["role"] == "user"
            assert prepared[2]["role"] == "assistant"

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_prepare_messages_tool(self):
        """Test message preparation with tool message."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = OllamaAdapter()
            messages = [
                Message(role="tool", content="Result", name="search"),
            ]
            prepared = adapter._prepare_messages(messages)
            assert len(prepared) == 1
            assert prepared[0]["role"] == "user"
            assert "[Tool Result (search)]" in prepared[0]["content"]

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_get_model_capabilities(self):
        """Test model capabilities."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = OllamaAdapter()
            caps = adapter.get_model_capabilities()
            assert caps["supports_streaming"] is True
            assert caps["supports_async"] is True
            assert caps["supports_tool_calling"] is False
            assert caps["provider"] == "ollama"
            assert caps["local"] is True

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_invoke_success(self):
        """Test successful invoke."""
        mock_client = Mock()
        mock_client.chat.return_value = {"message": {"content": "Hello from Ollama!"}}

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter()
            result = adapter.invoke([Message(role="user", content="Hi")])

            assert result.role == "assistant"
            assert result.content == "Hello from Ollama!"

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_invoke_error(self):
        """Test invoke handles errors."""
        mock_client = Mock()
        mock_client.chat.side_effect = Exception("Connection Error")

        with patch("ctf_solver.llm.adapters.OllamaClient", return_value=mock_client):
            adapter = OllamaAdapter()
            result = adapter.invoke([Message(role="user", content="Hi")])

            assert result.role == "assistant"
            assert "Error:" in result.content


# =============================================================================
# HybridAdapter Tests
# =============================================================================


class TestHybridAdapter:
    """Tests for HybridAdapter."""

    def test_init_primary_only(self):
        """Test initialization with primary adapter only."""
        mock_primary = Mock()
        adapter = HybridAdapter(primary=mock_primary)

        assert adapter.primary == mock_primary
        assert adapter.fallback is None
        assert "primary" in adapter.adapters

    def test_init_with_fallback(self):
        """Test initialization with fallback."""
        mock_primary = Mock()
        mock_fallback = Mock()
        adapter = HybridAdapter(primary=mock_primary, fallback=mock_fallback)

        assert adapter.primary == mock_primary
        assert adapter.fallback == mock_fallback
        assert "primary" in adapter.adapters
        assert "fallback" in adapter.adapters

    def test_init_with_router(self):
        """Test initialization with router function."""
        mock_primary = Mock()
        mock_router = Mock(return_value="primary")
        adapter = HybridAdapter(primary=mock_primary, router=mock_router)

        assert adapter.router == mock_router

    def test_invoke_uses_primary(self):
        """Test invoke uses primary adapter by default."""
        mock_primary = Mock()
        mock_primary.invoke.return_value = Message(role="assistant", content="Primary")

        adapter = HybridAdapter(primary=mock_primary)
        result = adapter.invoke([Message(role="user", content="Hi")])

        assert result.content == "Primary"
        mock_primary.invoke.assert_called_once()

    def test_invoke_fallback_on_error(self):
        """Test invoke falls back on primary error."""
        mock_primary = Mock()
        mock_primary.invoke.side_effect = Exception("Primary failed")

        mock_fallback = Mock()
        mock_fallback.invoke.return_value = Message(
            role="assistant", content="Fallback"
        )

        adapter = HybridAdapter(primary=mock_primary, fallback=mock_fallback)
        result = adapter.invoke([Message(role="user", content="Hi")])

        assert result.content == "Fallback"
        mock_primary.invoke.assert_called_once()
        mock_fallback.invoke.assert_called_once()

    def test_invoke_no_fallback_raises(self):
        """Test invoke raises when no fallback available."""
        mock_primary = Mock()
        mock_primary.invoke.side_effect = Exception("Primary failed")

        adapter = HybridAdapter(primary=mock_primary)
        with pytest.raises(Exception, match="Primary failed"):
            adapter.invoke([Message(role="user", content="Hi")])

    def test_invoke_with_router(self):
        """Test invoke uses router for adapter selection."""
        mock_primary = Mock()
        mock_secondary = Mock()
        mock_secondary.invoke.return_value = Message(
            role="assistant", content="Secondary"
        )

        mock_router = Mock(return_value="secondary")

        adapter = HybridAdapter(
            primary=mock_primary,
            router=mock_router,
            adapters={"primary": mock_primary, "secondary": mock_secondary},
        )
        result = adapter.invoke([Message(role="user", content="Hi")])

        assert result.content == "Secondary"
        mock_router.assert_called_once()
        mock_secondary.invoke.assert_called_once()
        mock_primary.invoke.assert_not_called()

    def test_get_model_capabilities(self):
        """Test model capabilities include hybrid info."""
        mock_primary = Mock()
        mock_primary.get_model_capabilities.return_value = {
            "supports_streaming": True,
            "provider": "openai",
        }

        adapter = HybridAdapter(primary=mock_primary)
        caps = adapter.get_model_capabilities()

        assert caps["supports_streaming"] is True
        assert caps["hybrid"] is True
        assert caps["has_fallback"] is False
        assert caps["adapter_count"] == 1

    def test_get_model_capabilities_with_fallback(self):
        """Test capabilities show fallback status."""
        mock_primary = Mock()
        mock_primary.get_model_capabilities.return_value = {}
        mock_fallback = Mock()

        adapter = HybridAdapter(primary=mock_primary, fallback=mock_fallback)
        caps = adapter.get_model_capabilities()

        assert caps["hybrid"] is True
        assert caps["has_fallback"] is True
        assert caps["adapter_count"] == 2


# =============================================================================
# Async Tests
# =============================================================================


class TestAsyncOperations:
    """Tests for async operations."""

    def test_hybrid_ainvoke(self):
        """Test HybridAdapter ainvoke."""
        import asyncio

        mock_primary = Mock()
        mock_primary.ainvoke = AsyncMock(
            return_value=Message(role="assistant", content="Async Primary")
        )

        adapter = HybridAdapter(primary=mock_primary)

        async def run_test():
            return await adapter.ainvoke([Message(role="user", content="Hi")])

        result = asyncio.run(run_test())
        assert result.content == "Async Primary"

    def test_hybrid_ainvoke_fallback(self):
        """Test HybridAdapter ainvoke with fallback."""
        import asyncio

        mock_primary = Mock()
        mock_primary.ainvoke = AsyncMock(side_effect=Exception("Async error"))

        mock_fallback = Mock()
        mock_fallback.ainvoke = AsyncMock(
            return_value=Message(role="assistant", content="Async Fallback")
        )

        adapter = HybridAdapter(primary=mock_primary, fallback=mock_fallback)

        async def run_test():
            return await adapter.ainvoke([Message(role="user", content="Hi")])

        result = asyncio.run(run_test())
        assert result.content == "Async Fallback"


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateAdapter:
    """Tests for create_adapter factory function."""

    def test_create_openai_adapter(self):
        """Test creating OpenAI adapter."""
        adapter = create_adapter(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
        )
        # OpenAIAdapter is from fairlib, just verify it was created
        assert adapter is not None
        assert hasattr(adapter, "invoke")

    def test_create_openai_adapter_returns_ctf_subclass(self):
        """Factory must return the CTFOpenAIAdapter subclass that forces JSON."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        adapter = create_adapter(provider=LLMProvider.OPENAI, api_key="test-key")
        assert isinstance(adapter, CTFOpenAIAdapter)
        assert adapter.force_json_output is True

    def test_ctf_openai_adapter_injects_response_format(self):
        """``invoke`` must pass response_format=json_object to the underlying client."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        # Construct with a mocked client so we can inspect the create() call.
        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = '{"thought": "ok"}'
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
            adapter.invoke([Message(role="user", content="hi")])

            call_kwargs = mock_client.chat.completions.create.call_args[1]
            assert call_kwargs["response_format"] == {"type": "json_object"}

    def test_ctf_openai_adapter_respects_caller_override(self):
        """If the caller passes response_format, don't overwrite it."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "text"
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
            adapter.invoke(
                [Message(role="user", content="hi")],
                response_format={"type": "text"},
            )

            call_kwargs = mock_client.chat.completions.create.call_args[1]
            assert call_kwargs["response_format"] == {"type": "text"}

    def test_ctf_openai_adapter_detects_moderation_error_invoke(self):
        """fairlib surfaces 400 invalid_prompt as a stringified error Message.
        The CTF subclass must detect this and return a synthetic valid-JSON
        pivot response so the agent's format-error counter is not bumped."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = (
                "Error: Error code: 400 - {'error': {'message': "
                "'Invalid prompt: your prompt was flagged as potentially "
                "violating our usage policy', 'code': 'invalid_prompt'}}"
            )
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
            result = adapter.invoke([Message(role="user", content="hi")])

            # Result must be valid JSON with the moderation pivot shape.
            payload = json.loads(result.content)
            assert payload["action"]["tool_name"] == "__moderation_blocked__"
            assert "MODERATION" in payload["thought"]

    def test_ctf_openai_adapter_detects_moderation_error_ainvoke(self):
        """Same as above but via async ainvoke."""
        import asyncio
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        async def _run():
            with (
                patch("fairlib.modules.mal.openai_adapter.OpenAI"),
                patch(
                    "fairlib.modules.mal.openai_adapter.AsyncOpenAI"
                ) as mock_async_ctor,
            ):
                mock_client = MagicMock()
                mock_response = MagicMock()
                mock_response.choices[0].message.content = (
                    "Error: Error code: 400 - invalid_prompt usage policy"
                )
                mock_response.choices[0].message.tool_calls = None

                async def _async_create(*a, **kw):
                    return mock_response

                mock_client.chat.completions.create = _async_create
                mock_async_ctor.return_value = mock_client

                adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
                return await adapter.ainvoke([Message(role="user", content="hi")])

        result = asyncio.run(_run())
        payload = json.loads(result.content)
        assert payload["action"]["tool_name"] == "__moderation_blocked__"

    def test_ctf_openai_adapter_generic_error_passes_through(self):
        """A non-moderation error ("Error: timeout") must NOT be rewritten."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "Error: network timeout"
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
            result = adapter.invoke([Message(role="user", content="hi")])

            # Untouched — no moderation rewrite.
            assert result.content == "Error: network timeout"
            assert "__moderation_blocked__" not in result.content

    def test_ctf_openai_adapter_normal_response_passes_through(self):
        """Happy-path JSON response must not be mistaken for moderation."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = (
                '{"thought": "ok", "action": {"tool_name": "http_fetch"}}'
            )
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(api_key="test-key", model_name="gpt-4o-mini")
            result = adapter.invoke([Message(role="user", content="hi")])

            # Must not be rewritten.
            payload = json.loads(result.content)
            assert payload["action"]["tool_name"] == "http_fetch"

    def test_ctf_openai_adapter_opt_out_disables_forcing(self):
        """force_json_output=False preserves fairlib's default behavior."""
        from ctf_solver.llm.adapters import CTFOpenAIAdapter

        with (
            patch("fairlib.modules.mal.openai_adapter.OpenAI") as mock_sync_ctor,
            patch("fairlib.modules.mal.openai_adapter.AsyncOpenAI"),
        ):
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.choices[0].message.content = "text"
            mock_response.choices[0].message.tool_calls = None
            mock_client.chat.completions.create.return_value = mock_response
            mock_sync_ctor.return_value = mock_client

            adapter = CTFOpenAIAdapter(
                api_key="test-key",
                model_name="gpt-4o-mini",
                force_json_output=False,
            )
            adapter.invoke([Message(role="user", content="hi")])

            call_kwargs = mock_client.chat.completions.create.call_args[1]
            assert "response_format" not in call_kwargs

    def test_create_adapter_string_provider(self):
        """Test creating adapter with string provider."""
        adapter = create_adapter(
            provider="openai",
            api_key="test-key",
        )
        assert adapter is not None

    def test_create_adapter_invalid_provider(self):
        """Test invalid provider raises error."""
        with pytest.raises(ValueError, match="Unknown provider"):
            create_adapter(provider="invalid")

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_create_anthropic_adapter(self):
        """Test creating Anthropic adapter."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = create_adapter(
                    provider=LLMProvider.ANTHROPIC,
                    api_key="test-key",
                )
                assert isinstance(adapter, AnthropicAdapter)

    @pytest.mark.skipif(not OLLAMA_INSTALLED, reason="ollama not installed")
    def test_create_ollama_adapter(self):
        """Test creating Ollama adapter."""
        with patch("ctf_solver.llm.adapters.OllamaClient"):
            adapter = create_adapter(
                provider=LLMProvider.OLLAMA,
                model_name="llama3",
            )
            assert isinstance(adapter, OllamaAdapter)

    def test_create_hybrid_adapter(self):
        """Test creating Hybrid adapter."""
        adapter = create_adapter(
            provider=LLMProvider.HYBRID,
            api_key="test-key",
            primary_provider=LLMProvider.OPENAI,
        )
        assert isinstance(adapter, HybridAdapter)

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_create_hybrid_with_fallback(self):
        """Test creating Hybrid adapter with fallback."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                adapter = create_adapter(
                    provider=LLMProvider.HYBRID,
                    api_key="openai-key",
                    primary_provider=LLMProvider.OPENAI,
                    fallback_provider=LLMProvider.ANTHROPIC,
                    fallback_api_key="anthropic-key",
                )
                assert isinstance(adapter, HybridAdapter)
                assert adapter.fallback is not None


# =============================================================================
# Check Provider Available Tests
# =============================================================================


class TestCheckProviderAvailable:
    """Tests for check_provider_available function."""

    def test_check_openai(self):
        """Test checking OpenAI availability."""
        available, msg = check_provider_available(LLMProvider.OPENAI)
        # OpenAI should be available (it's a dependency)
        assert "OpenAI" in msg

    def test_check_anthropic(self):
        """Test checking Anthropic availability."""
        available, msg = check_provider_available(LLMProvider.ANTHROPIC)
        if ANTHROPIC_INSTALLED:
            assert available is True
            assert "available" in msg.lower()
        else:
            assert available is False
            assert "not installed" in msg.lower()

    def test_check_ollama(self):
        """Test checking Ollama availability."""
        available, msg = check_provider_available(LLMProvider.OLLAMA)
        if OLLAMA_INSTALLED:
            assert available is True
            assert "available" in msg.lower()
        else:
            assert available is False
            assert "not installed" in msg.lower()

    def test_check_hybrid(self):
        """Test checking Hybrid availability."""
        available, msg = check_provider_available(LLMProvider.HYBRID)
        assert available is True
        assert "available" in msg.lower()

    def test_check_string_provider(self):
        """Test checking with string provider."""
        available, msg = check_provider_available("openai")
        assert "OpenAI" in msg

    def test_check_invalid_provider(self):
        """Test checking invalid provider."""
        available, msg = check_provider_available("invalid")
        assert available is False
        assert "Unknown provider" in msg


# =============================================================================
# Config Integration Tests
# =============================================================================


class TestConfigIntegration:
    """Tests for config integration."""

    def test_solver_config_default_provider(self):
        """Test SolverConfig has default provider."""
        config = SolverConfig(openai_api_key="test-key")
        assert config.llm_provider == LLMProviderType.OPENAI

    def test_solver_config_string_provider(self):
        """Test SolverConfig normalizes string provider."""
        config = SolverConfig(
            openai_api_key="test-key",
            llm_provider="anthropic",
        )
        assert config.llm_provider == LLMProviderType.ANTHROPIC

    def test_solver_config_anthropic_key(self):
        """Test SolverConfig has anthropic_api_key field."""
        config = SolverConfig(
            openai_api_key="openai-key",
            anthropic_api_key="anthropic-key",
        )
        assert config.anthropic_api_key == "anthropic-key"

    def test_solver_config_llm_base_url(self):
        """Test SolverConfig has llm_base_url field."""
        config = SolverConfig(
            openai_api_key="test-key",
            llm_base_url="http://localhost:11434",
        )
        assert config.llm_base_url == "http://localhost:11434"

    def test_solver_config_merge_with_args(self):
        """Test merge_with_args includes new fields."""
        config = SolverConfig(openai_api_key="test-key")
        merged = config.merge_with_args(
            llm_provider=LLMProviderType.ANTHROPIC,
            anthropic_api_key="new-key",
        )
        assert merged.llm_provider == LLMProviderType.ANTHROPIC
        assert merged.anthropic_api_key == "new-key"

    def test_create_adapter_from_config_openai(self):
        """Test creating adapter from config with OpenAI."""
        config = SolverConfig(
            openai_api_key="test-key",
            llm_provider=LLMProviderType.OPENAI,
        )
        adapter = create_adapter_from_config(config)
        assert adapter is not None
        assert hasattr(adapter, "invoke")

    @pytest.mark.skipif(not ANTHROPIC_INSTALLED, reason="anthropic not installed")
    def test_create_adapter_from_config_anthropic(self):
        """Test creating adapter from config with Anthropic."""
        with patch("ctf_solver.llm.adapters.Anthropic"):
            with patch("ctf_solver.llm.adapters.AsyncAnthropic"):
                config = SolverConfig(
                    openai_api_key="openai-key",
                    anthropic_api_key="anthropic-key",
                    llm_provider=LLMProviderType.ANTHROPIC,
                )
                adapter = create_adapter_from_config(config)
                assert isinstance(adapter, AnthropicAdapter)


# =============================================================================
# LLMProviderType Enum Tests
# =============================================================================


class TestLLMProviderType:
    """Tests for LLMProviderType config enum."""

    def test_provider_type_values(self):
        """Test all provider type values."""
        assert LLMProviderType.OPENAI.value == "openai"
        assert LLMProviderType.ANTHROPIC.value == "anthropic"
        assert LLMProviderType.OLLAMA.value == "ollama"
        assert LLMProviderType.HYBRID.value == "hybrid"

    def test_provider_type_from_string(self):
        """Test creating provider type from string."""
        assert LLMProviderType("openai") == LLMProviderType.OPENAI
        assert LLMProviderType("anthropic") == LLMProviderType.ANTHROPIC

    def test_provider_type_is_string(self):
        """Test provider type is string subclass."""
        assert isinstance(LLMProviderType.OPENAI, str)
