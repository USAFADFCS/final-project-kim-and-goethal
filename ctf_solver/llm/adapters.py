"""
Multi-model LLM adapters for CTF Solver.

Provides adapters for different LLM providers that implement the fairlib
AbstractChatModel interface, enabling seamless switching between providers.

Supported providers:
- OpenAI (via fairlib OpenAIAdapter)
- Anthropic (Claude models)
- Ollama (local models)
- Hybrid (multi-model routing)
"""

import json
import logging
import os
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Union,
)

from fairlib import AbstractChatModel, Message, OpenAIAdapter

logger = logging.getLogger(__name__)

# Check for optional dependencies
try:
    import anthropic
    from anthropic import Anthropic, AsyncAnthropic

    ANTHROPIC_INSTALLED = True
except ImportError:
    ANTHROPIC_INSTALLED = False
    anthropic = None  # type: ignore

try:
    import ollama
    from ollama import Client as OllamaClient

    OLLAMA_INSTALLED = True
except ImportError:
    OLLAMA_INSTALLED = False
    ollama = None  # type: ignore


def _is_transient_error(error: Exception) -> bool:
    """Check if an error is transient and worth retrying."""
    # Anthropic transient errors
    if ANTHROPIC_INSTALLED:
        if isinstance(error, anthropic.RateLimitError):
            return True
        if isinstance(error, anthropic.APIConnectionError):
            return True
        if isinstance(error, anthropic.APITimeoutError):
            return True
        if isinstance(error, anthropic.InternalServerError):
            return True
        # Auth and bad request errors should NOT be retried
        if isinstance(error, anthropic.AuthenticationError):
            return False
        if isinstance(error, anthropic.BadRequestError):
            return False

    # Ollama transient errors (connection refused, timeout)
    if isinstance(error, (ConnectionError, TimeoutError, OSError)):
        return True

    # httpx errors (used by both anthropic and ollama under the hood)
    error_name = type(error).__name__
    if error_name in ("ConnectError", "ReadTimeout", "ConnectTimeout"):
        return True

    return False


def _retry_with_backoff(
    fn: Callable[[], Any],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Any:
    """
    Retry a callable with exponential backoff on transient errors.

    Args:
        fn: Zero-argument callable to execute.
        max_retries: Maximum number of retry attempts.
        base_delay: Base delay in seconds (doubles each retry).

    Returns:
        The return value of fn() on success.

    Raises:
        The original exception if it is not transient or retries are exhausted.
    """
    last_error: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as e:
            last_error = e
            if not _is_transient_error(e):
                raise
            if attempt == max_retries:
                raise
            delay = base_delay * (2**attempt) + random.uniform(0, 0.5)
            logger.warning(
                "Transient error (attempt %d/%d), retrying in %.1fs: %s",
                attempt + 1,
                max_retries + 1,
                delay,
                e,
            )
            time.sleep(delay)

    # Should never reach here, but satisfy type checker
    raise last_error  # type: ignore[misc]


async def _async_retry_with_backoff(
    fn: Callable[[], Any],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Any:
    """
    Async version of _retry_with_backoff.

    Args:
        fn: Zero-argument async callable to execute.
        max_retries: Maximum number of retry attempts.
        base_delay: Base delay in seconds (doubles each retry).

    Returns:
        The return value of await fn() on success.

    Raises:
        The original exception if it is not transient or retries are exhausted.
    """
    import asyncio

    last_error: Optional[Exception] = None
    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except Exception as e:
            last_error = e
            if not _is_transient_error(e):
                raise
            if attempt == max_retries:
                raise
            delay = base_delay * (2**attempt) + random.uniform(0, 0.5)
            logger.warning(
                "Transient error (attempt %d/%d), retrying in %.1fs: %s",
                attempt + 1,
                max_retries + 1,
                delay,
                e,
            )
            await asyncio.sleep(delay)

    # Should never reach here, but satisfy type checker
    raise last_error  # type: ignore[misc]


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    HYBRID = "hybrid"


@dataclass
class ModelConfig:
    """Configuration for an LLM model.

    Attributes:
        provider: The LLM provider
        model_name: The model identifier
        api_key: API key (optional for local models)
        base_url: Base URL for API (optional, for custom endpoints)
        temperature: Default temperature for generation
        max_tokens: Maximum tokens to generate
        timeout: Request timeout in seconds
    """

    provider: LLMProvider
    model_name: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: float = 60.0


# Default model configurations
DEFAULT_CONFIGS: Dict[LLMProvider, ModelConfig] = {
    LLMProvider.OPENAI: ModelConfig(
        provider=LLMProvider.OPENAI,
        model_name="gpt-5.2",
        #   gpt-5.2
        #   gpt-4o
    ),
    LLMProvider.ANTHROPIC: ModelConfig(
        provider=LLMProvider.ANTHROPIC,
        model_name="claude-sonnet-4-20250514",
    ),
    LLMProvider.OLLAMA: ModelConfig(
        provider=LLMProvider.OLLAMA,
        model_name="llama3.2",
        base_url="http://localhost:11434",
    ),
}


# JSON schema for the ReAct response format.
# Used with output_config to guarantee valid JSON from Claude.
_REACT_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "action": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "tool_input": {"type": "string"},
            },
            "required": ["tool_name", "tool_input"],
            "additionalProperties": False,
        },
    },
    "required": ["thought", "action"],
    "additionalProperties": False,
}


class AnthropicAdapter(AbstractChatModel):
    """
    An adapter for interacting with Anthropic's Claude models.

    Implements the AbstractChatModel interface for Claude API compatibility.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout: float = 120.0,
    ):
        """
        Initialize the Anthropic adapter.

        Args:
            api_key: Anthropic API key. If not provided, reads from
                     ANTHROPIC_API_KEY environment variable.
            model_name: The Claude model to use.
            max_tokens: Maximum tokens to generate.
            timeout: Request timeout in seconds.

        Raises:
            ImportError: If the anthropic library is not installed.
            ValueError: If no API key is provided.
        """
        if not ANTHROPIC_INSTALLED:
            raise ImportError(
                "The 'anthropic' library is not installed. "
                "Please install it with `pip install anthropic` to use this adapter."
            )

        resolved_api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not resolved_api_key:
            raise ValueError(
                "Anthropic API key not found. Please provide it directly or "
                "set the ANTHROPIC_API_KEY environment variable."
            )

        self.sync_client = Anthropic(api_key=resolved_api_key, timeout=timeout)
        self.async_client = AsyncAnthropic(api_key=resolved_api_key, timeout=timeout)
        self.model_name = model_name
        self.max_tokens = max_tokens

    def _prepare_messages(
        self, messages: List[Message]
    ) -> tuple[Optional[str], List[Dict[str, Any]]]:
        """
        Convert fairlib Messages to Anthropic format.

        Anthropic requires system messages to be separate from the messages list.

        Returns:
            Tuple of (system_prompt, messages_list)
        """
        system_prompt = None
        anthropic_messages: List[Dict[str, Any]] = []

        # Only the FIRST system message becomes the Anthropic `system`
        # parameter (the static prompt).  All later system messages
        # (tool observations, progress checks) stay inline as "user"
        # messages so the conversation flow is preserved.
        first_system_seen = False

        for msg in messages:
            if msg.role == "system":
                if not first_system_seen:
                    # First system message → Anthropic system parameter
                    if system_prompt:
                        system_prompt += "\n\n" + (msg.content or "")
                    else:
                        system_prompt = msg.content
                    first_system_seen = True
                else:
                    # Subsequent system messages → user role (inline)
                    role = "user"
                    content = msg.content or ""
                    if anthropic_messages and anthropic_messages[-1]["role"] == role:
                        anthropic_messages[-1]["content"] += "\n\n" + content
                    else:
                        anthropic_messages.append({"role": role, "content": content})
            else:
                role = "assistant" if msg.role == "assistant" else "user"

                if msg.role == "tool":
                    role = "user"
                    content = f"[Tool Result ({msg.name})]: {msg.content}"
                else:
                    content = msg.content or ""

                # Merge consecutive messages with the same role (Claude
                # rejects adjacent messages from the same role).
                if anthropic_messages and anthropic_messages[-1]["role"] == role:
                    anthropic_messages[-1]["content"] += "\n\n" + content
                else:
                    anthropic_messages.append({"role": role, "content": content})

        # Claude requires the conversation to end with a user message.
        if anthropic_messages and anthropic_messages[-1]["role"] != "user":
            anthropic_messages.append(
                {
                    "role": "user",
                    "content": "Continue solving the challenge. "
                    'Respond with ONLY a JSON object with "thought" and "action" keys.',
                }
            )

        # Claude requires at least one user message.
        if not anthropic_messages:
            anthropic_messages.append(
                {"role": "user", "content": "Begin solving the challenge."}
            )

        return system_prompt, anthropic_messages

    def _parse_tool_calls(self, response) -> Optional[List[Dict[str, Any]]]:
        """Extract tool calls from Anthropic response if present."""
        tool_calls = []
        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(
                    {
                        "id": block.id,
                        "type": "function",
                        "function": {
                            "name": block.name,
                            "arguments": block.input,
                        },
                    }
                )
        return tool_calls if tool_calls else None

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Synchronously invoke the Claude model."""
        system_prompt, anthropic_messages = self._prepare_messages(messages)

        try:
            create_kwargs = {
                "model": self.model_name,
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": anthropic_messages,
            }

            if system_prompt:
                create_kwargs["system"] = system_prompt

            # Default to low temperature for consistent JSON output
            create_kwargs["temperature"] = kwargs.get("temperature", 0.2)

            # Force JSON output matching the ReAct schema.
            # This guarantees every response is valid JSON — no more
            # format errors or wasted steps on __format_error__.
            create_kwargs["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": _REACT_SCHEMA,
                }
            }

            # Add tools if provided
            if "tools" in kwargs:
                create_kwargs["tools"] = kwargs["tools"]

            response = _retry_with_backoff(
                lambda: self.sync_client.messages.create(**create_kwargs)
            )

            # Log non-normal stop reasons visibly
            if response.stop_reason not in ("end_turn",):
                print(f"[Anthropic] WARNING: stop_reason={response.stop_reason}")

            # Extract text content from response blocks
            content = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text

            # If content is empty or not JSON (refusal/truncation), create
            # a valid JSON fallback so the parser doesn't trigger format errors
            if not content.strip() or not content.strip().startswith("{"):
                content = json.dumps(
                    {
                        "thought": f"[stop_reason={response.stop_reason}] "
                        "The previous attempt had an issue. "
                        "Let me try a different approach.",
                        "action": {
                            "tool_name": "attack_planner",
                            "tool_input": "Suggest alternative approaches "
                            "for this challenge.",
                        },
                    }
                )

            return Message(
                role="assistant",
                content=content,
                tool_calls=self._parse_tool_calls(response),
            )

        except Exception as e:
            print(f"[Anthropic] API error (invoke): {e}")
            logger.error(f"Anthropic API error (invoke): {e}")
            content = json.dumps(
                {
                    "thought": f"[API error] {e}. Let me try again.",
                    "action": {
                        "tool_name": "attack_planner",
                        "tool_input": "Suggest a fresh approach.",
                    },
                }
            )
            return Message(role="assistant", content=content)

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Asynchronously invoke the Claude model."""
        system_prompt, anthropic_messages = self._prepare_messages(messages)

        try:
            create_kwargs = {
                "model": self.model_name,
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": anthropic_messages,
            }

            if system_prompt:
                create_kwargs["system"] = system_prompt

            # Default to low temperature for consistent JSON output
            create_kwargs["temperature"] = kwargs.get("temperature", 0.2)

            # Force JSON output matching the ReAct schema.
            create_kwargs["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": _REACT_SCHEMA,
                }
            }

            if "tools" in kwargs:
                create_kwargs["tools"] = kwargs["tools"]

            response = await _async_retry_with_backoff(
                lambda: self.async_client.messages.create(**create_kwargs)
            )

            # Log non-normal stop reasons visibly
            if response.stop_reason not in ("end_turn",):
                print(f"[Anthropic] WARNING: stop_reason={response.stop_reason}")

            # Extract text content from response blocks
            content = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text

            # If content is empty or not JSON (refusal/truncation), create
            # a valid JSON fallback so the parser doesn't trigger format errors
            if not content.strip() or not content.strip().startswith("{"):
                content = json.dumps(
                    {
                        "thought": f"[stop_reason={response.stop_reason}] "
                        "The previous attempt had an issue. "
                        "Let me try a different approach.",
                        "action": {
                            "tool_name": "attack_planner",
                            "tool_input": "Suggest alternative approaches "
                            "for this challenge.",
                        },
                    }
                )

            return Message(
                role="assistant",
                content=content,
                tool_calls=self._parse_tool_calls(response),
            )

        except Exception as e:
            print(f"[Anthropic] API error (ainvoke): {e}")
            logger.error(f"Anthropic API error (ainvoke): {e}")
            content = json.dumps(
                {
                    "thought": f"[API error] {e}. Let me try again.",
                    "action": {
                        "tool_name": "attack_planner",
                        "tool_input": "Suggest a fresh approach.",
                    },
                }
            )
            return Message(role="assistant", content=content)

    def stream(
        self, messages: List[Message], **kwargs: Any
    ) -> Generator[Message, None, None]:
        """Stream responses from the Claude model."""
        system_prompt, anthropic_messages = self._prepare_messages(messages)

        try:
            create_kwargs = {
                "model": self.model_name,
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": anthropic_messages,
            }

            if system_prompt:
                create_kwargs["system"] = system_prompt

            if "temperature" in kwargs:
                create_kwargs["temperature"] = kwargs["temperature"]

            with self.sync_client.messages.stream(**create_kwargs) as stream:
                for text in stream.text_stream:
                    yield Message(role="assistant", content=text)

        except Exception as e:
            logger.error(f"Anthropic API error (stream): {e}")
            yield Message(role="assistant", content=f"Error: {e}")

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncGenerator[Message, None]:
        """Asynchronously stream responses from the Claude model."""
        system_prompt, anthropic_messages = self._prepare_messages(messages)

        try:
            create_kwargs = {
                "model": self.model_name,
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "messages": anthropic_messages,
            }

            if system_prompt:
                create_kwargs["system"] = system_prompt

            if "temperature" in kwargs:
                create_kwargs["temperature"] = kwargs["temperature"]

            async with self.async_client.messages.stream(**create_kwargs) as stream:
                async for text in stream.text_stream:
                    yield Message(role="assistant", content=text)

        except Exception as e:
            logger.error(f"Anthropic API error (astream): {e}")
            yield Message(role="assistant", content=f"Error: {e}")

    def get_model_capabilities(self) -> Dict[str, Any]:
        """Return Claude model capabilities."""
        return {
            "supports_streaming": True,
            "supports_async": True,
            "supports_tool_calling": True,
            "max_context_window": 200000,  # Claude 3+ context window
            "provider": "anthropic",
            "model": self.model_name,
        }


class OllamaAdapter(AbstractChatModel):
    """
    An adapter for interacting with local Ollama models.

    Implements the AbstractChatModel interface for Ollama compatibility.
    """

    def __init__(
        self,
        model_name: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
    ):
        """
        Initialize the Ollama adapter.

        Args:
            model_name: The Ollama model to use.
            base_url: Ollama server URL.
            timeout: Request timeout in seconds.

        Raises:
            ImportError: If the ollama library is not installed.
        """
        if not OLLAMA_INSTALLED:
            raise ImportError(
                "The 'ollama' library is not installed. "
                "Please install it with `pip install ollama` to use this adapter."
            )

        self.client = OllamaClient(host=base_url, timeout=timeout)
        self.model_name = model_name
        self.base_url = base_url

    def _prepare_messages(self, messages: List[Message]) -> List[Dict[str, str]]:
        """Convert fairlib Messages to Ollama format."""
        ollama_messages = []

        for msg in messages:
            role = msg.role
            content = msg.content or ""

            # Handle tool messages
            if role == "tool":
                role = "user"
                content = f"[Tool Result ({msg.name})]: {content}"

            ollama_messages.append({"role": role, "content": content})

        return ollama_messages

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Synchronously invoke the Ollama model."""
        ollama_messages = self._prepare_messages(messages)

        try:
            response = _retry_with_backoff(
                lambda: self.client.chat(
                    model=self.model_name,
                    messages=ollama_messages,
                    options={
                        "temperature": kwargs.get("temperature", 0.7),
                    },
                )
            )

            return Message(
                role="assistant",
                content=response["message"]["content"],
            )

        except Exception as e:
            logger.error(f"Ollama error (invoke): {e}")
            return Message(role="assistant", content=f"Error: {e}")

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """
        Asynchronously invoke the Ollama model.

        Note: Ollama Python library doesn't have native async support,
        so this wraps the sync call.
        """
        import asyncio

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.invoke(messages, **kwargs))

    def stream(
        self, messages: List[Message], **kwargs: Any
    ) -> Generator[Message, None, None]:
        """Stream responses from the Ollama model."""
        ollama_messages = self._prepare_messages(messages)

        try:
            stream = self.client.chat(
                model=self.model_name,
                messages=ollama_messages,
                stream=True,
                options={
                    "temperature": kwargs.get("temperature", 0.7),
                },
            )

            for chunk in stream:
                content = chunk.get("message", {}).get("content", "")
                if content:
                    yield Message(role="assistant", content=content)

        except Exception as e:
            logger.error(f"Ollama error (stream): {e}")
            yield Message(role="assistant", content=f"Error: {e}")

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncGenerator[Message, None]:
        """
        Asynchronously stream responses from the Ollama model.

        Note: Wraps sync streaming since ollama library lacks async support.
        """
        import asyncio

        loop = asyncio.get_event_loop()
        gen = self.stream(messages, **kwargs)

        for msg in gen:
            yield msg
            await asyncio.sleep(0)  # Allow other tasks to run

    def get_model_capabilities(self) -> Dict[str, Any]:
        """Return Ollama model capabilities."""
        return {
            "supports_streaming": True,
            "supports_async": True,  # Via wrapper
            "supports_tool_calling": False,  # Most Ollama models don't support this
            "max_context_window": 8192,  # Varies by model
            "provider": "ollama",
            "model": self.model_name,
            "local": True,
        }


class HybridAdapter(AbstractChatModel):
    """
    A hybrid adapter that can route between multiple LLM providers.

    Supports routing based on:
    - Task type (e.g., reasoning vs quick responses)
    - Fallback on errors
    - Cost optimization
    """

    def __init__(
        self,
        primary: AbstractChatModel,
        fallback: Optional[AbstractChatModel] = None,
        router: Optional[Callable[[List[Message]], str]] = None,
        adapters: Optional[Dict[str, AbstractChatModel]] = None,
    ):
        """
        Initialize the hybrid adapter.

        Args:
            primary: The primary/default adapter to use.
            fallback: Optional fallback adapter on errors.
            router: Optional function to route messages to a specific adapter.
                    Should return an adapter key from the adapters dict.
            adapters: Optional dict of named adapters for routing.
        """
        self.primary = primary
        self.fallback = fallback
        self.router = router
        self.adapters = adapters or {}

        # Add primary to adapters if not already present
        if "primary" not in self.adapters:
            self.adapters["primary"] = primary
        if fallback and "fallback" not in self.adapters:
            self.adapters["fallback"] = fallback

    def _get_adapter(self, messages: List[Message]) -> AbstractChatModel:
        """Determine which adapter to use based on the router."""
        if self.router:
            try:
                adapter_key = self.router(messages)
                if adapter_key in self.adapters:
                    return self.adapters[adapter_key]
            except Exception as e:
                logger.warning(f"Router error, using primary: {e}")

        return self.primary

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Invoke with fallback support."""
        adapter = self._get_adapter(messages)

        try:
            return adapter.invoke(messages, **kwargs)
        except Exception as e:
            logger.warning(f"Primary adapter error: {e}")
            if self.fallback:
                logger.info("Falling back to secondary adapter")
                return self.fallback.invoke(messages, **kwargs)
            raise

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Async invoke with fallback support."""
        adapter = self._get_adapter(messages)

        try:
            return await adapter.ainvoke(messages, **kwargs)
        except Exception as e:
            logger.warning(f"Primary adapter error: {e}")
            if self.fallback:
                logger.info("Falling back to secondary adapter")
                return await self.fallback.ainvoke(messages, **kwargs)
            raise

    def stream(
        self, messages: List[Message], **kwargs: Any
    ) -> Generator[Message, None, None]:
        """Stream with fallback support."""
        adapter = self._get_adapter(messages)

        try:
            yield from adapter.stream(messages, **kwargs)
        except Exception as e:
            logger.warning(f"Primary adapter error: {e}")
            if self.fallback:
                logger.info("Falling back to secondary adapter")
                yield from self.fallback.stream(messages, **kwargs)
            else:
                raise

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncGenerator[Message, None]:
        """Async stream with fallback support."""
        adapter = self._get_adapter(messages)

        try:
            async for msg in adapter.astream(messages, **kwargs):
                yield msg
        except Exception as e:
            logger.warning(f"Primary adapter error: {e}")
            if self.fallback:
                logger.info("Falling back to secondary adapter")
                async for msg in self.fallback.astream(messages, **kwargs):
                    yield msg
            else:
                raise

    def get_model_capabilities(self) -> Dict[str, Any]:
        """Return combined capabilities."""
        primary_caps = self.primary.get_model_capabilities()
        return {
            **primary_caps,
            "hybrid": True,
            "has_fallback": self.fallback is not None,
            "adapter_count": len(self.adapters),
        }


def create_adapter(
    provider: Union[str, LLMProvider] = LLMProvider.OPENAI,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> AbstractChatModel:
    """
    Factory function to create an LLM adapter.

    Args:
        provider: The LLM provider to use.
        model_name: Model name (uses provider default if not specified).
        api_key: API key for the provider.
        base_url: Base URL for the API (for custom endpoints or Ollama).
        **kwargs: Additional provider-specific options.

    Returns:
        An AbstractChatModel adapter instance.

    Raises:
        ValueError: If the provider is not supported.
        ImportError: If required dependencies are not installed.
    """
    if isinstance(provider, str):
        try:
            provider = LLMProvider(provider.lower())
        except ValueError:
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Supported: {[p.value for p in LLMProvider]}"
            )

    if provider == LLMProvider.OPENAI:
        return OpenAIAdapter(
            api_key=api_key,
            model_name=model_name or DEFAULT_CONFIGS[LLMProvider.OPENAI].model_name,
        )

    elif provider == LLMProvider.ANTHROPIC:
        return AnthropicAdapter(
            api_key=api_key,
            model_name=model_name or DEFAULT_CONFIGS[LLMProvider.ANTHROPIC].model_name,
            max_tokens=kwargs.get("max_tokens", 4096),
            timeout=kwargs.get("timeout", 120.0),
        )

    elif provider == LLMProvider.OLLAMA:
        return OllamaAdapter(
            model_name=model_name or DEFAULT_CONFIGS[LLMProvider.OLLAMA].model_name,
            base_url=base_url or DEFAULT_CONFIGS[LLMProvider.OLLAMA].base_url,
            timeout=kwargs.get("timeout", 120.0),
        )

    elif provider == LLMProvider.HYBRID:
        # For hybrid, we need primary and optionally fallback configurations
        primary_provider = kwargs.get("primary_provider", LLMProvider.OPENAI)
        fallback_provider = kwargs.get("fallback_provider")

        primary = create_adapter(
            provider=primary_provider,
            model_name=kwargs.get("primary_model"),
            api_key=kwargs.get("primary_api_key") or api_key,
        )

        fallback = None
        if fallback_provider:
            fallback = create_adapter(
                provider=fallback_provider,
                model_name=kwargs.get("fallback_model"),
                api_key=kwargs.get("fallback_api_key"),
            )

        return HybridAdapter(
            primary=primary,
            fallback=fallback,
            router=kwargs.get("router"),
            adapters=kwargs.get("adapters"),
        )

    else:
        raise ValueError(f"Unsupported provider: {provider}")


def create_adapter_from_config(config: "SolverConfig") -> AbstractChatModel:
    """
    Create an LLM adapter from a SolverConfig.

    Args:
        config: The solver configuration.

    Returns:
        An AbstractChatModel adapter instance.
    """
    # Import here to avoid circular imports

    provider = getattr(config, "llm_provider", LLMProvider.OPENAI)
    model_name = config.model_name

    # Determine which API key to use based on provider
    if provider == LLMProvider.OPENAI:
        api_key = config.openai_api_key
    elif provider == LLMProvider.ANTHROPIC:
        api_key = getattr(config, "anthropic_api_key", None) or os.getenv(
            "ANTHROPIC_API_KEY"
        )
    else:
        api_key = None

    return create_adapter(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        base_url=getattr(config, "llm_base_url", None),
        max_tokens=getattr(config, "max_tokens", 2048),
        timeout=getattr(config, "llm_timeout", 120.0),
    )


def check_provider_available(provider: Union[str, LLMProvider]) -> tuple[bool, str]:
    """
    Check if a provider's dependencies are available.

    Args:
        provider: The provider to check.

    Returns:
        Tuple of (is_available, message).
    """
    if isinstance(provider, str):
        try:
            provider = LLMProvider(provider.lower())
        except ValueError:
            return False, f"Unknown provider: {provider}"

    if provider == LLMProvider.OPENAI:
        try:
            import openai

            return True, "OpenAI is available"
        except ImportError:
            return False, "OpenAI package not installed. Run: pip install openai"

    elif provider == LLMProvider.ANTHROPIC:
        if ANTHROPIC_INSTALLED:
            return True, "Anthropic is available"
        return False, "Anthropic package not installed. Run: pip install anthropic"

    elif provider == LLMProvider.OLLAMA:
        if OLLAMA_INSTALLED:
            return True, "Ollama is available"
        return False, "Ollama package not installed. Run: pip install ollama"

    elif provider == LLMProvider.HYBRID:
        return True, "Hybrid adapter is always available"

    return False, f"Unknown provider: {provider}"
