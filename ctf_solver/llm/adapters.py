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
    Tuple,
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
    MLX = "mlx"
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
    LLMProvider.MLX: ModelConfig(
        provider=LLMProvider.MLX,
        model_name="mlx-community/gemma-4-26b-a4b-it-4bit",
    ),
}


# JSON schema for the ReAct response format.
# Used with output_config to guarantee valid JSON from Claude (Anthropic),
# OpenAI strict structured output, and MLX via Outlines. ``maxLength``
# bounds are load-bearing for the MLX path: ``outlines-core`` compiles
# unbounded-string JSON schema to a greedy regex that never forces the
# closing quote, so Gemma4's rambling ``thought`` can truncate mid-string
# at ``max_tokens`` → unterminated JSON → format-recovery cascades. The
# bounds are safe for hosted models too — their outputs never approach
# these limits in practice (GPT/Claude thoughts average ~600 chars).
_REACT_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string", "maxLength": 2000},
        "action": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "maxLength": 64},
                "tool_input": {"type": "string", "maxLength": 8000},
            },
            "required": ["tool_name", "tool_input"],
            "additionalProperties": False,
        },
    },
    "required": ["thought", "action"],
    "additionalProperties": False,
}


# v3.9 N.1: per-tool ``tool_input`` discrimination via ``oneOf``.
#
# When the agent has access to ``parameters_schema`` for each tool, we can
# replace the single ``{tool_name: string, tool_input: string}`` action
# shape with a discriminated union — one branch per tool, where each
# branch's ``tool_input`` shape is the tool's actual ``parameters_schema``.
# Outlines' FSM masks ``tool_input`` keys based on which ``tool_name`` the
# model committed to, making malformed-args structurally impossible.
#
# The dispatch path accepts ``tool_input`` as either a string (legacy /
# fallback branches) or a dict (constrained branches) — see
# ``agent.py``'s tool-call dispatch.


def _sanitize_for_outlines(schema: Any) -> Optional[Dict[str, Any]]:
    """Return a schema Outlines can compile, or None if it can't be salvaged.

    Outlines requires every property to have a ``type``, ``oneOf``,
    ``anyOf``, ``enum``, ``const``, or ``$ref``. A property like
    ``{"description": "..."}`` (no type) raises ``Unsupported JSON
    Schema structure``.

    Strategy: walk the schema; for any property dict that lacks one of
    the required discriminators, drop it from ``properties`` (and from
    ``required`` if present). If the resulting schema has no properties
    left, return None so the caller falls back to the string-tool_input
    branch.
    """
    if not isinstance(schema, dict):
        return None

    import copy

    out = copy.deepcopy(schema)

    def _has_discriminator(d: Dict[str, Any]) -> bool:
        return any(
            k in d for k in ("type", "oneOf", "anyOf", "allOf", "enum", "const", "$ref")
        )

    def _walk(node: Dict[str, Any]) -> None:
        # Recurse into nested object-typed schemas.
        if "properties" in node and isinstance(node["properties"], dict):
            bad_keys: List[str] = []
            for prop_name, prop_schema in list(node["properties"].items()):
                if not isinstance(prop_schema, dict):
                    bad_keys.append(prop_name)
                    continue
                if not _has_discriminator(prop_schema):
                    bad_keys.append(prop_name)
                    continue
                # Recurse — the property may itself be an object schema.
                _walk(prop_schema)
            for k in bad_keys:
                node["properties"].pop(k, None)
                if isinstance(node.get("required"), list) and k in node["required"]:
                    node["required"].remove(k)
        # Recurse into branches of unions.
        for key in ("oneOf", "anyOf", "allOf"):
            if key in node and isinstance(node[key], list):
                for branch in node[key]:
                    if isinstance(branch, dict):
                        _walk(branch)
        # Recurse into items of arrays.
        if "items" in node and isinstance(node["items"], dict):
            _walk(node["items"])

    _walk(out)
    # If the outer schema has nothing Outlines can compile against —
    # no ``type``, no union keys, no enum/const — return None so the
    # caller falls back to string-tool_input. An empty ``properties: {}``
    # on a typed object schema is fine (Outlines treats it as a
    # permissive object).
    if not _has_discriminator(out):
        return None
    return out


def build_react_schema(
    tool_descriptors: Optional[
        List[Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]]
    ] = None,
    *,
    mode: str = "enum",
) -> Dict[str, Any]:
    """Build a ReAct grammar schema constrained to the registered tools.

    ``tool_descriptors`` is the list returned by
    ``ctf_solver.tools.schema.collect_tool_descriptors``: tuples of
    ``(name, description, parameters_schema, samples)``. When None or
    empty, returns the legacy ``_REACT_SCHEMA`` (backwards compatible).

    Two modes:

    * ``mode="enum"`` (default, **production-safe**): emit a single
      action shape with ``tool_name: {enum: [<all registered names>]}``
      and a permissive string ``tool_input``. The FSM locks tool_name
      to the dispatcher's known set (the v3.4 win that stopped
      hallucinations like ``'deeply recon'``) and keeps the regex small
      enough that ``outlines-core`` can build the DFA in seconds.
      Per-tool argument validation still happens in Python via
      ``parse_json_input`` and each tool's runtime ``parameters_schema``
      check, just not at decode time.

    * ``mode="oneof"`` (research / experimental): emit a discriminated
      union with one branch per tool, each branch keyed on
      ``tool_name: {const: name}`` and constraining ``tool_input`` to
      that tool's ``parameters_schema``. **DO NOT use with > ~10
      tools**: ``outlines-core`` expands the union into a regex whose
      DFA exceeds the ``i32::MAX`` state limit (verified at 76 tools:
      ``ValueError: Failed to build DFA — number of DFA states exceeds
      limit``). Kept for future two-phase generation work where
      ``tool_input`` is constrained on a *second* invoke against a
      single-branch schema.

    Returns a deep-copied standalone schema — the caller can pass it
    straight to Outlines / Ollama ``format=`` / etc.
    """
    if not tool_descriptors:
        import copy

        return copy.deepcopy(_REACT_SCHEMA)

    if mode == "oneof":
        return _build_per_tool_oneof_schema(tool_descriptors)
    if mode == "enum":
        return _build_flat_enum_schema(tool_descriptors)
    raise ValueError(
        f"build_react_schema: unknown mode={mode!r}; expected 'enum' or 'oneof'"
    )


def _build_flat_enum_schema(
    tool_descriptors: List[
        Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]
    ],
) -> Dict[str, Any]:
    """Production schema: ``tool_name`` is locked to the registered
    enum; ``tool_input`` stays a JSON-encoded string. Compiles in
    seconds against any reasonable vocab; never overflows.

    ``maxLength`` bounds are kept tight so the resulting DFA stays
    small. ``thought=1500`` covers Gemma 4's typical 600-char thought
    plus headroom; ``tool_input=2000`` covers every tool except a
    few payload-generator outputs (which the model can split across
    turns). On Gemma 4's ~256k-token vocab the 8000-char maxLength
    that worked for hosted models was the dominant FSM-build cost
    (multi-minute first invoke + tens of GB RAM); 2000 cuts that to
    sub-minute on M-series Macs.
    """
    names = [name for name, _, _, _ in tool_descriptors]
    return {
        "type": "object",
        "properties": {
            "thought": {"type": "string", "maxLength": 1500},
            "action": {
                "type": "object",
                "properties": {
                    "tool_name": {"type": "string", "enum": names},
                    "tool_input": {"type": "string", "maxLength": 2000},
                },
                "required": ["tool_name", "tool_input"],
                "additionalProperties": False,
            },
        },
        "required": ["thought", "action"],
        "additionalProperties": False,
    }


def _build_per_tool_oneof_schema(
    tool_descriptors: List[
        Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]
    ],
) -> Dict[str, Any]:
    """Experimental ``oneOf`` per-tool union. **Triggers DFA-state
    overflow at scale** — see ``build_react_schema`` docstring. Useful
    only when the registered tool surface is small (< ~10 tools) or
    when constraining ``tool_input`` on a single-branch schema during
    a future two-phase generation pass.
    """
    branches: List[Dict[str, Any]] = []
    for name, _desc, schema, _samples in tool_descriptors:
        sanitized = _sanitize_for_outlines(schema) if schema is not None else None
        if sanitized is None:
            branches.append(
                {
                    "type": "object",
                    "properties": {
                        "tool_name": {"const": name, "type": "string"},
                        "tool_input": {"type": "string", "maxLength": 8000},
                    },
                    "required": ["tool_name", "tool_input"],
                    "additionalProperties": False,
                }
            )
        else:
            branches.append(
                {
                    "type": "object",
                    "properties": {
                        "tool_name": {"const": name, "type": "string"},
                        "tool_input": sanitized,
                    },
                    "required": ["tool_name", "tool_input"],
                    "additionalProperties": False,
                }
            )

    return {
        "type": "object",
        "properties": {
            "thought": {"type": "string", "maxLength": 2000},
            "action": {"oneOf": branches},
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
        enable_prompt_cache: bool = True,
    ):
        """
        Initialize the Anthropic adapter.

        Args:
            api_key: Anthropic API key. If not provided, reads from
                     ANTHROPIC_API_KEY environment variable.
            model_name: The Claude model to use.
            max_tokens: Maximum tokens to generate.
            timeout: Request timeout in seconds.
            enable_prompt_cache: If True, mark the system prompt with
                ``cache_control: ephemeral``.  Costs 1.25x base input on the
                first turn (cache write) and 0.1x on every subsequent turn
                (cache read) within the 5-minute TTL.  Silently no-ops below
                each model's min cacheable length (1024 for Sonnet, 4096 for
                Opus/Haiku 4.5).

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
        self.enable_prompt_cache = enable_prompt_cache

    def _cached_system(self, system_prompt: str) -> Any:
        """Wrap the system prompt for Anthropic prompt caching when enabled.

        Returns a block list with ``cache_control: ephemeral`` on the text
        block so the full prefix (tools + system) is cached; falls back to a
        plain string when caching is disabled.
        """
        if not self.enable_prompt_cache:
            return system_prompt
        return [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ]

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

    def invoke_with_tools(
        self,
        messages: List[Message],
        tools: List[Dict[str, Any]],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Invoke Claude with native ``tools`` (not forced JSON schema).

        Returns a dict of the form::

            {
                "text": str,                        # any assistant free text
                "tool_calls": List[{"id","name","input"}],
                "stop_reason": str,
            }

        When ``tool_calls`` is non-empty, Claude emitted one or more
        ``tool_use`` blocks in a single response — the caller can execute
        them concurrently and feed each result back as a ``tool_result``
        block in the next user turn.  Parallel tool use is enabled by
        default; pass ``tool_choice={"type":"auto","disable_parallel_tool_use":True}``
        to force sequential.

        This path is deliberately *not* used by the default ReAct loop yet
        (Stage 2a — adapter-only).  It is covered by its own tests and will
        be wired to the agent when parallel execution lands.
        """
        system_prompt, anthropic_messages = self._prepare_messages(messages)

        create_kwargs: Dict[str, Any] = {
            "model": self.model_name,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "messages": anthropic_messages,
            "tools": tools,
            "temperature": kwargs.get("temperature", 0.2),
        }
        if system_prompt:
            create_kwargs["system"] = self._cached_system(system_prompt)
        if "tool_choice" in kwargs:
            create_kwargs["tool_choice"] = kwargs["tool_choice"]

        response = _retry_with_backoff(
            lambda: self.sync_client.messages.create(**create_kwargs)
        )

        text_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        for block in response.content:
            btype = getattr(block, "type", None)
            if btype == "text" and hasattr(block, "text"):
                text_parts.append(block.text)
            elif btype == "tool_use":
                tool_calls.append(
                    {
                        "id": getattr(block, "id", ""),
                        "name": getattr(block, "name", ""),
                        "input": getattr(block, "input", {}) or {},
                    }
                )

        return {
            "text": "".join(text_parts),
            "tool_calls": tool_calls,
            "stop_reason": getattr(response, "stop_reason", ""),
        }

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
                create_kwargs["system"] = self._cached_system(system_prompt)

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
                create_kwargs["system"] = self._cached_system(system_prompt)

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
                create_kwargs["system"] = self._cached_system(system_prompt)

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
                create_kwargs["system"] = self._cached_system(system_prompt)

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


class CTFOpenAIAdapter(OpenAIAdapter):
    """OpenAIAdapter subclass that forces JSON output on the legacy ReAct path.

    fairlib's ``OpenAIAdapter.invoke`` passes ``**kwargs`` straight through
    to ``client.chat.completions.create``, but the planner never sends any,
    so the API returns free-form text.  When the planner monkey-patch at
    ``agent._patch_planner_parsing`` can't find JSON, it treats the whole
    response as a FinalAnswer and the run terminates prematurely — on
    OpenAI specifically this has been observed to add ~5-10% token
    overhead from format-retry loops.

    Forcing ``response_format={"type": "json_object"}`` on every ``invoke``
    and ``ainvoke`` call gets the same guarantee the Anthropic path already
    has via its ``output_config.json_schema``.  The caller can still
    override by passing their own ``response_format`` kwarg (e.g. if a
    future use case wants raw text).  Streaming paths skip the injection
    because JSON mode and streaming don't mix well and the agent doesn't
    stream anyway.

    Does not affect the native parallel-tools path
    (``openai_invoke_with_tools``) — that uses real ``tools`` and wouldn't
    benefit from response_format forcing.
    """

    def __init__(self, *args: Any, force_json_output: bool = True, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.force_json_output = force_json_output

    def _maybe_force_json(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        if self.force_json_output and "response_format" not in kwargs:
            kwargs = dict(kwargs)
            kwargs["response_format"] = {"type": "json_object"}
        return kwargs

    @staticmethod
    def _is_moderation_error(content: str) -> bool:
        """Heuristically detect fairlib's string-ified OpenAI 400 moderation
        error. fairlib catches the API exception with a bare ``except`` and
        returns ``Message(content="Error: Error code: 400 - {...}")`` — we
        match against the canonical OpenAI error code and the human-readable
        message text.

        OpenAI's documented moderation rejection (verified 2026-05) returns::

            {"error": {"type": "invalid_request_error",
                       "code": "content_policy_violation",
                       "message": "Your request was rejected ... flagged as
                                   potentially violating our usage policy ..."}}

        We match on:
        - ``content_policy_violation`` — canonical OpenAI error ``code``
        - ``flagged as potentially violating`` — substring of the human-
          readable ``message`` (long-stable phrasing)
        - ``content_filter`` — Azure OpenAI variant of the error code; also
          the ``finish_reason`` value on output-side filtering when it
          surfaces through fairlib's string path.
        - ``moderation_blocked`` — image-API variant; harmless for chat
          paths but included for safety as the surface broadens.
        """
        if not content:
            return False
        lower = content.lower()
        return (
            "content_policy_violation" in lower
            or "flagged as potentially violating" in lower
            or "content_filter" in lower
            or "moderation_blocked" in lower
        )

    @staticmethod
    def _moderation_pivot_message() -> Message:
        """Synthetic valid-JSON response the ReAct parser will accept without
        incrementing the consecutive-format-error counter. The Thought text
        carries the pivot instruction the model will see on its next turn."""
        payload = {
            "thought": (
                "MODERATION: my previous payload was blocked by the API "
                "content filter. I must rephrase without pasting literal "
                "exploit strings — options: base64-encode webshell bodies, "
                "split payloads across tool calls, describe the attack "
                "shape rather than emitting the raw content, or pivot to "
                "a different attack vector entirely."
            ),
            "action": {
                "tool_name": "__moderation_blocked__",
                "tool_input": (
                    "The previous model response was rejected by the "
                    "OpenAI content filter. Do not retry the same payload "
                    "verbatim — rephrase or pivot."
                ),
            },
        }
        return Message(role="assistant", content=json.dumps(payload))

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        result = super().invoke(messages, **self._maybe_force_json(kwargs))
        if self._is_moderation_error(result.content):
            logger.warning(
                "[MODERATION] OpenAI content filter rejected prompt; "
                "injecting pivot continuation."
            )
            return self._moderation_pivot_message()
        return result

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        result = await super().ainvoke(messages, **self._maybe_force_json(kwargs))
        if self._is_moderation_error(result.content):
            logger.warning(
                "[MODERATION] OpenAI content filter rejected prompt; "
                "injecting pivot continuation."
            )
            return self._moderation_pivot_message()
        return result


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
        num_ctx: int = 16384,
        thinking_callback: Optional[Callable[[str], None]] = None,
        grammar_schema: Optional[Dict[str, Any]] = None,
        enable_thinking: bool = False,
    ):
        """
        Initialize the Ollama adapter.

        Args:
            model_name: The Ollama model to use.
            base_url: Ollama server URL.
            timeout: Request timeout in seconds.
            num_ctx: Ollama context window size passed in every chat
                options dict. Defaults to 16384, which is large enough for
                the CTF agent's full tool-instruction region (~10k tokens)
                plus headroom. Ollama's Modelfile default (often 4096) is
                too small for the CTF agent's prompt and causes silent
                truncation of the system message → empty/garbage responses.
            thinking_callback: Optional callback that receives the raw
                ``message.thinking`` string from thinking-capable models
                (gpt-oss, gemma4, etc.) after each chat call. Only fires
                for models with the ``thinking`` capability — non-thinking
                models (llama3.1, mistral-small, edgerunner-medium) will
                never produce a thinking payload and this callback stays
                silent. Errors raised by the callback are swallowed so a
                buggy UI consumer cannot crash the adapter.
            grammar_schema: Optional JSON Schema dict. When non-None, it is
                passed as ``format=`` to ``client.chat()`` so llama.cpp
                constrains decoding to valid JSON matching the schema
                (internally compiled to a GBNF grammar). For the CTF agent
                this is ``_REACT_SCHEMA`` — it eliminates the empty/
                malformed responses that trigger the planner's
                ``Could not parse simplified ReAct response`` fallback.
                If the installed Ollama client version does not accept
                ``format``, the adapter probes once and degrades silently
                to unconstrained decoding.

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
        self.num_ctx = num_ctx
        self.thinking_callback = thinking_callback
        self.grammar_schema = grammar_schema
        # Off by default — CTF tool selection rarely benefits from CoT and
        # thinking tokens add 5-30s per turn on reasoning models. Opt in via
        # SolverConfig.enable_thinking when you actually want reasoning.
        self.enable_thinking = enable_thinking
        # Whether the installed ollama client supports the ``think=True``
        # kwarg on .chat(). Probed lazily on first invoke — older Ollama
        # server/client combos (<0.5.x) raise TypeError when given it, and
        # we should only pay that penalty once per process.
        self._think_supported: Optional[bool] = None
        # Same probe-once pattern for the ``format=`` kwarg. Older clients
        # reject it; once we know, skip it for the rest of the process.
        # v3.9 N.4: ``CTF_OLLAMA_GRAMMAR_DISABLE=1`` skips ``format=``
        # entirely. Useful for models whose GGUF can't be compiled to a
        # GBNF (e.g. ``failed to load model vocabulary required for
        # format`` HTTP 500 from Ollama). The agent's JSON-parser
        # fallback handles unconstrained output.
        if os.environ.get("CTF_OLLAMA_GRAMMAR_DISABLE", "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        ):
            self._format_supported: Optional[bool] = False
            logger.warning(
                "[Ollama] CTF_OLLAMA_GRAMMAR_DISABLE=1 set — `format=` "
                "kwarg will not be sent. Decoding is unconstrained; rely "
                "on the agent's JSON-parser fallback."
            )
        else:
            self._format_supported = None
        # v3.9 N.1: probe-once for ``oneOf`` support in ``format=``.
        # llama.cpp's grammar parser supports ``oneOf`` in modern builds
        # but older versions reject it; on rejection, fall back to the
        # original ``grammar_schema`` (legacy ``_REACT_SCHEMA``). MLX is
        # unaffected — it uses Outlines which has full Draft-07 support.
        self._oneof_supported: Optional[bool] = None
        self._tool_descriptors: Optional[
            List[Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]]
        ] = None
        # Cache for the per-tool oneOf format schema. Built lazily on first
        # use and invalidated when set_tool_descriptors() rewires the catalog.
        # Reading the schema is hot — it runs in _build_chat_kwargs on every
        # invoke() — and build_react_schema() over 77 tools is non-trivial.
        self._format_schema_cache: Optional[Dict[str, Any]] = None
        # Count of consecutive empty responses. Drives the escalation ladder
        # in ``invoke`` so context-overflow doesn't cascade into a
        # tool-repetition loop.
        self._consecutive_empty: int = 0

    def set_tool_descriptors(
        self,
        descriptors: List[
            Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]
        ],
    ) -> None:
        """v3.9 N.1: set per-tool descriptors so ``format=`` uses the
        ``oneOf`` per-tool schema instead of the single-shape
        ``grammar_schema``. On grammar-parser rejection, ``_chat_with_think``
        falls back automatically. No-op when descriptors is empty.
        """
        self._tool_descriptors = list(descriptors) if descriptors else None
        # Reset the support flag so the next call re-probes.
        self._oneof_supported = None
        # Invalidate the cached schema so the next call rebuilds it from
        # the new descriptors.
        self._format_schema_cache = None

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

    def _build_chat_kwargs(
        self, ollama_messages: List[Dict[str, str]], options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the kwargs dict for ``client.chat()``. ``think`` and
        ``format`` are layered in only when the installed client has been
        probed to support them."""
        chat_kwargs: Dict[str, Any] = {
            "model": self.model_name,
            "messages": ollama_messages,
            "options": options,
        }
        if self.enable_thinking and self._think_supported is not False:
            chat_kwargs["think"] = True
        # v3.9 N.1: prefer the per-tool ``oneOf`` schema when descriptors
        # have been wired and ``oneOf`` hasn't been ruled out by a prior
        # rejection. On rejection (set ``_oneof_supported=False`` in
        # ``_chat_with_think``), fall back to the legacy schema.
        format_schema = self._select_format_schema()
        if format_schema is not None and self._format_supported is not False:
            chat_kwargs["format"] = format_schema
        return chat_kwargs

    def _select_format_schema(self) -> Optional[Dict[str, Any]]:
        """Pick the right schema for ``format=``. Per-tool ``oneOf`` when
        descriptors are wired and ``oneOf`` is supported; legacy
        ``grammar_schema`` otherwise.

        The per-tool schema is cached in ``_format_schema_cache`` because
        ``build_react_schema`` over 77 tools costs 50-200ms; this method
        runs in ``_build_chat_kwargs`` on every ``invoke()``.
        """
        if self._tool_descriptors and self._oneof_supported is not False:
            if self._format_schema_cache is None:
                self._format_schema_cache = build_react_schema(self._tool_descriptors)
            return self._format_schema_cache
        return self.grammar_schema

    def _chat_with_think(self, ollama_messages, options):
        """Call ``client.chat()`` with the best-available kwarg set. The
        ``think=True`` and ``format=<schema>`` kwargs are feature-detected
        once per process: if the installed Ollama client raises TypeError
        for either, flip the corresponding support flag and retry without
        it. Subsequent calls skip the kwarg entirely.

        v3.9 N.1: also detects ``oneOf``-specific rejection from
        llama.cpp's grammar parser. Newer Ollama versions accept the
        kwarg but the underlying GBNF compiler may not handle ``oneOf``
        — when that surfaces as a runtime error, drop the per-tool
        schema and retry with the legacy single-shape schema.
        """
        while True:
            chat_kwargs = self._build_chat_kwargs(ollama_messages, options)
            try:
                resp = self.client.chat(**chat_kwargs)
                if "think" in chat_kwargs:
                    self._think_supported = True
                if "format" in chat_kwargs:
                    self._format_supported = True
                    # Only lock in ``_oneof_supported = True`` when the
                    # format we just sent actually contained a oneOf
                    # union. Under the v3.9 flat-enum default the schema
                    # never has oneOf, so this flag stays ``None``.
                    if (
                        self._tool_descriptors
                        and self._oneof_supported is None
                        and "oneOf"
                        in (
                            chat_kwargs["format"]
                            .get("properties", {})
                            .get("action", {})
                        )
                    ):
                        self._oneof_supported = True
                return resp
            except TypeError as te:
                msg = str(te)
                if "think" in chat_kwargs and "think" in msg:
                    self._think_supported = False
                    continue
                if "format" in chat_kwargs and "format" in msg:
                    self._format_supported = False
                    logger.warning(
                        "Ollama client does not accept `format=` kwarg; "
                        "falling back to unconstrained decoding. "
                        "Upgrade the ollama python package for grammar-constrained output."
                    )
                    continue
                raise
            except Exception as exc:
                err_text = str(exc).lower()

                # v3.9 N.1: oneOf-specific rejection from the grammar
                # parser. Disables only the per-tool oneOf path; the
                # legacy single-shape schema still gets applied.
                used_oneof = (
                    "format" in chat_kwargs
                    and self._tool_descriptors is not None
                    and self._oneof_supported is not False
                    and "oneOf"
                    in chat_kwargs["format"].get("properties", {}).get("action", {})
                )
                if used_oneof and (
                    "oneof" in err_text
                    or "one_of" in err_text
                    or "union" in err_text
                    or "unsupported schema" in err_text
                ):
                    self._oneof_supported = False
                    logger.warning(
                        "Ollama grammar parser rejected the per-tool "
                        "`oneOf` schema; falling back to the legacy "
                        "single-shape ReAct schema. MLX is unaffected."
                    )
                    continue

                # v3.9 N.4 hotfix: generic ``format=``-rejection. Some
                # Ollama models can't compile *any* JSON-schema format
                # constraint — typical wording is
                # ``failed to load model vocabulary required for format
                # (status code: 500)`` from older GGUFs that lack the
                # tokenizer metadata Ollama needs to build the GBNF.
                # Cause is model-side, not schema-side, so disabling
                # ``format=`` entirely is the right fallback (the
                # agent's JSON-parser fallback handles unconstrained
                # output). Server-side fix: ``ollama pull <model>``.
                used_format = (
                    "format" in chat_kwargs and self._format_supported is not False
                )
                if used_format and (
                    "failed to load model vocabulary" in err_text
                    or "required for format" in err_text
                    or ("vocabulary" in err_text and "format" in err_text)
                ):
                    self._format_supported = False
                    logger.warning(
                        "Ollama returned a format-vocabulary error: %s. "
                        "This model's GGUF lacks the metadata Ollama "
                        "needs for grammar-constrained output. Disabling "
                        "`format=` for this process; the agent's JSON "
                        "parser will tolerate unconstrained output. "
                        "To restore constrained decoding, try "
                        "`ollama pull <model>` to refresh the GGUF, or "
                        "switch to a newer model.",
                        exc,
                    )
                    continue
                raise

    def _extract_thinking(self, response: Any) -> str:
        """Pull out ``message.thinking`` from an Ollama chat response,
        handling both dict-style and Pydantic ChatResponse shapes. Returns
        empty string when the model didn't produce thinking."""
        try:
            msg = response["message"]
        except (TypeError, KeyError):
            msg = getattr(response, "message", None)
        if msg is None:
            return ""
        # Pydantic ChatResponse exposes attrs; dict mode exposes keys.
        thinking = None
        if isinstance(msg, dict):
            thinking = msg.get("thinking")
        else:
            thinking = getattr(msg, "thinking", None)
        return thinking or ""

    def _maybe_fire_thinking(self, response: Any) -> None:
        """Forward any thinking payload on ``response`` to the configured
        callback. Swallows callback exceptions so a buggy UI consumer
        can't crash the LLM path."""
        if self.thinking_callback is None:
            return
        thinking = self._extract_thinking(response)
        if not thinking:
            return
        try:
            self.thinking_callback(thinking)
        except Exception:
            pass

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        """Synchronously invoke the Ollama model."""
        ollama_messages = self._prepare_messages(messages)

        try:
            options = {
                "temperature": kwargs.get("temperature", 0.7),
                "num_ctx": kwargs.get("num_ctx", self.num_ctx),
            }
            response = _retry_with_backoff(
                lambda: self._chat_with_think(ollama_messages, options)
            )

            # Thinking (if any) goes out-of-band to the optional callback;
            # the Message.content contract is unchanged so existing parser
            # paths keep working without modification.
            self._maybe_fire_thinking(response)

            content = response["message"]["content"]

            # Empty-content escalation ladder. When grammar-constrained
            # decoding is on, Ollama can still emit empty output after
            # context overflow, generation aborts, or backend hiccups.
            # The prior fallback hard-coded ``attack_planner`` with a
            # bare-string ``tool_input`` — but that tool requires JSON,
            # so every fallback produced a tool error, and three in a
            # row tripped the repetition detector (cf. recentTestRun.txt
            # run 4 steps 5–7, run 5 steps 5–7). Replace that with a
            # two-step escalation:
            #   1st empty → ``ctf_knowledge_query`` (accepts plain
            #               strings, so no tool-error cascade).
            #   2nd+ empty → ``final_answer`` with a CONTEXT_OVERFLOW
            #               diagnostic so the run aborts instead of
            #               burning the remaining step budget on more
            #               empty turns.
            # Non-empty content resets the counter.
            if self.grammar_schema is not None and not (content or "").strip():
                self._consecutive_empty += 1
                if self._consecutive_empty == 1:
                    content = json.dumps(
                        {
                            "thought": (
                                "[Ollama returned empty content] "
                                "Context may have overflowed. Consulting the "
                                "knowledge base for a fresh angle before continuing."
                            ),
                            "action": {
                                "tool_name": "ctf_knowledge_query",
                                "tool_input": (
                                    "Summarize the most common web CTF attack "
                                    "vectors I should consider when initial "
                                    "reconnaissance has stalled."
                                ),
                            },
                        }
                    )
                else:
                    content = json.dumps(
                        {
                            "thought": (
                                "[CONTEXT_OVERFLOW] Ollama returned empty "
                                f"content for {self._consecutive_empty} "
                                "consecutive turns. Aborting so the runner can "
                                "surface the failure instead of burning the "
                                "remaining step budget."
                            ),
                            "action": {
                                "tool_name": "final_answer",
                                "tool_input": (
                                    "[CONTEXT_OVERFLOW] Local model produced "
                                    "repeated empty responses; unable to "
                                    "continue. Consider raising num_ctx or "
                                    "shortening the system prompt."
                                ),
                            },
                        }
                    )
            else:
                self._consecutive_empty = 0

            return Message(role="assistant", content=content)

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
        options = {
            "temperature": kwargs.get("temperature", 0.7),
            "num_ctx": kwargs.get("num_ctx", self.num_ctx),
        }

        try:
            # Reuse the feature-detected kwargs builder so streaming
            # behaviour matches non-streaming (same think/format handling).
            chat_kwargs = self._build_chat_kwargs(ollama_messages, options)
            chat_kwargs["stream"] = True

            while True:
                try:
                    stream = self.client.chat(**chat_kwargs)
                    break
                except TypeError as te:
                    tmsg = str(te)
                    if "think" in chat_kwargs and "think" in tmsg:
                        self._think_supported = False
                        chat_kwargs.pop("think", None)
                        continue
                    if "format" in chat_kwargs and "format" in tmsg:
                        self._format_supported = False
                        chat_kwargs.pop("format", None)
                        continue
                    raise

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


# ---------------------------------------------------------------------------
# MLXAdapter — Apple-Silicon-native local inference via mlx-lm + Outlines
# ---------------------------------------------------------------------------
#
# mlx_lm + outlines are NOT installed in the main project venv. They live
# in the user's ``~/mlx-env/`` venv; the imports below are deferred until
# first ``invoke`` so the rest of the codebase remains portable (Linux CI
# keeps working). An ImportError surfaces an actionable fix.
#
# Loading a 26B MoE takes ~8 s plus ~15-20 s for Metal kernel compile and
# expert materialization on first generate; we cache the (model, tokenizer,
# outlines-wrapper) triple at module scope so subsequent runs reuse it.

_MLX_CACHE: Dict[str, Any] = {}


def _build_mlx_schema(
    base_schema: Dict[str, Any],
    allowed_tool_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Clone ``base_schema`` and optionally lock ``action.tool_name`` to an
    enum of exactly ``allowed_tool_names``.

    Used by ``MLXAdapter`` to produce a per-instance schema that the
    Outlines FSM can't violate — i.e. the decoder cannot emit tool names
    the dispatcher would reject (``'deeply recon'``, ``'http-fetch'``,
    ``'javascript_{source}'`` from MLXtestrun.txt).

    Does not mutate ``base_schema``. Returns a deep copy so subsequent
    callers continue to see the unmodified shared schema.
    """
    import copy

    schema = copy.deepcopy(base_schema)
    if allowed_tool_names:
        try:
            schema["properties"]["action"]["properties"]["tool_name"] = {
                "type": "string",
                "enum": list(allowed_tool_names),
            }
        except (KeyError, TypeError):
            # Base schema shape changed — keep the (maxLength-bounded)
            # unbounded-name fallback rather than crashing.
            pass
    return schema


def _load_mlx_stack(model_name: str, *, prewarm: bool, seed: Optional[int]) -> Any:
    """Lazy-import mlx_lm + outlines and load the model once per process.

    Returns the tuple ``(mlx_model, tokenizer, outlines_model)``. Raises
    ``ImportError`` with an actionable message pointing at
    ``~/mlx-env`` when either package is unavailable.
    """
    if model_name in _MLX_CACHE:
        return _MLX_CACHE[model_name]
    try:
        import mlx.core as mx  # noqa: F401
        import mlx_lm
        import outlines
    except ImportError as exc:
        raise ImportError(
            "MLXAdapter requires mlx_lm and outlines. "
            "Activate your MLX venv and install: "
            "`source ~/mlx-env/bin/activate && "
            'pip install "outlines[mlxlm]"`. '
            f"Underlying error: {exc}"
        ) from exc

    if seed is not None:
        import mlx.core as mx

        mx.random.seed(seed)

    mlx_model, tok = mlx_lm.load(model_name)
    ol_model = outlines.from_mlxlm(mlx_model, tok)

    if prewarm:
        # Force Metal kernel compile + expert materialization so the
        # first real ``invoke`` doesn't eat a 15-20 s latency spike.
        try:
            mlx_lm.generate(mlx_model, tok, "hi", max_tokens=1, verbose=False)
        except Exception as warm_exc:  # pragma: no cover — best effort
            logger.warning("MLX prewarm failed: %s", warm_exc)

    _MLX_CACHE[model_name] = (mlx_model, tok, ol_model)
    return _MLX_CACHE[model_name]


class MLXAdapter(AbstractChatModel):
    """Apple-Silicon-native chat adapter using mlx-lm + Outlines.

    When ``grammar_schema`` is set, Outlines compiles the schema to an
    FSM and masks logits at each decode step so the output is guaranteed
    to be valid JSON matching the schema. Consumers wire this adapter to
    the strict ``ReActPlanner`` (not ``SimpleReActPlanner``) because the
    schema guarantee makes the key-value fallback obsolete.

    Args:
        model_name: HuggingFace repo id of an MLX-quantized model.
        grammar_schema: Optional JSON schema dict passed to Outlines as
            ``JsonSchema(schema)``. When None, decoding is unconstrained.
        max_tokens: Hard cap on generation length per call.
        temperature / top_p: Sampling parameters, forwarded to mlx-lm's
            sampler. Outlines masks first, the sampler draws second — so
            these are fully respected under the grammar constraint.
        kv_bits: Optional KV-cache quantization (set to 4 for 4-bit KV
            after a 512-token warmup). Saves ~6 GB on long contexts.
        seed: Optional ``mx.random.seed`` value for reproducibility.
        prewarm: If True (default), a 1-token generate fires right after
            load to compile Metal kernels and materialize MoE experts.
        thinking_callback: Accepted for interface parity with the other
            adapters; unused by the current Gemma4 MLX build.
        allowed_tool_names: Optional list of valid tool names. When set,
            the schema's ``action.tool_name`` is replaced with an enum of
            these values so the FSM cannot produce names the dispatcher
            would reject. Usually populated via ``set_allowed_tool_names``
            from ``build_agent`` after tool registration.
    """

    def __init__(
        self,
        model_name: str = "mlx-community/gemma-4-26b-a4b-it-4bit",
        *,
        grammar_schema: Optional[Dict[str, Any]] = None,
        max_tokens: int = 2048,
        # Defaults below match Google's official Gemma 4 sampling
        # recommendation (model card on ai.google.dev/gemma/docs/core/
        # model_card_4). Earlier values (0.2 / 0.9 / no top_k) were
        # carried over from generic-LLM defaults and amplified Gemma 4's
        # repetition-collapse mode under FSM-masked decoding — see
        # MLXtestrun.txt and Gemma issue #622 for the failure trace.
        temperature: float = 1.0,
        top_p: float = 0.95,
        top_k: int = 64,
        kv_bits: Optional[int] = None,
        seed: Optional[int] = None,
        prewarm: bool = True,
        thinking_callback: Optional[Callable[[str], None]] = None,
        allowed_tool_names: Optional[List[str]] = None,
    ) -> None:
        self.model_name = model_name
        self.grammar_schema = grammar_schema
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.top_p = top_p
        self.top_k = top_k
        self.kv_bits = kv_bits
        self.seed = seed
        self.prewarm = prewarm
        self.thinking_callback = thinking_callback
        self.allowed_tool_names = allowed_tool_names
        # v3.9 N.1: optional per-tool ``tool_input`` discrimination via
        # ``oneOf``. When set, ``_build_output_type`` builds a richer
        # schema from these descriptors instead of locking only
        # ``tool_name``. ``None`` means use the legacy schema +
        # ``allowed_tool_names`` enum.
        self._tool_descriptors: Optional[
            List[Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]]
        ] = None
        # v3.9 N.1 hotfix-2: cache the compiled ``output_type`` so we
        # don't reallocate the wrapper / re-trigger Outlines'
        # ``Index(regex, vocab)`` work on every invoke. The actual FSM
        # is cached internally by ``outlines-core`` keyed on
        # ``(regex, tokenizer)``, but the Python-level wrapper objects
        # also accumulate GC pressure when rebuilt per step.
        # Invalidated by ``set_allowed_tool_names`` /
        # ``set_tool_descriptors`` (the only mutators that change the
        # schema).
        self._output_type_cache: Any = None
        # v3.9 N.1 hotfix-2: ``CTF_MLX_GRAMMAR_DISABLE=1`` skips Outlines
        # entirely. Useful when the FSM build's RAM/CPU footprint is
        # the bottleneck (Gemma 4 26B + 256k vocab pays a heavy upfront
        # cost vs. llama.cpp's GBNF). The agent's
        # ``parse_json_input`` / ``_robust_json_parse`` already
        # tolerate malformed JSON, so unconstrained decoding is a
        # workable fallback for development runs.
        if os.environ.get("CTF_MLX_GRAMMAR_DISABLE", "").strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        ):
            self.grammar_schema = None
            logger.warning(
                "[MLX] CTF_MLX_GRAMMAR_DISABLE=1 set — Outlines grammar "
                "OFF. Decoding is unconstrained; rely on the agent's "
                "JSON-parser fallback."
            )

    def set_allowed_tool_names(self, names: List[str]) -> None:
        """Lock the grammar-constrained schema's ``tool_name`` field to an
        enum of exactly ``names``. Called by ``build_agent`` after the
        tool registry is populated so the FSM cannot emit hallucinated
        tool names (``'deeply recon'``, ``'http-fetch'``, etc. observed
        in MLXtestrun.txt).

        Must be invoked before the first ``invoke`` to take effect — the
        output_type is rebuilt per-call from the currently stored list.
        """
        self.allowed_tool_names = list(names)
        self._output_type_cache = None  # invalidate cached compile

    def set_tool_descriptors(
        self,
        descriptors: List[
            Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Any]]]
        ],
    ) -> None:
        """v3.9 N.1: set per-tool descriptors so the grammar schema
        knows the registered tool surface (used by the flat-enum
        production schema and the experimental ``oneof`` schema).

        Called by ``build_agent`` *in addition to* ``set_allowed_tool_names``.
        """
        self._tool_descriptors = list(descriptors)
        self._output_type_cache = None  # invalidate cached compile

    # ----- AbstractChatModel contract ---------------------------------

    def invoke(self, messages: List[Message], **kwargs: Any) -> Message:
        _, tok, ol_model = _load_mlx_stack(
            self.model_name, prewarm=self.prewarm, seed=self.seed
        )
        chat = [{"role": self._role_for(m), "content": m.content} for m in messages]
        prompt_str = tok.apply_chat_template(
            chat, add_generation_prompt=True, tokenize=False
        )
        gen_kwargs = self._build_gen_kwargs(kwargs)
        output_type = self._build_output_type()
        if output_type is not None:
            text = ol_model(prompt_str, output_type=output_type, **gen_kwargs)
        else:
            text = ol_model(prompt_str, **gen_kwargs)
        return Message(role="assistant", content=text)

    async def ainvoke(self, messages: List[Message], **kwargs: Any) -> Message:
        import asyncio

        return await asyncio.to_thread(self.invoke, messages, **kwargs)

    def stream(
        self, messages: List[Message], **kwargs: Any
    ) -> Generator[Message, None, None]:
        # v1: non-streaming only. Outlines `.stream(...)` works but no
        # consumer in the agent reads streams today; add if needed.
        raise NotImplementedError("MLXAdapter.stream is not implemented in v1")

    async def astream(
        self, messages: List[Message], **kwargs: Any
    ) -> AsyncGenerator[Message, None]:
        raise NotImplementedError("MLXAdapter.astream is not implemented in v1")
        # Unreachable, satisfies generator typing
        yield Message(role="assistant", content="")

    def get_model_capabilities(self) -> Dict[str, Any]:
        return {
            "supports_streaming": False,
            "supports_async": True,
            "supports_tool_calling": False,
            "supports_json_schema": self.grammar_schema is not None,
            "provider": "mlx",
            "model": self.model_name,
            "local": True,
        }

    # ----- internals --------------------------------------------------

    def _role_for(self, m: Message) -> str:
        # Gemma's chat template has no native "tool" role — wrap tool
        # observations as user turns, same treatment as OllamaAdapter.
        if m.role == "tool":
            return "user"
        return m.role

    def _build_output_type(self) -> Any:
        if self.grammar_schema is None:
            return None
        # v3.9 N.1 hotfix-2: cache the wrapper across invokes. The
        # output_type contents change only when the caller mutates the
        # tool registry (``set_allowed_tool_names`` /
        # ``set_tool_descriptors`` invalidate the cache there).
        if self._output_type_cache is not None:
            return self._output_type_cache

        import outlines

        # When per-tool descriptors are available, ``build_react_schema``
        # produces a flat-enum schema (default ``mode='enum'``): the
        # ``tool_name`` is locked to the registered set, ``tool_input``
        # stays a permissive string. This compiles in seconds against
        # any reasonable vocab and avoids the i32::MAX DFA overflow the
        # legacy ``oneof`` schema hit at scale (76 branches → 459 KB
        # regex → unbuilable DFA). Per-tool ``tool_input`` validation
        # still happens in Python via each tool's ``parameters_schema``.
        if self._tool_descriptors:
            schema = build_react_schema(self._tool_descriptors)
            try:
                self._output_type_cache = outlines.types.JsonSchema(schema)
                return self._output_type_cache
            except Exception as exc:
                logger.warning(
                    "[MLX] Outlines rejected the descriptor-driven "
                    "schema: %s. Falling back to the legacy single-shape "
                    "_REACT_SCHEMA.",
                    exc,
                )
                self._tool_descriptors = None

        schema = _build_mlx_schema(self.grammar_schema, self.allowed_tool_names)
        self._output_type_cache = outlines.types.JsonSchema(schema)
        return self._output_type_cache

    def _build_gen_kwargs(self, caller_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        # mlx_lm.generate_step takes a pre-built ``sampler`` callable, NOT
        # raw temperature/top_p. Build the sampler here via make_sampler
        # (which uses ``temp=``, not ``temperature=``) so Outlines forwards
        # a single ``sampler`` kwarg downstream. The v3.4 initial impl
        # passed raw temperature/top_p and tripped
        # ``TypeError: generate_step() got an unexpected keyword argument
        # 'temperature'`` on the first real invoke.
        from mlx_lm.sample_utils import make_sampler

        temp = caller_kwargs.get("temperature", self.temperature)
        top_p = caller_kwargs.get("top_p", self.top_p)
        top_k = caller_kwargs.get("top_k", self.top_k)
        out: Dict[str, Any] = {
            "max_tokens": caller_kwargs.get("max_tokens", self.max_tokens),
            "sampler": make_sampler(temp=temp, top_p=top_p, top_k=top_k),
        }
        if self.kv_bits is not None:
            out["kv_bits"] = self.kv_bits
            out["kv_group_size"] = 64
            out["quantized_kv_start"] = 512
        # NOTE: ``seed`` is applied once at load time via ``mx.random.seed``
        # inside ``_load_mlx_stack``; passing it per-call to generate_step
        # would raise TypeError (no such kwarg).
        return out


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


def openai_invoke_with_tools(
    messages: List[Message],
    tools: List[Dict[str, Any]],
    *,
    model_name: str,
    api_key: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    parallel_tool_calls: bool = True,
) -> Dict[str, Any]:
    """OpenAI parallel-tool-use helper (Stage 2a — adapter parity with Anthropic).

    Returns the same dict shape as ``AnthropicAdapter.invoke_with_tools``::

        {
            "text": str,
            "tool_calls": List[{"id","name","input"}],
            "stop_reason": str,
        }

    OpenAI's function-calling is enabled by default and returns multiple
    ``tool_calls[]`` entries when the model wants to invoke several tools in
    one turn.  ``parallel_tool_calls=False`` forces sequential.

    This helper uses the OpenAI SDK directly (bypassing fairlib's adapter) so
    the tool-call shape is preserved without translation.  Not yet wired to
    the agent loop — covered by its own tests and will integrate in a
    follow-up pass.
    """
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise ImportError(
            "The 'openai' library is required for native tool-use. "
            "Install with `pip install openai`."
        ) from exc

    resolved_api_key = api_key or os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=resolved_api_key)

    openai_messages: List[Dict[str, Any]] = []
    for msg in messages:
        role = msg.role
        if role == "tool":
            role = "user"
        openai_messages.append({"role": role, "content": msg.content or ""})

    response = _retry_with_backoff(
        lambda: client.chat.completions.create(
            model=model_name,
            messages=openai_messages,
            tools=tools,
            tool_choice="auto",
            parallel_tool_calls=parallel_tool_calls,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    )

    choice = response.choices[0]
    finish_reason_raw = getattr(choice, "finish_reason", "")
    finish_reason = finish_reason_raw if isinstance(finish_reason_raw, str) else ""
    refusal_raw = getattr(choice.message, "refusal", None)
    # Tightly typed: only treat ``refusal`` as a real refusal when the SDK
    # actually populated it with a string. Defensive against mocks and any
    # SDK that returns a placeholder object.
    refusal = refusal_raw if isinstance(refusal_raw, str) and refusal_raw else ""

    # Detect typed moderation/refusal signals that fairlib's string-path
    # would miss: ``finish_reason == "content_filter"`` (output-side filter
    # masked the response) and a non-null ``message.refusal`` (the model
    # itself declined via the structured field rather than free-form text).
    moderation_signal = ""
    if finish_reason == "content_filter":
        moderation_signal = "content_filter"
    elif refusal:
        moderation_signal = "refusal"

    tool_calls: List[Dict[str, Any]] = []
    for tc in getattr(choice.message, "tool_calls", []) or []:
        fn = getattr(tc, "function", None)
        raw_args = getattr(fn, "arguments", "") if fn else ""
        try:
            parsed_args = (
                json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            )
        except (json.JSONDecodeError, TypeError):
            parsed_args = {"tool_input": raw_args}
        tool_calls.append(
            {
                "id": getattr(tc, "id", ""),
                "name": getattr(fn, "name", "") if fn else "",
                "input": (
                    parsed_args
                    if isinstance(parsed_args, dict)
                    else {"tool_input": parsed_args}
                ),
            }
        )

    raw_text = getattr(choice.message, "content", "") or ""
    if not isinstance(raw_text, str):
        raw_text = ""

    return {
        "text": raw_text,
        "tool_calls": tool_calls,
        "stop_reason": finish_reason,
        # Surface typed moderation signals so the agent loop can count them
        # via ``tracker.moderation_hits`` even when fairlib's string-path
        # never sees the underlying API error.
        "refusal": refusal,
        "moderation_signal": moderation_signal,
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
        # Use the CTF subclass so the legacy JSON-ReAct path gets
        # ``response_format={"type": "json_object"}`` injected on every call
        # (eliminates format-error retries when the model hedges with prose).
        return CTFOpenAIAdapter(
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
        # Resolve grammar_mode → concrete schema. "auto" and "json_schema"
        # both attach _REACT_SCHEMA; "none" (or any falsy value) leaves
        # decoding unconstrained. The Ollama adapter handles unsupported-
        # kwarg probing and silent degradation internally.
        grammar_mode = (kwargs.get("grammar_mode") or "auto").lower()
        grammar_schema = (
            _REACT_SCHEMA if grammar_mode in ("auto", "json_schema") else None
        )
        return OllamaAdapter(
            model_name=model_name or DEFAULT_CONFIGS[LLMProvider.OLLAMA].model_name,
            base_url=base_url or DEFAULT_CONFIGS[LLMProvider.OLLAMA].base_url,
            timeout=kwargs.get("timeout", 120.0),
            num_ctx=kwargs.get("num_ctx", 16384),
            thinking_callback=kwargs.get("thinking_callback"),
            grammar_schema=grammar_schema,
            enable_thinking=kwargs.get("enable_thinking", False),
        )

    elif provider == LLMProvider.MLX:
        # MLX + Outlines grammar-constrains output to _REACT_SCHEMA so the
        # strict ReActPlanner gets guaranteed valid JSON. Same grammar_mode
        # semantics as the Ollama branch.
        grammar_mode = (kwargs.get("grammar_mode") or "auto").lower()
        grammar_schema = (
            _REACT_SCHEMA if grammar_mode in ("auto", "json_schema") else None
        )
        return MLXAdapter(
            model_name=model_name or DEFAULT_CONFIGS[LLMProvider.MLX].model_name,
            grammar_schema=grammar_schema,
            max_tokens=kwargs.get("max_tokens", 2048),
            kv_bits=kwargs.get("mlx_kv_bits"),
            seed=kwargs.get("mlx_seed"),
            prewarm=kwargs.get("mlx_prewarm", True),
            thinking_callback=kwargs.get("thinking_callback"),
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


def create_adapter_from_config(
    config: "SolverConfig",
    thinking_callback: Optional[Callable[[str], None]] = None,
) -> AbstractChatModel:
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

    # Local providers (Ollama / MLX) on the first inference call against a
    # newly-loaded model can legitimately take 2-5 minutes — Metal kernels
    # get JIT-compiled per architecture, and reasoning models with
    # think=True + a large tool catalog + grammar-constrained decoding
    # easily exceed the 120s default that's fine for hosted endpoints.
    # Only widen when the user has not set an explicit timeout.
    user_timeout = getattr(config, "llm_timeout", None)
    if user_timeout is None or user_timeout == 120.0:
        if provider in (LLMProvider.OLLAMA, LLMProvider.MLX):
            timeout = 600.0
        else:
            timeout = 120.0
    else:
        timeout = float(user_timeout)

    return create_adapter(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        base_url=getattr(config, "llm_base_url", None),
        max_tokens=getattr(config, "max_tokens", 2048),
        timeout=timeout,
        num_ctx=getattr(config, "ollama_num_ctx", 16384),
        thinking_callback=thinking_callback,
        grammar_mode=getattr(config, "grammar_mode", "auto"),
        mlx_kv_bits=getattr(config, "mlx_kv_bits", None),
        mlx_seed=getattr(config, "mlx_seed", None),
        mlx_prewarm=getattr(config, "mlx_prewarm", True),
        enable_thinking=getattr(config, "enable_thinking", False),
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

    elif provider == LLMProvider.MLX:
        try:
            import mlx_lm  # noqa: F401
            import outlines  # noqa: F401

            return True, "MLX is available"
        except ImportError:
            return (
                False,
                "MLX not installed. Activate ~/mlx-env and run: "
                'pip install "outlines[mlxlm]"',
            )

    elif provider == LLMProvider.HYBRID:
        return True, "Hybrid adapter is always available"

    return False, f"Unknown provider: {provider}"
