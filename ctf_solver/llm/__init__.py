"""
LLM Adapters for CTF Solver.

Provides multi-model support with adapters for different LLM providers.
"""

from ctf_solver.llm.adapters import (
    # Enums and configs
    LLMProvider,
    ModelConfig,
    DEFAULT_CONFIGS,
    # Adapters
    AnthropicAdapter,
    OllamaAdapter,
    HybridAdapter,
    # Factory functions
    create_adapter,
    create_adapter_from_config,
    check_provider_available,
    # Availability flags
    ANTHROPIC_INSTALLED,
    OLLAMA_INSTALLED,
)

__all__ = [
    # Enums and configs
    "LLMProvider",
    "ModelConfig",
    "DEFAULT_CONFIGS",
    # Adapters
    "AnthropicAdapter",
    "OllamaAdapter",
    "HybridAdapter",
    # Factory functions
    "create_adapter",
    "create_adapter_from_config",
    "check_provider_available",
    # Availability flags
    "ANTHROPIC_INSTALLED",
    "OLLAMA_INSTALLED",
]
