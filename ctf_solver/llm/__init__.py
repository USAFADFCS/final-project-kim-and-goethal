"""
LLM Adapters for CTF Solver.

Provides multi-model support with adapters for different LLM providers.
"""

from ctf_solver.llm.adapters import (
    # Availability flags
    ANTHROPIC_INSTALLED,
    DEFAULT_CONFIGS,
    OLLAMA_INSTALLED,
    # Adapters
    AnthropicAdapter,
    HybridAdapter,
    # Enums and configs
    LLMProvider,
    MLXAdapter,
    ModelConfig,
    OllamaAdapter,
    check_provider_available,
    # Factory functions
    create_adapter,
    create_adapter_from_config,
)

__all__ = [
    # Enums and configs
    "LLMProvider",
    "ModelConfig",
    "DEFAULT_CONFIGS",
    # Adapters
    "AnthropicAdapter",
    "OllamaAdapter",
    "MLXAdapter",
    "HybridAdapter",
    # Factory functions
    "create_adapter",
    "create_adapter_from_config",
    "check_provider_available",
    # Availability flags
    "ANTHROPIC_INSTALLED",
    "OLLAMA_INSTALLED",
]
