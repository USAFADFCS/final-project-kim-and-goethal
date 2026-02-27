"""
CTF Solver - A platform-agnostic agentic CTF solving framework.

This package provides tools and agents for solving Capture-The-Flag challenges
using the FAIR agentic framework with RAG-enhanced knowledge retrieval.
"""

from ctf_solver.config import SolverConfig, LLMProviderType
from ctf_solver.agent import (
    build_agent,
    classify_challenge,
    get_classification_context,
)
from ctf_solver.classifier import (
    ChallengeClassifier,
    ChallengeCategory,
    ClassificationResult,
    create_classifier,
)
from ctf_solver.run_tracker import RunTracker
from ctf_solver.llm import (
    LLMProvider,
    AnthropicAdapter,
    OllamaAdapter,
    HybridAdapter,
    create_adapter,
    create_adapter_from_config,
    check_provider_available,
)

__version__ = "1.0.0"
__all__ = [
    # Config
    "SolverConfig",
    "LLMProviderType",
    # Agent
    "build_agent",
    "classify_challenge",
    "get_classification_context",
    # Classifier
    "ChallengeClassifier",
    "ChallengeCategory",
    "ClassificationResult",
    "create_classifier",
    # Run tracker
    "RunTracker",
    # LLM adapters
    "LLMProvider",
    "AnthropicAdapter",
    "OllamaAdapter",
    "HybridAdapter",
    "create_adapter",
    "create_adapter_from_config",
    "check_provider_available",
    # Version
    "__version__",
]
