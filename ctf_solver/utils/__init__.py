"""
CTF Solver Utilities - Response caching and request deduplication.

``AsyncToolExecutor`` was removed in Batch C: it was a pre-native-tools
attempt at parallelism that is now redundant.  Parallel tool use is handled
by the LLM's own batching (``_arun_native_tools`` on the Anthropic path,
``_arun_native_tools_openai`` on the OpenAI path), so a separate async
executor layer has no live caller.
"""

from ctf_solver.utils.response_cache import RequestDeduplicator, ResponseCache

__all__ = [
    "ResponseCache",
    "RequestDeduplicator",
]
