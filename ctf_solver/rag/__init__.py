"""
RAG (Retrieval-Augmented Generation) module for CTF Solver.

Provides knowledge base initialization and query capabilities
for CTF-related documents.
"""

from ctf_solver.rag.knowledge_base import (
    initialize_knowledge_base,
    build_knowledge_tool,
    split_text,
    clear_cache,
    SafeKnowledgeQueryTool,
)

__all__ = [
    "initialize_knowledge_base",
    "build_knowledge_tool",
    "split_text",
    "clear_cache",
    "SafeKnowledgeQueryTool",
]
