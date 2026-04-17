"""
RAG (Retrieval-Augmented Generation) module for CTF Solver.

Provides knowledge base initialization and query capabilities
for CTF-related documents.

Enhanced with:
- Query expansion for improved recall
- Simple reranking for better precision
- Hybrid search (BM25 + vector similarity)
- Chunk metadata for context
"""

from ctf_solver.rag.hybrid_search import (
    BM25Index,
    DocumentWithMetadata,
    HybridResult,
    HybridSearcher,
    create_hybrid_searcher,
)
from ctf_solver.rag.knowledge_base import (
    SafeKnowledgeQueryTool,
    build_knowledge_tool,
    clear_cache,
    get_active_knowledge_tool,
    get_hybrid_searcher,
    get_optimization_status,
    get_query_expander,
    get_reranker,
    initialize_knowledge_base,
    set_active_knowledge_tool,
    split_text,
    split_text_with_metadata,
)
from ctf_solver.rag.query_expander import (
    QueryExpander,
    create_query_expander,
)
from ctf_solver.rag.reranker import (
    ScoredDocument,
    SimpleReranker,
    create_reranker,
)

__all__ = [
    # Knowledge base
    "initialize_knowledge_base",
    "build_knowledge_tool",
    "split_text",
    "split_text_with_metadata",
    "clear_cache",
    "SafeKnowledgeQueryTool",
    "get_optimization_status",
    "get_query_expander",
    "get_reranker",
    "get_hybrid_searcher",
    "get_active_knowledge_tool",
    "set_active_knowledge_tool",
    # Query expansion
    "QueryExpander",
    "create_query_expander",
    # Reranking
    "SimpleReranker",
    "ScoredDocument",
    "create_reranker",
    # Hybrid search
    "HybridSearcher",
    "HybridResult",
    "BM25Index",
    "DocumentWithMetadata",
    "create_hybrid_searcher",
]
