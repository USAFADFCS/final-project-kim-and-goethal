"""
Knowledge base initialization and management for CTF Solver.

Provides RAG (Retrieval-Augmented Generation) capabilities using
FAIR framework components with configurable document sources.

Enhanced with:
- Query expansion for improved recall
- Simple reranking for better precision
- Hybrid search (BM25 + vector similarity)
- Chunk metadata for context
"""

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple

# =============================================================================
# CRITICAL: Set environment variables to prevent multiprocessing crashes
# on Apple Silicon when using FAISS + sentence-transformers + Streamlit
# =============================================================================
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from ctf_solver.config import SolverConfig

# FAIR framework imports
from fairlib import (
    Document,
    SentenceTransformerEmbedder,
    SimpleRetriever,
    KnowledgeBaseQueryTool,
    settings,
)
from fairlib.utils.document_processor import DocumentProcessor
from fairlib.modules.memory.vector_faiss import FaissVectorStore

# Local RAG optimization imports
from ctf_solver.rag.query_expander import QueryExpander, create_query_expander
from ctf_solver.rag.reranker import SimpleReranker, ScoredDocument, create_reranker
from ctf_solver.rag.hybrid_search import (
    HybridSearcher,
    BM25Index,
    HybridResult,
    create_hybrid_searcher,
)

logger = logging.getLogger(__name__)

# Module-level cache for the retriever and optimization components
_cached_retriever: Optional[SimpleRetriever] = None
_cached_sources_hash: Optional[str] = None
_cached_hybrid_searcher: Optional[HybridSearcher] = None
_cached_query_expander: Optional[QueryExpander] = None
_cached_reranker: Optional[SimpleReranker] = None
_cached_documents: List[Any] = []


def split_text(text: str, chunk_size: int = 1000, chunk_overlap: int = 150) -> List[str]:
    """
    Simple text splitter for RAG.

    Splits a long text into overlapping chunks so that:
      - Each chunk has up to `chunk_size` characters.
      - Consecutive chunks overlap by `chunk_overlap` characters.

    Args:
        text: The text to split
        chunk_size: Maximum characters per chunk
        chunk_overlap: Overlap between consecutive chunks

    Returns:
        List of text chunks
    """
    if not text:
        return []
    chunks: List[str] = []
    start = 0
    length = len(text)
    while start < length:
        end = start + chunk_size
        chunks.append(text[start:end])
        start += max(1, chunk_size - chunk_overlap)
    return chunks


def split_text_with_metadata(
    text: str,
    source_file: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 150,
) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Split text into chunks with associated metadata.

    Each chunk includes metadata about its source file, position,
    and any detected section headers.

    Args:
        text: The text to split
        source_file: Source filename for metadata
        chunk_size: Maximum characters per chunk
        chunk_overlap: Overlap between consecutive chunks

    Returns:
        List of (chunk_text, metadata) tuples
    """
    if not text:
        return []

    chunks_with_meta: List[Tuple[str, Dict[str, Any]]] = []
    start = 0
    length = len(text)
    chunk_idx = 0

    # Pre-extract section headers from full text
    section_pattern = re.compile(r'^#+\s+(.+)$|^([A-Z][A-Za-z\s]+):$', re.MULTILINE)
    sections = [(m.start(), m.group(1) or m.group(2)) for m in section_pattern.finditer(text)]

    while start < length:
        end = min(start + chunk_size, length)
        chunk_text = text[start:end]

        # Find section header for this chunk
        current_section = None
        for sec_start, sec_title in reversed(sections):
            if sec_start <= start:
                current_section = sec_title.strip()
                break

        # Detect CTF-relevant tags in chunk
        tags = _detect_chunk_tags(chunk_text)

        metadata = {
            "source_file": source_file,
            "chunk_index": chunk_idx,
            "char_start": start,
            "char_end": end,
            "section": current_section,
            "tags": tags,
        }

        chunks_with_meta.append((chunk_text, metadata))

        start += max(1, chunk_size - chunk_overlap)
        chunk_idx += 1

    return chunks_with_meta


def _detect_chunk_tags(text: str) -> List[str]:
    """
    Detect CTF-relevant tags in a text chunk.

    Args:
        text: The chunk text

    Returns:
        List of detected tag strings
    """
    text_lower = text.lower()
    tags = []

    # Tag patterns to detect
    tag_patterns = {
        "sql_injection": ["sql injection", "sqli", "union select", "' or '"],
        "xss": ["cross-site scripting", "xss", "<script", "onerror="],
        "authentication": ["auth", "login", "password", "credential", "session"],
        "file_inclusion": ["lfi", "rfi", "file inclusion", "path traversal"],
        "command_injection": ["command injection", "os injection", "rce", "shell"],
        "ssti": ["template injection", "ssti", "jinja", "twig"],
        "jwt": ["jwt", "json web token", "bearer"],
        "xxe": ["xxe", "xml external", "entity"],
        "deserialization": ["deserializ", "pickle", "unserialize"],
        "race_condition": ["race condition", "toctou", "concurrency"],
        "cryptography": ["crypto", "encryption", "cipher", "hash"],
        "encoding": ["base64", "url encode", "hex", "decode"],
    }

    for tag, patterns in tag_patterns.items():
        for pattern in patterns:
            if pattern in text_lower:
                tags.append(tag)
                break

    return tags


def _compute_sources_hash(config: SolverConfig) -> str:
    """Compute a hash of the knowledge base sources for cache invalidation.

    Includes the vector_store_dir so that switching RAG modes (which use
    different vector store directories) properly invalidates the cache.
    """
    sources = sorted(str(p) for p in config.get_all_kb_paths())
    # Include vector_store_dir to differentiate original vs augmented caches
    return config.vector_store_dir + "::" + "|".join(sources)


def initialize_knowledge_base(
    config: SolverConfig,
    force_rebuild: bool = False,
    log_callback: Optional[Callable[[str], None]] = None,
    enable_hybrid_search: bool = True,
    enable_query_expansion: bool = True,
    enable_reranking: bool = True,
) -> Optional[SimpleRetriever]:
    """
    Build and cache a RAG knowledge base from configured sources.

    Data sources are determined by the config:
      - config.kb_files: Specific files to include
      - config.docs_dirs: Directories to scan for *.md, *.txt, *.pdf

    Pipeline:
      - DocumentProcessor for extraction (PDF/Markdown/Text).
      - SentenceTransformerEmbedder for embeddings.
      - FaissVectorStore as the vector store.
      - SimpleRetriever wrapping the vector store.
      - Optional: QueryExpander for improved recall
      - Optional: HybridSearcher for BM25 + vector search
      - Optional: SimpleReranker for better precision

    Args:
        config: Solver configuration
        force_rebuild: Force rebuild even if cached
        log_callback: Optional callback for log messages
        enable_hybrid_search: Enable BM25 + vector hybrid search
        enable_query_expansion: Enable query expansion
        enable_reranking: Enable result reranking

    Returns:
        SimpleRetriever instance or None if initialization fails
    """
    global _cached_retriever, _cached_sources_hash
    global _cached_hybrid_searcher, _cached_query_expander, _cached_reranker
    global _cached_documents

    def log(msg: str) -> None:
        if log_callback:
            log_callback(msg)
        logger.info(msg)

    # Check cache
    sources_hash = _compute_sources_hash(config)
    if not force_rebuild and _cached_retriever is not None and _cached_sources_hash == sources_hash:
        log("Using cached knowledge base retriever")
        return _cached_retriever

    log("Initializing CTF RAG knowledge base...")
    log(f"  Configured dirs: {config.docs_dirs}")
    log(f"  Configured files: {config.kb_files}")

    # Get all document paths
    doc_paths = config.get_all_kb_paths()

    if not doc_paths:
        log("WARNING: No knowledge base documents found. RAG will be disabled.")
        log("  Possible causes:")
        log("    - Paths do not exist or are misspelled")
        log("    - Relative paths not resolved correctly")
        log("    - No .md, .txt, or .pdf files in specified directories")
        return None

    log(f"Found {len(doc_paths)} document(s) for knowledge base:")
    for p in doc_paths:
        log(f"  - {p}")

    # RAG configuration from settings or defaults
    rag_cfg = getattr(settings, "rag_system", None)

    # Vector store directory
    index_dir = Path(config.vector_store_dir).resolve()
    index_dir.mkdir(parents=True, exist_ok=True)

    # Embedding model / config
    embed_model = getattr(
        getattr(rag_cfg, "embeddings", None),
        "embedding_model",
        "sentence-transformers/all-MiniLM-L6-v2",
    )
    use_gpu = getattr(getattr(rag_cfg, "vector_store", None), "use_gpu", False)
    batch_size = getattr(getattr(rag_cfg, "embeddings", None), "batch_size", 128)

    try:
        # Force CPU for Apple Silicon compatibility (MPS can have issues with sentence-transformers)
        embedder = SentenceTransformerEmbedder(model_name=embed_model, device="cpu")
        log(f"Initialized embedder with model: {embed_model} (device: cpu)")
    except TypeError:
        # Fallback if device parameter not supported
        embedder = SentenceTransformerEmbedder(model_name=embed_model)
        log(f"Initialized embedder with model: {embed_model}")
    except Exception as e:
        logger.error("Failed to initialize SentenceTransformerEmbedder: %s", e, exc_info=True)
        log(f"ERROR: Failed to initialize embedder: {e}")
        return None

    # Build FAISS vector store
    try:
        vector_store = FaissVectorStore(
            embedder=embedder,
            index_dir=str(index_dir),
            use_gpu=use_gpu,
            normalize=True,
            batch_size=batch_size,
        )
        # Try to load existing index
        try:
            vector_store.load()
            log(f"Loaded existing FAISS index from {index_dir}")
        except Exception:
            log(f"Creating new FAISS index at {index_dir}")
    except Exception as e:
        logger.error("Failed to initialize FaissVectorStore: %s", e, exc_info=True)
        return None

    # Process documents
    # Use the first doc path's parent as the base directory
    base_dir = doc_paths[0].parent if doc_paths else Path.cwd()
    doc_proc = DocumentProcessor({"files_directory": str(base_dir)})

    all_chunks: List[str] = []
    doc_chunks_with_meta: List[Document] = []

    for path in doc_paths:
        try:
            docs = doc_proc.process_file(str(path))
        except Exception as e:
            logger.error("DocumentProcessor failed for %s: %s", path, e, exc_info=True)
            continue

        if not docs:
            log(f"WARNING: No content extracted from {path}")
            continue

        for doc in docs:
            text = getattr(doc, "page_content", None)
            if not isinstance(text, str) or not text.strip():
                continue

            # Chunk with metadata for enhanced retrieval
            chunks_meta = split_text_with_metadata(
                text, source_file=path.name, chunk_size=1200, chunk_overlap=200
            )

            for chunk_text, metadata in chunks_meta:
                all_chunks.append(chunk_text)
                # Create Document with metadata
                doc_with_meta = Document(page_content=chunk_text)
                # Store metadata as attribute (FAIR Document supports this)
                doc_with_meta.metadata = metadata
                doc_chunks_with_meta.append(doc_with_meta)

        log(f"Processed {path.name}: {len(docs)} document(s)")

    if not all_chunks:
        log("WARNING: No document chunks were created; knowledge base will be empty.")
    else:
        log(f"Adding {len(all_chunks)} chunks to FAISS vector store...")
        try:
            vector_store.add_documents(doc_chunks_with_meta)
            log("Successfully indexed all chunks")
        except Exception as e:
            logger.error("Failed to add chunks to FAISS vector store: %s", e, exc_info=True)
            log(f"ERROR: Failed to index chunks: {e}")
            return None

    # Create and cache retriever
    _cached_retriever = SimpleRetriever(vector_store)
    _cached_sources_hash = sources_hash
    _cached_documents = doc_chunks_with_meta

    # Initialize optimization components
    if enable_query_expansion:
        _cached_query_expander = create_query_expander(max_expansions=5)
        log("Initialized query expander for improved recall")

    if enable_reranking:
        _cached_reranker = create_reranker(similarity_threshold=0.1)
        log("Initialized reranker for improved precision")

    if enable_hybrid_search and _cached_documents:
        _cached_hybrid_searcher = create_hybrid_searcher(
            vector_retriever=_cached_retriever,
            bm25_weight=0.4,
            vector_weight=0.6,
            documents=_cached_documents,
        )
        log("Initialized hybrid search (BM25 + vector)")

    log(f"Knowledge base initialized with {len(all_chunks)} chunks from {len(doc_paths)} source(s)")
    return _cached_retriever


class SafeKnowledgeQueryTool:
    """
    A crash-safe wrapper around KnowledgeBaseQueryTool.

    Enhanced with:
    - Query expansion for improved recall
    - Hybrid search (BM25 + vector) for better coverage
    - Reranking for improved precision
    - Content-fingerprint contamination filter (v2.4): excludes docs whose
      stored site fingerprint (title/h1/form) matches the current run's
      fingerprint — robust to URL changes and similar challenges at different
      paths.  URL-based filtering was removed because it was fragile.
    - Seen-doc exclusion per run: prevents the same doc from appearing in
      every query response within a single run (VOYAGER, Wang et al. 2023)
    - rag_queries_made counter incremented on every use() call
    - Mid-session index refresh via refresh_index()
    """

    def __init__(
        self,
        retriever: SimpleRetriever,
        platform_name: str = "Generic CTF",
        use_query_expansion: bool = True,
        use_hybrid_search: bool = True,
        use_reranking: bool = True,
        top_k: int = 5,
        rag_config: Optional["SolverConfig"] = None,
    ):
        self._retriever = retriever
        self._use_query_expansion = use_query_expansion
        self._use_hybrid_search = use_hybrid_search
        self._use_reranking = use_reranking
        self._top_k = top_k
        self._rag_config = rag_config  # Stored so refresh_index() can rebuild

        # Tracker reference for fingerprint access + rag_queries_made tracking
        # (TYPE_CHECKING import avoided; we access attributes by name at runtime)
        self._tracker: Optional[Any] = None

        # Seen-doc exclusion (reset via reset_session)
        self._seen_source_files: set = set()

        self.name = "ctf_knowledge_query"
        self.description = (
            f"Consult an internal {platform_name} knowledge base for help on topics such as "
            "SQL injection, XSS, CSRF, robots.txt enumeration, cookies, client-side validation, "
            "authentication bypasses, deserialization, race conditions, GraphQL, WebSocket, "
            "JWT attacks, SSTI, XXE, file uploads, and other web exploitation techniques. "
            "Input should be a natural-language question like 'How do I exploit a simple login "
            "form with SQL injection?' or 'What payloads work for template injection?'. "
            "The tool returns the most relevant passages from the knowledge base. "
            "Use this tool when you need guidance on exploitation techniques."
        )

    def set_challenge_context(
        self,
        challenge_name: Optional[str] = None,
        tracker: Optional[Any] = None,
    ) -> None:
        """Store tracker reference for fingerprint-based contamination filtering.

        The site fingerprint (page title/h1/form action extracted by RunTracker
        from the first http_fetch output) is used at query time to exclude docs
        that describe the same website — avoiding contamination from the agent's
        own prior runs on the same challenge.

        challenge_name is kept for Reflexion slug lookup only (not filtering).
        """
        self._tracker = tracker

    def reset_session(self) -> None:
        """Reset the seen-doc set. Call at the start of each agent run."""
        self._seen_source_files = set()

    def _is_excluded(self, doc_content: str) -> bool:
        """Return True if doc_content belongs to the current challenge.

        Compares the stored site fingerprint in the doc (written by
        generate_atomic_rule_doc) against the current run's fingerprint
        (lazily populated by RunTracker from the first http_fetch output).

        Returns False if either fingerprint is empty — never over-filters.
        """
        if not self._tracker:
            return False
        current_fp: str = getattr(self._tracker, "site_fingerprint", "")
        if not current_fp:
            return False
        fp_match = re.search(r"\*\*Site fingerprint:\*\*\s*(.+)", doc_content)
        if not fp_match:
            return False
        doc_fp = fp_match.group(1).strip()
        if not doc_fp:
            return False
        # Jaccard similarity on word tokens
        wa = set(re.findall(r"\w+", current_fp.lower()))
        wb = set(re.findall(r"\w+", doc_fp.lower()))
        if not wa or not wb:
            return False
        overlap = len(wa & wb) / len(wa | wb)
        return overlap >= 0.60

    def refresh_index(self) -> None:
        """Rebuild the retriever from the stored rag_config.

        Call this after run_lessons_learned_pipeline() writes new docs so the
        new atomic rules become queryable in the same session without restarting.
        """
        if self._rag_config is None:
            logger.warning("[RAG] refresh_index called but no rag_config stored; skipping.")
            return
        try:
            clear_cache()
            new_retriever = initialize_knowledge_base(self._rag_config)
            if new_retriever is not None:
                self._retriever = new_retriever
                logger.info("[RAG] Index rebuilt — new lessons docs are now queryable.")
        except Exception as exc:
            logger.error("[RAG] refresh_index failed: %s", exc, exc_info=True)

    def use(self, query: str) -> str:
        """Execute a knowledge base query with crash protection.

        This is the primary method called by FAIR's LoggingToolWrapper.

        Uses query expansion, hybrid search, reranking, fingerprint-based
        contamination filtering, and seen-doc exclusion for improved retrieval.
        """
        # Increment rag_queries_made metric
        if self._tracker is not None:
            try:
                self._tracker.rag_queries_made += 1
            except AttributeError:
                pass

        try:
            expanded_query = query

            # Step 1: Query expansion
            if self._use_query_expansion and _cached_query_expander is not None:
                expanded_query = _cached_query_expander.expand_query(query)
                logger.debug(f"Expanded query: {expanded_query}")

            # Step 2: Retrieve results (hybrid or vector-only) — over-retrieve
            # to account for filtering losses in steps 3–4
            over_k = self._top_k * 3
            if self._use_hybrid_search and _cached_hybrid_searcher is not None:
                hybrid_results = _cached_hybrid_searcher.search(
                    expanded_query, top_k=over_k
                )
                results = [hr.document for hr in hybrid_results]
            else:
                results = self._retriever.retrieve(expanded_query, top_k=over_k)

            if not results:
                return "No relevant information found in the knowledge base."

            # Step 3: Apply fingerprint-based contamination filter and seen-doc exclusion
            filtered: list = []
            for doc in results:
                content = getattr(doc, "page_content", str(doc))
                metadata = getattr(doc, "metadata", {})
                sf = metadata.get("source_file", "")
                if self._is_excluded(content):
                    logger.debug(f"[RAG] Excluded same-challenge doc (fingerprint match): {sf}")
                    continue
                if sf in self._seen_source_files:
                    logger.debug(f"[RAG] Excluded already-seen doc: {sf}")
                    continue
                filtered.append(doc)

            if not filtered:
                return "No relevant information found in the knowledge base (all results filtered)."

            # Step 4: Rerank filtered results
            if self._use_reranking and _cached_reranker is not None:
                scored_results = _cached_reranker.rerank(
                    query,  # Use original query for reranking
                    filtered,
                    top_k=self._top_k,
                )
                results = [sr.document for sr in scored_results]
            else:
                results = filtered[: self._top_k]

            # Step 5: Apply doc_type boosting — prefer consolidated_wisdom > success > failure
            _DOC_TYPE_BOOST = {
                "consolidated": 1.15,
                "experience_success": 1.10,
                "experience_failure": 1.0,
                "curated": 1.0,
            }

            def _boost_key(d: object) -> float:
                dt = getattr(d, "metadata", {}).get("doc_type", "")
                for k, boost in _DOC_TYPE_BOOST.items():
                    if k in dt:
                        return -boost  # negative for sort ascending
                return -1.0

            results.sort(key=_boost_key)

            # Step 6: Record seen docs to prevent repetition within this run
            for doc in results:
                sf = getattr(doc, "metadata", {}).get("source_file", "")
                if sf:
                    self._seen_source_files.add(sf)

            # Format results with metadata
            formatted = []
            for i, doc in enumerate(results, 1):
                content = getattr(doc, "page_content", str(doc))
                metadata = getattr(doc, "metadata", {})

                # Build header with metadata
                header_parts = [f"[Result {i}]"]
                if metadata.get("source_file"):
                    header_parts.append(f"Source: {metadata['source_file']}")
                if metadata.get("section"):
                    header_parts.append(f"Section: {metadata['section']}")
                if metadata.get("tags"):
                    header_parts.append(f"Tags: {', '.join(metadata['tags'][:3])}")

                header = " | ".join(header_parts)

                # Truncate very long results
                if len(content) > 1500:
                    content = content[:1500] + "..."

                formatted.append(f"{header}\n{content}")

            return "\n\n".join(formatted)
        except Exception as e:
            logger.error("Knowledge base query failed: %s", e, exc_info=True)
            return f"Knowledge base query failed: {str(e)}. Try a different approach."

    def run(self, query: str) -> str:
        """Alias for use() for compatibility."""
        return self.use(query)

    def __call__(self, query: str) -> str:
        """Allow the tool to be called directly."""
        return self.use(query)


# ---------------------------------------------------------------------------
# Module-level active-tool registry (for mid-session refresh)
# ---------------------------------------------------------------------------

_active_tool: Optional[SafeKnowledgeQueryTool] = None


def get_active_knowledge_tool() -> Optional[SafeKnowledgeQueryTool]:
    """Return the currently registered SafeKnowledgeQueryTool, or None."""
    return _active_tool


def set_active_knowledge_tool(tool: SafeKnowledgeQueryTool) -> None:
    """Register the active SafeKnowledgeQueryTool for post-run index refresh."""
    global _active_tool
    _active_tool = tool


def build_knowledge_tool(
    retriever: Optional[SimpleRetriever],
    platform_name: str = "Generic CTF",
    use_query_expansion: bool = True,
    use_hybrid_search: bool = True,
    use_reranking: bool = True,
    top_k: int = 5,
    rag_config: Optional["SolverConfig"] = None,
) -> Optional[SafeKnowledgeQueryTool]:
    """
    Create a crash-safe CTF knowledge query tool.

    Uses SafeKnowledgeQueryTool wrapper instead of raw KnowledgeBaseQueryTool
    to prevent segmentation faults on Apple Silicon.

    Args:
        retriever: The SimpleRetriever instance
        platform_name: Name of the CTF platform for tool description
        use_query_expansion: Enable query expansion for better recall
        use_hybrid_search: Enable BM25 + vector hybrid search
        use_reranking: Enable result reranking for better precision
        top_k: Number of results to return
        rag_config: SolverConfig used to build this retriever (for refresh_index)

    Returns:
        SafeKnowledgeQueryTool instance or None if retriever is None
    """
    if retriever is None:
        logger.warning(
            "No retriever available; knowledge query tool will not be registered."
        )
        return None

    return SafeKnowledgeQueryTool(
        retriever,
        platform_name,
        use_query_expansion=use_query_expansion,
        use_hybrid_search=use_hybrid_search,
        use_reranking=use_reranking,
        top_k=top_k,
        rag_config=rag_config,
    )


def clear_cache() -> None:
    """Clear all cached components to force rebuild on next initialization."""
    global _cached_retriever, _cached_sources_hash
    global _cached_hybrid_searcher, _cached_query_expander, _cached_reranker
    global _cached_documents

    _cached_retriever = None
    _cached_sources_hash = None
    _cached_hybrid_searcher = None
    _cached_query_expander = None
    _cached_reranker = None
    _cached_documents = []


def get_optimization_status() -> Dict[str, bool]:
    """
    Get the status of RAG optimization components.

    Returns:
        Dict with component availability status
    """
    return {
        "retriever": _cached_retriever is not None,
        "query_expander": _cached_query_expander is not None,
        "reranker": _cached_reranker is not None,
        "hybrid_searcher": _cached_hybrid_searcher is not None,
        "documents_indexed": len(_cached_documents) > 0,
        "document_count": len(_cached_documents),
    }


def get_query_expander() -> Optional[QueryExpander]:
    """Get the cached query expander instance."""
    return _cached_query_expander


def get_reranker() -> Optional[SimpleReranker]:
    """Get the cached reranker instance."""
    return _cached_reranker


def get_hybrid_searcher() -> Optional[HybridSearcher]:
    """Get the cached hybrid searcher instance."""
    return _cached_hybrid_searcher
