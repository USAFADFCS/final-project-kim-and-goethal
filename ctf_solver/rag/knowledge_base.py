"""
Knowledge base initialization and management for CTF Solver.

Provides RAG (Retrieval-Augmented Generation) capabilities using
FAIR framework components with configurable document sources.
"""

import logging
import os
from pathlib import Path
from typing import List, Optional, Callable

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

logger = logging.getLogger(__name__)

# Module-level cache for the retriever
_cached_retriever: Optional[SimpleRetriever] = None
_cached_sources_hash: Optional[str] = None


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


def _compute_sources_hash(config: SolverConfig) -> str:
    """Compute a hash of the knowledge base sources for cache invalidation."""
    sources = sorted(str(p) for p in config.get_all_kb_paths())
    return "|".join(sources)


def initialize_knowledge_base(
    config: SolverConfig,
    force_rebuild: bool = False,
    log_callback: Optional[Callable[[str], None]] = None,
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

    Args:
        config: Solver configuration
        force_rebuild: Force rebuild even if cached
        log_callback: Optional callback for log messages

    Returns:
        SimpleRetriever instance or None if initialization fails
    """
    global _cached_retriever, _cached_sources_hash

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
        except Exception as e:
            log(f"Creating new FAISS index at {index_dir}")
    except Exception as e:
        logger.error("Failed to initialize FaissVectorStore: %s", e, exc_info=True)
        return None

    # Process documents
    # Use the first doc path's parent as the base directory
    base_dir = doc_paths[0].parent if doc_paths else Path.cwd()
    doc_proc = DocumentProcessor({"files_directory": str(base_dir)})

    all_chunks: List[str] = []

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
            # Chunk the document for retrieval
            chunks = split_text(text, chunk_size=1200, chunk_overlap=200)
            all_chunks.extend(chunks)

        log(f"Processed {path.name}: {len(docs)} document(s)")

    if not all_chunks:
        log("WARNING: No document chunks were created; knowledge base will be empty.")
    else:
        log(f"Adding {len(all_chunks)} chunks to FAISS vector store...")
        try:
            # Wrap string chunks in Document objects (FaissVectorStore expects .page_content)
            doc_chunks = [Document(page_content=chunk) for chunk in all_chunks]
            vector_store.add_documents(doc_chunks)
            log("Successfully indexed all chunks")
        except Exception as e:
            logger.error("Failed to add chunks to FAISS vector store: %s", e, exc_info=True)
            log(f"ERROR: Failed to index chunks: {e}")
            return None

    # Create and cache retriever
    _cached_retriever = SimpleRetriever(vector_store)
    _cached_sources_hash = sources_hash

    log(f"Knowledge base initialized with {len(all_chunks)} chunks from {len(doc_paths)} source(s)")
    return _cached_retriever


class SafeKnowledgeQueryTool:
    """
    A crash-safe wrapper around KnowledgeBaseQueryTool.

    This wrapper catches exceptions during retrieval to prevent segmentation
    faults or crashes from bringing down the entire application.
    """

    def __init__(self, retriever: SimpleRetriever, platform_name: str = "Generic CTF"):
        self._retriever = retriever
        self.name = "ctf_knowledge_query"
        self.description = (
            f"Consult an internal {platform_name} knowledge base for help on topics such as "
            "SQL injection, XSS, CSRF, robots.txt enumeration, cookies, client-side validation, "
            "authentication bypasses, and other web exploitation techniques. Input should be a "
            "natural-language question like 'How do I exploit a simple login form with SQL injection?' "
            "or 'What should I look for in robots.txt?'. The tool returns the most relevant passages "
            "from the knowledge base. Use this tool when you need guidance on exploitation techniques."
        )

    def use(self, query: str) -> str:
        """Execute a knowledge base query with crash protection.

        This is the primary method called by FAIR's LoggingToolWrapper.
        """
        try:
            results = self._retriever.retrieve(query, top_k=3)
            if not results:
                return "No relevant information found in the knowledge base."

            # Format results
            formatted = []
            for i, doc in enumerate(results, 1):
                content = getattr(doc, "page_content", str(doc))
                # Truncate very long results
                if len(content) > 1500:
                    content = content[:1500] + "..."
                formatted.append(f"[Result {i}]\n{content}")

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


def build_knowledge_tool(
    retriever: Optional[SimpleRetriever],
    platform_name: str = "Generic CTF",
) -> Optional[SafeKnowledgeQueryTool]:
    """
    Create a crash-safe CTF knowledge query tool.

    Uses SafeKnowledgeQueryTool wrapper instead of raw KnowledgeBaseQueryTool
    to prevent segmentation faults on Apple Silicon.

    Args:
        retriever: The SimpleRetriever instance
        platform_name: Name of the CTF platform for tool description

    Returns:
        SafeKnowledgeQueryTool instance or None if retriever is None
    """
    if retriever is None:
        logger.warning(
            "No retriever available; knowledge query tool will not be registered."
        )
        return None

    return SafeKnowledgeQueryTool(retriever, platform_name)


def clear_cache() -> None:
    """Clear the cached retriever to force rebuild on next initialization."""
    global _cached_retriever, _cached_sources_hash
    _cached_retriever = None
    _cached_sources_hash = None
