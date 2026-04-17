"""
Hybrid search combining BM25 (keyword) and vector (semantic) search.

Provides better retrieval by combining the precision of keyword matching
with the semantic understanding of embeddings.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DocumentWithMetadata:
    """A document with associated metadata for enhanced retrieval."""

    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    doc_id: Optional[str] = None

    @property
    def page_content(self) -> str:
        """Compatibility property for FAIR Document interface."""
        return self.content


@dataclass
class HybridResult:
    """Result from hybrid search with combined scoring."""

    document: Any
    bm25_score: float
    vector_score: float
    combined_score: float
    rank_bm25: int
    rank_vector: int


class BM25Index:
    """
    BM25 (Best Matching 25) index for keyword-based retrieval.

    Implementation of the Okapi BM25 ranking function for
    efficient keyword search over document collections.
    """

    def __init__(
        self,
        k1: float = 1.5,
        b: float = 0.75,
        epsilon: float = 0.25,
    ):
        """
        Initialize BM25 index.

        Args:
            k1: Term frequency saturation parameter (1.2-2.0 typical)
            b: Length normalization parameter (0-1, 0.75 typical)
            epsilon: Floor for IDF to prevent negative scores
        """
        self.k1 = k1
        self.b = b
        self.epsilon = epsilon

        self.documents: List[Any] = []
        self.doc_lengths: List[int] = []
        self.avg_doc_length: float = 0.0
        self.doc_freqs: Dict[str, int] = {}  # term -> num docs containing term
        self.term_freqs: List[Dict[str, int]] = []  # per-doc term frequencies
        self.idf: Dict[str, float] = {}
        self._indexed = False

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into lowercase terms."""
        return re.findall(r"\b[a-z0-9]+\b", text.lower())

    def index(self, documents: List[Any]) -> None:
        """
        Build BM25 index from documents.

        Args:
            documents: List of documents with page_content attribute
        """
        self.documents = documents
        self.doc_lengths = []
        self.doc_freqs = Counter()
        self.term_freqs = []

        # First pass: compute term frequencies and document frequencies
        for doc in documents:
            content = getattr(doc, "page_content", str(doc))
            terms = self._tokenize(content)
            self.doc_lengths.append(len(terms))

            # Term frequency for this document
            tf = Counter(terms)
            self.term_freqs.append(tf)

            # Document frequency (count unique terms)
            for term in set(terms):
                self.doc_freqs[term] += 1

        # Compute average document length
        if self.doc_lengths:
            self.avg_doc_length = sum(self.doc_lengths) / len(self.doc_lengths)
        else:
            self.avg_doc_length = 0.0

        # Compute IDF for all terms
        n_docs = len(documents)
        for term, df in self.doc_freqs.items():
            # Standard BM25 IDF with epsilon floor
            idf = math.log((n_docs - df + 0.5) / (df + 0.5) + 1)
            self.idf[term] = max(idf, self.epsilon)

        self._indexed = True

    def search(
        self,
        query: str,
        top_k: int = 10,
    ) -> List[Tuple[Any, float]]:
        """
        Search index with BM25 scoring.

        Args:
            query: Search query string
            top_k: Number of results to return

        Returns:
            List of (document, score) tuples, sorted by score descending
        """
        if not self._indexed:
            raise RuntimeError("Index not built. Call index() first.")

        query_terms = self._tokenize(query)
        if not query_terms:
            return []

        scores: List[Tuple[int, float]] = []

        for doc_idx, doc in enumerate(self.documents):
            score = self._score_document(query_terms, doc_idx)
            if score > 0:
                scores.append((doc_idx, score))

        # Sort by score descending
        scores.sort(key=lambda x: x[1], reverse=True)

        # Return top_k results
        results = []
        for doc_idx, score in scores[:top_k]:
            results.append((self.documents[doc_idx], score))

        return results

    def _score_document(self, query_terms: List[str], doc_idx: int) -> float:
        """
        Compute BM25 score for a document.

        Args:
            query_terms: Tokenized query
            doc_idx: Document index

        Returns:
            BM25 score
        """
        doc_len = self.doc_lengths[doc_idx]
        term_freq = self.term_freqs[doc_idx]

        score = 0.0
        for term in query_terms:
            if term not in self.idf:
                continue

            tf = term_freq.get(term, 0)
            if tf == 0:
                continue

            idf = self.idf[term]

            # BM25 scoring formula
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (
                1 - self.b + self.b * (doc_len / self.avg_doc_length)
            )
            score += idf * (numerator / denominator)

        return score


class HybridSearcher:
    """
    Hybrid search combining BM25 and vector similarity.

    Uses Reciprocal Rank Fusion (RRF) to combine results from
    keyword-based (BM25) and semantic (vector) search.
    """

    def __init__(
        self,
        vector_retriever: Any,
        bm25_weight: float = 0.4,
        vector_weight: float = 0.6,
        rrf_k: int = 60,
    ):
        """
        Initialize HybridSearcher.

        Args:
            vector_retriever: FAIR SimpleRetriever for vector search
            bm25_weight: Weight for BM25 scores in combination
            vector_weight: Weight for vector scores in combination
            rrf_k: RRF constant (typically 60)
        """
        self.vector_retriever = vector_retriever
        self.bm25_weight = bm25_weight
        self.vector_weight = vector_weight
        self.rrf_k = rrf_k

        self.bm25_index = BM25Index()
        self._documents_indexed = False

    def index_documents(self, documents: List[Any]) -> None:
        """
        Build BM25 index from documents.

        Args:
            documents: List of documents to index
        """
        self.bm25_index.index(documents)
        self._documents_indexed = True

    def _normalize_scores(self, scores: List[float]) -> List[float]:
        """Normalize scores to 0-1 range."""
        if not scores:
            return []

        min_score = min(scores)
        max_score = max(scores)
        score_range = max_score - min_score

        if score_range == 0:
            return [1.0] * len(scores)

        return [(s - min_score) / score_range for s in scores]

    def _compute_rrf_score(self, ranks: List[int]) -> float:
        """
        Compute Reciprocal Rank Fusion score.

        Args:
            ranks: List of ranks (1-indexed)

        Returns:
            RRF score
        """
        return sum(1.0 / (self.rrf_k + rank) for rank in ranks)

    def search(
        self,
        query: str,
        top_k: int = 5,
        vector_top_k: int = 10,
        bm25_top_k: int = 10,
    ) -> List[HybridResult]:
        """
        Perform hybrid search combining BM25 and vector results.

        Args:
            query: Search query
            top_k: Number of final results to return
            vector_top_k: Number of results from vector search
            bm25_top_k: Number of results from BM25 search

        Returns:
            List of HybridResult objects
        """
        # Get vector search results
        vector_results = self.vector_retriever.retrieve(query, top_k=vector_top_k)

        # Get BM25 results if indexed
        if self._documents_indexed:
            bm25_results = self.bm25_index.search(query, top_k=bm25_top_k)
        else:
            bm25_results = []

        # Build document ID to result mapping
        doc_scores: Dict[int, Dict[str, Any]] = {}

        # Process vector results
        for rank, doc in enumerate(vector_results, 1):
            doc_id = id(doc)
            doc_scores[doc_id] = {
                "document": doc,
                "vector_rank": rank,
                "bm25_rank": bm25_top_k + 1,  # Default to out of ranking
                "vector_score": 1.0 - (rank - 1) / vector_top_k,  # Approximate score
                "bm25_score": 0.0,
            }

        # Process BM25 results
        for rank, (doc, score) in enumerate(bm25_results, 1):
            doc_id = id(doc)
            if doc_id in doc_scores:
                doc_scores[doc_id]["bm25_rank"] = rank
                doc_scores[doc_id]["bm25_score"] = score
            else:
                doc_scores[doc_id] = {
                    "document": doc,
                    "vector_rank": vector_top_k + 1,
                    "bm25_rank": rank,
                    "vector_score": 0.0,
                    "bm25_score": score,
                }

        # Normalize BM25 scores
        if bm25_results:
            max_bm25 = max(s["bm25_score"] for s in doc_scores.values())
            if max_bm25 > 0:
                for scores in doc_scores.values():
                    scores["bm25_score"] /= max_bm25

        # Compute combined scores using RRF
        results = []
        for doc_id, scores in doc_scores.items():
            # RRF-based combination
            rrf_vector = 1.0 / (self.rrf_k + scores["vector_rank"])
            rrf_bm25 = 1.0 / (self.rrf_k + scores["bm25_rank"])
            combined = self.vector_weight * rrf_vector + self.bm25_weight * rrf_bm25

            results.append(
                HybridResult(
                    document=scores["document"],
                    bm25_score=scores["bm25_score"],
                    vector_score=scores["vector_score"],
                    combined_score=combined,
                    rank_bm25=scores["bm25_rank"],
                    rank_vector=scores["vector_rank"],
                )
            )

        # Sort by combined score
        results.sort(key=lambda x: x.combined_score, reverse=True)

        return results[:top_k]

    def search_vector_only(
        self,
        query: str,
        top_k: int = 5,
    ) -> List[Any]:
        """
        Search using only vector similarity.

        Args:
            query: Search query
            top_k: Number of results

        Returns:
            List of documents
        """
        return self.vector_retriever.retrieve(query, top_k=top_k)

    def search_bm25_only(
        self,
        query: str,
        top_k: int = 5,
    ) -> List[Tuple[Any, float]]:
        """
        Search using only BM25.

        Args:
            query: Search query
            top_k: Number of results

        Returns:
            List of (document, score) tuples
        """
        if not self._documents_indexed:
            return []
        return self.bm25_index.search(query, top_k=top_k)


def create_hybrid_searcher(
    vector_retriever: Any,
    bm25_weight: float = 0.4,
    vector_weight: float = 0.6,
    documents: Optional[List[Any]] = None,
) -> HybridSearcher:
    """
    Factory function to create a HybridSearcher.

    Args:
        vector_retriever: FAIR SimpleRetriever for vector search
        bm25_weight: Weight for BM25 scores
        vector_weight: Weight for vector scores
        documents: Optional documents to index for BM25

    Returns:
        Configured HybridSearcher instance
    """
    searcher = HybridSearcher(
        vector_retriever=vector_retriever,
        bm25_weight=bm25_weight,
        vector_weight=vector_weight,
    )

    if documents:
        searcher.index_documents(documents)

    return searcher
