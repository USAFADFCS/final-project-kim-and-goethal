"""
Simple reranking for improved RAG retrieval in CTF solving.

Provides lightweight reranking of retrieval results based on
keyword overlap, term frequency, and domain-specific signals.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ScoredDocument:
    """A document with its reranking score."""

    document: Any  # The original Document object
    score: float
    match_details: Dict[str, float]

    @property
    def page_content(self) -> str:
        """Get document content."""
        return getattr(self.document, "page_content", str(self.document))


class SimpleReranker:
    """
    Lightweight reranker for retrieval results.

    Scores documents based on:
    - Query term overlap (TF-IDF-like scoring)
    - Exact phrase matching
    - CTF-specific term boosting
    - Position-based scoring (terms early in doc score higher)
    """

    # CTF-specific high-value terms that should boost scores
    HIGH_VALUE_TERMS: Set[str] = {
        # Vulnerabilities
        "sql injection", "sqli", "xss", "csrf", "ssrf", "xxe", "lfi", "rfi",
        "ssti", "rce", "deserialization", "race condition", "jwt",
        # Actions
        "exploit", "bypass", "payload", "injection", "attack", "vulnerability",
        # Results
        "flag", "shell", "admin", "root", "password", "secret", "key",
        # Techniques
        "bruteforce", "enumeration", "fuzzing", "scanning",
    }

    # Section headers that indicate high-relevance content
    SECTION_INDICATORS: List[str] = [
        "when to use",
        "agent takeaway",
        "quick reference",
        "exploit",
        "payload",
        "attack",
        "technique",
        "detection",
        "example",
        "script",
    ]

    def __init__(
        self,
        term_weight: float = 0.4,
        phrase_weight: float = 0.3,
        boost_weight: float = 0.2,
        position_weight: float = 0.1,
        similarity_threshold: float = 0.1,
    ):
        """
        Initialize SimpleReranker.

        Args:
            term_weight: Weight for term overlap scoring (0-1)
            phrase_weight: Weight for exact phrase matching (0-1)
            boost_weight: Weight for CTF-specific term boosting (0-1)
            position_weight: Weight for position-based scoring (0-1)
            similarity_threshold: Minimum score to include document
        """
        self.term_weight = term_weight
        self.phrase_weight = phrase_weight
        self.boost_weight = boost_weight
        self.position_weight = position_weight
        self.similarity_threshold = similarity_threshold

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization to lowercase words."""
        return re.findall(r'\b[a-z0-9]+\b', text.lower())

    def _compute_term_overlap(
        self, query_terms: List[str], doc_terms: List[str]
    ) -> float:
        """
        Compute term overlap score using TF-IDF-like weighting.

        Args:
            query_terms: Tokenized query terms
            doc_terms: Tokenized document terms

        Returns:
            Overlap score between 0 and 1
        """
        if not query_terms or not doc_terms:
            return 0.0

        query_set = set(query_terms)
        doc_counter = Counter(doc_terms)
        doc_len = len(doc_terms)

        overlap_score = 0.0
        for term in query_set:
            if term in doc_counter:
                # TF component: log-scaled term frequency
                tf = 1 + math.log(doc_counter[term]) if doc_counter[term] > 0 else 0
                # Length normalization
                overlap_score += tf / math.sqrt(doc_len)

        # Normalize by query length
        return overlap_score / len(query_set)

    def _compute_phrase_match(self, query: str, doc_content: str) -> float:
        """
        Compute exact phrase matching score.

        Args:
            query: Original query string
            doc_content: Document content

        Returns:
            Phrase match score between 0 and 1
        """
        query_lower = query.lower()
        doc_lower = doc_content.lower()

        # Check for exact query match
        if query_lower in doc_lower:
            return 1.0

        # Check for significant subphrases (3+ words)
        words = query_lower.split()
        if len(words) >= 3:
            # Try progressively smaller phrases
            max_score = 0.0
            for phrase_len in range(len(words), 2, -1):
                for i in range(len(words) - phrase_len + 1):
                    phrase = " ".join(words[i:i + phrase_len])
                    if phrase in doc_lower:
                        # Score based on phrase length relative to query
                        score = phrase_len / len(words)
                        max_score = max(max_score, score)
            return max_score

        return 0.0

    def _compute_boost_score(self, doc_content: str) -> float:
        """
        Compute CTF-specific term boost score.

        Args:
            doc_content: Document content

        Returns:
            Boost score between 0 and 1
        """
        doc_lower = doc_content.lower()
        matches = 0

        for term in self.HIGH_VALUE_TERMS:
            if term in doc_lower:
                matches += 1

        # Also check section indicators
        for indicator in self.SECTION_INDICATORS:
            if indicator in doc_lower:
                matches += 0.5

        # Cap at 1.0
        return min(matches / 10.0, 1.0)

    def _compute_position_score(
        self, query_terms: List[str], doc_content: str
    ) -> float:
        """
        Score based on where query terms appear in document.

        Terms appearing early in the document score higher.

        Args:
            query_terms: Tokenized query terms
            doc_content: Document content

        Returns:
            Position score between 0 and 1
        """
        if not query_terms or not doc_content:
            return 0.0

        doc_lower = doc_content.lower()
        doc_len = len(doc_lower)
        if doc_len == 0:
            return 0.0

        position_scores = []
        for term in set(query_terms):
            pos = doc_lower.find(term)
            if pos != -1:
                # Earlier position = higher score
                position_scores.append(1.0 - (pos / doc_len))

        if position_scores:
            return sum(position_scores) / len(position_scores)
        return 0.0

    def score_document(
        self, query: str, document: Any
    ) -> Tuple[float, Dict[str, float]]:
        """
        Score a single document against a query.

        Args:
            query: The search query
            document: Document object with page_content attribute

        Returns:
            Tuple of (total_score, score_details)
        """
        doc_content = getattr(document, "page_content", str(document))

        query_terms = self._tokenize(query)
        doc_terms = self._tokenize(doc_content)

        # Compute component scores
        term_score = self._compute_term_overlap(query_terms, doc_terms)
        phrase_score = self._compute_phrase_match(query, doc_content)
        boost_score = self._compute_boost_score(doc_content)
        position_score = self._compute_position_score(query_terms, doc_content)

        # Weighted combination
        total_score = (
            self.term_weight * term_score
            + self.phrase_weight * phrase_score
            + self.boost_weight * boost_score
            + self.position_weight * position_score
        )

        details = {
            "term_overlap": term_score,
            "phrase_match": phrase_score,
            "ctf_boost": boost_score,
            "position": position_score,
        }

        return total_score, details

    def rerank(
        self,
        query: str,
        documents: List[Any],
        top_k: Optional[int] = None,
    ) -> List[ScoredDocument]:
        """
        Rerank a list of documents based on query relevance.

        Args:
            query: The search query
            documents: List of documents to rerank
            top_k: Maximum number of results to return

        Returns:
            List of ScoredDocument objects, sorted by score descending
        """
        scored_docs = []

        for doc in documents:
            score, details = self.score_document(query, doc)

            # Apply similarity threshold
            if score >= self.similarity_threshold:
                scored_docs.append(
                    ScoredDocument(document=doc, score=score, match_details=details)
                )

        # Sort by score descending
        scored_docs.sort(key=lambda x: x.score, reverse=True)

        if top_k is not None:
            scored_docs = scored_docs[:top_k]

        return scored_docs

    def rerank_with_original_scores(
        self,
        query: str,
        documents: List[Any],
        original_scores: List[float],
        original_weight: float = 0.3,
        top_k: Optional[int] = None,
    ) -> List[ScoredDocument]:
        """
        Rerank documents, incorporating original retrieval scores.

        Args:
            query: The search query
            documents: List of documents to rerank
            original_scores: Original similarity scores from vector search
            original_weight: Weight to give original scores (0-1)
            top_k: Maximum number of results to return

        Returns:
            List of ScoredDocument objects with combined scores
        """
        if len(documents) != len(original_scores):
            raise ValueError("documents and original_scores must have same length")

        scored_docs = []
        rerank_weight = 1.0 - original_weight

        for doc, orig_score in zip(documents, original_scores):
            rerank_score, details = self.score_document(query, doc)

            # Normalize original score to 0-1 range if needed
            orig_normalized = min(max(orig_score, 0.0), 1.0)

            # Combine scores
            combined_score = (
                original_weight * orig_normalized + rerank_weight * rerank_score
            )

            details["original_score"] = orig_normalized
            details["rerank_score"] = rerank_score

            if combined_score >= self.similarity_threshold:
                scored_docs.append(
                    ScoredDocument(
                        document=doc, score=combined_score, match_details=details
                    )
                )

        scored_docs.sort(key=lambda x: x.score, reverse=True)

        if top_k is not None:
            scored_docs = scored_docs[:top_k]

        return scored_docs


def create_reranker(
    similarity_threshold: float = 0.1,
    term_weight: float = 0.4,
    phrase_weight: float = 0.3,
    boost_weight: float = 0.2,
    position_weight: float = 0.1,
) -> SimpleReranker:
    """
    Factory function to create a SimpleReranker.

    Args:
        similarity_threshold: Minimum score to include document
        term_weight: Weight for term overlap scoring
        phrase_weight: Weight for exact phrase matching
        boost_weight: Weight for CTF-specific term boosting
        position_weight: Weight for position-based scoring

    Returns:
        Configured SimpleReranker instance
    """
    return SimpleReranker(
        term_weight=term_weight,
        phrase_weight=phrase_weight,
        boost_weight=boost_weight,
        position_weight=position_weight,
        similarity_threshold=similarity_threshold,
    )
