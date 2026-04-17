"""
Tests for RAG optimization components.

Tests QueryExpander, SimpleReranker, HybridSearcher, and integration.
"""

import pytest
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from unittest.mock import Mock, MagicMock, patch

# =============================================================================
# Test Fixtures
# =============================================================================


@dataclass
class MockDocument:
    """Mock document for testing."""

    page_content: str
    metadata: Optional[Dict[str, Any]] = None


@pytest.fixture
def sample_documents():
    """Create sample documents for testing."""
    return [
        MockDocument(
            page_content="SQL injection is a code injection technique. "
            "Use UNION SELECT to extract data from databases. "
            "Common payloads include ' OR '1'='1 for authentication bypass.",
            metadata={"source_file": "sqli.md", "section": "Basics"},
        ),
        MockDocument(
            page_content="Cross-site scripting (XSS) allows attackers to inject "
            "malicious scripts. Use <script>alert(1)</script> to test. "
            "DOM-based XSS occurs in client-side code.",
            metadata={"source_file": "xss.md", "section": "Overview"},
        ),
        MockDocument(
            page_content="JWT tokens can be attacked using the none algorithm. "
            "Decode the token, modify claims, and remove signature. "
            "Common secrets to try: secret, password, 123456.",
            metadata={"source_file": "jwt.md", "section": "Attacks"},
        ),
        MockDocument(
            page_content="Server-side template injection (SSTI) occurs when "
            "user input is embedded into templates. Test with {{7*7}}. "
            "Jinja2, Twig, and Freemarker are common engines.",
            metadata={"source_file": "ssti.md", "section": "Detection"},
        ),
        MockDocument(
            page_content="File upload vulnerabilities allow arbitrary file upload. "
            "Bypass extensions with .php.jpg or null bytes. "
            "Use magic bytes to bypass content-type checks.",
            metadata={"source_file": "upload.md", "section": "Bypass"},
        ),
    ]


@pytest.fixture
def mock_retriever(sample_documents):
    """Create mock retriever."""
    retriever = Mock()
    retriever.retrieve = Mock(return_value=sample_documents[:3])
    return retriever


# =============================================================================
# QueryExpander Tests
# =============================================================================


class TestQueryExpander:
    """Tests for QueryExpander class."""

    def test_import(self):
        """Test QueryExpander can be imported."""
        from ctf_solver.rag.query_expander import QueryExpander, create_query_expander

        assert QueryExpander is not None
        assert create_query_expander is not None

    def test_create_expander(self):
        """Test creating QueryExpander instance."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander(max_expansions=5)
        assert expander is not None
        assert expander.max_expansions == 5

    def test_expand_sqli_query(self):
        """Test expansion of SQL injection query."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        query = "How do I do sqli"
        expanded = expander.expand_query(query)

        # Should contain original query
        assert "sqli" in expanded.lower()
        # Should contain expansion terms
        assert "sql injection" in expanded.lower() or "union" in expanded.lower()

    def test_expand_xss_query(self):
        """Test expansion of XSS query."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        query = "xss attack"
        expanded = expander.expand_query(query)

        assert "xss" in expanded.lower()
        assert len(expanded) > len(query)  # Should be expanded

    def test_expand_compound_term(self):
        """Test expansion preserves compound terms."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        query = "sql injection bypass"
        expanded = expander.expand_query(query)

        # Should recognize "sql injection" as compound term
        assert "sql injection" in query.lower()

    def test_expand_empty_query(self):
        """Test expansion of empty query."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        assert expander.expand_query("") == ""
        assert expander.expand_query("   ") == "   "

    def test_no_expansion_unknown_term(self):
        """Test no expansion for unknown terms."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        query = "foobar baz qux"
        expanded = expander.expand_query(query)

        # Should return original query unchanged
        assert expanded == query

    def test_get_expansion_terms(self):
        """Test getting expansion terms for a term."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        terms = expander.get_expansion_terms("jwt")

        assert isinstance(terms, list)
        assert "json web token" in terms or "token" in terms

    def test_add_custom_expansion(self):
        """Test adding custom expansion."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        expander.add_custom_expansion("myterm", ["expansion1", "expansion2"])

        query = "test myterm"
        expanded = expander.expand_query(query)

        assert "expansion1" in expanded or "expansion2" in expanded

    def test_max_expansions_limit(self):
        """Test max expansions limit is respected."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander(max_expansions=2)
        query = "sqli"
        expanded = expander.expand_query(query)

        # Count expansion terms added
        original_words = set(query.lower().split())
        expanded_words = set(expanded.lower().split())
        new_words = expanded_words - original_words

        # Should not exceed max_expansions
        assert len(new_words) <= 2

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        lower = expander.expand_query("sqli attack")
        upper = expander.expand_query("SQLI ATTACK")

        # Both should get expanded (case insensitive)
        assert len(lower) > len("sqli attack")
        assert len(upper) > len("SQLI ATTACK")


# =============================================================================
# SimpleReranker Tests
# =============================================================================


class TestSimpleReranker:
    """Tests for SimpleReranker class."""

    def test_import(self):
        """Test SimpleReranker can be imported."""
        from ctf_solver.rag.reranker import (
            SimpleReranker,
            ScoredDocument,
            create_reranker,
        )

        assert SimpleReranker is not None
        assert ScoredDocument is not None
        assert create_reranker is not None

    def test_create_reranker(self):
        """Test creating SimpleReranker instance."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker(similarity_threshold=0.1)
        assert reranker is not None
        assert reranker.similarity_threshold == 0.1

    def test_score_document(self, sample_documents):
        """Test scoring a single document."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker()
        query = "SQL injection UNION attack"
        doc = sample_documents[0]  # SQL injection document

        score, details = reranker.score_document(query, doc)

        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0
        assert "term_overlap" in details
        assert "phrase_match" in details
        assert "ctf_boost" in details
        assert "position" in details

    def test_rerank_documents(self, sample_documents):
        """Test reranking a list of documents."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker()
        query = "SQL injection"

        results = reranker.rerank(query, sample_documents)

        assert len(results) > 0
        # Should be sorted by score descending
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_rerank_top_k(self, sample_documents):
        """Test top_k limit in reranking."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker(similarity_threshold=0.0)
        query = "attack"

        results = reranker.rerank(query, sample_documents, top_k=2)

        assert len(results) <= 2

    def test_similarity_threshold(self, sample_documents):
        """Test similarity threshold filtering."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker(similarity_threshold=0.9)  # High threshold
        query = "xyz123"  # Unlikely to match

        results = reranker.rerank(query, sample_documents)

        # Should filter out low-scoring documents
        for result in results:
            assert result.score >= 0.9

    def test_scored_document_content(self, sample_documents):
        """Test ScoredDocument page_content property."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker(similarity_threshold=0.0)
        results = reranker.rerank("attack", sample_documents[:1])

        if results:
            assert results[0].page_content == sample_documents[0].page_content

    def test_high_value_terms_boost(self, sample_documents):
        """Test CTF high-value terms get boosted."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker()

        # Document with high-value terms should score higher
        sqli_doc = sample_documents[0]  # Has "SQL injection", "UNION", "payload"
        generic_doc = MockDocument(
            page_content="This is a generic document with no exploits."
        )

        sqli_score, _ = reranker.score_document("test", sqli_doc)
        generic_score, _ = reranker.score_document("test", generic_doc)

        assert sqli_score > generic_score

    def test_rerank_with_original_scores(self, sample_documents):
        """Test reranking with original retrieval scores."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker(similarity_threshold=0.0)
        query = "SQL"
        original_scores = [0.9, 0.7, 0.5, 0.3, 0.1]

        results = reranker.rerank_with_original_scores(
            query, sample_documents, original_scores, original_weight=0.3
        )

        assert len(results) > 0
        for result in results:
            assert "original_score" in result.match_details
            assert "rerank_score" in result.match_details

    def test_rerank_empty_documents(self):
        """Test reranking empty document list."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker()
        results = reranker.rerank("query", [])

        assert results == []


# =============================================================================
# BM25Index Tests
# =============================================================================


class TestBM25Index:
    """Tests for BM25Index class."""

    def test_import(self):
        """Test BM25Index can be imported."""
        from ctf_solver.rag.hybrid_search import BM25Index

        assert BM25Index is not None

    def test_create_index(self):
        """Test creating BM25Index instance."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index(k1=1.5, b=0.75)
        assert index is not None
        assert index.k1 == 1.5
        assert index.b == 0.75

    def test_index_documents(self, sample_documents):
        """Test indexing documents."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index()
        index.index(sample_documents)

        assert index._indexed
        assert len(index.documents) == len(sample_documents)

    def test_search(self, sample_documents):
        """Test BM25 search."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index()
        index.index(sample_documents)

        results = index.search("SQL injection", top_k=3)

        assert len(results) <= 3
        assert all(isinstance(r, tuple) for r in results)
        assert all(len(r) == 2 for r in results)  # (doc, score)

    def test_search_returns_relevant(self, sample_documents):
        """Test BM25 search returns relevant documents first."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index()
        index.index(sample_documents)

        results = index.search("SQL injection UNION", top_k=1)

        if results:
            top_doc, _ = results[0]
            assert "SQL" in top_doc.page_content or "UNION" in top_doc.page_content

    def test_search_before_index(self):
        """Test search before indexing raises error."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index()

        with pytest.raises(RuntimeError):
            index.search("query")

    def test_search_empty_query(self, sample_documents):
        """Test search with empty query."""
        from ctf_solver.rag.hybrid_search import BM25Index

        index = BM25Index()
        index.index(sample_documents)

        results = index.search("")
        assert results == []


# =============================================================================
# HybridSearcher Tests
# =============================================================================


class TestHybridSearcher:
    """Tests for HybridSearcher class."""

    def test_import(self):
        """Test HybridSearcher can be imported."""
        from ctf_solver.rag.hybrid_search import (
            HybridSearcher,
            HybridResult,
            create_hybrid_searcher,
        )

        assert HybridSearcher is not None
        assert HybridResult is not None
        assert create_hybrid_searcher is not None

    def test_create_hybrid_searcher(self, mock_retriever):
        """Test creating HybridSearcher instance."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            bm25_weight=0.4,
            vector_weight=0.6,
        )

        assert searcher is not None
        assert searcher.bm25_weight == 0.4
        assert searcher.vector_weight == 0.6

    def test_index_documents(self, mock_retriever, sample_documents):
        """Test indexing documents for BM25."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(vector_retriever=mock_retriever)
        searcher.index_documents(sample_documents)

        assert searcher._documents_indexed

    def test_hybrid_search(self, mock_retriever, sample_documents):
        """Test hybrid search combining BM25 and vector."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            documents=sample_documents,
        )

        results = searcher.search("SQL injection", top_k=3)

        assert len(results) <= 3
        assert all(hasattr(r, "combined_score") for r in results)
        assert all(hasattr(r, "bm25_score") for r in results)
        assert all(hasattr(r, "vector_score") for r in results)

    def test_hybrid_search_sorted(self, mock_retriever, sample_documents):
        """Test hybrid results are sorted by combined score."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            documents=sample_documents,
        )

        results = searcher.search("attack", top_k=5)

        scores = [r.combined_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_vector_only_search(self, mock_retriever):
        """Test vector-only search."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(vector_retriever=mock_retriever)
        results = searcher.search_vector_only("SQL injection", top_k=3)

        assert len(results) == 3
        mock_retriever.retrieve.assert_called_once()

    def test_bm25_only_search(self, mock_retriever, sample_documents):
        """Test BM25-only search."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            documents=sample_documents,
        )

        results = searcher.search_bm25_only("SQL", top_k=3)

        assert len(results) <= 3
        assert all(isinstance(r, tuple) for r in results)

    def test_bm25_only_not_indexed(self, mock_retriever):
        """Test BM25-only search when not indexed."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(vector_retriever=mock_retriever)
        results = searcher.search_bm25_only("SQL")

        assert results == []

    def test_hybrid_result_attributes(self, mock_retriever, sample_documents):
        """Test HybridResult has correct attributes."""
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            documents=sample_documents,
        )

        results = searcher.search("test", top_k=1)

        if results:
            result = results[0]
            assert hasattr(result, "document")
            assert hasattr(result, "bm25_score")
            assert hasattr(result, "vector_score")
            assert hasattr(result, "combined_score")
            assert hasattr(result, "rank_bm25")
            assert hasattr(result, "rank_vector")


# =============================================================================
# Integration Tests
# =============================================================================


class TestRAGIntegration:
    """Integration tests for RAG optimization components."""

    def test_full_pipeline(self, mock_retriever, sample_documents):
        """Test full RAG optimization pipeline."""
        from ctf_solver.rag.query_expander import create_query_expander
        from ctf_solver.rag.reranker import create_reranker
        from ctf_solver.rag.hybrid_search import create_hybrid_searcher

        # Step 1: Create components
        expander = create_query_expander()
        reranker = create_reranker(similarity_threshold=0.0)
        searcher = create_hybrid_searcher(
            vector_retriever=mock_retriever,
            documents=sample_documents,
        )

        # Step 2: Expand query
        query = "sqli attack"
        expanded = expander.expand_query(query)
        assert len(expanded) >= len(query)

        # Step 3: Hybrid search
        hybrid_results = searcher.search(expanded, top_k=5)
        assert len(hybrid_results) > 0

        # Step 4: Rerank
        docs = [hr.document for hr in hybrid_results]
        reranked = reranker.rerank(query, docs, top_k=3)
        assert len(reranked) <= 3

    def test_module_exports(self):
        """Test all components are exported from module."""
        from ctf_solver.rag import (
            QueryExpander,
            create_query_expander,
            SimpleReranker,
            ScoredDocument,
            create_reranker,
            HybridSearcher,
            HybridResult,
            BM25Index,
            create_hybrid_searcher,
        )

        assert QueryExpander is not None
        assert SimpleReranker is not None
        assert HybridSearcher is not None

    def test_split_text_with_metadata(self):
        """Test split_text_with_metadata function."""
        from ctf_solver.rag.knowledge_base import split_text_with_metadata

        text = "# SQL Injection\nSQL injection is a technique.\n\nUse UNION SELECT."
        chunks = split_text_with_metadata(
            text, "test.md", chunk_size=50, chunk_overlap=10
        )

        assert len(chunks) > 0
        for chunk_text, metadata in chunks:
            assert isinstance(chunk_text, str)
            assert isinstance(metadata, dict)
            assert "source_file" in metadata
            assert metadata["source_file"] == "test.md"
            assert "chunk_index" in metadata

    def test_chunk_metadata_tags(self):
        """Test chunk metadata includes detected tags."""
        from ctf_solver.rag.knowledge_base import split_text_with_metadata

        text = "SQL injection vulnerability with UNION SELECT payload"
        chunks = split_text_with_metadata(
            text, "test.md", chunk_size=1000, chunk_overlap=0
        )

        assert len(chunks) == 1
        _, metadata = chunks[0]
        assert "tags" in metadata
        assert "sql_injection" in metadata["tags"]


# =============================================================================
# DocumentWithMetadata Tests
# =============================================================================


class TestDocumentWithMetadata:
    """Tests for DocumentWithMetadata class."""

    def test_import(self):
        """Test DocumentWithMetadata can be imported."""
        from ctf_solver.rag.hybrid_search import DocumentWithMetadata

        assert DocumentWithMetadata is not None

    def test_create_document(self):
        """Test creating DocumentWithMetadata instance."""
        from ctf_solver.rag.hybrid_search import DocumentWithMetadata

        doc = DocumentWithMetadata(
            content="Test content",
            metadata={"source": "test.md"},
            doc_id="doc_001",
        )

        assert doc.content == "Test content"
        assert doc.metadata["source"] == "test.md"
        assert doc.doc_id == "doc_001"

    def test_page_content_property(self):
        """Test page_content property for FAIR compatibility."""
        from ctf_solver.rag.hybrid_search import DocumentWithMetadata

        doc = DocumentWithMetadata(content="Test content")
        assert doc.page_content == "Test content"


# =============================================================================
# Optimization Status Tests
# =============================================================================


class TestOptimizationStatus:
    """Tests for optimization status tracking."""

    def test_get_optimization_status(self):
        """Test get_optimization_status function."""
        from ctf_solver.rag.knowledge_base import get_optimization_status, clear_cache

        # Clear cache first
        clear_cache()

        status = get_optimization_status()

        assert isinstance(status, dict)
        assert "retriever" in status
        assert "query_expander" in status
        assert "reranker" in status
        assert "hybrid_searcher" in status
        assert "documents_indexed" in status
        assert "document_count" in status

    def test_clear_cache(self):
        """Test clear_cache clears all components."""
        from ctf_solver.rag.knowledge_base import (
            clear_cache,
            get_optimization_status,
            get_query_expander,
            get_reranker,
            get_hybrid_searcher,
        )

        clear_cache()

        status = get_optimization_status()
        assert not status["retriever"]
        assert not status["query_expander"]
        assert not status["reranker"]
        assert not status["hybrid_searcher"]

        assert get_query_expander() is None
        assert get_reranker() is None
        assert get_hybrid_searcher() is None


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_reranker_mismatched_scores(self, sample_documents):
        """Test reranker with mismatched document/score lengths."""
        from ctf_solver.rag.reranker import create_reranker

        reranker = create_reranker()

        with pytest.raises(ValueError):
            reranker.rerank_with_original_scores(
                "query",
                sample_documents,
                [0.5, 0.3],  # Wrong length
            )

    def test_expander_special_characters(self):
        """Test query expander with special characters."""
        from ctf_solver.rag.query_expander import create_query_expander

        expander = create_query_expander()
        query = "SQL' OR '1'='1"
        expanded = expander.expand_query(query)

        # Should not crash, may or may not expand
        assert expanded is not None

    def test_bm25_single_document(self):
        """Test BM25 with single document."""
        from ctf_solver.rag.hybrid_search import BM25Index

        doc = MockDocument(page_content="Single document with SQL injection")
        index = BM25Index()
        index.index([doc])

        results = index.search("SQL", top_k=5)
        assert len(results) == 1

    def test_reranker_identical_documents(self):
        """Test reranker with identical documents."""
        from ctf_solver.rag.reranker import create_reranker

        docs = [MockDocument(page_content="Same content")] * 3
        reranker = create_reranker(similarity_threshold=0.0)

        results = reranker.rerank("Same", docs)
        # All should have similar scores
        scores = [r.score for r in results]
        assert max(scores) - min(scores) < 0.01


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
