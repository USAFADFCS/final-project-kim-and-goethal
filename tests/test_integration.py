"""
Integration tests for CTF Solver.

Tests how different components work together as a complete system.
"""

import json
from unittest.mock import Mock

import pytest

# ==============================================================================
# Tool Integration Tests
# ==============================================================================


class TestToolIntegration:
    """Test integration between different tools."""

    def test_encoding_tool_jwt_decode_integration(self, sample_jwt):
        """Test using encoding tool followed by JWT analysis."""
        from ctf_solver.tools.encoding_tools import EncodingTool
        from ctf_solver.tools.jwt_tools import JwtTool

        encoding_tool = EncodingTool()
        jwt_tool = JwtTool()

        # First decode JWT using JWT tool
        jwt_result = jwt_tool.use(
            json.dumps({"operation": "decode", "token": sample_jwt})
        )

        assert "HEADER" in jwt_result
        assert "PAYLOAD" in jwt_result
        assert "HS256" in jwt_result

    def test_sqli_probe_column_counter_workflow(
        self, mock_session, mock_response_factory
    ):
        """Test typical SQLi workflow: probe then column count."""
        from ctf_solver.tools.sqli_tools import SqliColumnCounter, SqliProbeTool

        # Setup mock responses for probe
        baseline_probe = mock_response_factory(text="Normal page content")
        error_probe = mock_response_factory(
            text="You have an error in your SQL syntax near ''"
        )
        mock_session.get.side_effect = [baseline_probe, error_probe]

        probe_tool = SqliProbeTool(session=mock_session)
        probe_result = probe_tool.use(
            json.dumps(
                {
                    "url": "http://test.local/page",
                    "method": "GET",
                    "param": "id",
                    "payload_set": "custom",
                    "custom_payloads": ["'"],
                }
            )
        )

        assert "INTERESTING PAYLOADS" in probe_result

        # Reset mock for column counter
        mock_session.reset_mock()
        baseline_cols = mock_response_factory(text="Data results")
        ok_order = mock_response_factory(text="Data results with order")
        error_order = mock_response_factory(text="Unknown column '3' in order clause")

        mock_session.get.side_effect = [baseline_cols, ok_order, ok_order, error_order]

        column_tool = SqliColumnCounter(session=mock_session)
        column_result = column_tool.use(
            json.dumps(
                {
                    "url": "http://test.local/page",
                    "method": "GET",
                    "param": "id",
                    "technique": "order_by",
                    "prefix": "'",
                    "suffix": " --",
                }
            )
        )

        assert "Column Count Detection" in column_result

    def test_jwt_forge_decode_roundtrip(self, jwt_factory):
        """Test forging a JWT and then decoding it."""
        from ctf_solver.tools.jwt_tools import JwtTool

        jwt_tool = JwtTool()

        # Forge a new token
        forge_result = jwt_tool.use(
            json.dumps(
                {
                    "operation": "forge_none",
                    "payload": {"sub": "admin", "role": "admin", "iat": 1234567890},
                }
            )
        )

        assert "none" in forge_result.lower()
        # Extract the forged token from the result
        lines = forge_result.split("\n")
        token_line = [l for l in lines if "eyJ" in l]

        if token_line:
            # Find the JWT in the output
            import re

            match = re.search(
                r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*)", forge_result
            )
            if match:
                forged_token = match.group(1)

                # Now decode the forged token
                decode_result = jwt_tool.use(
                    json.dumps({"operation": "decode", "token": forged_token})
                )

                assert "admin" in decode_result
                assert "none" in decode_result.lower()


class TestClassifierToolIntegration:
    """Test classifier integration with tools."""

    def test_classifier_suggests_correct_tools(self, sample_challenge_descriptions):
        """Test that classifier suggests appropriate tools for challenges."""
        from ctf_solver.classifier.challenge_classifier import ChallengeClassifier

        classifier = ChallengeClassifier()

        # Test SQL injection challenge
        sqli_result = classifier.classify(sample_challenge_descriptions["sqli"])
        assert (
            "sql" in str(sqli_result).lower()
            or sqli_result.primary_category == "sql_injection"
        )

        # Test XSS challenge
        xss_result = classifier.classify(sample_challenge_descriptions["xss"])
        assert "xss" in str(xss_result).lower() or xss_result.primary_category == "xss"

        # Test JWT challenge
        jwt_result = classifier.classify(sample_challenge_descriptions["jwt"])
        assert "jwt" in str(jwt_result).lower() or "auth" in str(jwt_result).lower()


class TestEncodingChains:
    """Test encoding/decoding chains common in CTFs."""

    def test_base64_url_chain(self, encoding_test_cases):
        """Test base64 -> URL decode chain."""
        from ctf_solver.tools.encoding_tools import EncodingTool

        tool = EncodingTool()

        # Encode a flag with base64, then URL encode
        import base64
        import urllib.parse

        original = "CTF{ch41n3d_3nc0d1ng}"
        b64 = base64.b64encode(original.encode()).decode()
        url_encoded = urllib.parse.quote(b64)

        # Decode URL first
        url_result = tool.use(
            json.dumps({"text": url_encoded, "operation": "url_decode"})
        )
        # Extract decoded value
        decoded_url = (
            url_result.split("Result: ")[1].strip() if "Result: " in url_result else b64
        )

        # Then decode base64
        b64_result = tool.use(
            json.dumps({"text": decoded_url, "operation": "base64_decode"})
        )

        assert "CTF{ch41n3d_3nc0d1ng}" in b64_result

    def test_rot13_base64_chain(self):
        """Test ROT13 + base64 combination."""
        import base64
        import codecs

        from ctf_solver.tools.encoding_tools import EncodingTool

        tool = EncodingTool()

        # Create encoded flag: ROT13 then base64
        original = "FLAG{r0t13_b4s3}"
        rot13 = codecs.encode(original, "rot_13")
        encoded = base64.b64encode(rot13.encode()).decode()

        # Decode base64
        b64_result = tool.use(
            json.dumps({"text": encoded, "operation": "base64_decode"})
        )
        intermediate = (
            b64_result.split("Result: ")[1].strip() if "Result: " in b64_result else ""
        )

        # Decode ROT13
        rot_result = tool.use(json.dumps({"text": intermediate, "operation": "rot13"}))

        assert "FLAG{r0t13_b4s3}" in rot_result


# ==============================================================================
# RAG Integration Tests
# ==============================================================================


class TestRAGIntegration:
    """Test RAG system integration."""

    def test_query_expansion_with_reranking(self, sample_documents):
        """Test query expansion followed by reranking."""
        from ctf_solver.rag.query_expander import QueryExpander
        from ctf_solver.rag.reranker import SimpleReranker

        expander = QueryExpander()
        reranker = SimpleReranker()

        # Expand query
        original_query = "sqli login bypass"
        expanded = expander.expand_query(original_query)

        assert "sql injection" in expanded.lower() or "sql" in expanded.lower()

        # Rerank documents
        results = reranker.rerank(original_query, sample_documents, top_k=3)

        assert len(results) > 0
        # SQL document should rank higher for this query
        top_content = results[0].page_content.lower()
        assert "sql" in top_content or "injection" in top_content

    def test_hybrid_search_components(self, sample_documents):
        """Test BM25 index functionality."""
        from ctf_solver.rag.hybrid_search import BM25Index

        bm25 = BM25Index()
        bm25.index(sample_documents)

        # Search for SQL-related terms
        results = bm25.search("sql injection database", top_k=3)

        assert len(results) > 0
        # First result should be the SQL document
        top_doc, score = results[0]
        assert "sql" in top_doc.page_content.lower()
        assert score > 0

    def test_chunk_metadata_detection(self):
        """Test that chunk metadata tags are detected correctly."""
        from ctf_solver.rag.knowledge_base import _detect_chunk_tags

        sqli_text = "SQL injection UNION SELECT attack payloads"
        tags = _detect_chunk_tags(sqli_text)
        assert "sql_injection" in tags

        xss_text = "Cross-site scripting <script>alert(1)</script>"
        tags = _detect_chunk_tags(xss_text)
        assert "xss" in tags

        jwt_text = "JSON Web Token authentication bypass"
        tags = _detect_chunk_tags(jwt_text)
        assert "jwt" in tags


# ==============================================================================
# Utility Integration Tests
# ==============================================================================


class TestUtilityIntegration:
    """Test utility module integration."""

    def test_diff_analyzer_with_responses(self, mock_response_factory):
        """Test diff analyzer on HTTP responses."""
        from ctf_solver.tools.diff_tools import ResponseDiffTool

        tool = ResponseDiffTool()

        baseline = "Normal page with login form. Please enter credentials."
        modified = "Welcome admin! Dashboard loaded. picoCTF{diff_found}"

        result = tool.use(json.dumps({"text1": baseline, "text2": modified}))

        # Should detect significant differences
        assert "Welcome" in result or "admin" in result or "diff" in result.lower()

    def test_path_enumeration_generates_paths(self):
        """Test path enumeration tool generates valid paths."""
        from ctf_solver.tools.enumeration_tools import PathEnumeratorTool

        # Create mock session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not found"
        mock_session.get.return_value = mock_response

        tool = PathEnumeratorTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://test.local",
                    "wordlist": "common",
                }
            )
        )

        # Should attempt path enumeration
        assert "Path Enumeration" in result or "paths" in result.lower()


# ==============================================================================
# Full Workflow Tests
# ==============================================================================


@pytest.mark.integration
class TestFullWorkflows:
    """Test complete CTF-solving workflows."""

    def test_login_bypass_workflow(self, mock_session, mock_response_factory):
        """Test complete login bypass workflow."""
        from ctf_solver.tools.encoding_tools import EncodingTool
        from ctf_solver.tools.sqli_tools import SqliProbeTool

        # Setup: Login page that's vulnerable
        baseline = mock_response_factory(text="Invalid username or password")
        success = mock_response_factory(
            text="Welcome admin! Flag: cGljb0NURntzcWxpX2J5cGFzc30="  # base64 encoded flag
        )

        mock_session.post.side_effect = [baseline, success]

        # Step 1: Probe for SQLi
        probe = SqliProbeTool(session=mock_session)
        probe_result = probe.use(
            json.dumps(
                {
                    "url": "http://test.local/login",
                    "method": "POST",
                    "param": "username",
                    "payload_set": "custom",
                    "custom_payloads": ["admin' --"],
                    "data": {"password": "x"},
                }
            )
        )

        assert "admin' --" in probe_result or "INTERESTING" in probe_result

        # Step 2: Decode the flag found
        encoding = EncodingTool()
        decode_result = encoding.use(
            json.dumps(
                {
                    "text": "cGljb0NURntzcWxpX2J5cGFzc30=",
                    "operation": "base64_decode",
                }
            )
        )

        assert "picoCTF" in decode_result

    def test_jwt_forgery_workflow(self, sample_jwt):
        """Test complete JWT forgery workflow."""
        from ctf_solver.tools.jwt_tools import JwtTool

        jwt_tool = JwtTool()

        # Step 1: Decode existing token
        decode_result = jwt_tool.use(
            json.dumps({"operation": "decode", "token": sample_jwt})
        )

        assert "HEADER" in decode_result

        # Step 2: Analyze for weaknesses
        analyze_result = jwt_tool.use(
            json.dumps({"operation": "analyze", "token": sample_jwt})
        )

        # Analysis should be in the result
        assert "JWT" in analyze_result or "alg" in analyze_result.lower()

        # Step 3: Forge new token with none algorithm
        forge_result = jwt_tool.use(
            json.dumps(
                {
                    "operation": "forge_none",
                    "payload": {"sub": "admin", "role": "admin"},
                }
            )
        )

        assert "none" in forge_result.lower()


# ==============================================================================
# Error Handling Integration
# ==============================================================================


class TestErrorHandlingIntegration:
    """Test error handling across components."""

    def test_network_error_handling(self, mock_session):
        """Test handling of network errors across tools."""
        import requests

        mock_session.get.side_effect = requests.exceptions.ConnectionError(
            "Connection refused"
        )

        from ctf_solver.tools.sqli_tools import SqliProbeTool

        tool = SqliProbeTool(session=mock_session)

        result = tool.use(
            json.dumps(
                {
                    "url": "http://unreachable.local",
                    "method": "GET",
                    "param": "id",
                    "payload_set": "custom",
                    "custom_payloads": ["'"],
                }
            )
        )

        # Should handle error gracefully
        assert "Error" in result or "error" in result.lower()

    def test_malformed_input_across_tools(self):
        """Test that all tools handle malformed input gracefully."""
        from ctf_solver.tools.encoding_tools import EncodingTool
        from ctf_solver.tools.jwt_tools import JwtTool
        from ctf_solver.tools.sqli_tools import SqliProbeTool

        tools = [
            EncodingTool(),
            JwtTool(),
            SqliProbeTool(),
        ]

        malformed_inputs = [
            "not json",
            "{}",
            '{"incomplete": ',
            "",
        ]

        for tool in tools:
            for bad_input in malformed_inputs:
                try:
                    result = tool.use(bad_input)
                    # Should return error message, not crash
                    assert isinstance(result, str)
                except json.JSONDecodeError:
                    # This is acceptable for malformed JSON
                    pass
                except Exception as e:
                    pytest.fail(
                        f"{tool.__class__.__name__} crashed on input '{bad_input}': {e}"
                    )


# ==============================================================================
# Configuration Integration
# ==============================================================================


class TestConfigIntegration:
    """Test configuration system integration."""

    def test_config_affects_tool_behavior(self, temp_dir):
        """Test that configuration properly affects tool behavior."""
        from ctf_solver.config import SolverConfig

        # Create config with custom settings
        config = SolverConfig(
            challenge_url="http://custom.test.local",
            max_steps=50,
            cache_enabled=True,
        )

        assert config.challenge_url == "http://custom.test.local"
        assert config.max_steps == 50
        assert config.cache_enabled is True


# ==============================================================================
# LLM Adapter Integration
# ==============================================================================


class TestLLMAdapterIntegration:
    """Test LLM adapter integration."""

    def test_adapter_factory_creates_correct_type(self):
        """Test that adapter factory creates correct adapter types."""
        from ctf_solver.llm.adapters import (
            LLMProvider,
            OllamaAdapter,
            create_adapter,
        )

        # Test Anthropic adapter creation (skip if library not installed)
        try:
            from ctf_solver.llm.adapters import AnthropicAdapter

            anthropic = create_adapter(
                provider=LLMProvider.ANTHROPIC,
                api_key="test_key",
                model_name="claude-3-haiku-20240307",
            )
            assert isinstance(anthropic, AnthropicAdapter)
        except ImportError:
            pytest.skip("anthropic library not installed")

        # Test Ollama adapter creation
        ollama = create_adapter(
            provider=LLMProvider.OLLAMA,
            base_url="http://localhost:11434",
            model_name="llama2",
        )
        assert isinstance(ollama, OllamaAdapter)


# ==============================================================================
# Async Integration Tests removed in Batch C — ``AsyncToolExecutor`` and
# ``ProgressTracker`` were deleted alongside ``async_executor.py`` because
# the LLM's native parallel tool use (``_arun_native_tools`` on the
# Anthropic path, ``_arun_native_tools_openai`` on the OpenAI path) now
# replaces that abstraction.  See ``tests/test_parallel_tools_loop.py``
# for the current parallel-execution coverage.
# ==============================================================================
