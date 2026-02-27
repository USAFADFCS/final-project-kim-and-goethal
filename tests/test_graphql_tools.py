"""
Tests for GraphQL tools (GraphqlIntrospectionTool and GraphqlQueryTool).

Covers:
- GraphqlIntrospectionTool: introspection queries, bypass techniques, error handling
- GraphqlQueryTool: arbitrary queries, batch mode, variables, flag detection
"""

import json
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.graphql_tools import GraphqlIntrospectionTool, GraphqlQueryTool


# ==============================================================================
# Shared introspection response data
# ==============================================================================

INTROSPECTION_RESULT = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": None,
            "subscriptionType": None,
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "user",
                            "type": {"name": "User", "kind": "OBJECT", "ofType": None},
                            "args": [
                                {
                                    "name": "id",
                                    "type": {"name": "Int", "kind": "SCALAR", "ofType": None},
                                }
                            ],
                        }
                    ],
                },
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "id",
                            "type": {"name": "Int", "kind": "SCALAR", "ofType": None},
                            "args": [],
                        },
                        {
                            "name": "name",
                            "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            "args": [],
                        },
                    ],
                },
                {
                    "name": "Flag",
                    "kind": "OBJECT",
                    "fields": [
                        {
                            "name": "value",
                            "type": {"name": "String", "kind": "SCALAR", "ofType": None},
                            "args": [],
                        }
                    ],
                },
            ],
        }
    }
}


# ==============================================================================
# TestGraphqlIntrospectionTool
# ==============================================================================


class TestGraphqlIntrospectionTool:
    """Tests for GraphqlIntrospectionTool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = GraphqlIntrospectionTool(session=self.mock_session)

    def test_tool_name(self):
        """Verify tool name is 'graphql_introspection'."""
        assert self.tool.name == "graphql_introspection"

    def test_missing_url(self):
        """Test that 'url' is required."""
        result = self.tool.use(json.dumps({"method": "POST"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json {{{")
        assert "Error" in result
        assert "JSON" in result

    def test_successful_introspection(self):
        """Test successful introspection with a valid schema response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = INTROSPECTION_RESULT
        mock_resp.text = json.dumps(INTROSPECTION_RESULT)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
        }))

        # Verify introspection was successful
        assert "Introspection Successful" in result

        # Verify Query type fields are found
        assert "QUERY TYPES" in result
        assert "user" in result

        # Verify User custom type is found
        assert "CUSTOM TYPES" in result
        assert "User" in result

        # Verify Flag is highlighted as interesting
        assert "INTERESTING FINDINGS" in result
        assert "Flag" in result
        assert "sensitive" in result.lower() or "interesting" in result.lower()

    def test_introspection_blocked_then_bypass(self):
        """Test bypass when initial introspection is blocked (403), then GET succeeds."""
        # First POST call returns 403 (blocked)
        blocked_resp = MagicMock()
        blocked_resp.status_code = 403
        blocked_resp.json.return_value = {"errors": [{"message": "Forbidden"}]}
        blocked_resp.text = '{"errors": [{"message": "Forbidden"}]}'
        blocked_resp.headers = {}

        # GET call returns the introspection data (bypass succeeds)
        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = INTROSPECTION_RESULT
        success_resp.text = json.dumps(INTROSPECTION_RESULT)
        success_resp.headers = {}

        # POST is called multiple times (standard, compact, newline attempts),
        # all blocked. Then GET (alternate method) succeeds.
        self.mock_session.post.return_value = blocked_resp
        self.mock_session.get.return_value = success_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
        }))

        # The tool should have tried the alternate method (GET) and succeeded
        assert "Introspection Successful" in result
        assert "method switch" in result.lower() or "GET" in result

        # Verify GET was called as a bypass
        assert self.mock_session.get.called

    def test_connection_error(self):
        """Test error handling when session.post raises an exception."""
        self.mock_session.post.side_effect = Exception("Connection refused")

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
        }))

        assert "Error" in result
        assert "Connection refused" in result

    def test_get_method(self):
        """Test that method='GET' causes session.get to be called instead of session.post."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = INTROSPECTION_RESULT
        mock_resp.text = json.dumps(INTROSPECTION_RESULT)
        mock_resp.headers = {}
        self.mock_session.get.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "method": "GET",
        }))

        # session.get should be called, not session.post
        assert self.mock_session.get.called
        assert "Introspection Successful" in result
        assert "Method: GET" in result


# ==============================================================================
# TestGraphqlQueryTool
# ==============================================================================


class TestGraphqlQueryTool:
    """Tests for GraphqlQueryTool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_session = MagicMock()
        self.tool = GraphqlQueryTool(session=self.mock_session)

    def test_tool_name(self):
        """Verify tool name is 'graphql_query'."""
        assert self.tool.name == "graphql_query"

    def test_missing_url(self):
        """Test that 'url' is required."""
        result = self.tool.use(json.dumps({
            "query": "{ users { id } }",
        }))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_query(self):
        """Test that 'query' is required."""
        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
        }))
        assert "Error" in result
        assert "query" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON input."""
        result = self.tool.use("not valid json at all")
        assert "Error" in result
        assert "JSON" in result

    def test_successful_query(self):
        """Test successful query with data in the response."""
        response_data = {"data": {"user": {"id": 1, "name": "admin"}}}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "query": "{ user(id: 1) { id name } }",
        }))

        assert "Query Result" in result
        assert "admin" in result
        assert "RESPONSE DATA" in result

    def test_query_with_errors(self):
        """Test query response containing errors."""
        response_data = {
            "data": None,
            "errors": [{"message": "Access denied"}],
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "query": "{ secretData { value } }",
        }))

        assert "ERRORS" in result
        assert "Access denied" in result

    def test_flag_detection(self):
        """Test that CTF flag patterns are highlighted in the response."""
        response_data = {"data": {"flag": "CTF{test_flag_123}"}}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "query": "{ flag }",
        }))

        assert "FLAGS FOUND" in result
        assert "CTF{test_flag_123}" in result

    def test_batch_mode(self):
        """Test batch mode sends an array of queries."""
        batch_response = [
            {"data": {"user": {"id": 1}}},
            {"data": {"user": {"id": 1}}},
            {"data": {"user": {"id": 1}}},
        ]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = batch_response
        mock_resp.text = json.dumps(batch_response)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "query": "{ user(id: 1) { id } }",
            "batch": True,
            "batch_count": 3,
        }))

        # Verify the POST body was sent as an array of 3 queries
        call_kwargs = self.mock_session.post.call_args
        sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert isinstance(sent_json, list), "Batch mode should send a JSON array"
        assert len(sent_json) == 3, "batch_count=3 should produce 3 entries"
        for entry in sent_json:
            assert "query" in entry
            assert entry["query"] == "{ user(id: 1) { id } }"

        # Verify batch response is shown
        assert "BATCHED RESPONSE" in result

    def test_variables_sent(self):
        """Test that variables are included in the POST body."""
        response_data = {"data": {"user": {"id": 1, "name": "admin"}}}

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)
        mock_resp.headers = {}
        self.mock_session.post.return_value = mock_resp

        result = self.tool.use(json.dumps({
            "url": "http://target.local/graphql",
            "query": "query GetUser($id: Int!) { user(id: $id) { id name } }",
            "variables": {"id": 1},
        }))

        # Verify variables were included in the POST body
        call_kwargs = self.mock_session.post.call_args
        sent_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert isinstance(sent_json, dict)
        assert "variables" in sent_json
        assert sent_json["variables"] == {"id": 1}
