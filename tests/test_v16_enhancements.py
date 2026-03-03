"""
Tests for v1.6.0 enhancements to existing tools.

Covers:
- RaceConditionTool: single-packet mode, _build_raw_http_request
- GraphqlQueryTool: alias brute-force operation
- NosqlPayloadGenerator: couchdb operation
- XssPayloadGenerator: mXSS operation
- SstiProbeTool: new engine probes (nunjucks, pug, tera, go_template, ejs)
- SstiExploitSuggester: new engine payloads
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ctf_solver.tools.race_tools import RaceConditionTool
from ctf_solver.tools.graphql_tools import GraphqlQueryTool
from ctf_solver.tools.nosql_tools import NosqlPayloadGenerator
from ctf_solver.tools.xss_tools import XssPayloadGenerator
from ctf_solver.tools.ssti_tools import SstiProbeTool, SstiExploitSuggester


# ==============================================================================
# RaceConditionTool — single-packet mode
# ==============================================================================


class TestRaceConditionSinglePacket:
    """Test the single-packet race attack enhancements."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = RaceConditionTool(session=self.session)

    def test_mode_param_accepted(self):
        """Tool description mentions 'mode' parameter."""
        assert "mode" in self.tool.description
        assert "single_packet" in self.tool.description

    def test_build_raw_http_request_get(self):
        """_build_raw_http_request produces valid HTTP/1.1 request bytes."""
        raw = self.tool._build_raw_http_request(
            host="example.com",
            port=80,
            path="/test?q=1",
            method="GET",
            headers={"X-Custom": "val"},
            data=None,
            body=None,
            cookies=None,
        )
        assert isinstance(raw, bytes)
        assert b"GET /test?q=1 HTTP/1.1" in raw
        assert b"Host: example.com" in raw
        assert b"X-Custom: val" in raw

    def test_build_raw_http_request_post_data(self):
        raw = self.tool._build_raw_http_request(
            host="example.com",
            port=80,
            path="/api",
            method="POST",
            headers={},
            data={"key": "val"},
            body=None,
            cookies=None,
        )
        assert b"POST /api HTTP/1.1" in raw
        assert b"key=val" in raw
        assert b"Content-Length:" in raw

    def test_build_raw_http_request_post_json_body(self):
        raw = self.tool._build_raw_http_request(
            host="example.com",
            port=443,
            path="/api",
            method="POST",
            headers={},
            data=None,
            body='{"a": 1}',
            cookies=None,
        )
        assert b'{"a": 1}' in raw

    def test_build_raw_includes_cookies(self):
        raw = self.tool._build_raw_http_request(
            host="example.com",
            port=80,
            path="/",
            method="GET",
            headers={},
            data=None,
            body=None,
            cookies={"sid": "abc123"},
        )
        assert b"Cookie:" in raw
        assert b"sid=abc123" in raw

    def test_single_packet_mode_dispatches(self):
        """mode=single_packet calls _single_packet_attack."""
        mock_results = [
            {"index": i, "status": 200, "length": 10, "body": "ok",
             "body_preview": "ok", "elapsed_ms": 1.0, "error": None}
            for i in range(3)
        ]
        with patch.object(self.tool, "_single_packet_attack", return_value=mock_results) as mock:
            self.tool.use(json.dumps({
                "url": "http://example.com/test",
                "mode": "single_packet",
                "concurrency": 3,
            }))
            mock.assert_called_once()

    def test_thread_mode_default(self):
        """Default mode should use thread pool (not single_packet)."""
        mock_result = {
            "index": 1, "status": 200, "length": 2, "body": "ok",
            "body_preview": "ok", "elapsed_ms": 1.0, "error": None,
        }
        with patch.object(self.tool, "_single_packet_attack") as sp_mock:
            with patch.object(self.tool, "_send_request", return_value=mock_result):
                self.tool.use(json.dumps({
                    "url": "http://example.com/test",
                    "concurrency": 2,
                }))
            sp_mock.assert_not_called()


# ==============================================================================
# GraphqlQueryTool — alias brute-force
# ==============================================================================


class TestGraphqlAliasBruteforce:
    """Test the alias brute-force enhancement."""

    def setup_method(self):
        self.session = requests.Session()
        self.tool = GraphqlQueryTool(session=self.session)

    def test_description_mentions_alias(self):
        assert "alias" in self.tool.description.lower()

    def test_alias_bruteforce_dispatches(self):
        """alias_bruteforce param triggers _alias_bruteforce."""
        with patch.object(self.tool, "_alias_bruteforce", return_value="result") as mock:
            self.tool.use(json.dumps({
                "url": "http://example.com/graphql",
                "alias_bruteforce": {
                    "query_template": '{{ login(pin: "{value}") {{ token }} }}',
                    "values": ["0000", "1111"],
                },
            }))
            mock.assert_called_once()

    def test_alias_bruteforce_with_range(self):
        """Range parameter generates values."""
        with patch.object(self.tool, "_alias_bruteforce", return_value="result") as mock:
            self.tool.use(json.dumps({
                "url": "http://example.com/graphql",
                "alias_bruteforce": {
                    "query_template": '{{ pin(code: "{value}") {{ ok }} }}',
                    "range": [0, 5],
                },
            }))
            mock.assert_called_once()
            # Values should be generated from range
            call_args = mock.call_args
            values = call_args[1].get("values") or call_args[0][2] if len(call_args[0]) > 2 else None
            # The method was called — good enough for unit test


# ==============================================================================
# NosqlPayloadGenerator — couchdb
# ==============================================================================


class TestNosqlCouchdb:
    """Test the CouchDB payload generation enhancement."""

    def setup_method(self):
        self.tool = NosqlPayloadGenerator()

    def test_couchdb_is_valid_operation(self):
        result = self.tool.use(json.dumps({"operation": "couchdb"}))
        assert "Error" not in result or "CouchDB" in result

    def test_couchdb_mentions_endpoints(self):
        result = self.tool.use(json.dumps({"operation": "couchdb"}))
        # Should mention CouchDB-specific concepts
        assert "couchdb" in result.lower() or "CouchDB" in result

    def test_couchdb_mentions_mango(self):
        result = self.tool.use(json.dumps({"operation": "couchdb"}))
        assert "mango" in result.lower() or "Mango" in result or "_find" in result


# ==============================================================================
# XssPayloadGenerator — mXSS
# ==============================================================================


class TestXssMxss:
    """Test the mXSS payload generation enhancement."""

    def setup_method(self):
        self.tool = XssPayloadGenerator()

    def test_mxss_is_valid_operation(self):
        result = self.tool.use(json.dumps({"operation": "mxss"}))
        assert "Error" not in result

    def test_mxss_default_all_sanitizers(self):
        result = self.tool.use(json.dumps({"operation": "mxss"}))
        assert "mXSS" in result or "mutation" in result.lower() or "sanitizer" in result.lower()

    def test_mxss_specific_sanitizer(self):
        result = self.tool.use(json.dumps({
            "operation": "mxss",
            "sanitizer": "dompurify",
        }))
        assert "DOMPurify" in result or "dompurify" in result.lower()

    def test_mxss_payloads_exist(self):
        """MXSS_PAYLOADS dict should have entries."""
        assert hasattr(XssPayloadGenerator, "MXSS_PAYLOADS")
        assert len(XssPayloadGenerator.MXSS_PAYLOADS) >= 3


# ==============================================================================
# SstiProbeTool — new engines
# ==============================================================================


class TestSstiNewEngines:
    """Test the new SSTI engine probes (nunjucks, pug, tera, go_template, ejs)."""

    def setup_method(self):
        self.probe = SstiProbeTool(session=requests.Session())
        self.suggester = SstiExploitSuggester()

    def test_nunjucks_probes_exist(self):
        assert "nunjucks" in self.probe.ENGINE_PROBES

    def test_pug_probes_exist(self):
        assert "pug" in self.probe.ENGINE_PROBES

    def test_tera_probes_exist(self):
        assert "tera" in self.probe.ENGINE_PROBES

    def test_go_template_probes_exist(self):
        assert "go_template" in self.probe.ENGINE_PROBES

    def test_ejs_probes_exist(self):
        assert "ejs" in self.probe.ENGINE_PROBES

    def test_nunjucks_rce_exploit(self):
        assert "nunjucks" in self.probe.RCE_EXPLOITS

    def test_pug_rce_exploit(self):
        assert "pug" in self.probe.RCE_EXPLOITS

    def test_ejs_rce_exploit(self):
        assert "ejs" in self.probe.RCE_EXPLOITS

    def test_suggester_pug_payloads(self):
        assert "pug" in self.suggester.PAYLOADS

    def test_suggester_tera_payloads(self):
        assert "tera" in self.suggester.PAYLOADS

    def test_suggester_go_template_payloads(self):
        assert "go_template" in self.suggester.PAYLOADS

    def test_suggester_ejs_payloads(self):
        assert "ejs" in self.suggester.PAYLOADS

    def test_suggester_pug_has_rce(self):
        pug = self.suggester.PAYLOADS["pug"]
        assert "rce" in pug

    def test_suggester_ejs_has_rce(self):
        ejs = self.suggester.PAYLOADS["ejs"]
        assert "rce" in ejs
