"""
Tests for SSRF (Server-Side Request Forgery) detection and exploitation tools.
"""

import json
import pytest
from unittest.mock import MagicMock

from ctf_solver.tools.ssrf_tools import SsrfProbeTool, SsrfPayloadGenerator


class TestSsrfProbeTool:
    """Tests for SsrfProbeTool."""

    def setup_method(self):
        self.mock_session = MagicMock()
        self.tool = SsrfProbeTool(session=self.mock_session)

    def test_missing_url(self):
        """Test that url is required."""
        result = self.tool.use(json.dumps({"param": "url"}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_missing_param(self):
        """Test that param is required."""
        result = self.tool.use(json.dumps({"url": "http://target.com/fetch"}))
        assert "Error" in result
        assert "param" in result.lower()

    def test_invalid_json(self):
        """Test handling of invalid JSON."""
        result = self.tool.use("not valid json{{{")
        assert "Error" in result
        assert "JSON" in result

    def test_invalid_method(self):
        """Test handling of invalid HTTP method."""
        result = self.tool.use(
            json.dumps(
                {"url": "http://target.com/fetch", "param": "url", "method": "DELETE"}
            )
        )
        assert "Error" in result
        assert "GET" in result or "POST" in result

    def test_baseline_failure(self):
        """Test handling when baseline request fails."""
        self.mock_session.get.side_effect = Exception("Connection refused")
        result = self.tool.use(
            json.dumps({"url": "http://target.com/fetch", "param": "url"})
        )
        assert "Error" in result
        assert "baseline" in result.lower() or "Connection" in result

    def test_ssrf_detected_cloud_metadata(self):
        """Test detection of cloud metadata via SSRF (response contains ami-id)."""
        baseline_resp = MagicMock()
        baseline_resp.text = "No content found"
        baseline_resp.status_code = 200

        cloud_resp = MagicMock()
        cloud_resp.text = "ami-id\ninstance-id\nlocal-hostname\navailability-zone"
        cloud_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [cloud_resp] * 20

        result = self.tool.use(
            json.dumps(
                {"url": "http://target.com/fetch", "param": "url", "targets": "cloud"}
            )
        )

        assert "SSRF DETECTED" in result or "SSRF VULNERABILITY DETECTED" in result
        assert "ami-id" in result

    def test_ssrf_detected_file_protocol(self):
        """Test detection of file:// protocol reading (response contains root:x:0:0:)."""
        baseline_resp = MagicMock()
        baseline_resp.text = "No content found"
        baseline_resp.status_code = 200

        file_resp = MagicMock()
        file_resp.text = (
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"
        )
        file_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [file_resp] * 20

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/fetch",
                    "param": "url",
                    "targets": "protocols",
                }
            )
        )

        assert "SSRF DETECTED" in result or "SSRF VULNERABILITY DETECTED" in result
        assert "root:x:0:0:" in result

    def test_ssrf_detected_internal_service(self):
        """Test detection when internal service returns different response from baseline."""
        baseline_resp = MagicMock()
        baseline_resp.text = "No content found"
        baseline_resp.status_code = 200

        internal_resp = MagicMock()
        internal_resp.text = (
            '<html><body><h1>Internal Admin Panel</h1>{"status": "ok"}</body></html>'
            + "A" * 100
        )
        internal_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [internal_resp] * 20

        result = self.tool.use(
            json.dumps(
                {
                    "url": "http://target.com/fetch",
                    "param": "url",
                    "targets": "internal",
                }
            )
        )

        assert "SSRF DETECTED" in result or "SSRF VULNERABILITY DETECTED" in result
        assert "differs from baseline" in result or "finding" in result

    def test_no_ssrf_all_same(self):
        """Test that no SSRF is reported when all responses match baseline."""
        same_resp = MagicMock()
        same_resp.text = "No content found"
        same_resp.status_code = 200

        self.mock_session.get.return_value = same_resp

        result = self.tool.use(
            json.dumps({"url": "http://target.com/fetch", "param": "url"})
        )

        assert "No obvious SSRF" in result or "not detected" in result.lower()

    def test_flag_detection(self):
        """Test that CTF flags are detected in SSRF responses."""
        baseline_resp = MagicMock()
        baseline_resp.text = "No content found"
        baseline_resp.status_code = 200

        flag_resp = MagicMock()
        flag_resp.text = "Here is the flag: flag{ssrf_is_cool_123}"
        flag_resp.status_code = 200

        self.mock_session.get.side_effect = [baseline_resp] + [flag_resp] * 20

        result = self.tool.use(
            json.dumps(
                {"url": "http://target.com/fetch", "param": "url", "targets": "cloud"}
            )
        )

        assert "FLAG" in result
        assert "flag{ssrf_is_cool_123}" in result

    def test_cloud_only_targets(self):
        """Test that cloud-only targets only probe cloud metadata endpoints."""
        same_resp = MagicMock()
        same_resp.text = "No content found"
        same_resp.status_code = 200

        self.mock_session.get.return_value = same_resp

        result = self.tool.use(
            json.dumps(
                {"url": "http://target.com/fetch", "param": "url", "targets": "cloud"}
            )
        )

        # Should mention cloud targets are being tested
        assert "cloud" in result.lower() or "Summary" in result

    def test_get_method(self):
        """Test that GET method uses session.get."""
        same_resp = MagicMock()
        same_resp.text = "No content found"
        same_resp.status_code = 200

        self.mock_session.get.return_value = same_resp

        self.tool.use(
            json.dumps(
                {"url": "http://target.com/fetch", "param": "url", "method": "GET"}
            )
        )

        assert self.mock_session.get.called
        assert not self.mock_session.post.called


class TestSsrfPayloadGenerator:
    """Tests for SsrfPayloadGenerator."""

    def setup_method(self):
        self.tool = SsrfPayloadGenerator()

    def test_missing_operation(self):
        """Test that operation is required."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()

    def test_invalid_operation(self):
        """Test handling of unknown operation."""
        result = self.tool.use(json.dumps({"operation": "nonexistent"}))
        assert "Error" in result
        assert "Unknown" in result or "nonexistent" in result

    def test_invalid_json(self):
        """Test handling of invalid JSON."""
        result = self.tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_ip_bypass_decimal(self):
        """Test IP bypass generates decimal representation."""
        result = self.tool.use(
            json.dumps({"operation": "ip_bypass", "target_ip": "127.0.0.1"})
        )
        assert "2130706433" in result

    def test_ip_bypass_hex(self):
        """Test IP bypass generates hex representations."""
        result = self.tool.use(
            json.dumps({"operation": "ip_bypass", "target_ip": "127.0.0.1"})
        )
        assert "0x7f000001" in result or "0x7f" in result

    def test_ip_bypass_ipv6(self):
        """Test IP bypass generates IPv6 representations."""
        result = self.tool.use(
            json.dumps({"operation": "ip_bypass", "target_ip": "127.0.0.1"})
        )
        assert "[::1]" in result
        assert "ffff" in result

    def test_ip_bypass_domain(self):
        """Test IP bypass generates domain bypass variants."""
        result = self.tool.use(
            json.dumps({"operation": "ip_bypass", "target_ip": "127.0.0.1"})
        )
        assert "nip.io" in result
        assert "localtest.me" in result
        assert "burpcollaborator.net" in result

    def test_cloud_metadata_aws(self):
        """Test cloud metadata includes AWS endpoints."""
        result = self.tool.use(json.dumps({"operation": "cloud_metadata"}))
        assert "169.254.169.254" in result
        assert "AWS" in result
        assert "iam" in result.lower() or "security-credentials" in result

    def test_cloud_metadata_gcp(self):
        """Test cloud metadata includes GCP endpoints."""
        result = self.tool.use(json.dumps({"operation": "cloud_metadata"}))
        assert "metadata.google.internal" in result
        assert "GCP" in result
        assert "Metadata-Flavor" in result

    def test_protocol_smuggling_gopher(self):
        """Test protocol smuggling includes gopher:// payloads."""
        result = self.tool.use(json.dumps({"operation": "protocol_smuggling"}))
        assert "gopher://" in result
        assert "raw TCP" in result.lower() or "TCP" in result

    def test_protocol_smuggling_dict(self):
        """Test protocol smuggling includes dict:// payloads."""
        result = self.tool.use(json.dumps({"operation": "protocol_smuggling"}))
        assert "dict://" in result
        assert "Redis" in result or "redis" in result.lower()

    def test_custom_target_ip(self):
        """Test IP bypass with custom target IP (not 127.0.0.1)."""
        result = self.tool.use(
            json.dumps({"operation": "ip_bypass", "target_ip": "10.0.0.1"})
        )
        assert "10.0.0.1" in result
        # Decimal of 10.0.0.1 = 167772161
        assert "167772161" in result

    def test_all_operations_return_content(self):
        """Test that all three operations return non-empty content."""
        for op in ["ip_bypass", "cloud_metadata", "protocol_smuggling"]:
            result = self.tool.use(json.dumps({"operation": op}))
            assert "Error" not in result
            assert len(result) > 100
            assert "SsrfPayloadGenerator" in result
