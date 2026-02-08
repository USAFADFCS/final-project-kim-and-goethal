"""
Tests for XXE (XML External Entity) detection and exploitation tools.
"""

import json
import pytest
from unittest.mock import Mock, patch

from ctf_solver.tools.xxe_tools import XxeProbeTool, XxePayloadGenerator, XxeDocTypeBuilder


class TestXxeProbeToolBasics:
    """Test basic XxeProbeTool functionality."""

    def test_has_required_attributes(self):
        """Test that XxeProbeTool has name and description."""
        tool = XxeProbeTool()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "xxe_probe"
        assert "XXE" in tool.description

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = XxeProbeTool()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_url(self):
        """Test that url is required."""
        tool = XxeProbeTool()
        result = tool.use(json.dumps({}))
        assert "Error" in result
        assert "url" in result.lower()

    def test_invalid_probe_type(self):
        """Test handling of invalid probe type."""
        tool = XxeProbeTool()
        result = tool.use(json.dumps({
            "url": "http://test.com/api",
            "probe_type": "invalid"
        }))
        assert "Error" in result
        assert "probe_type" in result

    def test_accepts_session(self):
        """Test that tool accepts a requests session."""
        mock_session = Mock()
        tool = XxeProbeTool(session=mock_session)
        assert tool.session == mock_session

    def test_default_values(self):
        """Test that defaults are applied correctly."""
        tool = XxeProbeTool()
        # Create a mock session for testing
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "no xxe here"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response
        tool.session = mock_session

        result = tool.use(json.dumps({"url": "http://test.com/api"}))

        # Check defaults are used
        assert "POST" in result  # default method
        assert "/etc/passwd" in result  # default target file


class TestXxeProbeFileRead:
    """Test XXE file read detection functionality."""

    def test_detects_etc_passwd(self):
        """Test detection of /etc/passwd content."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "file_read",
            "target_file": "/etc/passwd"
        }))

        assert "VULNERABLE" in result
        assert "root:" in result

    def test_detects_etc_hosts(self):
        """Test detection of /etc/hosts content."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "127.0.0.1 localhost\n::1 localhost"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "file_read",
            "target_file": "/etc/hosts"
        }))

        assert "VULNERABLE" in result or "127.0.0.1" in result

    def test_detects_flag_content(self):
        """Test detection of flag content."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "flag{xxe_is_fun_12345}"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "file_read",
            "target_file": "/flag.txt"
        }))

        assert "VULNERABLE" in result or "flag" in result

    def test_detects_base64_encoded_content(self):
        """Test detection of base64 encoded file content (PHP filter)."""
        mock_session = Mock()
        mock_response = Mock()
        # "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh" in base64
        # Needs to be 50+ characters to trigger base64 detection
        mock_response.text = "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovYmluL3No"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "file_read"
        }))

        # Should detect base64 encoded content containing "root:"
        assert "Base64" in result or "VULNERABLE" in result

    def test_no_false_positive_on_normal_response(self):
        """Test that normal responses don't trigger false positives."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "XML processed successfully. No data found."
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "file_read"
        }))

        assert "No direct XXE" in result or "not confirmed" in result.lower()


class TestXxeProbeSSRF:
    """Test XXE SSRF detection functionality."""

    def test_detects_aws_metadata(self):
        """Test detection of AWS metadata response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "ami-id\ninstance-id\nlocal-hostname"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "ssrf"
        }))

        assert "SSRF" in result or "ami-id" in result

    def test_detects_gcp_metadata(self):
        """Test detection of GCP metadata response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "computeMetadata\nproject-id: my-project"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "ssrf"
        }))

        assert "SSRF" in result or "computeMetadata" in result

    def test_detects_azure_metadata(self):
        """Test detection of Azure metadata response."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = '{"vmId": "abc123", "subscriptionId": "sub-456"}'
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "ssrf"
        }))

        assert "SSRF" in result or "vmId" in result

    def test_reports_response_size_change(self):
        """Test that significant response size changes are reported."""
        mock_session = Mock()

        # First call is baseline (small response)
        baseline_response = Mock()
        baseline_response.text = "OK"
        baseline_response.status_code = 200

        # Subsequent calls have larger response
        ssrf_response = Mock()
        ssrf_response.text = "A" * 500  # Much larger than baseline
        ssrf_response.status_code = 200

        mock_session.post.side_effect = [baseline_response] + [ssrf_response] * 20

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "ssrf"
        }))

        # Should note response size change
        assert "Response size changed" in result or "Possible" in result


class TestXxeProbeOOB:
    """Test XXE Out-of-Band detection functionality."""

    def test_provides_oob_payloads(self):
        """Test that OOB payloads are provided."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "OK"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "oob",
            "callback_host": "evil.com"
        }))

        assert "OOB" in result or "Out-of-Band" in result
        assert "evil.com" in result
        assert "Burp Collaborator" in result or "interactsh" in result

    def test_oob_includes_external_dtd(self):
        """Test that external DTD payloads are included."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "OK"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "oob",
            "callback_host": "attacker.com"
        }))

        assert "DTD" in result
        assert "attacker.com" in result


class TestXxeProbeError:
    """Test XXE error-based detection functionality."""

    def test_detects_xml_error_indicators(self):
        """Test detection of XML/XXE error indicators."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "Error: XML parsing failed. External entity reference not allowed."
        mock_response.status_code = 500
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "error"
        }))

        assert "Error" in result or "external entity" in result.lower()

    def test_detects_libxml_errors(self):
        """Test detection of libxml error messages."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "libxml error: parser error at line 2"
        mock_response.status_code = 500
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api/xml",
            "probe_type": "error"
        }))

        assert "libxml" in result.lower() or "Error" in result


class TestXxeProbeXmlParam:
    """Test XXE with XML in a parameter."""

    def test_xml_in_parameter(self):
        """Test XXE payload in a form parameter."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/process",
            "xml_param": "data",
            "probe_type": "file_read"
        }))

        # Verify the parameter is noted in output
        assert "data" in result or "VULNERABLE" in result

    def test_get_method_with_xml_param(self):
        """Test GET method with XML in query parameter."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "root:x:0:0"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api",
            "method": "GET",
            "xml_param": "xml",
            "probe_type": "file_read"
        }))

        # Should use GET method
        mock_session.get.assert_called()


class TestXxePayloadGeneratorBasics:
    """Test basic XxePayloadGenerator functionality."""

    def test_has_required_attributes(self):
        """Test that XxePayloadGenerator has name and description."""
        tool = XxePayloadGenerator()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "xxe_payload_generator"
        assert "XXE" in tool.description

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = XxePayloadGenerator()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_missing_payload_type(self):
        """Test that payload_type is required."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({}))
        assert "Error" in result
        assert "payload_type" in result

    def test_invalid_payload_type(self):
        """Test handling of invalid payload type."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({"payload_type": "invalid"}))
        assert "Error" in result
        assert "Unknown" in result


class TestXxePayloadGeneratorFileRead:
    """Test XxePayloadGenerator file read payloads."""

    def test_generates_basic_file_read(self):
        """Test basic file read payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "file_read",
            "target": "/etc/passwd"
        }))

        assert "file:///etc/passwd" in result
        assert "ENTITY" in result
        assert "SYSTEM" in result

    def test_generates_php_base64_payload(self):
        """Test PHP base64 filter payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "file_read",
            "target": "/flag.txt"
        }))

        assert "php://filter" in result
        assert "base64" in result

    def test_generates_cdata_payload(self):
        """Test CDATA extraction payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "file_read",
            "target": "/etc/passwd"
        }))

        assert "CDATA" in result

    def test_custom_root_element(self):
        """Test custom root element in payload."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "file_read",
            "target": "/etc/passwd",
            "root_element": "data"
        }))

        assert "<data>" in result
        assert "</data>" in result

    def test_includes_tips(self):
        """Test that tips are included."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "file_read"
        }))

        assert "Tips" in result


class TestXxePayloadGeneratorSSRF:
    """Test XxePayloadGenerator SSRF payloads."""

    def test_generates_http_ssrf(self):
        """Test HTTP SSRF payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "ssrf",
            "target": "127.0.0.1:8080"
        }))

        assert "http://127.0.0.1:8080" in result
        assert "SYSTEM" in result

    def test_generates_https_ssrf(self):
        """Test HTTPS SSRF payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "ssrf",
            "target": "internal.server.com"
        }))

        assert "https" in result.lower()

    def test_generates_ftp_ssrf(self):
        """Test FTP SSRF payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "ssrf",
            "target": "localhost"
        }))

        assert "ftp://" in result

    def test_generates_gopher_ssrf(self):
        """Test Gopher SSRF payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "ssrf",
            "target": "127.0.0.1"
        }))

        assert "gopher://" in result


class TestXxePayloadGeneratorOOB:
    """Test XxePayloadGenerator OOB payloads."""

    def test_generates_external_dtd_payload(self):
        """Test external DTD payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "oob",
            "callback": "evil.com"
        }))

        assert "evil.com" in result
        assert "DTD" in result

    def test_generates_param_oob_payload(self):
        """Test parameter entity OOB payload."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "oob",
            "callback": "attacker.com"
        }))

        assert "%" in result  # Parameter entity
        assert "attacker.com" in result

    def test_generates_dns_exfil_payload(self):
        """Test DNS exfiltration payload."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "oob",
            "callback": "burp.net"
        }))

        assert "burp.net" in result

    def test_includes_external_dtd_templates(self):
        """Test that external DTD templates are included."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "oob",
            "callback": "test.com",
            "target": "/etc/passwd"
        }))

        assert "External DTD" in result
        assert "evil.dtd" in result


class TestXxePayloadGeneratorRCE:
    """Test XxePayloadGenerator RCE payloads."""

    def test_generates_expect_payload(self):
        """Test expect:// RCE payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "rce",
            "target": "id"
        }))

        assert "expect://" in result
        assert "id" in result

    def test_generates_data_payload(self):
        """Test data:// RCE payload generation."""
        tool = XxePayloadGenerator()
        result = tool.use(json.dumps({
            "payload_type": "rce",
            "target": "whoami"
        }))

        assert "data://" in result


class TestXxeDocTypeBuilderBasics:
    """Test basic XxeDocTypeBuilder functionality."""

    def test_has_required_attributes(self):
        """Test that XxeDocTypeBuilder has name and description."""
        tool = XxeDocTypeBuilder()
        assert hasattr(tool, "name")
        assert hasattr(tool, "description")
        assert tool.name == "xxe_doctype_builder"

    def test_invalid_json_input(self):
        """Test handling of invalid JSON."""
        tool = XxeDocTypeBuilder()
        result = tool.use("not valid json")
        assert "Error" in result
        assert "JSON" in result

    def test_shows_examples_when_no_entities(self):
        """Test that examples are shown when no entities provided."""
        tool = XxeDocTypeBuilder()
        result = tool.use(json.dumps({}))
        assert "Examples" in result or "example" in result.lower()


class TestXxeDocTypeBuilderPayloads:
    """Test XxeDocTypeBuilder payload generation."""

    def test_generates_basic_entity(self):
        """Test basic entity generation."""
        tool = XxeDocTypeBuilder()
        result = tool.use(json.dumps({
            "entities": [
                {"name": "xxe", "value": "file:///etc/passwd", "system": True}
            ],
            "root": "data",
            "content": "&xxe;"
        }))

        assert "DOCTYPE" in result
        assert "ENTITY xxe SYSTEM" in result
        assert "file:///etc/passwd" in result
        assert "<data>&xxe;</data>" in result

    def test_generates_parameter_entity(self):
        """Test parameter entity generation."""
        tool = XxeDocTypeBuilder()
        result = tool.use(json.dumps({
            "entities": [
                {"name": "file", "value": "file:///etc/passwd", "type": "parameter", "system": True}
            ]
        }))

        assert "% file" in result or "%file" in result
        assert "SYSTEM" in result

    def test_generates_multiple_entities(self):
        """Test multiple entity generation."""
        tool = XxeDocTypeBuilder()
        result = tool.use(json.dumps({
            "entities": [
                {"name": "a", "value": "file:///etc/passwd", "system": True},
                {"name": "b", "value": "&a;&a;"}
            ],
            "content": "&b;"
        }))

        assert "ENTITY a SYSTEM" in result
        assert "ENTITY b" in result
        assert "&b;" in result

    def test_accepts_raw_entity_string(self):
        """Test raw entity string input."""
        tool = XxeDocTypeBuilder()
        result = tool.use(json.dumps({
            "entities": [
                '<!ENTITY xxe SYSTEM "file:///flag.txt">'
            ],
            "content": "&xxe;"
        }))

        assert "file:///flag.txt" in result


class TestXxePayloadsContent:
    """Test that XXE tools have proper payload content."""

    def test_probe_tool_has_file_read_payloads(self):
        """Test that XxeProbeTool has file read payloads."""
        assert len(XxeProbeTool.FILE_READ_PAYLOADS) > 0
        for payload, desc in XxeProbeTool.FILE_READ_PAYLOADS:
            assert "{file}" in payload
            assert "ENTITY" in payload

    def test_probe_tool_has_ssrf_payloads(self):
        """Test that XxeProbeTool has SSRF payloads."""
        assert len(XxeProbeTool.SSRF_PAYLOADS) > 0
        for payload, desc in XxeProbeTool.SSRF_PAYLOADS:
            assert "ENTITY" in payload

    def test_probe_tool_has_oob_payloads(self):
        """Test that XxeProbeTool has OOB payloads."""
        assert len(XxeProbeTool.OOB_PAYLOADS) > 0
        for payload, desc in XxeProbeTool.OOB_PAYLOADS:
            assert "{callback}" in payload

    def test_probe_tool_has_common_files(self):
        """Test that XxeProbeTool has common file list."""
        assert len(XxeProbeTool.COMMON_FILES) > 0
        assert "/etc/passwd" in XxeProbeTool.COMMON_FILES
        assert "/flag.txt" in XxeProbeTool.COMMON_FILES or "/flag" in XxeProbeTool.COMMON_FILES

    def test_probe_tool_has_file_indicators(self):
        """Test that XxeProbeTool has file content indicators."""
        assert "/etc/passwd" in XxeProbeTool.FILE_INDICATORS
        assert "root:" in XxeProbeTool.FILE_INDICATORS["/etc/passwd"]

    def test_generator_has_all_payload_types(self):
        """Test that XxePayloadGenerator has all payload types."""
        types = XxePayloadGenerator.PAYLOAD_TEMPLATES
        assert "file_read" in types
        assert "ssrf" in types
        assert "oob" in types
        assert "rce" in types


class TestXxeIntegration:
    """Integration tests for XXE tools working together."""

    def test_probe_then_generate(self):
        """Test workflow: probe for vuln, then generate exploit."""
        # First, detect vulnerability
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        probe_tool = XxeProbeTool(session=mock_session)
        probe_result = probe_tool.use(json.dumps({
            "url": "http://target.com/api",
            "probe_type": "file_read"
        }))

        assert "VULNERABLE" in probe_result

        # Then generate targeted payload
        generator = XxePayloadGenerator()
        payload_result = generator.use(json.dumps({
            "payload_type": "file_read",
            "target": "/flag.txt"
        }))

        assert "file:///flag.txt" in payload_result

    def test_builder_then_inject(self):
        """Test workflow: build custom DOCTYPE, then use."""
        builder = XxeDocTypeBuilder()
        build_result = builder.use(json.dumps({
            "entities": [
                {"name": "xxe", "value": "file:///etc/passwd", "system": True}
            ],
            "root": "request",
            "content": "<user>&xxe;</user>"
        }))

        assert "DOCTYPE" in build_result
        assert "<request>" in build_result
        assert "&xxe;" in build_result


class TestXxeEdgeCases:
    """Test edge cases and error handling."""

    def test_request_exception_handling(self):
        """Test handling of request exceptions."""
        mock_session = Mock()
        mock_session.post.side_effect = Exception("Connection refused")

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api"
        }))

        assert "Error" in result or "Connection" in result

    def test_empty_response_handling(self):
        """Test handling of empty responses."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.text = ""
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response

        tool = XxeProbeTool(session=mock_session)
        result = tool.use(json.dumps({
            "url": "http://test.com/api"
        }))

        # Should complete without error
        assert "Scan" in result or "Summary" in result

    def test_special_characters_in_target(self):
        """Test handling of special characters in target file."""
        generator = XxePayloadGenerator()
        result = generator.use(json.dumps({
            "payload_type": "file_read",
            "target": "/path/with spaces/file.txt"
        }))

        assert "/path/with spaces/file.txt" in result

    def test_unicode_in_callback(self):
        """Test handling of unicode in callback host."""
        generator = XxePayloadGenerator()
        result = generator.use(json.dumps({
            "payload_type": "oob",
            "callback": "test.example.com"
        }))

        assert "test.example.com" in result
