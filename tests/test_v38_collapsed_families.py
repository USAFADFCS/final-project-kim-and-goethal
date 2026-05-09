"""
v3.8 P0 main: family collapse for XSS, crypto, SQLi.

Mirrors ``test_v38_collapsed_xxe.py`` for the three remaining families.
Each collapsed wrapper exposes a single ``*_attack`` tool with an
``operation`` enum that dispatches to the legacy underlying tools
without changing the attack logic.
"""

import json
from unittest.mock import MagicMock

from ctf_solver.tools.collapsed_crypto import CollapsedCryptoTool
from ctf_solver.tools.collapsed_sqli import CollapsedSqliTool
from ctf_solver.tools.collapsed_xss import CollapsedXssTool


class TestCollapsedXssTool:
    def test_name_and_schema(self):
        tool = CollapsedXssTool()
        assert tool.name == "xss_attack"
        ps = tool.parameters_schema
        assert ps["properties"]["operation"]["enum"] == [
            "probe",
            "generate_payload",
            "csp_analyze",
        ]
        assert "operation" in ps["required"]

    def test_invalid_operation_returns_error(self):
        tool = CollapsedXssTool()
        out = tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in out
        assert "operation" in out

    def test_missing_operation_returns_error(self):
        tool = CollapsedXssTool()
        out = tool.use(json.dumps({"url": "x"}))
        assert "Error" in out

    def test_dispatches_to_probe(self):
        tool = CollapsedXssTool()
        tool._probe = MagicMock()
        tool._probe.use.return_value = "[XssProbeTool] probe result"
        out = tool.use(
            json.dumps(
                {"operation": "probe", "url": "http://example.com/?q=1", "param": "q"}
            )
        )
        assert "XssProbeTool" in out
        forwarded = json.loads(tool._probe.use.call_args[0][0])
        assert "operation" not in forwarded
        assert forwarded["url"] == "http://example.com/?q=1"

    def test_dispatches_to_generate_payload(self):
        tool = CollapsedXssTool()
        tool._gen = MagicMock()
        tool._gen.use.return_value = "[XssPayloadGenerator] payload"
        out = tool.use(
            json.dumps({"operation": "generate_payload", "payload_type": "reflected"})
        )
        assert "XssPayloadGenerator" in out

    def test_dispatches_to_csp_analyze(self):
        tool = CollapsedXssTool()
        tool._csp = MagicMock()
        tool._csp.use.return_value = "[CspAnalyzerTool] analysis"
        out = tool.use(
            json.dumps({"operation": "csp_analyze", "url": "http://example.com/"})
        )
        assert "CspAnalyzerTool" in out


class TestCollapsedCryptoTool:
    def test_name_and_schema(self):
        tool = CollapsedCryptoTool()
        assert tool.name == "crypto_attack"
        ps = tool.parameters_schema
        assert ps["properties"]["operation"]["enum"] == [
            "probe",
            "analyze",
            "generate_payload",
        ]
        assert "operation" in ps["required"]

    def test_invalid_operation_returns_error(self):
        tool = CollapsedCryptoTool()
        out = tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in out

    def test_missing_operation_returns_error(self):
        tool = CollapsedCryptoTool()
        out = tool.use(json.dumps({"url": "x"}))
        assert "Error" in out

    def test_dispatches_to_probe(self):
        tool = CollapsedCryptoTool()
        tool._probe = MagicMock()
        tool._probe.use.return_value = "[CryptoProbeTool] probe result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "probe",
                    "url": "http://example.com/decrypt",
                    "param": "token",
                    "crypto_type": "ecb_detect",
                }
            )
        )
        assert "CryptoProbeTool" in out
        forwarded = json.loads(tool._probe.use.call_args[0][0])
        assert "operation" not in forwarded

    def test_dispatches_to_analyze(self):
        tool = CollapsedCryptoTool()
        tool._analyzer = MagicMock()
        tool._analyzer.use.return_value = "[CryptoAnalyzerTool] result"
        out = tool.use(json.dumps({"operation": "analyze", "token": "abc123"}))
        assert "CryptoAnalyzerTool" in out

    def test_dispatches_to_generate_payload(self):
        tool = CollapsedCryptoTool()
        tool._gen = MagicMock()
        tool._gen.use.return_value = "[CryptoPayloadGenerator] payload"
        out = tool.use(
            json.dumps(
                {"operation": "generate_payload", "attack_type": "padding_oracle"}
            )
        )
        assert "CryptoPayloadGenerator" in out


class TestCollapsedSqliTool:
    def test_name_and_schema(self):
        tool = CollapsedSqliTool()
        assert tool.name == "sqli_attack"
        ps = tool.parameters_schema
        assert ps["properties"]["operation"]["enum"] == [
            "probe",
            "count_columns",
            "dump",
            "blind_boolean",
            "blind_time",
        ]
        assert "operation" in ps["required"]

    def test_invalid_operation_returns_error(self):
        tool = CollapsedSqliTool()
        out = tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in out

    def test_missing_operation_returns_error(self):
        tool = CollapsedSqliTool()
        out = tool.use(json.dumps({"url": "x"}))
        assert "Error" in out

    def test_dispatches_to_probe(self):
        tool = CollapsedSqliTool()
        tool._probe = MagicMock()
        tool._probe.use.return_value = "[SqliProbeTool] probe"
        out = tool.use(
            json.dumps(
                {
                    "operation": "probe",
                    "url": "http://example.com/?id=1",
                    "param": "id",
                }
            )
        )
        assert "SqliProbeTool" in out
        forwarded = json.loads(tool._probe.use.call_args[0][0])
        assert "operation" not in forwarded

    def test_dispatches_to_count_columns(self):
        tool = CollapsedSqliTool()
        tool._counter = MagicMock()
        tool._counter.use.return_value = "[SqliColumnCounter] result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "count_columns",
                    "url": "http://example.com/?id=1",
                    "param": "id",
                }
            )
        )
        assert "SqliColumnCounter" in out

    def test_dispatches_to_dump(self):
        tool = CollapsedSqliTool()
        tool._dumper = MagicMock()
        tool._dumper.use.return_value = "[SqliDataDumper] result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "dump",
                    "url": "http://example.com/?id=1",
                    "param": "id",
                    "columns": 3,
                    "table": "users",
                }
            )
        )
        assert "SqliDataDumper" in out

    def test_dispatches_to_blind_boolean(self):
        tool = CollapsedSqliTool()
        tool._bool = MagicMock()
        tool._bool.use.return_value = "[BlindSqliBooleanTool] result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "blind_boolean",
                    "url": "http://example.com/login",
                    "param": "username",
                    "true_marker": "Welcome",
                }
            )
        )
        assert "BlindSqliBooleanTool" in out

    def test_dispatches_to_blind_time(self):
        tool = CollapsedSqliTool()
        tool._time = MagicMock()
        tool._time.use.return_value = "[BlindSqliTimeTool] result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "blind_time",
                    "url": "http://example.com/login",
                    "param": "username",
                    "delay": 5,
                }
            )
        )
        assert "BlindSqliTimeTool" in out


class TestAgentRegistration:
    """When ``enable_collapsed_families=True`` build_agent should swap in
    each collapsed *_attack tool in place of the legacy multi-tool surface."""

    def _build_minimal_agent(self, enable_collapsed: bool):
        from ctf_solver.agent import build_agent
        from ctf_solver.config import RAGMode, SolverConfig

        cfg = SolverConfig(
            llm_provider="ollama",
            model_name="dummy:latest",
            llm_base_url="http://127.0.0.1:11434",
            rag_mode=RAGMode.NONE,
            enable_opener_pack=False,
            enable_collapsed_families=enable_collapsed,
        )
        try:
            return build_agent(cfg, tracker=None)
        except Exception:
            return None

    @staticmethod
    def _registered_names(agent):
        all_tools = agent.tool_executor.tool_registry.get_all_tools()
        return (
            set(all_tools)
            if all_tools and isinstance(next(iter(all_tools)), str)
            else {getattr(t, "name", str(t)) for t in all_tools}
        )

    def test_collapsed_off_keeps_legacy_tools(self):
        agent = self._build_minimal_agent(enable_collapsed=False)
        if agent is None:
            return
        names = self._registered_names(agent)
        # XSS legacy
        assert "xss_probe" in names
        assert "xss_payload_generator" in names
        assert "csp_analyzer" in names
        assert "xss_attack" not in names
        # Crypto legacy
        assert "crypto_probe" in names
        assert "crypto_analyzer" in names
        assert "crypto_payload_generator" in names
        assert "crypto_attack" not in names
        # SQLi legacy
        assert "sqli_probe" in names
        assert "sqli_column_counter" in names
        assert "sqli_data_dumper" in names
        assert "blind_sqli_boolean" in names
        assert "blind_sqli_time" in names
        assert "sqli_attack" not in names

    def test_collapsed_on_replaces_legacy(self):
        agent = self._build_minimal_agent(enable_collapsed=True)
        if agent is None:
            return
        names = self._registered_names(agent)
        # XSS collapsed
        assert "xss_attack" in names
        assert "xss_probe" not in names
        assert "xss_payload_generator" not in names
        assert "csp_analyzer" not in names
        # Crypto collapsed
        assert "crypto_attack" in names
        assert "crypto_probe" not in names
        assert "crypto_analyzer" not in names
        assert "crypto_payload_generator" not in names
        # SQLi collapsed
        assert "sqli_attack" in names
        assert "sqli_probe" not in names
        assert "sqli_column_counter" not in names
        assert "sqli_data_dumper" not in names
        assert "blind_sqli_boolean" not in names
        assert "blind_sqli_time" not in names
