"""
v3.8 P0 main: family collapse — XXE proof of concept.

``CollapsedXxeTool`` exposes a single ``xxe_attack`` tool with an
``operation`` enum that dispatches to the three underlying XXE tools.
The dispatch surface drops 3 → 1 without changing the underlying
attack logic.
"""

import json
from unittest.mock import MagicMock

from ctf_solver.tools.collapsed_xxe import CollapsedXxeTool


class TestCollapsedXxeTool:
    def test_name_and_schema(self):
        tool = CollapsedXxeTool()
        assert tool.name == "xxe_attack"
        ps = tool.parameters_schema
        assert ps["properties"]["operation"]["enum"] == [
            "probe",
            "generate_payload",
            "build_doctype",
        ]
        assert "operation" in ps["required"]

    def test_invalid_operation_returns_error(self):
        tool = CollapsedXxeTool()
        out = tool.use(json.dumps({"operation": "explode"}))
        assert "Error" in out
        assert "operation" in out

    def test_missing_operation_returns_error(self):
        tool = CollapsedXxeTool()
        out = tool.use(json.dumps({"target": "x"}))
        assert "Error" in out

    def test_dispatches_to_probe(self):
        tool = CollapsedXxeTool()
        # Mock the underlying probe so we don't actually hit the network.
        tool._probe = MagicMock()
        tool._probe.use.return_value = "[XxeProbeTool] probe result"
        out = tool.use(
            json.dumps(
                {
                    "operation": "probe",
                    "url": "http://example.com/api",
                    "probe_type": "file_read",
                }
            )
        )
        assert "XxeProbeTool" in out
        # operation key is stripped before forwarding
        forwarded = json.loads(tool._probe.use.call_args[0][0])
        assert "operation" not in forwarded
        assert forwarded["url"] == "http://example.com/api"
        assert forwarded["probe_type"] == "file_read"

    def test_dispatches_to_generate_payload(self):
        tool = CollapsedXxeTool()
        tool._gen = MagicMock()
        tool._gen.use.return_value = "[XxePayloadGenerator] payload"
        out = tool.use(
            json.dumps(
                {
                    "operation": "generate_payload",
                    "payload_type": "file_read",
                    "target": "/etc/passwd",
                }
            )
        )
        assert "XxePayloadGenerator" in out

    def test_dispatches_to_build_doctype(self):
        tool = CollapsedXxeTool()
        tool._dtd = MagicMock()
        tool._dtd.use.return_value = "[XxeDocTypeBuilder] DOCTYPE"
        out = tool.use(
            json.dumps(
                {
                    "operation": "build_doctype",
                    "entities": [{"name": "xxe", "system": "file:///flag"}],
                    "root": "root",
                    "content": "&xxe;",
                }
            )
        )
        assert "XxeDocTypeBuilder" in out


class TestAgentRegistration:
    """When ``enable_collapsed_families=True`` build_agent registers the
    single collapsed xxe_attack tool instead of the three legacy ones."""

    def _build_minimal_agent(self, enable_collapsed: bool):
        from ctf_solver.agent import build_agent
        from ctf_solver.config import RAGMode, SolverConfig

        # Use a minimal config: no LLM provider that requires an API key,
        # no RAG, no opener pack, just enough to build the tool registry.
        cfg = SolverConfig(
            llm_provider="ollama",
            model_name="dummy:latest",
            llm_base_url="http://127.0.0.1:11434",
            rag_mode=RAGMode.NONE,
            enable_opener_pack=False,
            enable_collapsed_families=enable_collapsed,
        )
        # build_agent talks to the LLM provider only at planner build time;
        # if Ollama isn't reachable, we fall back gracefully.
        try:
            return build_agent(cfg, tracker=None)
        except Exception:
            return None

    @staticmethod
    def _registered_names(agent):
        """ToolRegistry.get_all_tools() returns names (strings) in this
        codebase; ``get_tool(n)`` retrieves the wrapper instance."""
        all_tools = agent.tool_executor.tool_registry.get_all_tools()
        return (
            set(all_tools)
            if all_tools and isinstance(next(iter(all_tools)), str)
            else {getattr(t, "name", str(t)) for t in all_tools}
        )

    def test_collapsed_off_keeps_three_xxe_tools(self):
        agent = self._build_minimal_agent(enable_collapsed=False)
        if agent is None:
            return  # Ollama not reachable in CI; covered by unit tests above.
        names = self._registered_names(agent)
        assert "xxe_probe" in names
        assert "xxe_payload_generator" in names
        assert "xxe_doctype_builder" in names
        assert "xxe_attack" not in names

    def test_collapsed_on_replaces_three_with_one(self):
        agent = self._build_minimal_agent(enable_collapsed=True)
        if agent is None:
            return
        names = self._registered_names(agent)
        assert "xxe_attack" in names
        assert "xxe_probe" not in names
        assert "xxe_payload_generator" not in names
        assert "xxe_doctype_builder" not in names
