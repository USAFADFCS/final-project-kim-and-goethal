"""
v3.8 P1: phase state machine.

The machine starts in RECON.  Recon / utility / RAG tools are always
allowed.  Category-specific exploit tools are gated behind a confirmed
category signal observed in some prior tool output.

Disabled by default for backwards compatibility.
"""

from ctf_solver.phases import (
    _ALWAYS_ALLOWED,
    _CATEGORY_TOOLS,
    Phase,
    PhaseStateMachine,
)


class TestDefaultDisabled:
    def test_disabled_lets_everything_through(self):
        sm = PhaseStateMachine()  # enabled=False by default
        assert sm.allowed("sqli_data_dumper")
        assert sm.allowed("ssti_exploit_suggester")
        assert sm.allowed("anything_at_all")

    def test_disabled_observe_is_noop(self):
        sm = PhaseStateMachine()
        sm.observe("sqli_probe", "SQL injection detected via auth_bypass")
        assert sm.phase == Phase.RECON
        assert sm.allowed_categories == set()


class TestEnabledRecon:
    def test_always_allowed_tools_pass_in_recon(self):
        sm = PhaseStateMachine(enabled=True)
        for name in [
            "http_fetch",
            "robots_txt",
            "javascript_source",
            "deep_recon",
            "ctf_knowledge_query",
            "attack_planner",
            "encoding",
            "final_answer",
        ]:
            assert sm.allowed(name), name

    def test_gated_tools_blocked_in_recon(self):
        sm = PhaseStateMachine(enabled=True)
        for name in [
            "sqli_data_dumper",
            "ssti_exploit_suggester",
            "xxe_payload_generator",
            "lfi_probe",
            "jwt_tool",
            "flask_session_forge",
        ]:
            assert not sm.allowed(name), name


class TestPromotionSignals:
    def test_sqli_signal_unlocks_sql_injection_category(self):
        sm = PhaseStateMachine(enabled=True)
        sm.observe("sqli_probe", "[SqliProbeTool] SQL injection detected.")
        assert sm.phase == Phase.EXPLOIT
        assert "sql_injection" in sm.allowed_categories
        assert sm.allowed("sqli_data_dumper")
        # Other categories remain locked
        assert not sm.allowed("ssti_exploit_suggester")

    def test_ssti_signal_via_arithmetic_marker(self):
        sm = PhaseStateMachine(enabled=True)
        sm.observe(
            "http_fetch",
            "Body: <p>49</p> SSTI engine appears to be jinja2",
        )
        assert "ssti" in sm.allowed_categories
        assert sm.allowed("ssti_exploit_suggester")

    def test_lfi_signal_via_passwd_leak(self):
        sm = PhaseStateMachine(enabled=True)
        sm.observe(
            "http_fetch",
            "Body: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...",
        )
        assert "lfi" in sm.allowed_categories
        assert sm.allowed("lfi_probe")
        assert sm.allowed("php_filter_chain")

    def test_implicit_unlock_via_successful_call(self):
        """A successful (non-Error:) call to a category tool unlocks the
        category even if the observation regex doesn't match — catches
        cases where the probe phrasing varies."""
        sm = PhaseStateMachine(enabled=True)
        # Calling jwt_tool with no signal-matching text but no Error prefix
        # should still unlock the jwt category for follow-up calls.
        result = sm.observe(
            "jwt_tool",
            "Header: {alg: 'none'}, Payload: {role: 'user'}",
        )
        assert result is not None
        assert "jwt" in sm.allowed_categories
        assert sm.allowed("jwt_tool")

    def test_error_observation_does_not_promote(self):
        sm = PhaseStateMachine(enabled=True)
        sm.observe(
            "sqli_probe",
            "Error: parse_json_input must be JSON. Decoding failed",
        )
        assert "sql_injection" not in sm.allowed_categories
        assert not sm.allowed("sqli_data_dumper")


class TestPhaseAdvanceMonotonic:
    def test_no_demotion(self):
        sm = PhaseStateMachine(enabled=True)
        sm._promote(Phase.EXPLOIT, "sql_injection")
        assert sm.phase == Phase.EXPLOIT
        # Trying to "promote" backwards is a no-op
        sm._promote(Phase.RECON, "sql_injection")
        assert sm.phase == Phase.EXPLOIT

    def test_extract_phase_via_mark(self):
        sm = PhaseStateMachine(enabled=True)
        sm.mark_extract()
        assert sm.phase == Phase.EXTRACT


class TestReason:
    def test_reason_for_blocked_attack_tool(self):
        sm = PhaseStateMachine(enabled=True)
        msg = sm.reason_blocked("sqli_data_dumper")
        assert "sql_injection" in msg
        assert "probe" in msg.lower()


class TestAgentLoopIntegration:
    """End-to-end check: when phase gating is on, the agent loop blocks
    a forbidden tool call and surfaces a [PHASE-GATE] observation
    instead of executing the tool."""

    def _make_agent(self, enable_phase_gate: bool = True):
        from unittest.mock import MagicMock

        from ctf_solver.agent import CTFAgent
        from tests.test_ctf_agent import FakeMemory

        agent = CTFAgent(
            llm=MagicMock(),
            planner=MagicMock(_parse_json_response=MagicMock()),
            tool_executor=MagicMock(),
            memory=FakeMemory(),
            max_steps=20,
            log_callback=lambda msg: None,
            enable_phase_gate=enable_phase_gate,
        )
        return agent

    def test_blocks_attack_tool_in_recon(self):
        import asyncio
        from unittest.mock import MagicMock

        from fairlib.core.message import Action, Thought

        from tests.test_ctf_agent import FakePlanner

        agent = self._make_agent(enable_phase_gate=True)
        # Tool executor would happily run sqli_data_dumper if reached;
        # the gate must block it before we get there.
        executor = MagicMock()
        executor.execute.return_value = "dumper output"
        agent.tool_executor = executor
        agent.planner = FakePlanner(
            [
                (
                    Thought(text="t"),
                    Action(tool_name="sqli_data_dumper", tool_input='{"x":1}'),
                ),
                (
                    Thought(text="t2"),
                    Action(tool_name="sqli_data_dumper", tool_input='{"x":1}'),
                ),
            ]
        )
        agent.max_steps = 2
        asyncio.run(agent.arun("solve"))
        # Executor should NOT have run because the gate blocked the tool.
        executor.execute.assert_not_called()
        # The agent's memory should contain a [PHASE-GATE] observation.
        history = agent.memory.get_history()
        gate_msgs = [m for m in history if "[PHASE-GATE]" in m.content]
        assert len(gate_msgs) >= 1

    def test_disabled_gate_does_not_block(self):
        import asyncio
        from unittest.mock import MagicMock

        from fairlib.core.message import Action, Thought

        from tests.test_ctf_agent import FakePlanner

        agent = self._make_agent(enable_phase_gate=False)
        executor = MagicMock()
        executor.execute.return_value = "dumper output"
        agent.tool_executor = executor
        agent.planner = FakePlanner(
            [
                (
                    Thought(text="t"),
                    Action(tool_name="sqli_data_dumper", tool_input='{"x":1}'),
                ),
            ]
        )
        agent.max_steps = 1
        asyncio.run(agent.arun("solve"))
        # Without the gate the tool runs immediately.
        executor.execute.assert_called_once()


class TestRegistryCoverage:
    def test_always_allowed_includes_recon_core(self):
        for must_have in (
            "http_fetch",
            "deep_recon",
            "ctf_knowledge_query",
            "attack_planner",
            "encoding",
            "final_answer",
        ):
            assert must_have in _ALWAYS_ALLOWED

    def test_category_tools_are_disjoint(self):
        seen = {}
        for cat, tools in _CATEGORY_TOOLS.items():
            for t in tools:
                assert t not in seen, f"{t} in both {seen.get(t)} and {cat}"
                seen[t] = cat
