"""
Tests for planner dispatch based on LLM provider (v2.9.0).

The default path (OpenAI, Anthropic, Hybrid) uses ReActPlanner, which requires
strict JSON output. Smaller/local Ollama models produce sloppy JSON that
triggers the format-error retry loop in _patch_planner_parsing.

build_agent() now dispatches to SimpleReActPlanner (key-value format) when
llm_provider is OLLAMA. The lighter DEFAULT_ROLE_DEFINITION is used for that
path (the JSON-shaped CTF few-shots are omitted).

_patch_planner_parsing on CTFAgent already guards with
hasattr(planner, "_parse_json_response") so it becomes a no-op on the
SimpleReActPlanner path without raising.
"""

import pytest
from fairlib import ReActPlanner
from fairlib.modules.planning.react_planner import SimpleReActPlanner

from ctf_solver.config import LLMProviderType, RAGMode, SolverConfig


def _make_config(provider: LLMProviderType, model: str) -> SolverConfig:
    """Minimal config that skips RAG and network side effects."""
    return SolverConfig(
        llm_provider=provider,
        model_name=model,
        openai_api_key="sk-test-dummy",
        anthropic_api_key="sk-ant-test-dummy",
        rag_mode=RAGMode.NONE,
        enable_opener_pack=False,
        challenge_url=None,
        challenge_description="test",
    )


def _build_agent_quietly(config: SolverConfig):
    """build_agent with a no-op log sink so tests stay clean."""
    # Import inside the helper so coverage measures the real import once.
    from ctf_solver.agent import build_agent

    return build_agent(config, log_callback=lambda _m: None)


class TestPlannerDispatch:
    """build_agent() picks the right planner class per LLM provider."""

    def test_openai_provider_uses_reactplanner(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        agent = _build_agent_quietly(config)
        assert isinstance(agent.planner, ReActPlanner)
        assert not isinstance(agent.planner, SimpleReActPlanner)

    def test_anthropic_provider_uses_reactplanner(self):
        config = _make_config(LLMProviderType.ANTHROPIC, "claude-3-5-sonnet-20241022")
        # ANTHROPIC adapter path pulls in anthropic sdk — skip if unavailable.
        pytest.importorskip("anthropic")
        agent = _build_agent_quietly(config)
        assert isinstance(agent.planner, ReActPlanner)
        assert not isinstance(agent.planner, SimpleReActPlanner)

    def test_ollama_provider_uses_simple_reactplanner(self):
        config = _make_config(LLMProviderType.OLLAMA, "llama3:8b")
        pytest.importorskip("ollama")
        agent = _build_agent_quietly(config)
        assert isinstance(agent.planner, SimpleReActPlanner)
        # SimpleReActPlanner is itself a subclass path, but ReActPlanner and
        # SimpleReActPlanner are siblings under AbstractPlanner — verify
        # we did not accidentally end up on the wrong branch.
        assert not isinstance(agent.planner, ReActPlanner)

    def test_claude_model_name_auto_upgrades_to_anthropic(self):
        """Regression guard: model_name starts with 'claude' → Anthropic → ReActPlanner.

        build_agent() has a pre-existing fixup that flips provider to Anthropic
        when model_name starts with 'claude', even if the config says OpenAI.
        The dispatch must still land on ReActPlanner.
        """
        pytest.importorskip("anthropic")
        config = _make_config(LLMProviderType.OPENAI, "claude-3-5-sonnet-20241022")
        agent = _build_agent_quietly(config)
        assert isinstance(agent.planner, ReActPlanner)


class TestPromptWiringByPlanner:
    """The two planner paths get different PromptBuilder content."""

    def test_reactplanner_path_injects_json_system_prompt_and_examples(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        agent = _build_agent_quietly(config)
        pb = agent.planner.prompt_builder

        # Role contains the JSON format rules from DEFAULT_SYSTEM_PROMPT.
        role_text = pb.role_definition.text
        assert "CRITICAL RESPONSE FORMAT RULES" in role_text
        assert "single, valid JSON object" in role_text

        # Six CTF few-shot examples are appended.
        assert len(pb.examples) == 6

    def test_simple_reactplanner_path_uses_lighter_role_and_no_json_examples(self):
        config = _make_config(LLMProviderType.OLLAMA, "llama3:8b")
        pytest.importorskip("ollama")
        agent = _build_agent_quietly(config)
        pb = agent.planner.prompt_builder

        # Role text from DEFAULT_ROLE_DEFINITION — NO strict JSON format rules.
        role_text = pb.role_definition.text
        assert "CRITICAL RESPONSE FORMAT RULES" not in role_text
        # DEFAULT_ROLE_DEFINITION uses this phrasing.
        assert "Thought -> Action -> Tool Observation loop" in role_text

        # CTF JSON few-shots are intentionally NOT appended (they would
        # teach the wrong output shape for a key-value planner). Any
        # examples present are planner-library defaults, not the six
        # CTF examples. Verify none of our CTF examples slipped in.
        from ctf_solver.prompts import ROBOTS_EXAMPLE, SELF_REFLECTION_EXAMPLE

        assert ROBOTS_EXAMPLE not in pb.examples
        assert SELF_REFLECTION_EXAMPLE not in pb.examples


class TestOllamaModelNameAutoDetection:
    """_looks_like_ollama_model heuristic + build_agent() auto-routing.

    Users commonly pass a model name without also setting --provider. A name
    in Ollama's name:tag form should auto-route to the Ollama path so
    edgerunner-medium / llama3.1 / mistral-small / gpt-oss "just work".
    """

    def test_edgerunner_medium_detected(self):
        from ctf_solver.agent import _looks_like_ollama_model

        assert _looks_like_ollama_model("edgerunner-medium:latest")

    def test_llama31_detected(self):
        from ctf_solver.agent import _looks_like_ollama_model

        assert _looks_like_ollama_model("llama3.1:latest")

    def test_mistral_small_detected(self):
        from ctf_solver.agent import _looks_like_ollama_model

        assert _looks_like_ollama_model("mistral-small:latest")

    def test_gpt_oss_detected(self):
        """gpt-oss is OpenAI's open-weight release served via Ollama locally.
        Must NOT be confused with gpt-4o or gpt-5.2 (OpenAI hosted)."""
        from ctf_solver.agent import _looks_like_ollama_model

        assert _looks_like_ollama_model("gpt-oss:20b")

    def test_gpt_4o_not_detected_as_ollama(self):
        """Regression guard: hosted OpenAI model must stay on OpenAI path."""
        from ctf_solver.agent import _looks_like_ollama_model

        assert not _looks_like_ollama_model("gpt-4o")
        assert not _looks_like_ollama_model("gpt-5.2")

    def test_claude_not_detected_as_ollama(self):
        from ctf_solver.agent import _looks_like_ollama_model

        assert not _looks_like_ollama_model("claude-sonnet-4-6")
        assert not _looks_like_ollama_model("claude-opus-4-6")

    def test_empty_name_handled(self):
        from ctf_solver.agent import _looks_like_ollama_model

        assert not _looks_like_ollama_model("")
        assert not _looks_like_ollama_model(None)  # type: ignore[arg-type]

    def test_edgerunner_model_name_routes_to_simple_planner(self):
        """End-to-end: config sets OPENAI provider, but model name is an
        Ollama local name. build_agent must auto-flip to OLLAMA + SimpleReActPlanner."""
        pytest.importorskip("ollama")
        config = _make_config(LLMProviderType.OPENAI, "edgerunner-medium:latest")
        agent = _build_agent_quietly(config)
        assert isinstance(agent.planner, SimpleReActPlanner)
        # build_agent mutates config.llm_provider on auto-detect — verify.
        assert config.llm_provider == LLMProviderType.OLLAMA


class TestOllamaNumCtxPlumbing:
    """num_ctx must reach Ollama's options dict, or the Modelfile default
    (often 4096) silently truncates the CTF agent's ~10k-token prompt and
    the model returns empty/garbage responses. Regression guard: every
    invocation site (invoke, stream) must include num_ctx."""

    def test_adapter_default_num_ctx_is_16384(self):
        pytest.importorskip("ollama")
        from ctf_solver.llm.adapters import OllamaAdapter

        adapter = OllamaAdapter(model_name="llama3.1:latest")
        assert adapter.num_ctx == 16384

    def test_adapter_constructor_accepts_custom_num_ctx(self):
        pytest.importorskip("ollama")
        from ctf_solver.llm.adapters import OllamaAdapter

        adapter = OllamaAdapter(model_name="llama3.1:latest", num_ctx=32768)
        assert adapter.num_ctx == 32768

    def test_invoke_passes_num_ctx_to_ollama_client(self):
        """Monkey-patch self.client.chat and inspect the options dict."""
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        adapter = OllamaAdapter(model_name="llama3.1:latest", num_ctx=16384)
        captured: dict = {}

        def _fake_chat(**kwargs):
            captured.update(kwargs)
            return {"message": {"content": "stub"}}

        adapter.client.chat = _fake_chat  # type: ignore[assignment]
        adapter.invoke([FairMessage(role="user", content="hello")])

        assert "options" in captured
        assert captured["options"].get("num_ctx") == 16384
        # Temperature is still preserved.
        assert "temperature" in captured["options"]

    def test_invoke_kwargs_override_default_num_ctx(self):
        """Per-call kwargs should win over the adapter's stored default
        so the agent can dynamically shrink context for cheap probes or
        raise it for long multi-turn runs without rebuilding the adapter."""
        pytest.importorskip("ollama")
        from fairlib.core.message import Message as FairMessage

        from ctf_solver.llm.adapters import OllamaAdapter

        adapter = OllamaAdapter(model_name="llama3.1:latest", num_ctx=16384)
        captured: dict = {}

        def _fake_chat(**kwargs):
            captured.update(kwargs)
            return {"message": {"content": "stub"}}

        adapter.client.chat = _fake_chat  # type: ignore[assignment]
        adapter.invoke([FairMessage(role="user", content="hello")], num_ctx=32768)
        assert captured["options"].get("num_ctx") == 32768

    def test_create_adapter_from_config_threads_num_ctx(self):
        """SolverConfig.ollama_num_ctx must reach the adapter."""
        pytest.importorskip("ollama")
        from ctf_solver.llm.adapters import create_adapter_from_config

        config = SolverConfig(
            llm_provider=LLMProviderType.OLLAMA,
            model_name="llama3.1:latest",
            openai_api_key="sk-dummy",
            rag_mode=RAGMode.NONE,
            ollama_num_ctx=24576,
        )
        adapter = create_adapter_from_config(config)
        assert adapter.num_ctx == 24576

    def test_solver_config_default_ollama_num_ctx(self):
        """Default is 16384 — large enough for the CTF tool-instruction region."""
        config = SolverConfig(openai_api_key="sk-dummy")
        assert config.ollama_num_ctx == 16384

    def test_from_env_reads_ctf_ollama_num_ctx(self, monkeypatch):
        monkeypatch.setenv("CTF_OLLAMA_NUM_CTX", "32768")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-dummy")
        config = SolverConfig.from_env()
        assert config.ollama_num_ctx == 32768


class TestParserPatchIsNoopForSimplePlanner:
    """_patch_planner_parsing guards with hasattr; SimpleReActPlanner has no
    _parse_json_response attribute, so the patch must not crash and must not
    replace any method on the simple planner."""

    def test_patch_is_noop_on_simple_planner(self):
        config = _make_config(LLMProviderType.OLLAMA, "llama3:8b")
        pytest.importorskip("ollama")
        agent = _build_agent_quietly(config)
        # SimpleReActPlanner defines _parse_simplified_response, not
        # _parse_json_response. The guard in _patch_planner_parsing should
        # leave the planner untouched.
        assert not hasattr(agent.planner, "_parse_json_response")
        assert hasattr(agent.planner, "_parse_simplified_response")

    def test_patch_replaces_method_on_react_planner(self):
        config = _make_config(LLMProviderType.OPENAI, "gpt-4o")
        agent = _build_agent_quietly(config)
        # ReActPlanner path: _parse_json_response is monkey-patched by
        # CTFAgent.__init__ → _patch_planner_parsing.
        assert hasattr(agent.planner, "_parse_json_response")
        # The patched callable is the closure inside _patch_planner_parsing;
        # sanity check it is NOT the original fairlib bound method.
        assert agent.planner._parse_json_response.__name__ == "_robust_parse"
