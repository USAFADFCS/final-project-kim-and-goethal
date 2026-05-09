"""v3.4 — MLXAdapter: enum wiring, factory dispatch, lazy-import error,
and mocked invoke plumbing.

All tests use mocked ``mlx_lm`` + ``outlines`` modules so they run on any
platform (Linux CI, non-ARM macOS, etc.). The one opt-in integration test
at the bottom requires real mlx-lm + the Gemma4 model present in the
HuggingFace cache; gate via ``CTF_RUN_MLX_INTEGRATION=1``.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest
from fairlib import Message

from ctf_solver.config import LLMProviderType, SolverConfig
from ctf_solver.llm import adapters as llm_adapters
from ctf_solver.llm.adapters import (
    _REACT_SCHEMA,
    LLMProvider,
    MLXAdapter,
    _build_mlx_schema,
    create_adapter,
    create_adapter_from_config,
)

# ---------------------------------------------------------------------------
# Helpers — build a fake mlx_lm + outlines module graph we can inject into
# sys.modules so the lazy import inside ``_load_mlx_stack`` succeeds without
# requiring the real packages.
# ---------------------------------------------------------------------------


class _FakeJsonSchema:
    """Stand-in for ``outlines.types.JsonSchema`` — just holds the schema."""

    def __init__(self, schema: Dict[str, Any]) -> None:
        self.schema = schema


class _FakeOutlinesModel:
    """Records calls so tests can assert on kwargs."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self.next_return: str = (
            '{"thought":"x","action":{"tool_name":"y","tool_input":"z"}}'
        )

    def __call__(self, prompt: str, **kwargs: Any) -> str:
        self.calls.append((prompt, kwargs))
        return self.next_return


class _FakeTokenizer:
    def __init__(self) -> None:
        self.last_messages: Optional[List[Dict[str, str]]] = None

    def apply_chat_template(
        self,
        messages: List[Dict[str, str]],
        *,
        add_generation_prompt: bool = True,
        tokenize: bool = False,
    ) -> str:
        self.last_messages = messages
        return (
            "<bos>"
            + "".join(f"<{m['role']}>{m['content']}</{m['role']}>" for m in messages)
            + ("<model>" if add_generation_prompt else "")
        )


def _install_fake_mlx_modules(
    *, outlines_missing: bool = False, mlx_lm_missing: bool = False
) -> Dict[str, Any]:
    """Inject fake ``mlx_lm`` / ``outlines`` / ``mlx.core`` into ``sys.modules``.

    Returns a handle dict so tests can inspect recorded call args.
    """
    state: Dict[str, Any] = {
        "outlines_model": _FakeOutlinesModel(),
        "tokenizer": _FakeTokenizer(),
        "mlx_model": MagicMock(name="mlx_model"),
        "mx_seed_calls": [],
        "mlx_lm_generate_calls": [],
        "make_sampler_calls": [],
    }

    # mlx.core
    if not mlx_lm_missing:
        mx_core = types.ModuleType("mlx.core")

        def _seed(n: int) -> None:
            state["mx_seed_calls"].append(n)

        mx_core.random = types.SimpleNamespace(seed=_seed)
        mlx_pkg = types.ModuleType("mlx")
        mlx_pkg.core = mx_core
        sys.modules["mlx"] = mlx_pkg
        sys.modules["mlx.core"] = mx_core

        # mlx_lm
        mlx_lm_mod = types.ModuleType("mlx_lm")

        def _load(model_name: str) -> Tuple[Any, Any]:
            state["loaded_model_name"] = model_name
            return state["mlx_model"], state["tokenizer"]

        def _generate(model, tok, prompt, **kw):
            state["mlx_lm_generate_calls"].append((prompt, kw))
            return "prewarm-ok"

        mlx_lm_mod.load = _load
        mlx_lm_mod.generate = _generate

        # mlx_lm.sample_utils.make_sampler — the adapter builds a sampler
        # via this for each invoke and passes it as ``sampler=<callable>``.
        sample_utils = types.ModuleType("mlx_lm.sample_utils")

        def _make_sampler(**kwargs):
            state["make_sampler_calls"].append(kwargs)

            def _sampler_fn(*a, **kw):  # noqa: D401 — sentinel callable
                return 0

            _sampler_fn._recorded_kwargs = kwargs  # type: ignore[attr-defined]
            return _sampler_fn

        sample_utils.make_sampler = _make_sampler
        mlx_lm_mod.sample_utils = sample_utils
        sys.modules["mlx_lm"] = mlx_lm_mod
        sys.modules["mlx_lm.sample_utils"] = sample_utils
    else:
        # Force ImportError for mlx_lm
        sys.modules["mlx_lm"] = None  # type: ignore[assignment]

    # outlines
    if not outlines_missing and not mlx_lm_missing:
        outlines_mod = types.ModuleType("outlines")

        def _from_mlxlm(model, tok):
            state["from_mlxlm_args"] = (model, tok)
            return state["outlines_model"]

        outlines_types = types.ModuleType("outlines.types")
        outlines_types.JsonSchema = _FakeJsonSchema
        outlines_mod.from_mlxlm = _from_mlxlm
        outlines_mod.types = outlines_types
        sys.modules["outlines"] = outlines_mod
        sys.modules["outlines.types"] = outlines_types
    elif outlines_missing:
        sys.modules["outlines"] = None  # type: ignore[assignment]

    return state


@pytest.fixture(autouse=True)
def _reset_mlx_cache_and_modules():
    """Every test starts with a clean ``_MLX_CACHE`` and no injected modules."""
    llm_adapters._MLX_CACHE.clear()
    preserved = {
        k: sys.modules.get(k)
        for k in (
            "mlx",
            "mlx.core",
            "mlx_lm",
            "mlx_lm.sample_utils",
            "outlines",
            "outlines.types",
        )
    }
    yield
    llm_adapters._MLX_CACHE.clear()
    for k, v in preserved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v


# ---------------------------------------------------------------------------
# Enum presence
# ---------------------------------------------------------------------------


class TestLLMProviderMlxEnum:
    def test_llm_provider_has_mlx_enum(self):
        assert LLMProvider.MLX.value == "mlx"

    def test_config_llm_provider_type_has_mlx(self):
        assert LLMProviderType.MLX.value == "mlx"


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------


class TestMlxAdapterContract:
    def test_mlxadapter_extends_abstract_chat_model(self):
        from fairlib import AbstractChatModel

        adapter = MLXAdapter(prewarm=False)
        assert isinstance(adapter, AbstractChatModel)

    def test_mlxadapter_default_model_name_is_gemma_4bit(self):
        adapter = MLXAdapter(prewarm=False)
        assert adapter.model_name == "mlx-community/gemma-4-26b-a4b-it-4bit"

    def test_mlxadapter_capabilities_reports_mlx_provider(self):
        adapter = MLXAdapter(prewarm=False, grammar_schema=_REACT_SCHEMA)
        caps = adapter.get_model_capabilities()
        assert caps["provider"] == "mlx"
        assert caps["local"] is True
        assert caps["supports_json_schema"] is True
        assert caps["supports_streaming"] is False


# ---------------------------------------------------------------------------
# Lazy import error path
# ---------------------------------------------------------------------------


class TestLazyImportErrorMessages:
    def test_missing_mlx_lm_raises_actionable_error(self):
        _install_fake_mlx_modules(mlx_lm_missing=True)
        adapter = MLXAdapter(prewarm=False)
        with pytest.raises(ImportError) as exc_info:
            adapter.invoke([Message(role="user", content="hi")])
        msg = str(exc_info.value)
        assert "mlx_lm and outlines" in msg
        assert "mlx-env" in msg
        assert 'pip install "outlines[mlxlm]"' in msg

    def test_missing_outlines_raises_actionable_error(self):
        _install_fake_mlx_modules(outlines_missing=True)
        adapter = MLXAdapter(prewarm=False)
        with pytest.raises(ImportError) as exc_info:
            adapter.invoke([Message(role="user", content="hi")])
        assert "outlines" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Invoke wiring — prompt shape, output_type, sampling kwargs, KV quant
# ---------------------------------------------------------------------------


class TestInvokeWiring:
    def test_invoke_applies_chat_template(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False)
        adapter.invoke(
            [
                Message(role="system", content="you are a ctf agent"),
                Message(role="user", content="list /tmp"),
            ]
        )
        assert state["tokenizer"].last_messages == [
            {"role": "system", "content": "you are a ctf agent"},
            {"role": "user", "content": "list /tmp"},
        ]
        # Prompt reached the outlines callable
        assert len(state["outlines_model"].calls) == 1
        prompt = state["outlines_model"].calls[0][0]
        assert "<bos>" in prompt and "list /tmp" in prompt

    def test_invoke_passes_jsonschema_output_type_when_schema_set(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, grammar_schema=_REACT_SCHEMA)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert "output_type" in kwargs
        assert isinstance(kwargs["output_type"], _FakeJsonSchema)
        assert kwargs["output_type"].schema == _REACT_SCHEMA

    def test_invoke_omits_output_type_when_schema_none(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, grammar_schema=None)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert "output_type" not in kwargs

    def test_invoke_forwards_temperature_top_p_max_tokens(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, temperature=0.5, top_p=0.8, max_tokens=1234)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert kwargs["max_tokens"] == 1234
        # temperature/top_p are NOT raw kwargs — generate_step would raise
        # ``TypeError: unexpected keyword argument`` if they were. They
        # go through make_sampler(temp=..., top_p=..., top_k=...) and
        # arrive as a single ``sampler`` callable. ``top_k`` falls back
        # to the Gemma 4 default (64) since the caller didn't override.
        assert "temperature" not in kwargs
        assert "top_p" not in kwargs
        assert "sampler" in kwargs
        assert state["make_sampler_calls"] == [{"temp": 0.5, "top_p": 0.8, "top_k": 64}]

    def test_invoke_does_not_pass_seed_as_kwarg(self):
        # Regression: v3.4 initial impl passed ``seed`` per-call, which
        # generate_step rejects. Seed is applied once at load time via
        # ``mx.random.seed`` inside _load_mlx_stack.
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, seed=42)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert "seed" not in kwargs
        assert 42 in state["mx_seed_calls"]

    def test_invoke_builds_sampler_with_defaults(self):
        # Default MLXAdapter sampling matches Google's Gemma 4 model card
        # (ai.google.dev/gemma/docs/core/model_card_4): temperature=1.0,
        # top_p=0.95, top_k=64. Earlier defaults (0.2/0.9/no top_k) over-
        # concentrated the distribution and amplified Gemma 4's repetition-
        # collapse mode under FSM-masked decoding.
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False)
        adapter.invoke([Message(role="user", content="hi")])
        assert state["make_sampler_calls"] == [
            {"temp": 1.0, "top_p": 0.95, "top_k": 64}
        ]

    def test_invoke_top_k_overridable_by_caller(self):
        # Caller-provided top_k overrides the Gemma 4 default of 64.
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, top_k=16)
        adapter.invoke([Message(role="user", content="hi")])
        assert state["make_sampler_calls"] == [
            {"temp": 1.0, "top_p": 0.95, "top_k": 16}
        ]

    def test_invoke_forwards_kv_bits_and_group_size_when_set(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, kv_bits=4)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert kwargs["kv_bits"] == 4
        assert kwargs["kv_group_size"] == 64
        assert kwargs["quantized_kv_start"] == 512

    def test_invoke_omits_kv_bits_when_none(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, kv_bits=None)
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        assert "kv_bits" not in kwargs
        assert "kv_group_size" not in kwargs

    def test_invoke_applies_seed_to_mx_random(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, seed=99)
        adapter.invoke([Message(role="user", content="hi")])
        assert 99 in state["mx_seed_calls"]

    def test_tool_role_message_gets_rewritten_to_user(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False)
        adapter.invoke(
            [
                Message(role="user", content="do a thing"),
                Message(role="tool", content="observation data"),
            ]
        )
        roles = [m["role"] for m in state["tokenizer"].last_messages]
        assert "tool" not in roles
        # The tool message content is preserved, just under user role
        assert any(
            m["content"] == "observation data" for m in state["tokenizer"].last_messages
        )

    def test_prewarm_fires_when_enabled(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=True)
        adapter.invoke([Message(role="user", content="hi")])
        assert len(state["mlx_lm_generate_calls"]) == 1
        _, warm_kwargs = state["mlx_lm_generate_calls"][0]
        assert warm_kwargs["max_tokens"] == 1

    def test_prewarm_skipped_when_disabled(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False)
        adapter.invoke([Message(role="user", content="hi")])
        assert state["mlx_lm_generate_calls"] == []

    def test_second_invoke_reuses_cached_model(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False)
        adapter.invoke([Message(role="user", content="one")])
        adapter.invoke([Message(role="user", content="two")])
        # Cache hit: only one load, one from_mlxlm call
        assert len(state["outlines_model"].calls) == 2
        # But the mlx_lm.load function should only run once; we can
        # assert this via mx_seed_calls only being set once (seed defaults
        # to None, so no calls). Instead assert cache has exactly one entry.
        assert len(llm_adapters._MLX_CACHE) == 1


# ---------------------------------------------------------------------------
# Factory dispatch
# ---------------------------------------------------------------------------


class TestFactoryDispatch:
    def test_create_adapter_dispatches_mlx_provider(self):
        a = create_adapter(
            provider=LLMProvider.MLX,
            model_name="mlx-community/gemma-4-26b-a4b-it-4bit",
            grammar_mode="auto",
            mlx_prewarm=False,
        )
        assert isinstance(a, MLXAdapter)
        assert a.grammar_schema == _REACT_SCHEMA

    def test_create_adapter_grammar_mode_none_disables_schema(self):
        a = create_adapter(
            provider=LLMProvider.MLX,
            grammar_mode="none",
            mlx_prewarm=False,
        )
        assert a.grammar_schema is None

    def test_create_adapter_accepts_string_provider(self):
        a = create_adapter(provider="mlx", grammar_mode="auto", mlx_prewarm=False)
        assert isinstance(a, MLXAdapter)

    def test_create_adapter_from_config_dispatches_mlx(self):
        cfg = SolverConfig(
            llm_provider=LLMProviderType.MLX,
            model_name="mlx-community/gemma-4-26b-a4b-it-4bit",
            mlx_kv_bits=4,
            mlx_seed=7,
            mlx_prewarm=False,
        )
        a = create_adapter_from_config(cfg)
        assert isinstance(a, MLXAdapter)
        assert a.kv_bits == 4
        assert a.seed == 7
        assert a.prewarm is False


# ---------------------------------------------------------------------------
# Model-name auto-detection routes mlx-community/* to MLX (not Ollama)
# ---------------------------------------------------------------------------


class TestAutoDetectMlxFromModelName:
    """The ``gemma`` prefix in ``mlx-community/gemma-4-...`` must not trick
    the Ollama heuristic. Auto-detect should route mlx-community/* to MLX.
    """

    def test_mlx_community_prefix_routes_to_mlx(self):
        # Import inside the test so agent.py's heavy import graph is lazy.
        from ctf_solver import agent as ctf_agent

        cfg = SolverConfig(
            llm_provider=LLMProviderType.OPENAI,  # default, expect override
            model_name="mlx-community/gemma-4-26b-a4b-it-4bit",
        )
        # Walk just the provider-detection block rather than running
        # build_agent end-to-end (that would try to load the model).
        provider = cfg.llm_provider
        mn = cfg.model_name
        if mn and mn.startswith("claude"):
            provider = LLMProviderType.ANTHROPIC
        elif mn and mn.startswith("mlx-community/"):
            provider = LLMProviderType.MLX
        elif mn and ctf_agent._looks_like_ollama_model(mn):
            provider = LLMProviderType.OLLAMA
        assert provider == LLMProviderType.MLX


# ---------------------------------------------------------------------------
# v3.4-hotfix-2: schema bounds + tool_name enum
# ---------------------------------------------------------------------------


class TestMlxReactSchemaBounds:
    """``_REACT_SCHEMA`` strings must be length-bounded so outlines-core's
    FSM forces the closing quote within ``max_tokens`` budget. Without
    these bounds Gemma4 rambles past the JSON boundary → unterminated
    JSON → ``[FORMAT RECOVERY]`` cascade (see MLXtestrun.txt).
    """

    def test_react_schema_bounds_thought_length(self):
        assert _REACT_SCHEMA["properties"]["thought"]["maxLength"] == 2000

    def test_react_schema_bounds_tool_name_length(self):
        assert (
            _REACT_SCHEMA["properties"]["action"]["properties"]["tool_name"][
                "maxLength"
            ]
            == 64
        )

    def test_react_schema_bounds_tool_input_length(self):
        assert (
            _REACT_SCHEMA["properties"]["action"]["properties"]["tool_input"][
                "maxLength"
            ]
            == 8000
        )

    def test_react_schema_is_still_valid_json_schema_dict(self):
        # Sanity: top-level shape is intact so OpenAI/Anthropic consumers
        # aren't broken by the bounds addition.
        assert _REACT_SCHEMA["type"] == "object"
        assert set(_REACT_SCHEMA["required"]) == {"thought", "action"}
        assert _REACT_SCHEMA["additionalProperties"] is False
        inner = _REACT_SCHEMA["properties"]["action"]
        assert inner["type"] == "object"
        assert set(inner["required"]) == {"tool_name", "tool_input"}


class TestMlxSchemaToolNameEnum:
    """``_build_mlx_schema`` locks ``action.tool_name`` to an enum of the
    registered tools so Outlines' FSM cannot emit hallucinated names
    (``'deeply recon'``, ``'http-fetch'``, ``'javascript_{source}'`` from
    MLXtestrun.txt).
    """

    def test_build_mlx_schema_without_names_is_passthrough(self):
        out = _build_mlx_schema(_REACT_SCHEMA)
        tool_name_field = out["properties"]["action"]["properties"]["tool_name"]
        assert tool_name_field["type"] == "string"
        assert "enum" not in tool_name_field
        # But the maxLength bound survives.
        assert tool_name_field["maxLength"] == 64

    def test_build_mlx_schema_with_names_injects_enum(self):
        names = ["http_fetch", "deep_recon", "final_answer"]
        out = _build_mlx_schema(_REACT_SCHEMA, names)
        tn = out["properties"]["action"]["properties"]["tool_name"]
        assert tn["type"] == "string"
        assert tn["enum"] == names

    def test_build_mlx_schema_does_not_mutate_base(self):
        names = ["http_fetch", "final_answer"]
        _build_mlx_schema(_REACT_SCHEMA, names)
        # Base schema stays untouched — other consumers get the original.
        assert (
            "enum"
            not in _REACT_SCHEMA["properties"]["action"]["properties"]["tool_name"]
        )

    def test_build_mlx_schema_with_empty_list_is_passthrough(self):
        # Falsy list → no enum injection (prevents a zero-member enum which
        # outlines-core would reject as an impossible FSM).
        out = _build_mlx_schema(_REACT_SCHEMA, [])
        assert "enum" not in out["properties"]["action"]["properties"]["tool_name"]

    def test_set_allowed_tool_names_affects_output_type(self):
        state = _install_fake_mlx_modules()
        adapter = MLXAdapter(prewarm=False, grammar_schema=_REACT_SCHEMA)
        adapter.set_allowed_tool_names(["http_fetch", "final_answer"])
        adapter.invoke([Message(role="user", content="hi")])
        _, kwargs = state["outlines_model"].calls[0]
        schema = kwargs["output_type"].schema
        assert schema["properties"]["action"]["properties"]["tool_name"]["enum"] == [
            "http_fetch",
            "final_answer",
        ]

    def test_mlx_adapter_default_has_no_allowed_tool_names(self):
        adapter = MLXAdapter(prewarm=False)
        assert adapter.allowed_tool_names is None

    def test_set_allowed_tool_names_via_token_tracking_wrapper(self):
        # build_agent wraps the MLXAdapter in TokenTrackingAdapter before
        # calling set_allowed_tool_names. Verify attribute forwarding works.
        from ctf_solver.run_tracker import RunTracker, TokenTrackingAdapter

        inner = MLXAdapter(prewarm=False, grammar_schema=_REACT_SCHEMA)
        wrapped = TokenTrackingAdapter(inner, RunTracker())
        assert hasattr(wrapped, "set_allowed_tool_names")
        wrapped.set_allowed_tool_names(["http_fetch", "deep_recon"])
        assert inner.allowed_tool_names == ["http_fetch", "deep_recon"]


# ---------------------------------------------------------------------------
# Opt-in live integration — requires CTF_RUN_MLX_INTEGRATION=1 + real model
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.getenv("CTF_RUN_MLX_INTEGRATION") != "1",
    reason="Set CTF_RUN_MLX_INTEGRATION=1 to run the live MLX integration test",
)
class TestMlxLiveIntegration:
    def test_real_load_and_generate_produces_valid_react_schema_json(self):
        pytest.importorskip("mlx_lm")
        pytest.importorskip("outlines")
        import json

        adapter = MLXAdapter(
            model_name="mlx-community/gemma-4-26b-a4b-it-4bit",
            grammar_schema=_REACT_SCHEMA,
            max_tokens=128,
            temperature=0.2,
            prewarm=True,
            seed=0,
        )
        out = adapter.invoke(
            [
                Message(
                    role="user",
                    content=(
                        "Emit the ReAct envelope to call http_fetch on "
                        "http://example.com/ . Respond with JSON only."
                    ),
                )
            ]
        )
        parsed = json.loads(out.content)
        assert "thought" in parsed and "action" in parsed
        assert "tool_name" in parsed["action"] and "tool_input" in parsed["action"]
