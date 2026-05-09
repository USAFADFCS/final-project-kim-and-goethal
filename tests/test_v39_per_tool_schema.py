"""
v3.9 N.1: per-tool ``tool_input`` discrimination via ``oneOf``.

Validates:
  * ``build_react_schema()`` emits the right shape per descriptor list
    (legacy fallback when no descriptors; oneOf union when set; string
    ``tool_input`` fallback for tools without a ``parameters_schema``).
  * MLX's ``set_tool_descriptors()`` plumbs the new schema into Outlines.
  * Ollama's ``format=`` kwarg receives the new schema and falls back
    gracefully when the grammar parser rejects ``oneOf``.
  * The agent loop coerces ``tool_input`` from dict → JSON-encoded
    string so downstream ``tool.use(str)`` always sees a string.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from ctf_solver.llm.adapters import (
    _REACT_SCHEMA,
    OllamaAdapter,
    _sanitize_for_outlines,
    build_react_schema,
)

# ── Outlines sanitizer ───────────────────────────────────────────────


class TestSanitizeForOutlines:
    """Outlines rejects schemas whose properties have no ``type`` /
    ``oneOf`` / ``anyOf`` / ``enum`` / ``const`` / ``$ref`` discriminator
    (raises ``Unsupported JSON Schema structure``). The sanitizer drops
    such properties so the rest of the schema still compiles."""

    def test_passes_clean_schema_unchanged(self):
        clean = {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        }
        out = _sanitize_for_outlines(clean)
        assert out == clean
        # Returned a copy, not the original.
        assert out is not clean

    def test_drops_property_with_only_description(self):
        bad = {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"description": "a string or an array"},
            },
            "required": ["url", "wordlist"],
        }
        out = _sanitize_for_outlines(bad)
        assert "wordlist" not in out["properties"]
        # And it gets removed from `required` so the schema stays valid.
        assert "wordlist" not in out["required"]
        # The clean property survives.
        assert out["properties"]["url"] == {"type": "string"}

    def test_drops_property_that_is_not_a_dict(self):
        bad = {
            "type": "object",
            "properties": {"url": {"type": "string"}, "weird": "not a dict"},
        }
        out = _sanitize_for_outlines(bad)
        assert "weird" not in out["properties"]
        assert "url" in out["properties"]

    def test_keeps_oneof_property(self):
        good = {
            "type": "object",
            "properties": {
                "wordlist": {
                    "oneOf": [{"type": "string"}, {"type": "array"}],
                    "description": "string or array",
                },
            },
        }
        out = _sanitize_for_outlines(good)
        assert "wordlist" in out["properties"]

    def test_keeps_enum_property_without_explicit_type(self):
        good = {
            "type": "object",
            "properties": {"op": {"enum": ["a", "b", "c"]}},
        }
        out = _sanitize_for_outlines(good)
        assert "op" in out["properties"]

    def test_recurses_into_nested_object_properties(self):
        nested = {
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "string"},
                        "bad": {"description": "no type"},
                    },
                },
            },
        }
        out = _sanitize_for_outlines(nested)
        assert "ok" in out["properties"]["outer"]["properties"]
        assert "bad" not in out["properties"]["outer"]["properties"]

    def test_recurses_into_oneof_branches(self):
        branched = {
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"a": {"type": "string"}, "b": {"description": "x"}},
                },
            ],
        }
        out = _sanitize_for_outlines(branched)
        branch = out["oneOf"][0]
        assert "a" in branch["properties"]
        assert "b" not in branch["properties"]

    def test_returns_none_for_unsalvageable_schema(self):
        # No type, no union, no enum, no const → nothing to constrain.
        bad = {"description": "just text"}
        assert _sanitize_for_outlines(bad) is None

    def test_returns_none_for_non_dict(self):
        assert _sanitize_for_outlines("nope") is None
        assert _sanitize_for_outlines(None) is None
        assert _sanitize_for_outlines([]) is None

    def test_empty_properties_with_type_object_survives(self):
        """A typed object schema with no constrained properties is fine —
        Outlines treats it as a permissive object."""
        permissive = {"type": "object", "properties": {}, "required": []}
        out = _sanitize_for_outlines(permissive)
        assert out is not None
        assert out["type"] == "object"


class TestBuildReactSchemaUsesSanitizer:
    """When ``build_react_schema(mode='oneof')`` is given a descriptor
    whose ``parameters_schema`` has untyped properties, the sanitizer
    strips them before the branch is emitted so Outlines can compile
    the oneOf. (``mode='enum'`` ignores per-tool schemas entirely;
    these checks only matter for the experimental two-phase mode.)"""

    def test_untyped_property_dropped_in_branch(self):
        descriptors = [
            (
                "path_enumerator",
                "",
                {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "wordlist": {"description": "string or array"},
                    },
                    "required": ["url", "wordlist"],
                },
                None,
            ),
        ]
        schema = build_react_schema(descriptors, mode="oneof")
        branch = schema["properties"]["action"]["oneOf"][0]
        ti = branch["properties"]["tool_input"]
        # The bad ``wordlist`` is gone; ``url`` survived.
        assert "url" in ti["properties"]
        assert "wordlist" not in ti["properties"]
        assert "wordlist" not in ti["required"]

    def test_unsalvageable_schema_falls_back_to_string(self):
        """If the sanitizer can't produce a valid schema, the branch
        uses the legacy string-tool_input fallback."""
        descriptors = [
            ("weird_tool", "", {"description": "no type at all"}, None),
        ]
        schema = build_react_schema(descriptors, mode="oneof")
        branch = schema["properties"]["action"]["oneOf"][0]
        ti = branch["properties"]["tool_input"]
        assert ti["type"] == "string"


# ── Schema builder ───────────────────────────────────────────────────


class TestBuildReactSchemaEnumDefault:
    """v3.9 N.1 hotfix: the default mode is now ``enum`` (flat-enum
    schema), not ``oneof``. The 76-branch oneOf overflowed
    ``outlines-core``'s DFA-state limit (i32::MAX); the flat enum locks
    ``tool_name`` to the registered set and stays small enough to
    compile on any vocab."""

    def test_no_descriptors_returns_legacy(self):
        schema = build_react_schema(None)
        assert schema == _REACT_SCHEMA

    def test_empty_descriptors_returns_legacy(self):
        schema = build_react_schema([])
        assert schema == _REACT_SCHEMA

    def test_default_mode_is_enum(self):
        descriptors = [
            ("http_fetch", "", {"type": "object"}, None),
            ("form_submit", "", {"type": "object"}, None),
            ("legacy_no_schema", "", None, None),
        ]
        schema = build_react_schema(descriptors)
        action = schema["properties"]["action"]
        # Flat shape — single object schema, no oneOf union.
        assert "oneOf" not in action
        assert action["properties"]["tool_name"]["enum"] == [
            "http_fetch",
            "form_submit",
            "legacy_no_schema",
        ]
        # tool_input stays a permissive string; per-tool argument
        # validation happens in Python, not in the FSM.
        ti = action["properties"]["tool_input"]
        assert ti["type"] == "string"
        assert "maxLength" in ti

    def test_enum_includes_every_descriptor_name_in_order(self):
        descriptors = [(f"tool_{i}", "", None, None) for i in range(10)]
        schema = build_react_schema(descriptors)
        assert schema["properties"]["action"]["properties"]["tool_name"]["enum"] == [
            f"tool_{i}" for i in range(10)
        ]

    def test_top_level_envelope_preserved(self):
        descriptors = [("x", "", None, None)]
        schema = build_react_schema(descriptors)
        assert schema["type"] == "object"
        assert "thought" in schema["properties"]
        assert schema["required"] == ["thought", "action"]
        assert schema["additionalProperties"] is False

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError, match="unknown mode"):
            build_react_schema([("x", "", None, None)], mode="bogus")


class TestBuildReactSchemaOneofMode:
    """``mode='oneof'`` is preserved as a research / experimental path
    for future two-phase generation work. It must NOT be used in
    production at scale — see the docstring."""

    def test_oneof_explicit_emits_per_tool_branches(self):
        descriptors = [
            (
                "http_fetch",
                "Fetch a URL",
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
                None,
            )
        ]
        schema = build_react_schema(descriptors, mode="oneof")
        action = schema["properties"]["action"]
        assert "oneOf" in action
        assert len(action["oneOf"]) == 1
        branch = action["oneOf"][0]
        assert branch["properties"]["tool_name"]["const"] == "http_fetch"
        assert branch["properties"]["tool_input"] == {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        }

    def test_oneof_tool_without_schema_falls_back_to_string(self):
        descriptors = [("legacy_tool", "", None, None)]
        schema = build_react_schema(descriptors, mode="oneof")
        branch = schema["properties"]["action"]["oneOf"][0]
        assert branch["properties"]["tool_input"]["type"] == "string"

    def test_oneof_mixed_schemas_one_branch_per_tool(self):
        descriptors = [
            ("a", "", {"type": "object", "properties": {}, "required": []}, None),
            ("b", "", None, None),
            ("c", "", {"type": "object", "properties": {}, "required": []}, None),
        ]
        schema = build_react_schema(descriptors, mode="oneof")
        branches = schema["properties"]["action"]["oneOf"]
        assert len(branches) == 3
        names = [b["properties"]["tool_name"]["const"] for b in branches]
        assert names == ["a", "b", "c"]
        assert branches[1]["properties"]["tool_input"]["type"] == "string"
        assert branches[0]["properties"]["tool_input"]["type"] == "object"
        assert branches[2]["properties"]["tool_input"]["type"] == "object"


class TestBuildReactSchemaLegacyIdiom:
    def test_legacy_schema_is_deep_copied(self):
        """Mutating the returned legacy schema must not affect the module
        constant ``_REACT_SCHEMA`` (shared across processes)."""
        s1 = build_react_schema(None)
        s1["properties"]["thought"]["maxLength"] = 999
        s2 = build_react_schema(None)
        # _REACT_SCHEMA's original maxLength is 2000; our mutation should
        # not have leaked.
        assert s2["properties"]["thought"]["maxLength"] == 2000


# ── MLX integration (mocked) ─────────────────────────────────────────


def _install_fake_mlx_modules() -> Dict[str, Any]:
    """Install the same minimal MLX/Outlines mock the v37 tests use."""
    state: Dict[str, Any] = {
        "outlines_calls": [],
    }

    class _FakeJsonSchema:
        def __init__(self, schema: Dict[str, Any]) -> None:
            self.schema = schema

    # outlines
    outlines_mod = types.ModuleType("outlines")
    outlines_types = types.ModuleType("outlines.types")
    outlines_types.JsonSchema = _FakeJsonSchema
    outlines_mod.types = outlines_types
    outlines_mod.from_mlxlm = lambda *a, **kw: MagicMock(name="ol_model")
    sys.modules["outlines"] = outlines_mod
    sys.modules["outlines.types"] = outlines_types

    # mlx + mlx_lm minimal stubs (only needed if _load_mlx_stack runs)
    mx_core = types.ModuleType("mlx.core")
    mx_core.random = types.SimpleNamespace(seed=lambda *a: None)
    mlx_pkg = types.ModuleType("mlx")
    mlx_pkg.core = mx_core
    sys.modules.setdefault("mlx", mlx_pkg)
    sys.modules.setdefault("mlx.core", mx_core)

    return state


@pytest.fixture
def fake_mlx():
    saved = {
        k: sys.modules.get(k) for k in ("outlines", "outlines.types", "mlx", "mlx.core")
    }
    state = _install_fake_mlx_modules()
    yield state
    for k, v in saved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v


class TestMlxAdapterIntegration:
    def test_set_tool_descriptors_stores_them(self, fake_mlx):
        from ctf_solver.llm.adapters import MLXAdapter

        adapter = MLXAdapter(grammar_schema=_REACT_SCHEMA, prewarm=False)
        descriptors = [
            ("a", "", {"type": "object", "properties": {}, "required": []}, None),
        ]
        adapter.set_tool_descriptors(descriptors)
        assert adapter._tool_descriptors == descriptors

    def test_build_output_type_uses_flat_enum_when_descriptors_set(self, fake_mlx):
        """v3.9 N.1 hotfix: descriptors → flat-enum schema (not oneOf).
        The oneOf path was overflowing outlines-core's DFA-state limit
        on production-sized tool surfaces (~76 tools)."""
        from ctf_solver.llm.adapters import MLXAdapter

        adapter = MLXAdapter(grammar_schema=_REACT_SCHEMA, prewarm=False)
        descriptors = [
            (
                "http_fetch",
                "",
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
                None,
            ),
            ("form_submit", "", None, None),
        ]
        adapter.set_tool_descriptors(descriptors)
        result = adapter._build_output_type()
        assert result is not None
        action = result.schema["properties"]["action"]
        # No oneOf union — flat shape with enum-locked tool_name.
        assert "oneOf" not in action
        assert action["properties"]["tool_name"]["enum"] == [
            "http_fetch",
            "form_submit",
        ]
        # tool_input stays a permissive string.
        assert action["properties"]["tool_input"]["type"] == "string"

    def test_build_output_type_falls_back_when_no_descriptors(self, fake_mlx):
        from ctf_solver.llm.adapters import MLXAdapter

        adapter = MLXAdapter(grammar_schema=_REACT_SCHEMA, prewarm=False)
        # No set_tool_descriptors call → legacy path (locks tool_name
        # via _build_mlx_schema's enum-on-allowed-tool-names hook).
        result = adapter._build_output_type()
        assert result is not None
        action = result.schema["properties"]["action"]
        assert "oneOf" not in action
        assert "tool_input" in action["properties"]

    def test_build_output_type_returns_none_when_grammar_off(self, fake_mlx):
        from ctf_solver.llm.adapters import MLXAdapter

        adapter = MLXAdapter(grammar_schema=None, prewarm=False)
        assert adapter._build_output_type() is None


# ── Ollama integration (mocked) ──────────────────────────────────────


def _make_ollama_adapter() -> OllamaAdapter:
    """Build an OllamaAdapter with a stub ``client`` that records calls.

    The real ``ollama.Client`` would require the package; we don't exercise
    it here. We only test the adapter's pure-Python helper methods.
    """
    adapter = OllamaAdapter.__new__(OllamaAdapter)
    adapter.client = MagicMock(name="ollama_client")
    adapter.model_name = "test-model"
    adapter.base_url = "http://localhost:11434"
    adapter.num_ctx = 16384
    adapter.thinking_callback = None
    adapter.grammar_schema = _REACT_SCHEMA
    adapter._think_supported = None
    adapter._format_supported = None
    adapter._oneof_supported = None
    adapter._tool_descriptors = None
    adapter._consecutive_empty = 0
    return adapter


class TestOllamaIntegration:
    def test_set_tool_descriptors_stores_and_resets_oneof_flag(self):
        adapter = _make_ollama_adapter()
        adapter._oneof_supported = False  # pretend a prior rejection
        descriptors = [
            ("a", "", {"type": "object", "properties": {}, "required": []}, None),
        ]
        adapter.set_tool_descriptors(descriptors)
        assert adapter._tool_descriptors == descriptors
        # Reset so we re-probe on the next call.
        assert adapter._oneof_supported is None

    def test_set_tool_descriptors_empty_clears_state(self):
        adapter = _make_ollama_adapter()
        adapter._tool_descriptors = [("x", "", None, None)]
        adapter.set_tool_descriptors([])
        assert adapter._tool_descriptors is None

    def test_select_format_uses_flat_enum_when_descriptors_set(self):
        """Hotfix: the production path emits a flat-enum schema, not a
        oneOf union. The oneOf path overflowed outlines-core's DFA-state
        limit on production-sized tool surfaces."""
        adapter = _make_ollama_adapter()
        descriptors = [
            ("http_fetch", "", {"type": "object"}, None),
            ("form_submit", "", None, None),
        ]
        adapter.set_tool_descriptors(descriptors)
        schema = adapter._select_format_schema()
        action = schema["properties"]["action"]
        assert "oneOf" not in action
        assert action["properties"]["tool_name"]["enum"] == [
            "http_fetch",
            "form_submit",
        ]

    def test_select_format_uses_legacy_when_no_descriptors(self):
        adapter = _make_ollama_adapter()
        # No descriptors set.
        schema = adapter._select_format_schema()
        assert schema is _REACT_SCHEMA

    def test_build_chat_kwargs_includes_format_when_supported(self):
        adapter = _make_ollama_adapter()
        adapter.set_tool_descriptors(
            [
                ("x", "", None, None),
            ]
        )
        kwargs = adapter._build_chat_kwargs([{"role": "user", "content": "hi"}], {})
        assert "format" in kwargs
        action = kwargs["format"]["properties"]["action"]
        assert action["properties"]["tool_name"]["enum"] == ["x"]

    def test_build_chat_kwargs_omits_format_when_unsupported(self):
        adapter = _make_ollama_adapter()
        adapter._format_supported = False
        kwargs = adapter._build_chat_kwargs([{"role": "user", "content": "hi"}], {})
        assert "format" not in kwargs

    def test_chat_with_think_falls_back_on_oneof_rejection(self):
        """Dormant safety net: if the experimental ``mode='oneof'`` path
        ever surfaces a oneOf schema (it doesn't in the v3.9 hotfix
        default), and the grammar parser rejects it, the adapter must
        retry with the legacy single-shape schema. We mirror the
        production selector — falls back to legacy when
        ``_oneof_supported is False``."""
        from ctf_solver.llm.adapters import build_react_schema

        adapter = _make_ollama_adapter()
        descriptors = [("x", "", {"type": "object"}, None)]
        adapter.set_tool_descriptors(descriptors)

        # Same logic as the real selector, but pinned to oneof mode so
        # the test exercises the rejection-fallback path.
        def _selector():
            if adapter._oneof_supported is False:
                return adapter.grammar_schema
            return build_react_schema(descriptors, mode="oneof")

        adapter._select_format_schema = _selector

        ok_response = {"message": {"content": "ok"}}
        call_count = {"n": 0}

        def _chat(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: per-tool oneOf schema present → reject.
                assert "oneOf" in kwargs["format"]["properties"]["action"]
                raise RuntimeError("invalid schema: oneOf not supported")
            # Second call: _oneof_supported was flipped to False by the
            # rejection handler; the selector now returns the legacy
            # single-shape schema.
            assert "oneOf" not in kwargs["format"]["properties"]["action"]
            return ok_response

        adapter.client.chat = _chat
        response = adapter._chat_with_think([{"role": "user", "content": "hi"}], {})
        assert response is ok_response
        assert adapter._oneof_supported is False
        assert call_count["n"] == 2

    def test_chat_with_think_succeeds_first_try_with_flat_enum(self):
        """Default path: flat-enum schema, no oneOf → first call wins,
        ``_oneof_supported`` stays None (never probed)."""
        adapter = _make_ollama_adapter()
        adapter.set_tool_descriptors(
            [("x", "", {"type": "object"}, None)],
        )
        adapter.client.chat = MagicMock(return_value={"message": {"content": "ok"}})
        response = adapter._chat_with_think([], {})
        assert response == {"message": {"content": "ok"}}
        # Default flat-enum schema doesn't have oneOf, so the
        # ``_oneof_supported is True`` lock-in branch never fires.
        assert adapter._oneof_supported is None


# ── v3.9 N.4 hotfix: format-vocabulary fallback ──────────────────────


class TestOllamaFormatVocabularyFallback:
    """Some Ollama models return HTTP 500 with ``failed to load model
    vocabulary required for format`` when ``format=<json_schema>`` is
    sent — the model GGUF lacks the metadata Ollama needs to compile a
    GBNF. The adapter must catch this, disable ``format=`` for the
    process, and retry. Otherwise the agent loops forever with the
    error string treated as the model's response."""

    def test_falls_back_on_exact_vocabulary_error(self):
        adapter = _make_ollama_adapter()
        adapter.set_tool_descriptors([("x", "", {"type": "object"}, None)])
        ok_response = {"message": {"content": "ok"}}
        call_count = {"n": 0}

        def _chat(**kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: format= present → Ollama's exact wording.
                assert "format" in kwargs
                raise RuntimeError(
                    "failed to load model vocabulary required for format "
                    "(status code: 500)"
                )
            # Second call: format= must be gone.
            assert "format" not in kwargs
            return ok_response

        adapter.client.chat = _chat
        response = adapter._chat_with_think([{"role": "user", "content": "hi"}], {})
        assert response is ok_response
        assert adapter._format_supported is False
        assert call_count["n"] == 2

    def test_falls_back_on_required_for_format_wording(self):
        """Defensive: catch the wording variant in case Ollama tweaks the
        message in a future release."""
        adapter = _make_ollama_adapter()
        adapter.set_tool_descriptors([("x", "", {"type": "object"}, None)])
        ok_response = {"message": {"content": "ok"}}
        seen: list = []

        def _chat(**kwargs):
            seen.append("format" in kwargs)
            if len(seen) == 1:
                raise RuntimeError("schema required for format: bad metadata")
            return ok_response

        adapter.client.chat = _chat
        response = adapter._chat_with_think([], {})
        assert response is ok_response
        assert seen == [True, False]
        assert adapter._format_supported is False

    def test_does_not_fall_back_on_unrelated_error(self):
        """Errors that are NOT format-vocabulary related must propagate
        — we don't want to swallow legitimate failures (auth, network,
        OOM, etc.) by accident."""
        adapter = _make_ollama_adapter()
        adapter.set_tool_descriptors([("x", "", {"type": "object"}, None)])

        def _chat(**kwargs):
            raise RuntimeError("connection reset by peer")

        adapter.client.chat = _chat
        with pytest.raises(RuntimeError, match="connection reset"):
            adapter._chat_with_think([], {})
        # _format_supported stays untouched — unrelated error.
        assert adapter._format_supported is None


class TestOllamaGrammarDisableEnvVar:
    """``CTF_OLLAMA_GRAMMAR_DISABLE=1`` skips ``format=`` upfront so
    users on a known-incompatible model get a clean startup without
    waiting for the auto-fallback to fire on the first call."""

    def test_env_var_disables_format(self, monkeypatch):
        monkeypatch.setenv("CTF_OLLAMA_GRAMMAR_DISABLE", "1")
        # Real adapter construction (we only need the __init__ branch).
        # Skip if the ollama package isn't importable in the test env.
        try:
            from ctf_solver.llm.adapters import OllamaAdapter

            adapter = OllamaAdapter(model_name="dummy", base_url="http://localhost:0")
        except ImportError:
            pytest.skip("ollama package not available")
        assert adapter._format_supported is False
        # _build_chat_kwargs must not include format=.
        kwargs = adapter._build_chat_kwargs([{"role": "user", "content": "hi"}], {})
        assert "format" not in kwargs

    def test_env_var_default_off_keeps_format_unprobed(self, monkeypatch):
        monkeypatch.delenv("CTF_OLLAMA_GRAMMAR_DISABLE", raising=False)
        try:
            from ctf_solver.llm.adapters import OllamaAdapter

            adapter = OllamaAdapter(
                model_name="dummy",
                base_url="http://localhost:0",
                grammar_schema=_REACT_SCHEMA,
            )
        except ImportError:
            pytest.skip("ollama package not available")
        # Default: not yet probed → None (not False).
        assert adapter._format_supported is None

    def test_env_var_truthy_variants_all_disable(self, monkeypatch):
        try:
            from ctf_solver.llm.adapters import OllamaAdapter
        except ImportError:
            pytest.skip("ollama package not available")
        for value in ("1", "true", "yes", "on", "TRUE", "Yes"):
            monkeypatch.setenv("CTF_OLLAMA_GRAMMAR_DISABLE", value)
            adapter = OllamaAdapter(model_name="dummy", base_url="http://localhost:0")
            assert (
                adapter._format_supported is False
            ), f"value {value!r} did not disable format"


# ── Agent dispatch coercion ──────────────────────────────────────────


class TestDispatchToolInputCoercion:
    """The new oneOf path emits ``tool_input`` as an object. The agent
    loop must coerce it to a JSON-encoded string before calling
    ``tool.use(str)``. The coercion is in ``arun()`` right after the
    plan_result unpack — these tests pin the coercion shape.

    Coercion targets:
      * dict → ``json.dumps(dict)``
      * list → ``json.dumps(list)``
      * None → ""
      * non-string scalar → ``str(scalar)``
      * existing string → unchanged
    """

    def _coerce(self, tool_input):
        """Replicate the coercion logic. The agent's coercion is at
        the top of the action handler in arun(); this helper exercises
        the same shape so we don't have to spin up the full agent loop."""
        import json

        if isinstance(tool_input, (dict, list)):
            return json.dumps(tool_input)
        elif tool_input is None:
            return ""
        elif not isinstance(tool_input, str):
            return str(tool_input)
        return tool_input

    def test_dict_to_json_string(self):
        result = self._coerce({"url": "http://x", "method": "GET"})
        assert isinstance(result, str)
        import json

        parsed = json.loads(result)
        assert parsed == {"url": "http://x", "method": "GET"}

    def test_list_to_json_string(self):
        result = self._coerce(["a", "b", "c"])
        assert result == '["a", "b", "c"]'

    def test_none_to_empty_string(self):
        assert self._coerce(None) == ""

    def test_string_unchanged(self):
        assert self._coerce("already a string") == "already a string"

    def test_int_to_string(self):
        assert self._coerce(42) == "42"

    def test_float_to_string(self):
        assert self._coerce(3.14) == "3.14"

    def test_empty_dict(self):
        assert self._coerce({}) == "{}"


class TestAgentBuildWiresGrammar:
    """When ``build_agent`` runs against an LLM that exposes
    ``set_tool_descriptors``, descriptors get pushed in. Mirror the
    minimal-agent harness used elsewhere in v38 tests so the assertion
    is robust to Ollama not being reachable in CI."""

    def test_set_tool_descriptors_called_on_capable_llm(self):
        from ctf_solver.agent import build_agent
        from ctf_solver.config import RAGMode, SolverConfig

        # Build a config that goes through the OllamaAdapter path so
        # the LLM has set_tool_descriptors. If Ollama isn't reachable,
        # the build can still complete (build_agent is robust to the
        # adapter not being live until first invoke).
        cfg = SolverConfig(
            llm_provider="ollama",
            model_name="dummy:latest",
            llm_base_url="http://127.0.0.1:11434",
            rag_mode=RAGMode.NONE,
            enable_opener_pack=False,
        )
        try:
            agent = build_agent(cfg, tracker=None)
        except Exception:
            pytest.skip("Ollama not available; skip wiring smoke test.")
        assert agent is not None
        # The adapter should have descriptors set by build_agent.
        llm = agent.llm
        if not hasattr(llm, "_tool_descriptors"):
            pytest.skip("LLM does not expose _tool_descriptors")
        assert (
            llm._tool_descriptors is not None and len(llm._tool_descriptors) > 0
        ), "build_agent did not push descriptors into the OllamaAdapter"
