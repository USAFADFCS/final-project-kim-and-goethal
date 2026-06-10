"""Parity-sprint item #2: local-model cost tracking.

Local backends (Ollama / MLX) have no per-token billing, but their model
names aren't in ``_PRICE_PER_M_TOKENS``, so the legacy rollup silently
inherited gpt-5.2 pricing and reported a nonzero ``est_cost_usd`` for free
inference. The fix adds ``est_cost_usd_v2`` — identical to ``est_cost_usd``
except local runs report ``$0`` — while leaving ``est_cost_usd`` unchanged
for cross-run comparability.
"""

import tempfile
from pathlib import Path

import pytest

from ctf_solver.batch import BatchItem, BatchResult, write_batch_summary
from ctf_solver.config import LLMProviderType
from ctf_solver.run_tracker import RunTracker, _is_cost_free_local

# 1000 prompt + 100 completion tokens, no cache.
_CALLS = [{"prompt_tokens": 1000, "completion_tokens": 100, "cached_tokens": 0}]
# gpt-5.2 row: (1000*1.25 + 100*10.0) / 1e6
_GPT52_COST = (1000 * 1.25 + 100 * 10.0) / 1_000_000
# gpt-4o-mini row: (1000*0.15 + 100*0.60) / 1e6
_MINI_COST = (1000 * 0.15 + 100 * 0.60) / 1_000_000


# ---------------------------------------------------------------------------
# _is_cost_free_local unit behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provider,model,expected",
    [
        (LLMProviderType.OLLAMA, "nemotron-3-super:120b-a12b-q4_K_M", True),
        (LLMProviderType.MLX, "mlx-community/whatever", True),
        ("ollama", "anything", True),
        ("mlx", "anything", True),
        # Provider unknown but model name looks local.
        (None, "nemotron3-prism:30b-q6", True),
        (None, "mlx-community/Qwen2.5-7B", True),
        # Remote providers / model names → not free.
        (LLMProviderType.OPENAI, "gpt-5.2", False),
        (LLMProviderType.ANTHROPIC, "claude-opus-4-7", False),
        (None, "gpt-4o-mini", False),
        (None, "", False),
    ],
)
def test_is_cost_free_local(provider, model, expected):
    assert _is_cost_free_local(provider, model) is expected


# ---------------------------------------------------------------------------
# Cost rollup: local → v2 is $0, est_cost_usd keeps legacy behavior
# ---------------------------------------------------------------------------


def test_ollama_provider_v2_is_zero():
    t = RunTracker()
    t.set_token_usage_from_adapter(
        _CALLS, "nemotron-3-super:120b-a12b-q4_K_M", LLMProviderType.OLLAMA
    )
    # Legacy column still inherits the gpt-5.2 fallback (unchanged for
    # comparability) — but the corrected column reads $0.
    assert t.est_cost_usd == pytest.approx(_GPT52_COST, abs=1e-12)
    assert t.est_cost_usd_v2 == 0.0


def test_mlx_provider_v2_is_zero():
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "mlx-community/Foo", LLMProviderType.MLX)
    assert t.est_cost_usd_v2 == 0.0


def test_local_detected_by_model_name_without_provider():
    # Provider omitted (None) but the Ollama-tag name betrays it as local.
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "nemotron3-prism:30b-q6")
    assert t.est_cost_usd_v2 == 0.0


def test_gpt52_v2_equals_legacy():
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "gpt-5.2", LLMProviderType.OPENAI)
    assert t.est_cost_usd == pytest.approx(_GPT52_COST, abs=1e-12)
    assert t.est_cost_usd_v2 == pytest.approx(_GPT52_COST, abs=1e-12)


def test_gpt4o_mini_priced_from_table():
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "gpt-4o-mini", LLMProviderType.OPENAI)
    assert t.est_cost_usd == pytest.approx(_MINI_COST, abs=1e-12)
    assert t.est_cost_usd_v2 == pytest.approx(_MINI_COST, abs=1e-12)


def test_unknown_remote_model_falls_back_and_v2_matches():
    # A remote model not in the price table (no ':' in name) still falls back
    # to gpt-5.2 — and since it's not local, v2 mirrors the legacy estimate.
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "gpt-6-preview", LLMProviderType.OPENAI)
    assert t.est_cost_usd == pytest.approx(_GPT52_COST, abs=1e-12)
    assert t.est_cost_usd_v2 == pytest.approx(_GPT52_COST, abs=1e-12)


def test_provider_omitted_remote_model_is_not_free():
    # No provider, remote-looking model name → not local, not $0.
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "gpt-5.2")
    assert t.est_cost_usd_v2 == pytest.approx(_GPT52_COST, abs=1e-12)


# ---------------------------------------------------------------------------
# Serialization + batch summary surface the new column
# ---------------------------------------------------------------------------


def test_to_dict_includes_v2():
    t = RunTracker()
    t.set_token_usage_from_adapter(_CALLS, "gpt-4o-mini", LLMProviderType.OPENAI)
    d = t.to_dict()
    assert "est_cost_usd_v2" in d
    assert d["est_cost_usd_v2"] == pytest.approx(_MINI_COST, abs=1e-6)
    # Legacy field still present.
    assert "est_cost_usd" in d


def test_default_v2_is_zero_before_rollup():
    assert RunTracker().est_cost_usd_v2 == 0.0


def test_batch_summary_has_v2_column_zero_for_local():
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "results.tsv"
        result = BatchResult(
            item=BatchItem(name="t", url="http://x"),
            outcome="success",
            flag="MetaCTF{x}",
            steps=4,
            duration_seconds=12.0,
            stats={
                "actual_prompt_tokens": 1000,
                "actual_completion_tokens": 100,
                "cached_prompt_tokens": 0,
                # Local run: legacy figure nonzero, corrected figure $0.
                "est_cost_usd": _GPT52_COST,
                "est_cost_usd_v2": 0.0,
            },
        )
        write_batch_summary([result], out)
        rows = out.read_text().splitlines()
        header = rows[0].split("\t")
        assert "est_cost_usd_v2" in header
        v2_idx = header.index("est_cost_usd_v2")
        legacy_idx = header.index("est_cost_usd")
        cells = rows[1].split("\t")
        assert cells[v2_idx] == "0.000000"
        assert float(cells[legacy_idx]) > 0.0
