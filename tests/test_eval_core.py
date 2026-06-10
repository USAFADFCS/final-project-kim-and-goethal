"""Eval core: RunResult + run_against_target grading/structure.

The agent is mocked at the ``build_agent`` boundary so these tests exercise
the build → run → strict/broad grade → RunResult flow without a real LLM.
"""

import ctf_solver.agent as agent_module
from ctf_solver.config import LLMProviderType, RAGMode, SolverConfig
from ctf_solver.eval._core import (
    RunResult,
    _build_eval_config,
    expected_flag_seen,
    run_against_target,
    run_against_target_sync,
)


class _FakeAgent:
    def __init__(self, tracker, response, tool_log=None, error=None, per_call=None):
        self._tracker = tracker
        self._response = response
        self._tool_log = tool_log or []
        self._error = error
        self._per_call = per_call

    async def arun(self, _message):
        for entry in self._tool_log:
            self._tracker.record_detailed_tool_call(
                entry["tool"], entry.get("input", ""), entry.get("output", "")
            )
            self._tracker.record_tool_call(entry["tool"])
        if self._per_call is not None:
            self._tracker.per_call_tokens = list(self._per_call)
        if self._error is not None:
            raise self._error
        return self._response


def _patch_agent(monkeypatch, **agent_kwargs):
    captured = {}

    def fake_build_agent(config, tracker=None, **_kw):
        captured["config"] = config
        captured["tracker"] = tracker
        agent = _FakeAgent(tracker, **agent_kwargs)
        return agent

    monkeypatch.setattr(agent_module, "build_agent", fake_build_agent)
    return captured


# ---------------------------------------------------------------------------
# expected_flag_seen
# ---------------------------------------------------------------------------


def test_expected_flag_seen_in_response():
    assert expected_flag_seen("MetaCTF{x}", "the flag is MetaCTF{x}!", []) is True


def test_expected_flag_seen_in_tool_output():
    log = [{"output": "page body MetaCTF{x} here"}]
    assert expected_flag_seen("MetaCTF{x}", "no flag in answer", log) is True


def test_expected_flag_seen_absent():
    assert expected_flag_seen("MetaCTF{x}", "nope", [{"output": "nada"}]) is False


def test_expected_flag_seen_none():
    assert expected_flag_seen(None, "MetaCTF{x}", []) is False
    assert expected_flag_seen("", "MetaCTF{x}", []) is False


# ---------------------------------------------------------------------------
# _build_eval_config — no-contamination default
# ---------------------------------------------------------------------------


def test_eval_config_forces_original_rag_when_not_injecting():
    cfg = _build_eval_config(
        config=None,
        url="http://x/",
        description="d",
        hints=None,
        challenge_name="c",
        files=None,
        model=None,
        provider=None,
        max_steps=None,
        flag_regex=None,
        inject_rag=False,
    )
    assert cfg.rag_mode == RAGMode.ORIGINAL


def test_eval_config_clones_base_with_overrides():
    base = SolverConfig(model_name="gpt-4o", max_steps=20)
    cfg = _build_eval_config(
        config=base,
        url="http://y/",
        description="desc",
        hints="h",
        challenge_name="name",
        files={"a.py": "print(1)"},
        model="gpt-5.2",
        provider=LLMProviderType.OPENAI,
        max_steps=7,
        flag_regex=None,
        inject_rag=True,  # keep base rag_mode (don't force ORIGINAL)
    )
    assert cfg.challenge_url == "http://y/"
    assert cfg.model_name == "gpt-5.2"
    assert cfg.max_steps == 7
    assert cfg.source_files == {"a.py": "print(1)"}
    # base untouched
    assert base.model_name == "gpt-4o"
    assert base.max_steps == 20


# ---------------------------------------------------------------------------
# run_against_target — grading paths
# ---------------------------------------------------------------------------


def test_solved_when_expected_flag_in_response(monkeypatch):
    _patch_agent(monkeypatch, response="solved: MetaCTF{win}")
    result = run_against_target_sync(
        url="http://t/", expected_flag="MetaCTF{win}", challenge_name="t"
    )
    assert isinstance(result, RunResult)
    assert result.solved is True
    assert result.flag_match is True
    assert result.flag_seen == "MetaCTF{win}"
    assert result.outcome == "success"
    assert result.error is None


def test_solved_when_expected_flag_in_tool_output(monkeypatch):
    _patch_agent(
        monkeypatch,
        response="done",
        tool_log=[{"tool": "http_fetch", "output": "body MetaCTF{win}"}],
    )
    result = run_against_target_sync(
        url="http://t/", expected_flag="MetaCTF{win}", challenge_name="t"
    )
    assert result.solved is True
    assert result.flag_match is True
    assert result.tool_calls == 1
    assert result.unique_tools == 1


def test_wrong_flag_does_not_count_in_benchmark_mode(monkeypatch):
    # Agent confirms a flag-shaped token, but NOT the expected one.
    _patch_agent(monkeypatch, response="found MetaCTF{other}")
    result = run_against_target_sync(
        url="http://t/", expected_flag="MetaCTF{win}", challenge_name="t"
    )
    assert result.flag_match is False
    assert result.solved is False  # benchmark mode requires the right flag
    assert result.flag_seen == "MetaCTF{other}"  # still recorded for audit


def test_live_mode_solved_on_any_confirmed_flag(monkeypatch):
    # No expected_flag → live mode → any strict-confirmed flag = solved.
    _patch_agent(monkeypatch, response="picoCTF{anything}")
    result = run_against_target_sync(url="http://t/", challenge_name="t")
    assert result.expected_flag is None
    assert result.solved is True
    assert result.flag_seen == "picoCTF{anything}"


def test_unsolved_no_flag(monkeypatch):
    _patch_agent(monkeypatch, response="could not solve")
    result = run_against_target_sync(url="http://t/", challenge_name="t")
    assert result.solved is False
    assert result.flag_seen is None
    assert result.outcome == "failure"


def test_agent_error_is_captured_not_raised(monkeypatch):
    _patch_agent(monkeypatch, response="", error=RuntimeError("boom"))
    result = run_against_target_sync(url="http://t/", challenge_name="t")
    assert result.solved is False
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "boom" in result.error


def test_local_provider_cost_v2_zero(monkeypatch):
    _patch_agent(
        monkeypatch,
        response="MetaCTF{win}",
        per_call=[
            {"prompt_tokens": 1000, "completion_tokens": 100, "cached_tokens": 0}
        ],
    )
    result = run_against_target_sync(
        url="http://t/",
        expected_flag="MetaCTF{win}",
        model="nemotron-3-super:120b-a12b-q4_K_M",
        provider=LLMProviderType.OLLAMA,
        challenge_name="t",
    )
    assert result.est_cost_usd_v2 == 0.0
    assert result.est_cost_usd > 0.0  # legacy still gpt-5.2 fallback
    assert result.provider == "ollama"


def test_to_record_shape_and_extra_override(monkeypatch):
    _patch_agent(monkeypatch, response="MetaCTF{win}")
    result = run_against_target_sync(
        url="http://t/", expected_flag="MetaCTF{win}", challenge_name="orig"
    )
    rec = result.to_record(config_label="treat", run_idx=2, challenge="override")
    assert rec["config_label"] == "treat"
    assert rec["run_idx"] == 2
    assert rec["challenge"] == "override"  # extra overrides result.challenge
    assert rec["solved"] is True
    assert "est_cost_usd_v2" in rec
    # bulky fields not in the flat record
    assert "stats" not in rec
    assert "response" not in rec


async def _await_run(**kw):
    return await run_against_target(**kw)


def test_async_entrypoint_runs(monkeypatch):
    import asyncio

    _patch_agent(monkeypatch, response="MetaCTF{win}")
    result = asyncio.run(
        _await_run(url="http://t/", expected_flag="MetaCTF{win}", challenge_name="t")
    )
    assert result.solved is True
