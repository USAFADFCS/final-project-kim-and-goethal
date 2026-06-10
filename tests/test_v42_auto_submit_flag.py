"""Follow-on #4: confirmed-flag early-termination.

When a tool output contains a strict-regex-confirmed flag (the same signal the
runner trusts for [FLAG DETECTED]), the agent should end the run immediately
with that flag instead of looping on the winning call until max_steps — the
exact behaviour observed in the nemotron-3-super Flag Command run (found the
flag at ~step 20, then re-submitted it 11 times to step 31).

Tests cover: the _find_confirmed_flag predicate (strict, not broad), the
arun() loop early-terminate (and that it's a no-op when disabled or on broad
noise), and the config plumbing.
"""

import asyncio
from unittest.mock import MagicMock

from fairlib.core.message import Action, Thought

from ctf_solver.agent import CTFAgent
from ctf_solver.config import (
    DEFAULT_FLAG_REGEX,
    DEFAULT_STRICT_FLAG_REGEX,
    SolverConfig,
)
from tests.test_ctf_agent import FakeMemory, FakePlanner


def _agent(
    observation, *, auto_submit=True, flag_regex=DEFAULT_FLAG_REGEX, max_steps=10
):
    """A CTFAgent whose single tool always returns ``observation``.

    The planner emits the same Action every turn, so without early-termination
    the loop runs to ``max_steps``. Returns (agent, executor_mock).
    """
    planner = FakePlanner(
        [(Thought(text="t"), Action(tool_name="form_submit", tool_input="{}"))] * 12
    )
    executor = MagicMock()
    executor.execute.return_value = observation
    agent = CTFAgent(
        llm=MagicMock(),
        planner=planner,
        tool_executor=executor,
        memory=FakeMemory(),
        max_steps=max_steps,
        flag_regex=flag_regex,
        strict_flag_regex=DEFAULT_STRICT_FLAG_REGEX,
        auto_submit_confirmed_flag=auto_submit,
        log_callback=lambda m: None,
    )
    return agent, executor


# ---------------------------------------------------------------------------
# _find_confirmed_flag predicate
# ---------------------------------------------------------------------------


def test_find_confirmed_flag_strict_matches():
    agent, _ = _agent("x")
    assert (
        agent._find_confirmed_flag("got MetaCTF{c0ld_h4nds}") == "MetaCTF{c0ld_h4nds}"
    )
    assert agent._find_confirmed_flag("HTB{d3v_t00ls}") == "HTB{d3v_t00ls}"
    assert agent._find_confirmed_flag("picoCTF{aabbcc}") == "picoCTF{aabbcc}"


def test_find_confirmed_flag_rejects_broad_noise():
    agent, _ = _agent("x")
    # broad-regex match (try{...}) but no CTF prefix → not confirmed
    assert agent._find_confirmed_flag("code: try{return null}") is None
    assert agent._find_confirmed_flag("no flags at all here") is None
    assert agent._find_confirmed_flag("") is None


def test_find_confirmed_flag_disabled_returns_none():
    agent, _ = _agent("x", auto_submit=False)
    assert agent._find_confirmed_flag("HTB{real_flag}") is None


def test_prefers_platform_flag_over_generic_decoy():
    # A generic decoy flag{...} must NOT pre-empt the real platform HTB{...},
    # in either document order (review finding: decoy-before-real).
    agent, _ = _agent("x")
    assert (
        agent._find_confirmed_flag("home: flag{decoy} ... win: HTB{the_real_one}")
        == "HTB{the_real_one}"
    )
    assert (
        agent._find_confirmed_flag("HTB{the_real_one} ... also flag{decoy}")
        == "HTB{the_real_one}"
    )


def test_lone_generic_flag_still_confirmed():
    # With no platform flag present, a lone generic flag{...} is still accepted.
    agent, _ = _agent("x")
    assert agent._find_confirmed_flag("flag{l0ne_generic}") == "flag{l0ne_generic}"


def test_placeholder_example_literal_not_confirmed():
    # Strict-prefixed example/placeholder literals in source must NOT confirm.
    agent, _ = _agent("x")
    assert agent._find_confirmed_flag('var f = "flag{your_flag_goes_here}"') is None
    assert agent._find_confirmed_flag("HTB{redacted}") is None


def test_real_flag_with_placeholderish_substring_still_confirmed():
    # Exact-match placeholder filter must NOT over-filter real flags whose
    # content merely CONTAINS a placeholder word as a substring.
    agent, _ = _agent("x")
    assert (
        agent._find_confirmed_flag("MetaCTF{sampling_attack}")
        == "MetaCTF{sampling_attack}"
    )


def test_find_confirmed_flag_inert_on_bad_strict_regex():
    agent = CTFAgent(
        llm=MagicMock(),
        planner=MagicMock(),
        tool_executor=MagicMock(),
        memory=FakeMemory(),
        max_steps=5,
        strict_flag_regex="(unclosed[",  # invalid → compile fails
        log_callback=lambda m: None,
    )
    assert agent._strict_flag_pattern is None
    assert agent._find_confirmed_flag("HTB{real_flag}") is None


# ---------------------------------------------------------------------------
# arun() loop early-terminate
# ---------------------------------------------------------------------------


def test_terminates_immediately_on_confirmed_flag():
    agent, executor = _agent('Body: {"message": "HTB{w1nn3r}"}', max_steps=10)
    result = asyncio.run(agent.arun("solve"))
    assert result == "Flag captured: HTB{w1nn3r}"
    # Stopped after the FIRST winning tool call — no looping to max_steps.
    assert executor.execute.call_count == 1


def test_no_early_terminate_when_disabled():
    agent, executor = _agent("HTB{w1nn3r}", auto_submit=False, max_steps=3)
    result = asyncio.run(agent.arun("solve"))
    assert result != "Flag captured: HTB{w1nn3r}"
    # Disabled → loops through all steps (the pre-fix behaviour).
    assert executor.execute.call_count == 3


def test_no_terminate_on_broad_noise():
    # A JS literal matches the broad regex but lacks a CTF prefix; the run must
    # NOT terminate on it (would otherwise abort on garbage — the G7 gap).
    agent, executor = _agent("code: try{return null}", max_steps=3)
    result = asyncio.run(agent.arun("solve"))
    assert not result.startswith("Flag captured:")
    assert executor.execute.call_count == 3


def test_terminated_run_records_flag_in_memory():
    agent, _ = _agent("out: HTB{m3m0ry}", max_steps=10)
    asyncio.run(agent.arun("solve"))
    contents = [getattr(m, "content", "") for m in agent.memory.get_history()]
    # The winning observation AND the final answer are both flushed to memory.
    assert any("HTB{m3m0ry}" in c for c in contents)
    assert any(c == "Flag captured: HTB{m3m0ry}" for c in contents)


def test_early_terminate_is_grading_neutral():
    # The design invariant: an early-terminated run grades as a confirmed solve
    # exactly as a full run would. Feed the returned response through the SAME
    # grading path the runner uses (extract_flags_from_run → strict filter →
    # determine_outcome) and assert it's a success.
    import re as _re

    from ctf_solver.ui.core import determine_outcome, extract_flags_from_run

    agent, _ = _agent("out: HTB{gr4d3_n3utr4l}", max_steps=10)
    response = asyncio.run(agent.arun("solve"))
    candidates = extract_flags_from_run(response, [], DEFAULT_FLAG_REGEX, dedup=True)
    confirmed = [c for c in candidates if _re.search(DEFAULT_STRICT_FLAG_REGEX, c)]
    assert confirmed == ["HTB{gr4d3_n3utr4l}"]
    assert determine_outcome(confirmed, []) == "success"


# ---------------------------------------------------------------------------
# config plumbing
# ---------------------------------------------------------------------------


def test_config_default_on():
    assert SolverConfig().auto_submit_confirmed_flag is True


def test_config_from_env_disable(monkeypatch):
    for val in ("0", "false", "no", "FALSE"):
        monkeypatch.setenv("CTF_AUTO_SUBMIT_FLAG", val)
        assert SolverConfig.from_env().auto_submit_confirmed_flag is False


def test_config_from_env_default_and_explicit_on(monkeypatch):
    monkeypatch.delenv("CTF_AUTO_SUBMIT_FLAG", raising=False)
    assert SolverConfig.from_env().auto_submit_confirmed_flag is True
    monkeypatch.setenv("CTF_AUTO_SUBMIT_FLAG", "true")
    assert SolverConfig.from_env().auto_submit_confirmed_flag is True


def test_config_merge_with_args_preserves():
    base = SolverConfig(auto_submit_confirmed_flag=False)
    merged = base.merge_with_args()
    assert merged.auto_submit_confirmed_flag is False
