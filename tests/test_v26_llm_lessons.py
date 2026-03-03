"""
Tests for v2.6.0: LLM-enhanced lessons generation via gpt-4o-mini.

All LLM calls are mocked — no real API calls are made.
"""

import json
from unittest.mock import MagicMock, patch

from ctf_solver.failure_analyzer import (
    LessonsLearnedDoc,
    _llm_enhance_doc,
    analyze_run,
    run_lessons_learned_pipeline,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

FLAG = "CTF{test_flag_value}"

TOOL_CALL_LOG = [
    {"tool": "http_fetch", "input": '{"url": "http://t/"}', "output": "<html>Hello</html>"},
    {"tool": "ssti_probe", "input": '{"url": "http://t/", "data": {"n": "{{7*7}}"}}', "output": "Hello 49!"},
    {
        "tool": "form_submit",
        "input": '{"url": "http://t/", "data": {"n": "{{config.items()}}"}}',
        "output": f"Hello {FLAG}!",
    },
]


def _make_doc(**kwargs) -> LessonsLearnedDoc:
    """Build a minimal LessonsLearnedDoc for testing."""
    from ctf_solver.failure_analyzer import AtomicRule

    defaults = dict(
        challenge_name="SSTI1",
        challenge_url="http://t/",
        outcome="success",
        category="ssti",
        total_steps=3,
        tool_sequence=["http_fetch", "ssti_probe", "form_submit"],
        partial_successes=["ssti_confirmed"],
        missed_signals=[],
        failed_approaches=[],
        template_engine="Jinja2/Twig",
        winning_inputs=['form_submit: {"name": "{{config.items()}}"}'],
        causal_diagnosis="Original diagnosis",
        reflexion_summary="Original summary.",
        atomic_rules=[
            AtomicRule(
                triggering_condition="When facing SSTI",
                agent_takeaway="Use ssti_probe",
                rule_type="do",
                tool_context=["ssti_probe"],
                causal_explanation="Original rule 0 explanation",
            ),
            AtomicRule(
                triggering_condition="When SSTI confirmed",
                agent_takeaway="Use config.items()",
                rule_type="do",
                tool_context=["form_submit"],
                causal_explanation="Original rule 1 explanation",
            ),
        ],
    )
    defaults.update(kwargs)
    return LessonsLearnedDoc(**defaults)


def _make_llm_json(
    reflexion="LLM reflexion summary.",
    causal="LLM causal explanation.",
    rule_explanations=None,
):
    if rule_explanations is None:
        rule_explanations = ["LLM rule 0 causal.", "LLM rule 1 causal."]
    return json.dumps(
        {
            "reflexion_summary": reflexion,
            "causal_explanation": causal,
            "rule_causal_explanations": rule_explanations,
        }
    )


# ---------------------------------------------------------------------------
# _llm_enhance_doc — happy path
# ---------------------------------------------------------------------------


def test_llm_enhance_doc_updates_reflexion_summary():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(reflexion="Brand new reflexion.")

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.reflexion_summary == "Brand new reflexion."


def test_llm_enhance_doc_updates_causal_diagnosis():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(causal="Template variable evaluated server-side.")

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.causal_diagnosis == "Template variable evaluated server-side."


def test_llm_enhance_doc_updates_rule_causal_explanations():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(rule_explanations=["Rule 0 LLM.", "Rule 1 LLM."])

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.atomic_rules[0].causal_explanation == "Rule 0 LLM."
    assert result.atomic_rules[1].causal_explanation == "Rule 1 LLM."


# ---------------------------------------------------------------------------
# _llm_enhance_doc — fallback on errors
# ---------------------------------------------------------------------------


def test_llm_enhance_doc_fallback_on_adapter_exception():
    doc = _make_doc()
    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_create.side_effect = RuntimeError("Network error")
        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    # Original fields unchanged
    assert result.reflexion_summary == "Original summary."
    assert result.causal_diagnosis == "Original diagnosis"
    assert result.atomic_rules[0].causal_explanation == "Original rule 0 explanation"


def test_llm_enhance_doc_fallback_on_invoke_exception():
    doc = _make_doc()
    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.side_effect = ConnectionError("Timeout")
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.reflexion_summary == "Original summary."
    assert result.causal_diagnosis == "Original diagnosis"


def test_llm_enhance_doc_fallback_on_invalid_json():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = "this is not json at all"

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.reflexion_summary == "Original summary."


def test_llm_enhance_doc_strips_markdown_fences():
    """gpt-4o-mini sometimes wraps JSON in ```json ... ``` fences."""
    doc = _make_doc()
    inner = _make_llm_json(reflexion="Fenced reflexion.")
    mock_response = MagicMock()
    mock_response.content = f"```json\n{inner}\n```"

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.reflexion_summary == "Fenced reflexion."


# ---------------------------------------------------------------------------
# _llm_enhance_doc — flag scrubbing (defense in depth)
# ---------------------------------------------------------------------------


def test_llm_enhance_doc_scrubs_flag_in_reflexion():
    """If LLM somehow includes a flag-like string, post-scrub catches it."""
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(
        reflexion=f"The flag was {FLAG} which gave access.",
        causal="Normal causal.",
    )

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert FLAG not in result.reflexion_summary
    assert "[FLAG_REDACTED]" in result.reflexion_summary


def test_llm_enhance_doc_scrubs_flag_in_causal():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(causal=f"Flag value {FLAG} was returned.")

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert FLAG not in result.causal_diagnosis
    assert "[FLAG_REDACTED]" in result.causal_diagnosis


def test_llm_enhance_doc_scrubs_flag_in_rule_explanations():
    doc = _make_doc()
    mock_response = MagicMock()
    mock_response.content = _make_llm_json(
        rule_explanations=[f"Rule leaks {FLAG}.", "Normal rule."]
    )

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert FLAG not in result.atomic_rules[0].causal_explanation
    assert "[FLAG_REDACTED]" in result.atomic_rules[0].causal_explanation


# ---------------------------------------------------------------------------
# _llm_enhance_doc — partial rule list (no IndexError)
# ---------------------------------------------------------------------------


def test_llm_enhance_doc_partial_rule_list():
    """LLM returns fewer explanations than rules — only existing indices updated."""
    doc = _make_doc()  # 2 rules
    mock_response = MagicMock()
    # Only 1 explanation for 2 rules
    mock_response.content = _make_llm_json(rule_explanations=["Only rule 0."])

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    assert result.atomic_rules[0].causal_explanation == "Only rule 0."
    # Rule 1 falls back to original
    assert result.atomic_rules[1].causal_explanation == "Original rule 1 explanation"


# ---------------------------------------------------------------------------
# Prompt content: flag values must NOT appear in the user prompt
# ---------------------------------------------------------------------------


def test_llm_enhance_doc_prompt_does_not_contain_flag():
    """Pre-scrubbing must remove the flag value before it reaches the LLM."""
    doc = _make_doc()
    captured_messages = []

    def capture_invoke(messages, **kwargs):
        captured_messages.extend(messages)
        return MagicMock(content=_make_llm_json())

    with patch("ctf_solver.llm.create_adapter") as mock_create:
        mock_adapter = MagicMock()
        mock_adapter.invoke.side_effect = capture_invoke
        mock_create.return_value = mock_adapter

        _llm_enhance_doc(doc, TOOL_CALL_LOG, openai_api_key="sk-test")

    # The raw flag must not appear in any message sent to the LLM
    all_content = " ".join(m.content for m in captured_messages)
    assert FLAG not in all_content


# ---------------------------------------------------------------------------
# analyze_run wiring
# ---------------------------------------------------------------------------


def test_analyze_run_calls_llm_enhance_when_enabled():
    config_data = {"challenge_url": "http://t/", "challenge_name": "SSTI1"}
    tracker_data = {"tool_calls": {"http_fetch": 1, "ssti_probe": 1, "form_submit": 1}}

    with patch("ctf_solver.failure_analyzer._llm_enhance_doc") as mock_enhance:
        mock_enhance.side_effect = lambda doc, *a, **kw: doc  # pass-through
        analyze_run(
            config_data, tracker_data, TOOL_CALL_LOG, None, [FLAG],
            use_llm=True, openai_api_key="sk-test",
        )
    mock_enhance.assert_called_once()


def test_analyze_run_skips_llm_when_disabled():
    config_data = {"challenge_url": "http://t/", "challenge_name": "SSTI1"}
    tracker_data = {"tool_calls": {"http_fetch": 1, "ssti_probe": 1, "form_submit": 1}}

    with patch("ctf_solver.failure_analyzer._llm_enhance_doc") as mock_enhance:
        analyze_run(
            config_data, tracker_data, TOOL_CALL_LOG, None, [FLAG],
            use_llm=False,
        )
    mock_enhance.assert_not_called()


def test_analyze_run_skips_llm_when_no_api_key():
    config_data = {"challenge_url": "http://t/", "challenge_name": "SSTI1"}
    tracker_data = {"tool_calls": {"http_fetch": 1, "ssti_probe": 1, "form_submit": 1}}

    with patch("ctf_solver.failure_analyzer._llm_enhance_doc") as mock_enhance:
        analyze_run(
            config_data, tracker_data, TOOL_CALL_LOG, None, [FLAG],
            use_llm=True, openai_api_key="",
        )
    mock_enhance.assert_not_called()


# ---------------------------------------------------------------------------
# run_lessons_learned_pipeline wiring
# ---------------------------------------------------------------------------


def test_pipeline_passes_use_llm_to_analyze_run(tmp_path):
    config_data = {"challenge_url": "http://t/", "challenge_name": "SSTI1"}
    tracker_data = {"tool_calls": {"http_fetch": 1, "ssti_probe": 1, "form_submit": 1}}

    with patch("ctf_solver.failure_analyzer.analyze_run", wraps=analyze_run) as mock_analyze:
        run_lessons_learned_pipeline(
            config_data, tracker_data, TOOL_CALL_LOG, None, [FLAG],
            lessons_docs_dir=str(tmp_path),
            use_llm=True,
            openai_api_key="sk-test",
            lessons_llm_model="gpt-4o-mini",
        )
    call_kwargs = mock_analyze.call_args.kwargs
    assert call_kwargs["use_llm"] is True
    assert call_kwargs["openai_api_key"] == "sk-test"
    assert call_kwargs["lessons_llm_model"] == "gpt-4o-mini"


def test_pipeline_use_llm_false_by_default(tmp_path):
    config_data = {"challenge_url": "http://t/", "challenge_name": "SSTI1"}
    tracker_data = {"tool_calls": {"http_fetch": 1, "ssti_probe": 1, "form_submit": 1}}

    with patch("ctf_solver.failure_analyzer.analyze_run", wraps=analyze_run) as mock_analyze:
        run_lessons_learned_pipeline(
            config_data, tracker_data, TOOL_CALL_LOG, None, [FLAG],
            lessons_docs_dir=str(tmp_path),
        )
    call_kwargs = mock_analyze.call_args.kwargs
    assert call_kwargs["use_llm"] is False


# ---------------------------------------------------------------------------
# SolverConfig new fields
# ---------------------------------------------------------------------------


def test_solver_config_new_fields_defaults():
    from ctf_solver.config import SolverConfig

    config = SolverConfig()
    assert config.use_llm_for_lessons is False
    assert config.lessons_llm_model == "gpt-4o-mini"


def test_solver_config_env_use_llm_for_lessons(monkeypatch):
    monkeypatch.setenv("CTF_LLM_LESSONS", "true")
    monkeypatch.setenv("CTF_LESSONS_MODEL", "gpt-4o")
    from ctf_solver.config import SolverConfig

    config = SolverConfig.from_env()
    assert config.use_llm_for_lessons is True
    assert config.lessons_llm_model == "gpt-4o"
