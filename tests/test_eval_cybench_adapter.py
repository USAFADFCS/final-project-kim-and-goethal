"""Cybench adapter: metadata parsing, flag extraction, TaskRunCompletion
emission, web-only filter, Docker guard.

Docker is absent here, so ``_require_docker`` genuinely raises (asserted), and
container-driven paths use ``start_container=False``.
"""

import json

import pytest

from ctf_solver.eval import cybench_adapter as cba
from ctf_solver.eval._core import RunResult


def _write_metadata(task_dir, metadata):
    meta_dir = task_dir / "metadata"
    meta_dir.mkdir(parents=True, exist_ok=True)
    (meta_dir / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")


_WEB_META = {
    "categories": ["web"],
    "target_host": "web_flag:1337",
    "hard_prompt": "minimal prompt",
    "easy_prompt": "prompt with hints",
    "subtasks": [
        {"question": "find api", "answer": "web_flag:1337/api"},
        {"question": "flag?", "answer": "HTB{the_real_flag}"},
    ],
}


# ---------------------------------------------------------------------------
# Metadata parsing + flag extraction
# ---------------------------------------------------------------------------


def test_parse_metadata_web(tmp_path):
    _write_metadata(tmp_path, _WEB_META)
    task = cba.parse_cybench_metadata(tmp_path)
    assert task.is_web is True
    assert task.target_host == "web_flag:1337"
    assert task.target_url == "http://web_flag:1337"
    assert task.flag == "HTB{the_real_flag}"
    assert task.prompt == "minimal prompt"  # hard by default
    assert task.num_subtasks == 2


def test_parse_metadata_easy_prompt(tmp_path):
    _write_metadata(tmp_path, _WEB_META)
    task = cba.parse_cybench_metadata(tmp_path, prompt_style="easy")
    assert task.prompt == "prompt with hints"


def test_non_web_task(tmp_path):
    _write_metadata(tmp_path, {**_WEB_META, "categories": ["crypto"]})
    task = cba.parse_cybench_metadata(tmp_path)
    assert task.is_web is False


def test_extract_flag_picks_flag_shaped_answer():
    meta = {
        "subtasks": [
            {"answer": "not a flag"},
            {"answer": "HTB{flagged}"},
            {"answer": "also not"},
        ]
    }
    assert cba._extract_flag(meta) == "HTB{flagged}"


def test_extract_flag_falls_back_to_last_answer():
    meta = {"subtasks": [{"answer": "alpha"}, {"answer": "omega"}]}
    assert cba._extract_flag(meta) == "omega"


def test_extract_flag_none_when_no_answers():
    assert cba._extract_flag({"subtasks": []}) is None


def test_target_url_does_not_double_scheme():
    task = cba.CybenchTask(
        name="x",
        task_dir=None,
        categories=["web"],
        target_host="http://h:1",
        prompt="",
        flag=None,
    )
    assert task.target_url == "http://h:1"


# ---------------------------------------------------------------------------
# TaskRunCompletion emission
# ---------------------------------------------------------------------------


def _result(solved, tool_log=None, response="answer text"):
    return RunResult(
        challenge="x",
        solved=solved,
        response=response,
        duration_seconds=2.0,
        stats={
            "tool_call_log": tool_log or [],
            "actual_prompt_tokens": 500,
            "actual_completion_tokens": 50,
            "total_tokens_est": 550,
        },
    )


def test_build_completion_score_and_flag_in_stdout():
    task = cba.CybenchTask(
        name="flagcmd",
        task_dir="/tasks/flagcmd",
        categories=["web"],
        target_host="web_flag:1337",
        prompt="p",
        flag="HTB{x}",
    )
    result = _result(
        True,
        tool_log=[{"tool": "http_fetch", "input": "GET /", "output": "page HTB{x}"}],
    )
    completion = cba.build_task_run_completion(result, task)

    assert completion["num_correct_subtasks"] == 1
    sub = completion["subtask_completions"]["subtask_1"]
    assert sub["score"] == 1
    assert sub["completion_status"] == "answered"
    # The flag appears in an iteration stdout (what grade_benchmark substring-scans).
    stdouts = [it["execution_output"]["stdout"] for it in sub["iterations"]]
    assert any("HTB{x}" in s for s in stdouts)
    # tool-call iterations + 1 trailing response iteration
    assert len(sub["iterations"]) == 2
    assert completion["ctf_solver_replay"] is True


def test_build_completion_unsolved_score_zero():
    task = cba.CybenchTask(
        name="x",
        task_dir="/t",
        categories=["web"],
        target_host="h:1",
        prompt="p",
        flag="HTB{x}",
    )
    completion = cba.build_task_run_completion(_result(False), task)
    assert completion["num_correct_subtasks"] == 0
    assert completion["subtask_completions"]["subtask_1"]["score"] == 0
    assert (
        completion["subtask_completions"]["subtask_1"]["completion_status"]
        == "not_answered"
    )


def test_build_completion_includes_synthetic_flag_subtask():
    # grade_benchmark.py reads challenge_task['subtasks'][0]['answer'] directly;
    # it MUST exist and carry the real (final) flag, or the grader KeyErrors /
    # scans for the wrong string. Regression for review findings #6 and #7.
    task = cba.CybenchTask(
        name="x",
        task_dir="/t",
        categories=["web"],
        target_host="h:1",
        prompt="p",
        flag="HTB{final_flag}",
    )
    completion = cba.build_task_run_completion(_result(True), task)
    subtasks = completion["task"]["subtasks"]
    assert isinstance(subtasks, list) and len(subtasks) == 1
    assert subtasks[0]["answer"] == "HTB{final_flag}"


def test_build_completion_flag_subtask_handles_missing_flag():
    # When flag extraction failed, answer must be "" (not None) so the grader's
    # re.search(pattern, flag) does not crash.
    task = cba.CybenchTask(
        name="x",
        task_dir="/t",
        categories=["web"],
        target_host="h:1",
        prompt="p",
        flag=None,
    )
    completion = cba.build_task_run_completion(_result(False), task)
    assert completion["task"]["subtasks"][0]["answer"] == ""


# ---------------------------------------------------------------------------
# run_cybench_task orchestration (no Docker)
# ---------------------------------------------------------------------------


def test_run_cybench_writes_json_and_returns_result(tmp_path, monkeypatch):
    _write_metadata(tmp_path, _WEB_META)
    logs = tmp_path / "logs"

    def fake_run(**kwargs):
        assert kwargs["url"] == "http://web_flag:1337"
        assert kwargs["expected_flag"] == "HTB{the_real_flag}"
        return _result(
            True,
            tool_log=[{"tool": "http_fetch", "output": "HTB{the_real_flag}"}],
        )

    monkeypatch.setattr(cba, "run_against_target_sync", fake_run)

    result = cba.run_cybench_task(tmp_path, start_container=False, logs_dir=logs)
    assert result.solved is True
    out_files = list(logs.glob("*_ctf_solver_replay.json"))
    assert len(out_files) == 1
    payload = json.loads(out_files[0].read_text())
    assert payload["num_correct_subtasks"] == 1


def test_run_cybench_non_web_raises(tmp_path, monkeypatch):
    _write_metadata(tmp_path, {**_WEB_META, "categories": ["pwn"]})
    monkeypatch.setattr(cba, "run_against_target_sync", lambda **k: _result(True))
    with pytest.raises(ValueError, match="web-only"):
        cba.run_cybench_task(tmp_path, start_container=False)


def test_require_docker_raises_when_missing(monkeypatch):
    monkeypatch.setattr(cba.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="Docker"):
        cba._require_docker()
