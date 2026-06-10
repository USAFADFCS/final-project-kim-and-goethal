"""Parity-sprint item #1: the batch grader must agree with the runner's own
confirmed-flag verdict by construction.

The runner (``ctf_solver/runner.py``) prints ``[FLAG DETECTED] <flag>`` for
every strict-regex-confirmed flag and ``[FLAG CANDIDATE] <flag>`` for broad
audit-only hits, then stores the former in ``RunTracker.confirmed_flags_found``.
``ctf_solver/log_grader.grade_log_text`` greps the ``[FLAG DETECTED]`` marker,
so it tracks ``confirmed_flags_found`` without re-implementing the regex.

These tests pin three things:
1. ``grade_log_text`` unit behavior (detect, ignore candidates, capture value).
2. Parity: for arbitrary runs, the marker-grade equals the strict-regex path
   that the runner uses to populate ``confirmed_flags_found``.
3. Regression: the real obs7 logs re-grade to the hand-corrected ``_v2`` TSV
   (the old case-sensitive grep had scored every row "no").
"""

import csv
import re
import subprocess
import sys
from pathlib import Path

import pytest

from ctf_solver.config import DEFAULT_FLAG_REGEX, DEFAULT_STRICT_FLAG_REGEX
from ctf_solver.log_grader import grade_log_text
from ctf_solver.ui.core import extract_flags_from_run

REPO_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = REPO_ROOT / "out" / "batch_window_test"


def _render_runner_markers(confirmed: list[str], candidates: list[str]) -> str:
    """Reproduce the exact stdout the runner emits for flags (runner.py).

    ``print(f"\\n[FLAG DETECTED] {flag}")`` for confirmed,
    ``print(f"\\n[FLAG CANDIDATE] {flag}")`` for the rest.
    """
    lines = []
    for flag in confirmed:
        lines.append(f"\n[FLAG DETECTED] {flag}")
    for flag in candidates:
        if flag not in confirmed:
            lines.append(f"\n[FLAG CANDIDATE] {flag}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 1. Unit behavior
# ---------------------------------------------------------------------------


def test_detects_metactf_marker():
    text = "some log\n\n[FLAG DETECTED] MetaCTF{capital_c_solve}\nmore log\n"
    seen, flag = grade_log_text(text)
    assert seen is True
    assert flag == "MetaCTF{capital_c_solve}"


def test_no_marker_returns_false_none():
    text = "agent did stuff\nno flag here\n[FLAG CANDIDATE] try{not_a_flag}\n"
    seen, flag = grade_log_text(text)
    assert seen is False
    assert flag is None


def test_candidate_marker_is_ignored():
    # A broad-match false positive (JS object literal) must NOT count.
    text = "\n[FLAG CANDIDATE] try{u||null==r.return||r.return()}\n"
    seen, flag = grade_log_text(text)
    assert seen is False
    assert flag is None


def test_first_confirmed_flag_is_captured():
    text = "\n[FLAG DETECTED] MetaCTF{first}\n" "\n[FLAG DETECTED] MetaCTF{second}\n"
    seen, flag = grade_log_text(text)
    assert seen is True
    assert flag == "MetaCTF{first}"


def test_flag_value_is_stripped():
    text = "\n[FLAG DETECTED]    MetaCTF{padded}   \n"
    seen, flag = grade_log_text(text)
    assert seen is True
    assert flag == "MetaCTF{padded}"


def test_marker_must_be_line_anchored():
    # An inline mention inside prose must not be graded as a confirmed flag.
    text = "the agent said [FLAG DETECTED] MetaCTF{inline} in a sentence\n"
    seen, flag = grade_log_text(text)
    assert seen is False
    assert flag is None


# ---------------------------------------------------------------------------
# 2. Parity with the runner's strict-regex path
# ---------------------------------------------------------------------------


def _confirmed_via_runner_path(response: str, tool_log: list[dict]) -> list[str]:
    """Mirror runner.py: broad extract → strict filter → confirmed flags."""
    candidates = extract_flags_from_run(
        response, tool_log, DEFAULT_FLAG_REGEX, dedup=True
    )
    strict = re.compile(DEFAULT_STRICT_FLAG_REGEX)
    return [f for f in candidates if strict.search(f)]


@pytest.mark.parametrize(
    "response,tool_log",
    [
        # Real solve: MetaCTF flag in the final answer.
        ("Found it: MetaCTF{capital_c_works}", []),
        # Flag surfaced in a tool output, not the response.
        ("done", [{"output": "page body MetaCTF{from_tool_output}"}]),
        # False positive only: a JS object literal, no real flag.
        ("here is code try{x()}finally{y()}", []),
        # Mixed: one real flag + one false positive.
        (
            "MetaCTF{the_real_one}",
            [{"output": "slate:{also_shaped_like_a_flag}"}],
        ),
        # No flags at all.
        ("could not solve the challenge", [{"output": "404 not found"}]),
        # picoCTF prefix (also strict-listed).
        ("picoCTF{another_platform}", []),
    ],
)
def test_marker_grade_matches_confirmed_flags(response, tool_log):
    confirmed = _confirmed_via_runner_path(response, tool_log)
    candidates = extract_flags_from_run(
        response, tool_log, DEFAULT_FLAG_REGEX, dedup=True
    )
    stdout = _render_runner_markers(confirmed, candidates)

    seen, flag = grade_log_text(stdout)

    # flag_seen agrees with "did the runner confirm any flag".
    assert seen is bool(confirmed)
    # When confirmed, the captured value is the runner's first confirmed flag.
    if confirmed:
        assert flag == confirmed[0]
    else:
        assert flag is None


# ---------------------------------------------------------------------------
# 3. Regression: re-grade the real obs7 logs against the hand-corrected v2 TSV
# ---------------------------------------------------------------------------


def _load_v2_truth(path: Path) -> dict[str, tuple[str, str]]:
    """Read a hand-corrected *_v2.tsv → {slug: (flag_seen, flag)}."""
    truth: dict[str, tuple[str, str]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            truth[row["slug"]] = (row["flag_seen"], row["flag"])
    return truth


@pytest.mark.parametrize("config_label", ["obs7", "baseline"])
def test_real_logs_regrade_matches_v2(config_label):
    """The mechanical re-grade of the saved logs must agree row-for-row with
    the hand-corrected ``summary_<label>_v2.tsv`` ground truth."""
    logs_dir = BATCH_DIR / f"logs_{config_label}"
    v2_path = BATCH_DIR / f"summary_{config_label}_v2.tsv"
    if not logs_dir.is_dir() or not v2_path.is_file():
        pytest.skip(f"fixtures for {config_label} not present")

    truth = _load_v2_truth(v2_path)
    assert truth, "expected at least one row in the v2 ground-truth TSV"

    for slug, (want_seen, want_flag) in truth.items():
        log_file = logs_dir / f"{slug}.log"
        assert log_file.is_file(), f"missing log for {slug}"
        seen, flag = grade_log_text(log_file.read_text(encoding="utf-8"))

        got_seen = "yes" if seen else "no"
        assert (
            got_seen == want_seen
        ), f"{config_label}/{slug}: grader said {got_seen}, v2 says {want_seen}"
        if want_seen == "yes":
            # The hand-corrected baseline livestream row is a known false
            # positive (a JS literal `try{...}` that the strict marker
            # correctly rejects). Where v2 records a *real* MetaCTF/picoCTF
            # flag, the marker grade must reproduce it exactly.
            if want_flag.startswith(("MetaCTF{", "picoCTF{")):
                assert (
                    flag == want_flag
                ), f"{config_label}/{slug}: grader flag {flag!r} != {want_flag!r}"


# ---------------------------------------------------------------------------
# 4. The CLI entrypoint the shell calls produces tab-separated output
# ---------------------------------------------------------------------------


def test_cli_entrypoint_tab_separated(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("\n[FLAG DETECTED] MetaCTF{cli_path}\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "ctf_solver.log_grader", str(log)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=True,
    ).stdout.strip()
    assert out == "yes\tMetaCTF{cli_path}"


def test_cli_entrypoint_no_flag(tmp_path):
    log = tmp_path / "run.log"
    log.write_text("no flag here\n[FLAG CANDIDATE] try{x}\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "ctf_solver.log_grader", str(log)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=True,
    ).stdout.strip()
    assert out == "no\t-"
